package aauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Call chaining (draft -11 §10.1.1): a resource that receives an authorized
// request may need to reach a downstream resource to fulfill it. It acts as
// an agent — its own agent provider, identity, and key (§10.1.1.1) — and
// routes its downstream token requests to the person server the upstream
// token names, presenting that token as upstream_token so the PS can issue
// for the same person and evaluate the request against the same mission.
// No delegation chain is carried in any token (Appendix C.1.11).

// ChainRouter tells an intermediary where to send downstream token requests
// and what to carry, derived from the upstream token per §10.1.1.
type ChainRouter struct {
	// PersonServer is the PS to send the downstream person token and auth
	// token requests to: the iss of an upstream person token, the ps of an
	// upstream auth token. Its endpoints are discovered from its metadata.
	PersonServer string
	// UpstreamToken is the raw upstream token to send as upstream_token.
	UpstreamToken string
	// MissionS256 is the mission the upstream token carries, if any; the PS
	// evaluates the downstream request against it. The intermediary does
	// not send mission_s256 of its own (§7.1).
	MissionS256 string
	// UpstreamExpiresAt is the upstream token's exp. Downstream person and
	// auth tokens expire no later; after it the intermediary uses a later
	// token from the calling agent.
	UpstreamExpiresAt time.Time
	// upstreamAud is the upstream token's audience: the intermediary's
	// resource identifier.
	upstreamAud string
}

// RouteDownstream computes the routing for a downstream call from the
// verified upstream token — the person token or auth token the calling
// agent presented on a request the intermediary served — and its raw form
// (§10.1.1). The ps claim in the intermediary's own agent token is NOT used:
// it names the intermediary's person server, not the person's.
func RouteDownstream(upstream PresentedToken, rawUpstream string) (ChainRouter, error) {
	if isNilPresented(upstream) || rawUpstream == "" {
		return ChainRouter{}, errors.New("aauth: RouteDownstream needs the verified upstream token")
	}
	v := upstream.presented()
	if v.ps == "" {
		return ChainRouter{}, fmt.Errorf("%w: upstream token names no person server", ErrInvalidToken)
	}
	var rc jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(rawUpstream, &rc); err != nil {
		return ChainRouter{}, fmt.Errorf("%w: upstream token: %w", ErrInvalidToken, err)
	}
	if rc.ID != v.jti {
		return ChainRouter{}, errors.New("aauth: RouteDownstream: the raw upstream token is not the verified one")
	}
	aud := ""
	if len(rc.Audience) == 1 {
		aud = rc.Audience[0]
	}
	return ChainRouter{
		PersonServer: v.ps, UpstreamToken: rawUpstream, MissionS256: v.missionS256,
		UpstreamExpiresAt: v.exp, upstreamAud: aud,
	}, nil
}

// PSClient returns a client for the person server the upstream token
// names, acting as intermediary — the intermediary's own agent identity,
// which signs every downstream request (§10.1.1).
func (r ChainRouter) PSClient(intermediary *Agent) *PSClient {
	return NewPSClient(r.PersonServer, intermediary)
}

// Transport returns a [Transport] for the intermediary's downstream calls
// (draft -11 §10.1.1): it obtains a person token for each downstream
// resource with the upstream token as upstream_token, presents it, and
// redeems the resource token at the same person server with the person
// token as presented_token and the upstream token as upstream_token, all
// signed with the intermediary's own key. No downstream token outlives the
// upstream token.
//
// The intermediary MUST be its own agent provider (§10.1.1.1): its agent
// token's iss is its resource identifier, the upstream token's aud. A
// different issuer is refused here, as a PS would refuse it with
// invalid_upstream_token. Use one Transport per upstream token: its caches
// hold tokens for that token's person.
func (r ChainRouter) Transport(intermediary *Agent) (*Transport, error) {
	switch {
	case intermediary == nil:
		return nil, errors.New("aauth: ChainRouter.Transport needs the intermediary agent")
	case r.UpstreamToken == "" || r.PersonServer == "":
		return nil, errors.New("aauth: ChainRouter has no upstream token; use RouteDownstream")
	case intermediary.Issuer != r.upstreamAud:
		return nil, fmt.Errorf("aauth: intermediary agent token iss %q is not the upstream token's aud %q; the intermediary must be its own agent provider (§10.1.1.1)", intermediary.Issuer, r.upstreamAud)
	}
	tr := NewTransport(intermediary, r.PSClient(intermediary))
	tr.UpstreamToken = r.UpstreamToken
	tr.UpstreamExpiresAt = r.UpstreamExpiresAt
	return tr, nil
}
