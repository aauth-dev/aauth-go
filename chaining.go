package aauth

import (
	"errors"
	"fmt"
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
	return ChainRouter{PersonServer: v.ps, UpstreamToken: rawUpstream, MissionS256: v.missionS256}, nil
}
