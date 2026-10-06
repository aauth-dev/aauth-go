package aauth

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
)

// Requirement values used in the AAuth-Requirement header (draft -11
// §11.6.2; AAuth Requirement Value registry, §15.8).
const (
	RequirementAgentToken    = "agent-token"   // 401: the agent's identity (§6.1)
	RequirementPersonToken   = "person-token"  // 401: the person's identity (§6.4)
	RequirementAuthToken     = "auth-token"    // 401 or 202: consent or policy for a scope (§6.5)
	RequirementInteraction   = "interaction"   // 202: user action at an interaction URL (§11.6.3)
	RequirementApproval      = "approval"      // 202: approval pending from another party (§11.6.4)
	RequirementClarification = "clarification" // 202: a question for the recipient (§7.5.1)
	RequirementClaims        = "claims"        // 202: identity claims required, AS only (§9.2)
)

// HeaderRequirement is the AAuth-Requirement header name.
const HeaderRequirement = "AAuth-Requirement"

// Requirement is a parsed AAuth-Requirement header value (draft -11
// §11.6.1): a Structured Field Dictionary (RFC 9651 §3.2) whose requirement
// member is a Token, with requirement-specific data as parameters on that
// member, e.g.:
//
//	requirement=auth-token; resource-token="eyJ..."
//	requirement=interaction; url="https://ps.example/interaction"; code="A1B2-C3D4"
//	requirement=person-token
type Requirement struct {
	// Requirement is the requirement value, one of the Requirement*
	// constants or an extension value.
	Requirement string
	// ResourceToken accompanies requirement=auth-token.
	ResourceToken string
	// URL accompanies requirement=interaction (where the user goes).
	URL string
	// Code accompanies requirement=interaction (shown to the user).
	Code string
}

// String renders the header value: the requirement token followed by its
// parameters as quoted Strings, in the "; " style of the draft's examples
// (RFC 9651 permits the space after ";").
func (r Requirement) String() string {
	var b strings.Builder
	b.WriteString("requirement=")
	b.WriteString(r.Requirement)
	for _, p := range []struct{ name, v string }{
		{"resource-token", r.ResourceToken}, {"url", r.URL}, {"code", r.Code},
	} {
		if p.v != "" {
			fmt.Fprintf(&b, "; %s=%s", p.name, sfString(p.v))
		}
	}
	return b.String()
}

// ParseRequirement parses an AAuth-Requirement header value as a
// Structured Field Dictionary (draft -11 §11.6.1). The requirement member
// MUST be present and MUST be a Token. Its resource-token, url, and code
// parameters are read as Strings (Tokens are tolerated); unknown
// parameters and members are ignored (recipients MUST ignore unknown
// parameters).
func ParseRequirement(v string) (Requirement, error) {
	var r Requirement
	if strings.TrimSpace(v) == "" {
		return r, fmt.Errorf("aauth: empty AAuth-Requirement value")
	}
	dict, err := httpsfv.UnmarshalDictionary([]string{v})
	if err != nil {
		return r, fmt.Errorf("aauth: malformed AAuth-Requirement: %w", err)
	}
	m, ok := dict.Get("requirement")
	if !ok {
		return r, fmt.Errorf("aauth: AAuth-Requirement missing requirement member")
	}
	it, ok := m.(httpsfv.Item)
	if !ok {
		return r, fmt.Errorf("aauth: AAuth-Requirement requirement member is not an item")
	}
	tok, ok := it.Value.(httpsfv.Token)
	if !ok {
		return r, fmt.Errorf("aauth: AAuth-Requirement requirement member is not a token")
	}
	r.Requirement = string(tok)
	for _, p := range []struct {
		name string
		dst  *string
	}{{"resource-token", &r.ResourceToken}, {"url", &r.URL}, {"code", &r.Code}} {
		pv, ok := it.Params.Get(p.name)
		if !ok {
			continue
		}
		switch s := pv.(type) {
		case string:
			*p.dst = s
		case httpsfv.Token:
			*p.dst = string(s)
		default:
			return r, fmt.Errorf("aauth: AAuth-Requirement %s parameter is not a string", p.name)
		}
	}
	return r, nil
}

// ChallengeAgentToken answers 401 with requirement=agent-token (§6.1): the
// resource decides on the agent's identity and the request presented no
// AAuth agent token.
func ChallengeAgentToken(w http.ResponseWriter) {
	w.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementAgentToken}.String())
	w.WriteHeader(http.StatusUnauthorized)
}

// ChallengePersonToken answers 401 with requirement=person-token (§6.4):
// the resource needs to know which person the agent acts for and has not
// verified a person token on the request. A resource MUST answer this way
// at its authorization endpoint when the request carries no person token,
// and whenever it would otherwise issue a resource token without having
// verified a person or auth token (§6.7; see [ErrPresentedTokenRequired]).
func ChallengePersonToken(w http.ResponseWriter) {
	w.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementPersonToken}.String())
	w.WriteHeader(http.StatusUnauthorized)
}

// ChallengeAuthToken answers 401 with requirement=auth-token and the
// resource token (§6.5); see [IssueResourceToken].
func ChallengeAuthToken(w http.ResponseWriter, resourceToken string) {
	w.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementAuthToken, ResourceToken: resourceToken}.String())
	w.WriteHeader(http.StatusUnauthorized)
}

// WriteApprovalPending writes a requirement=approval deferred response
// (§11.6.4): the server is obtaining approval from another party — by push
// notification, email, or administrator review — and the agent polls
// pendingURL until a terminal response, with no user action on its side.
// The response carries Location and Retry-After (retryAfter seconds), as
// it MUST.
func WriteApprovalPending(w http.ResponseWriter, pendingURL string, retryAfter int) {
	if retryAfter < 0 {
		retryAfter = 0
	}
	h := w.Header()
	h.Set(HeaderLocation, pendingURL)
	h.Set(HeaderRetryAfter, strconv.Itoa(retryAfter))
	h.Set("Cache-Control", "no-store")
	h.Set(HeaderRequirement, Requirement{Requirement: RequirementApproval}.String())
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_, _ = w.Write([]byte(`{"status":"pending"}` + "\n"))
}
