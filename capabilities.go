package aauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"
)

// Capability values for the AAuth-Capabilities header and the capabilities
// request parameter (draft -11 §11.7; AAuth Capability Value registry,
// §15.9).
const (
	// CapabilityInteraction: the agent can get a user to a URL, directly or
	// through its PS's interaction endpoint.
	CapabilityInteraction = "interaction"
	// CapabilityClarification: the agent can engage in clarification chat
	// (§7.5).
	CapabilityClarification = "clarification"
	// CapabilityPayment: the agent can handle 402 payment flows, directly or
	// through its PS's interaction endpoint.
	CapabilityPayment = "payment"
)

// HeaderCapabilities is the AAuth-Capabilities request header name (§11.7).
const HeaderCapabilities = "AAuth-Capabilities"

// FormatCapabilities renders capability values as an AAuth-Capabilities
// header value: a Structured Field List of Tokens (RFC 9651 §3.1), in the
// order given with duplicates removed. A value that is not a valid Token
// is an error. An empty list renders as "".
func FormatCapabilities(caps []string) (string, error) {
	caps = UnionCapabilities(caps)
	if len(caps) == 0 {
		return "", nil
	}
	list := make(httpsfv.List, 0, len(caps))
	for _, c := range caps {
		list = append(list, httpsfv.NewItem(httpsfv.Token(c)))
	}
	v, err := httpsfv.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("aauth: invalid capability value in %q: %w", caps, err)
	}
	return v, nil
}

// ParseCapabilities parses AAuth-Capabilities field values (§11.7): a List
// of Tokens. Parameters are ignored, as recipients MUST ignore parameters
// they do not recognize; members that are not Tokens are skipped.
// Unrecognized values are returned for the caller to ignore. A malformed
// field is an error.
func ParseCapabilities(values []string) ([]string, error) {
	nonEmpty := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			nonEmpty = append(nonEmpty, v)
		}
	}
	if len(nonEmpty) == 0 {
		return nil, nil
	}
	list, err := httpsfv.UnmarshalList(nonEmpty)
	if err != nil {
		return nil, fmt.Errorf("aauth: malformed AAuth-Capabilities: %w", err)
	}
	caps := make([]string, 0, len(list))
	for _, m := range list {
		it, ok := m.(httpsfv.Item)
		if !ok {
			continue
		}
		if tok, ok := it.Value.(httpsfv.Token); ok {
			caps = append(caps, string(tok))
		}
	}
	return UnionCapabilities(caps), nil
}

// RequestCapabilities is the capabilities an agent declared on r with
// AAuth-Capabilities (§11.7). When the header is absent or malformed the
// result is empty: recipients MUST NOT assume any capabilities.
func RequestCapabilities(r *http.Request) []string {
	caps, err := ParseCapabilities(r.Header.Values(HeaderCapabilities))
	if err != nil {
		// A malformed header declares nothing; the resource then raises
		// only requirements that need no capability.
		return nil
	}
	return caps
}

// HasCapability reports whether caps contains c.
func HasCapability(caps []string, c string) bool {
	for _, v := range caps {
		if v == c {
			return true
		}
	}
	return false
}

// UnionCapabilities merges capability lists in order, dropping duplicates
// and empty values: an agent's capabilities are the union of what it can do
// directly and what its PS can do for it, including a mission approval's
// capabilities (§8.2, §11.7).
func UnionCapabilities(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, c := range l {
			if c != "" && !HasCapability(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

// CanRaise reports whether a resource may answer r with requirement: one
// that needs the agent to act — interaction (§11.6.3) or clarification
// (§7.5) — only when the request declared that capability with
// AAuth-Capabilities (§11.7). A resource that cannot raise a requirement
// declines in its own way (for example, refusing the request with an error
// rather than deferring). Every other requirement value may always be
// raised. The Challenge* and Write* helpers do not check this themselves,
// so existing resources keep their behavior; call CanRaise before them.
func CanRaise(r *http.Request, requirement string) bool {
	switch requirement {
	case RequirementInteraction:
		return HasCapability(RequestCapabilities(r), CapabilityInteraction)
	case RequirementClarification:
		return HasCapability(RequestCapabilities(r), CapabilityClarification)
	default:
		return true
	}
}

// CanRequirePayment reports whether r declared the payment capability, so a
// resource may answer 402 Payment Required and expect the agent to settle
// (§11.7).
func CanRequirePayment(r *http.Request) bool {
	return HasCapability(RequestCapabilities(r), CapabilityPayment)
}
