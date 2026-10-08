package aauth

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidIdentifier means an agent or server identifier does not
// conform to draft -11 §5.2 or §11.1.1.
var ErrInvalidIdentifier = errors.New("aauth: invalid identifier")

// MaxAgentLocalPartLength is the longest permitted agent identifier local
// part (draft -11 §5.2).
const MaxAgentLocalPartLength = 255

// AgentIdentifier is the parsed form of an AAuth agent identifier
// (draft -11 §5.2):
//
//	aauth:<name>@<domain>                    — a top-level agent
//	aauth:<name>+<discriminator>@<domain>    — a sub-agent (§10.2)
//
// The local part (name, plus "+discriminator" for a sub-agent) consists of
// ASCII letters, digits, "-", "_", "+", and "."; it is 1–255 characters,
// compared case-sensitively, and never case-folded. The domain is the
// agent provider's domain: a lowercase DNS name in ASCII (A-label) form,
// with no scheme, port, or path (§11.1.1).
//
// The identifier is stable across key rotations (it is the token's sub);
// keys are conveyed separately via cnf.jwk. The "+" split is for
// readability only — the parent_agent claim, not the local part, is the
// authoritative sub-agent marker.
type AgentIdentifier struct {
	Name          string // the agent name
	Discriminator string // sub-agent discriminator; non-empty marks a sub-agent
	Domain        string // the agent's domain
}

// ParseAgentIdentifier parses and validates an "aauth:" identifier string
// per draft -11 §5.2. Failures wrap [ErrInvalidIdentifier].
func ParseAgentIdentifier(s string) (AgentIdentifier, error) {
	var id AgentIdentifier
	rest, ok := strings.CutPrefix(s, "aauth:")
	if !ok {
		return id, fmt.Errorf("%w: %q missing aauth: prefix", ErrInvalidIdentifier, s)
	}
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return id, fmt.Errorf("%w: %q not in aauth:local@domain form", ErrInvalidIdentifier, s)
	}
	local, domain := rest[:at], rest[at+1:]
	if err := validateLocalPart(local); err != nil {
		return id, fmt.Errorf("%w: %q: %w", ErrInvalidIdentifier, s, err)
	}
	if err := validateDomain(domain); err != nil {
		return id, fmt.Errorf("%w: %q: %w", ErrInvalidIdentifier, s, err)
	}
	name, disc, isSub := strings.Cut(local, "+")
	if name == "" || (isSub && disc == "") {
		return id, fmt.Errorf("%w: %q: sub-agent local part must be parent+discriminator", ErrInvalidIdentifier, s)
	}
	return AgentIdentifier{Name: name, Discriminator: disc, Domain: domain}, nil
}

// validateLocalPart checks the agent identifier local part (§5.2).
func validateLocalPart(local string) error {
	if local == "" {
		return errors.New("empty local part")
	}
	if len(local) > MaxAgentLocalPartLength {
		return fmt.Errorf("local part exceeds %d characters", MaxAgentLocalPartLength)
	}
	for i := 0; i < len(local); i++ {
		if !isLocalPartChar(local[i]) {
			return fmt.Errorf("local part contains %q", local[i])
		}
	}
	return nil
}

func isLocalPartChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '_' || c == '+' || c == '.'
}

// validateDomain checks a host per the server identifier rules (§11.1.1):
// a lowercase ASCII DNS name (internationalized names in A-label form) with
// no scheme, port, path, or trailing dot.
func validateDomain(d string) error {
	if d == "" {
		return errors.New("empty domain")
	}
	if len(d) > 253 {
		return errors.New("domain exceeds 253 characters")
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return fmt.Errorf("domain %q has an empty label", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("domain label %q exceeds 63 characters", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domain label %q begins or ends with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			case c >= 'A' && c <= 'Z':
				return fmt.Errorf("domain %q is not lowercase", d)
			default:
				return fmt.Errorf("domain %q contains %q (internationalized names use A-labels)", d, c)
			}
		}
	}
	return nil
}

// ValidateServerIdentifier checks an issuer value against draft -11
// §11.1.1: the https scheme and a host only — no port, path, query,
// fragment, or trailing slash — lowercase, with internationalized names in
// A-label form. Failures wrap [ErrInvalidIdentifier]. Server identifiers
// are compared by exact string equality.
func ValidateServerIdentifier(s string) error {
	host, ok := strings.CutPrefix(s, "https://")
	if !ok {
		return fmt.Errorf("%w: %q does not use the https scheme", ErrInvalidIdentifier, s)
	}
	if i := strings.IndexAny(host, "/?#:@"); i >= 0 {
		return fmt.Errorf("%w: %q must contain only scheme and host (found %q)", ErrInvalidIdentifier, s, host[i])
	}
	if err := validateDomain(host); err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalidIdentifier, s, err)
	}
	return nil
}

// String renders the canonical identifier form.
func (a AgentIdentifier) String() string {
	if a.Discriminator != "" {
		return fmt.Sprintf("aauth:%s+%s@%s", a.Name, a.Discriminator, a.Domain)
	}
	return fmt.Sprintf("aauth:%s@%s", a.Name, a.Domain)
}

// IsSubAgent reports whether the identifier carries a sub-agent discriminator.
func (a AgentIdentifier) IsSubAgent() bool { return a.Discriminator != "" }

// SubAgent derives a sub-agent identifier under this agent (draft -11
// §10.2: single level only — deriving from a sub-agent is an error). The
// discriminator is non-empty, uses the local-part characters other than
// "+", and the resulting local part fits in 255 characters.
func (a AgentIdentifier) SubAgent(discriminator string) (AgentIdentifier, error) {
	if a.IsSubAgent() {
		return AgentIdentifier{}, fmt.Errorf("aauth: %s is already a sub-agent (single-level rule)", a)
	}
	if discriminator == "" || strings.Contains(discriminator, "+") {
		return AgentIdentifier{}, fmt.Errorf("%w: sub-agent discriminator %q", ErrInvalidIdentifier, discriminator)
	}
	if err := validateLocalPart(a.Name + "+" + discriminator); err != nil {
		return AgentIdentifier{}, fmt.Errorf("%w: sub-agent discriminator %q: %w", ErrInvalidIdentifier, discriminator, err)
	}
	return AgentIdentifier{Name: a.Name, Discriminator: discriminator, Domain: a.Domain}, nil
}

// Parent returns the parent identifier of a sub-agent.
func (a AgentIdentifier) Parent() (AgentIdentifier, error) {
	if !a.IsSubAgent() {
		return AgentIdentifier{}, fmt.Errorf("aauth: %s is not a sub-agent", a)
	}
	return AgentIdentifier{Name: a.Name, Domain: a.Domain}, nil
}
