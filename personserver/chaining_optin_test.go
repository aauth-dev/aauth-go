package personserver

import (
	"context"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// Call chaining is refused unless the PS opts in, so a Decider written for
// ordinary requests never sees a chained request for a known person.
func TestCallChainingOffByDefault(t *testing.T) {
	w := newWorld(t, func(c *Config) { c.AllowCallChaining = false })
	ctx := context.Background()
	const r1 = "https://r1.example"
	upstream := w.personToken(w.agent, r1, "")
	inter := newAgent(t, "proxy", r1, "")
	w.pin(r1, inter.JWKS())
	decided := false
	w.setDecide(func(*TokenRequest) Decision {
		decided = true
		return Allow(Grant{})
	})
	_, err := w.psClient(inter).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: upstream})
	if tokenCode(err) != aauth.TokenErrInvalidUpstreamToken || decided {
		t.Fatalf("chained request: %v (decided %v)", err, decided)
	}
}
