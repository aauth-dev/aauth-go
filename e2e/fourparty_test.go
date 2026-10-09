package e2e_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// TestFourPartyDeployment runs the same scenario with the access server on
// its own origin (§9.1): the person server federates to it over HTTP,
// signing as the PS under the jwks_uri scheme, the AS issues the auth token
// for resource B under its own issuer, and revocation travels between the
// servers by their revocation endpoints rather than in-process.
func TestFourPartyDeployment(t *testing.T) {
	d := newDeployment(t, fourParty)
	if d.asURL == d.psURL {
		t.Fatalf("four-party deployment shares an origin: %s", d.psURL)
	}

	t.Run("the access server is discoverable on its own origin", func(t *testing.T) {
		var md aauth.AccessServerMetadata
		if err := aauth.FetchMetadata(context.Background(), http.DefaultClient, d.asURL, aauth.WellKnownAccess, &md); err != nil {
			t.Fatal(err)
		}
		if err := md.Validate(); err != nil {
			t.Fatal(err)
		}
		if md.Issuer != d.asURL || md.RevocationEndpoint == "" {
			t.Fatalf("metadata %+v", md)
		}
	})

	runScenario(t, d)

	t.Run("federation and revocation crossed the network", func(t *testing.T) {
		// Nothing here is in-process: the PS reached the AS's token endpoint
		// and, on revocation, the AS's revocation endpoint over HTTP.
		var md aauth.AccessServerMetadata
		if err := aauth.FetchMetadata(context.Background(), http.DefaultClient, d.asURL, aauth.WellKnownAccess, &md); err != nil {
			t.Fatal(err)
		}
		for name, endpoint := range map[string]string{"token": md.AuthTokenEndpoint, "revocation": md.RevocationEndpoint} {
			path := strings.TrimPrefix(endpoint, d.asURL)
			if d.asHits(path) == 0 {
				t.Errorf("no request reached the AS %s endpoint %s", name, path)
			}
		}
	})
}
