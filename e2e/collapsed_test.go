package e2e_test

import "testing"

// TestCollapsedDeployment runs one origin hosting an agent provider, a
// person server, and an access server (§4.3 org-wide bundle), with two
// resources: A, which uses the PS directly (three-party), and B, which
// chose the access server sharing the PS's origin (PS-AS collapse,
// §9.3.3). An agent whose key the hosting application registered for a
// work session reaches both, under a mission, through deferred approvals
// the application resolves; then the agent provider revokes the agent
// token and the revocation cascades to both resources.
func TestCollapsedDeployment(t *testing.T) {
	d := newDeployment(t, collapsed)
	if d.asURL != d.psURL {
		t.Fatalf("collapsed deployment has separate origins: ps %s, as %s", d.psURL, d.asURL)
	}
	runScenario(t, d)
}
