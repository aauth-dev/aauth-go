// Package e2e holds end-to-end tests that run the agent provider, person
// server, and access server packages together with an agent and
// resources, as a hosting application would deploy them.
//
// TestCollapsedDeployment hosts all three servers on one origin and
// federates in-process (§9.3.3). TestFourPartyDeployment puts the access
// server on its own origin and federates over HTTP (§9.1). Both run the
// same scenario (see runScenario) against a deployment built by
// newDeployment: three-party access at one resource, a mission, access at a
// second resource through the access server, audit and completion, and a
// revocation cascade.
package e2e
