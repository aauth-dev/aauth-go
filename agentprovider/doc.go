// Package agentprovider implements a hosted agent provider for AAuth
// (draft-hardt-oauth-aauth-protocol-11 §5.1;
// draft-hardt-aauth-bootstrap-02).
//
// A [Server] holds a provider signing key separate from every agent's
// key, publishes /.well-known/aauth-agent.json and its JWKS, and issues
// aa-agent+jwt tokens:
//
//   - for any public key the hosting application authorizes, directly
//     with [Server.IssueAgentToken] — so a token can be tied to the
//     application's own records, such as a work session — or over HTTP
//     for a key that proves possession under the hwk scheme (enrollment,
//     single-key refresh; bootstrap §8.2);
//   - by the two-key refresh ceremony (bootstrap §8.1): a jkt-jwt naming
//     JWT signed by the durable key delegates to a fresh ephemeral key,
//     which signs the request; naming JWTs are single-use;
//   - for sub-agents under a hosted provider (bootstrap §9.2): the parent
//     signs with its own agent token, and the sub-agent token has the
//     parent's iss and ps, parent_agent naming the parent, its own key,
//     and an exp no later than the parent's; a sub-agent cannot have
//     sub-agents.
//
// Every HTTP issuance goes through the caller's [Registrar], and optional
// platform attestation through an [AttestationVerifier] (bootstrap §5).
// [Server.RevokeAgentToken] revokes an agent token at the agent's person
// server (§11.12). [Client] is the agent side of the same endpoints.
package agentprovider
