// Package walkthrough holds tested Go code for each step of the AAuth
// walkthroughs (draft-hardt-oauth-aauth-protocol-11): the code an agent,
// resource, person server (PS), access server (AS) or agent provider (AP)
// writes to send or handle that step's message.
//
// The code lives in this package's tests, which run every step against
// real servers built from this module. Each snippet sits between
// "pidl:begin <region>" and "pidl:end <region>" comments, so documentation
// tools such as PIDL can quote it by name. Region names are
// <scenario>.<step>.<role>, matching the scenario and step IDs of the
// AAuth walkthrough. Steps the federated scenario shares with PS
// authorization use the ps-authorization regions.
//
// The snippets use the step-level API (SignRequest, VerifyResourceChallenge,
// PSClient.RequestAuthToken, VerifyAndExtractAuth and so on) so each shows
// one message. Applications usually let [aauth.Transport] perform the
// agent's steps.
//
// Regions:
//
//	agent-token.attest.agent                       create a key and enroll it with the agent provider (hwk)
//	agent-token.attest.ap                          the provider's registrar decides which agent a key is
//	agent-token.agent-token.ap                     configure the agent provider that signs agent tokens
//	agent-token.agent-token.agent                  verify the agent token and build the agent with a token source
//	person-token.request.agent                     request a person token for a resource
//	person-token.request.ps                        the PS decides a person token request
//	consent.interaction-required.ps                the PS defers an auth token request for the person
//	consent.direct-user.agent                      the agent shows the person the interaction URL and code
//	consent.approve.ps                             the PS interaction page: consume the code and approve
//	consent.poll.agent                             long-poll the pending request with Prefer: wait
//	agent-identity.request.agent                   sign a request presenting the agent token
//	agent-identity.request.resource                verify the signature and agent token
//	resource-managed.request.agent                 sign a request declaring the interaction capability
//	resource-managed.request.resource              verify the agent and dispatch on a session token
//	resource-managed.interaction-required.resource answer 202 requirement=interaction with a code
//	resource-managed.interaction-required.agent    show the person the URL and code, and set up polling
//	resource-managed.complete-interaction.resource the resource's interaction page approves and creates a session
//	resource-managed.poll.agent                    poll the pending URL until the resource answers
//	resource-managed.poll.resource                 answer polls: still pending, or approved
//	resource-managed.session-token.resource        answer the final poll with AAuth-Access
//	resource-managed.session-token.agent           keep the session token from AAuth-Access
//	resource-managed.session-request.agent         sign a request carrying the session token
//	resource-managed.session-request.resource      check the session token against the signing key
//	person-identity.request.agent                  sign a request presenting the person token
//	person-identity.request.resource               verify the person token and its issuer
//	ps-authorization.authorize.agent               ask the resource's authorization endpoint, presenting the person token
//	ps-authorization.authorize.resource            the authorization endpoint issues a resource token
//	ps-authorization.resource-token.agent          verify the resource token before sending it on
//	ps-authorization.auth-token-request.agent      redeem the resource token at the PS
//	ps-authorization.auth-token-request.ps         configure the PS that decides token requests
//	ps-authorization.auth-token.agent              verify the auth token from the PS or AS
//	ps-authorization.api-request.agent             call the API presenting the auth token
//	ps-authorization.api-request.resource          verify the auth token and its scope
//	federated-authorization.federate.ps            the PS's client for access servers
//	federated-authorization.federate.as            the AS's policy decides and issues the auth token
package walkthrough
