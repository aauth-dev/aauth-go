# ROADMAP — AAuth sandbox

**Initiative:** `INIT-AAUTHGO-002`
**Repository:** `github.com/aauth-dev/aauth-go`

Commits implementing an item carry `Refs: RMI-AAUTHGO-<NNN>`.

## Phase 1 — Sandbox Library

**Theme:** Every role in one process, as specified

- [ ] `RMI-AAUTHGO-019` `sandbox` package: configuration, local and remote roles, host routing, and demo resources for the five access modes
  - Depends on: `RMI-AAUTHGO-014`
- [ ] `RMI-AAUTHGO-020` Development CA, certificates per name, and a client that trusts it
- [ ] `RMI-AAUTHGO-021` Role keys generated and persisted, with fixed walkthrough keys for `.test` names
- [ ] `RMI-AAUTHGO-022` Consent and interaction pages with automatic, manual and headless approval
  - Depends on: `RMI-AAUTHGO-019`
- [ ] `RMI-AAUTHGO-023` Message trace of every exchange, with read and clear endpoints
  - Depends on: `RMI-AAUTHGO-016`, `RMI-AAUTHGO-019`

## Phase 2 — CLI and Signing Helper

**Theme:** Clients that cannot sign can still drive every flow

- [ ] `RMI-AAUTHGO-024` `aauth-sandbox` CLI: serve, ca, keys, hosts and trace
  - Depends on: `RMI-AAUTHGO-020`, `RMI-AAUTHGO-021`, `RMI-AAUTHGO-022`, `RMI-AAUTHGO-023`
- [ ] `RMI-AAUTHGO-025` Signing helper: forwarding and `/sign`, token presentation headers, loopback only
  - Depends on: `RMI-AAUTHGO-019`, `RMI-AAUTHGO-021`
- [ ] `RMI-AAUTHGO-026` Sandbox guide: run locally, trust the CA, drive flows with curl, test an external role
  - Depends on: `RMI-AAUTHGO-024`, `RMI-AAUTHGO-025`

## Phase 3 — Docker

**Theme:** One container per role

- [ ] `RMI-AAUTHGO-027` Image and Compose file with network aliases, shared CA volume and health checks
  - Depends on: `RMI-AAUTHGO-024`
- [ ] `RMI-AAUTHGO-028` CI that builds the image and runs the five access modes against Compose
  - Depends on: `RMI-AAUTHGO-025`, `RMI-AAUTHGO-027`

## Phase 4 — Kubernetes

**Theme:** Distributed roles on minikube

- [ ] `RMI-AAUTHGO-029` Kustomize base and minikube overlay with ingress and TLS
  - Depends on: `RMI-AAUTHGO-027`
- [ ] `RMI-AAUTHGO-030` Documented distributed run on minikube, with an optional CI job
  - Depends on: `RMI-AAUTHGO-029`
