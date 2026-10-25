# PLAN — AAuth sandbox

**Initiative:** `INIT-AAUTHGO-002`

1. **Library first:** configuration, CA, keys, routing, demo resources, consent and trace, tested in-process. The walkthrough deployment (`examples/walkthrough`) is the starting point.
2. **CLI and signing helper:** the pieces HTTP clients and the Postman collection need. This phase is enough for the AAuth workshop.
3. **Docker:** image and Compose, with CI running the flows against Compose.
4. **Kubernetes:** kustomize and the minikube overlay.

Phases 1 and 2 can ship with v0.3.0 or follow it; phases 3 and 4 follow.

## Dependencies

- The end-to-end JSON trace types (`RMI-AAUTHGO-016`).
- Walkthrough samples (`RMI-AAUTHGO-014`) for the deployment wiring.
- New modules (Cobra, a YAML parser) are added at their latest releases, verified when added.

## Consumers

- PIDL's Postman generator (`INIT-PIDL-006`) targets the signing helper.
- The `aauth-dev/aauth-postman` repository runs the generated AAuth collection against the sandbox image in CI.
