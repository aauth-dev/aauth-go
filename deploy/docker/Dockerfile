# The AAuth sandbox: every AAuth role from aauth-go, plus a signing helper
# for HTTP clients that cannot sign. A development tool; see
# docs/guides/sandbox.md.
#
# Build from the repository root:
#   docker build -f deploy/docker/Dockerfile -t aauth-sandbox:dev .
#
# Run it with both ports published on the host's loopback address only:
#   docker run --rm -p 127.0.0.1:443:443 -p 127.0.0.1:8099:8099 aauth-sandbox:dev
#
# Never publish them as -p 443:443 -p 8099:8099: Docker then listens on
# every interface of the host, and anyone on the network can read the
# trace (every token), get consent approved automatically, and use the
# signing helper to sign requests as the test agent.

# Base images are pinned by digest; update GO_VERSION and GO_DIGEST
# together (docker buildx imagetools inspect golang:<version>-alpine).
ARG GO_VERSION=1.27.3
ARG GO_DIGEST=sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c

FROM golang:${GO_VERSION}-alpine@${GO_DIGEST} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aauth-sandbox ./cmd/aauth-sandbox \
 && mkdir -p /out/state

# distroless/static has no shell; the binary's own `health` command is the
# health check. nonroot (uid 65532) can bind 443 because Docker sets
# net.ipv4.ip_unprivileged_port_start=0 in container network namespaces.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/aauth-sandbox /usr/local/bin/aauth-sandbox
COPY --from=build --chown=65532:65532 /out/state /state
VOLUME /state
EXPOSE 443 8099
ENTRYPOINT ["aauth-sandbox"]
# Every role on :443 and the signing helper on :8099, on every interface of
# the container. Publish both ports on the host's loopback address only
# (-p 127.0.0.1:443:443 -p 127.0.0.1:8099:8099): the trace shows every
# token, consent is automatic, and the helper signs as the test agent.
CMD ["serve", "--state", "/state", "--listen", "0.0.0.0:443", "--listen-any-interface", "--signer", "0.0.0.0:8099", "--signer-any-interface"]
