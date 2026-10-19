# The AAuth sandbox: every AAuth role from aauth-go, plus a signing helper
# for HTTP clients that cannot sign. A development tool; see
# docs/guides/sandbox.md.
#
# Build from the repository root:
#   docker build -f deploy/docker/Dockerfile -t aauth-sandbox:dev .

ARG GO_VERSION=1.27.1

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aauth-sandbox ./cmd/aauth-sandbox \
 && mkdir -p /out/state

# distroless/static has no shell; the binary's own `health` command is the
# health check. nonroot (uid 65532) can bind 443 because Docker sets
# net.ipv4.ip_unprivileged_port_start=0 in container network namespaces.
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/aauth-sandbox /usr/local/bin/aauth-sandbox
COPY --from=build --chown=65532:65532 /out/state /state
VOLUME /state
EXPOSE 443 8099
ENTRYPOINT ["aauth-sandbox"]
# Every role on :443 and the signing helper on :8099. Publish both ports on
# the host's loopback address only: the helper signs anything it is sent.
CMD ["serve", "--state", "/state", "--signer", "0.0.0.0:8099", "--signer-any-interface"]
