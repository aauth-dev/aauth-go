#!/usr/bin/env bash
# Drives the five AAuth access modes against a running sandbox through its
# signing helper, with curl and jq only. Exits non-zero on the first
# failure.
#
#   deploy/docker/smoke.sh [signer-url]     (default http://127.0.0.1:8099)
set -euo pipefail

SIGNER="${1:-http://127.0.0.1:8099}"
D="aauth.test"

# call <present> <token-or-empty> <method> <url> [body] -> prints "status\nbody"
call() {
  local present="$1" token="$2" method="$3" url="$4" body="${5:-}"
  local args=(-sS -m 30 -X "$method" -H "X-Sandbox-Present: $present" -w '\n%{http_code}' -D /dev/stderr)
  [[ -n "$token" ]] && args+=(-H "X-Sandbox-Token: $token")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data-binary "$body")
  curl "${args[@]}" "$SIGNER/$url" 2>"$HDRS"
}

HDRS="$(mktemp)"
trap 'rm -f "$HDRS"' EXIT

expect() { # expect <want-status> <step>
  local out="$1" want="$2" step="$3" got
  got="$(tail -n1 <<<"$out")"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL $step: status $got, want $want" >&2
    sed '$d' <<<"$out" >&2
    exit 1
  fi
  echo "ok   $step ($got)"
}
body() { sed '$d' <<<"$1"; }

# auth_token <resource-host>: person token, authorize, token (follows a 202), echoes the auth token
auth_token() {
  local host="$1" out pt rt at loc
  out="$(call agent "" POST "https://ps.$D/person" "{\"resource\":\"https://$host\"}")"; expect "$out" 200 "person token for $host" >&2
  pt="$(body "$out" | jq -r .person_token)"
  out="$(call person "$pt" POST "https://$host/authorize" '{"scope":"documents:read"}')"; expect "$out" 200 "authorize at $host" >&2
  rt="$(body "$out" | jq -r .resource_token)"
  out="$(call agent "" POST "https://ps.$D/token" "{\"resource_token\":\"$rt\",\"presented_token\":\"$pt\"}")"
  local status; status="$(tail -n1 <<<"$out")"
  if [[ "$status" == 202 ]]; then
    loc="$(grep -i '^location:' "$HDRS" | tail -n1 | tr -d '\r' | cut -d' ' -f2)"
    for _ in $(seq 1 30); do
      out="$(call agent "" GET "$loc")"
      [[ "$(tail -n1 <<<"$out")" != 202 ]] && break
      sleep 1
    done
  fi
  expect "$out" 200 "auth token for $host" >&2
  body "$out" | jq -r .auth_token
}

out="$(call agent "" GET "https://resource.$D/api/documents")"; expect "$out" 200 "agent identity"

out="$(call agent "" GET "https://resource.$D/api/data")"
if [[ "$(tail -n1 <<<"$out")" == 202 ]]; then
  loc="$(grep -i '^location:' "$HDRS" | tail -n1 | tr -d '\r' | cut -d' ' -f2)"
  for _ in $(seq 1 30); do
    out="$(call agent "" GET "$loc")"
    [[ "$(tail -n1 <<<"$out")" != 202 ]] && break
    sleep 1
  done
fi
expect "$out" 200 "resource-managed access"

out="$(call agent "" POST "https://ps.$D/person" "{\"resource\":\"https://resource.$D\"}")"; expect "$out" 200 "person token"
pt="$(body "$out" | jq -r .person_token)"
out="$(call person "$pt" GET "https://resource.$D/api/documents")"; expect "$out" 200 "person identity"

at="$(auth_token "resource.$D")"
out="$(call auth "$at" GET "https://resource.$D/api/documents")"; expect "$out" 200 "PS authorization"

at="$(auth_token "docs.$D")"
out="$(call auth "$at" GET "https://docs.$D/api/documents")"; expect "$out" 200 "federated authorization"

echo "all five access modes passed"
