#!/usr/bin/env bash
# Run one end-to-end test with the trace on, keep the log, and write a
# summary of its steps to the job summary (or stdout outside GitHub Actions).
#
#   .github/scripts/e2e.sh TestFourPartyDeployment "Four-party: ..."
set -uo pipefail

test_name=${1:?usage: e2e.sh TestName "title"}
title=${2:-$test_name}
log=$(mktemp)
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}

AAUTH_E2E_TRACE=${AAUTH_E2E_TRACE:-1} go test -race -count=1 -v -run "^${test_name}\$" ./e2e 2>&1 | tee "$log"
status=${PIPESTATUS[0]}

{
  echo "## $title"
  echo
  echo "| Step | Result |"
  echo "|---|---|"
  # Subtest result lines look like: "    --- PASS: TestX/step_name (0.01s)".
  grep -E '^\s+--- (PASS|FAIL|SKIP): ' "$log" | while read -r _ result name _; do
    step=${name#*/}
    step=${step//_/ }
    echo "| $step | ${result%:} |"
  done
  echo
  if [ "$status" -eq 0 ]; then
    echo "**Passed.** The full log has every HTTP exchange (\`trace:\` lines) and each step's flow summary."
  else
    echo "**Failed.** See the log for the failing step and the exchanges around it."
  fi
} >>"$summary"

exit "$status"
