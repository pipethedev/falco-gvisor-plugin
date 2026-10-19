#!/usr/bin/env bash
#
# Runs every fixture in rules/tests against a real Falco with the gvisor
# plugin and checks that exactly the expected rules fire.
#
# Requires docker, a linux libgvisor.so and a linux replay binary in
# PLUGIN_DIR (make rules-test builds both).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLUGIN_DIR="${PLUGIN_DIR:-${ROOT}/dist/$(go env GOARCH)}"
FALCO_IMAGE="${FALCO_IMAGE:-falcosecurity/falco:0.45.0}"
NAME="falco-gvisor-rules-test-$$"
WORK="$(mktemp -d)"
STARTUP_TIMEOUT=60
SETTLE_SECONDS=3

cleanup() {
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

write_config() {
  local out="$1" enables="$2"
  cat > "${out}" <<EOF
plugins:
  - name: gvisor
    library_path: /plugin/libgvisor.so
    init_config:
      metadataProvider: none
      attachOnOpen: false
      attachIntervalSeconds: 0
      statsIntervalSeconds: 0
load_plugins: [gvisor]
rules_files:
  - /rules/gvisor_rules.yaml
${enables}
json_output: true
json_include_output_property: true
stdout_output:
  enabled: true
EOF
}

start_falco() {
  local config="$1"
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
  docker run -d --name "${NAME}" \
    -v "${PLUGIN_DIR}:/plugin:ro" \
    -v "${ROOT}/rules:/rules:ro" \
    -e HOST_ROOT=/ \
    -v "${config}:/etc/falco/falco.yaml:ro" \
    "${FALCO_IMAGE}" falco -c /etc/falco/falco.yaml --disable-source=syscall >/dev/null
  for _ in $(seq "${STARTUP_TIMEOUT}"); do
    if docker logs "${NAME}" 2>&1 | grep "listening on" >/dev/null; then
      return 0
    fi
    if ! docker inspect -f '{{.State.Running}}' "${NAME}" | grep true >/dev/null; then
      docker logs "${NAME}"
      echo "falco exited during startup" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "${NAME}" 2>&1 | tail -20
  echo "falco did not start listening within ${STARTUP_TIMEOUT}s" >&2
  exit 1
}

# run_pass CONFIG DIR: replays every fixture in rules/DIR and checks that
# each fires exactly its expected rules.
run_pass() {
  local config="$1" dir="$2"
  start_falco "${config}"
  local fixtures=()
  for f in "${ROOT}/rules/${dir}"/*.json; do
    fixtures+=("/rules/${dir}/$(basename "${f}")")
  done
  docker exec "${NAME}" /plugin/replay send -socket /run/falco/gvisor.sock "${fixtures[@]}"
  sleep "${SETTLE_SECONDS}"
  docker logs "${NAME}" > "${WORK}/falco-${dir//\//-}.log" 2>&1
  (cd "${ROOT}" && go run ./tools/replay verify -log "${WORK}/falco-${dir//\//-}.log" "rules/${dir}"/*.json)
}

# Main pass: rules that are disabled by default are enabled so their attack
# fixtures can be checked.
write_config "${WORK}/gvisor.yaml" "rules:
  - enable:
      rule: gVisor Terminal Shell in Container
  - enable:
      rule: gVisor Connection to Cloud Metadata Service
  - enable:
      rule: gVisor Service Account Token Read"
run_pass "${WORK}/gvisor.yaml" tests

# Defaults pass: the shipped rule selection must stay quiet on routine
# behaviour that the opt-in rules would flag.
write_config "${WORK}/defaults.yaml" ""
run_pass "${WORK}/defaults.yaml" tests/defaults

# Health: with runsc unreachable, the attacher must report the sandboxes it
# cannot monitor, and an event larger than maxEventSize must be reported as a
# drop, through the default-enabled health rule.
cat > "${WORK}/health.yaml" <<'EOF'
plugins:
  - name: gvisor
    library_path: /plugin/libgvisor.so
    init_config:
      metadataProvider: none
      runscPath: /nonexistent/runsc
      attachOnOpen: true
      attachIntervalSeconds: 0
      statsIntervalSeconds: 1
      maxEventSize: 1024
load_plugins: [gvisor]
rules_files:
  - /rules/gvisor_rules.yaml
json_output: true
stdout_output:
  enabled: true
EOF
start_falco "${WORK}/health.yaml"
docker exec "${NAME}" /plugin/replay send -socket /run/falco/gvisor.sock /rules/tests/health/oversize_event.json
# Each check is one gVisor Monitoring Degraded alert showing the problem.
failed=0
for want in 'attacher_failed=true' 'drops_since_last=[1-9]'; do
  found=0
  for _ in $(seq "${STARTUP_TIMEOUT}"); do
    if docker logs "${NAME}" 2>/dev/null | grep '"rule":"gVisor Monitoring Degraded"' | grep "${want}" >/dev/null; then
      found=1
      break
    fi
    sleep 1
  done
  if [[ "${found}" == 1 ]]; then
    echo "PASS health: ${want}"
  else
    echo "FAIL health: no gVisor Monitoring Degraded alert with ${want}" >&2
    failed=1
  fi
done
exit "${failed}"
