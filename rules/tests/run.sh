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

cat > "${WORK}/gvisor.yaml" <<'EOF'
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
json_output: true
json_include_output_property: true
stdout_output:
  enabled: true
EOF

docker run -d --name "${NAME}" \
  -v "${PLUGIN_DIR}:/plugin:ro" \
  -v "${ROOT}/rules:/rules:ro" \
  -e HOST_ROOT=/ \
  -v "${WORK}/gvisor.yaml:/etc/falco/falco.yaml:ro" \
  "${FALCO_IMAGE}" falco -c /etc/falco/falco.yaml --disable-source=syscall >/dev/null

for _ in $(seq "${STARTUP_TIMEOUT}"); do
  if docker logs "${NAME}" 2>&1 | grep -q "listening on"; then
    break
  fi
  if ! docker inspect -f '{{.State.Running}}' "${NAME}" | grep -q true; then
    docker logs "${NAME}"
    echo "falco exited during startup" >&2
    exit 1
  fi
  sleep 1
done

fixtures=()
for f in "${ROOT}"/rules/tests/*.json; do
  fixtures+=("/rules/tests/$(basename "${f}")")
done
docker exec "${NAME}" /plugin/replay send -socket /run/falco/gvisor.sock "${fixtures[@]}"
sleep "${SETTLE_SECONDS}"
docker logs "${NAME}" > "${WORK}/falco.log" 2>&1

cd "${ROOT}"
go run ./tools/replay verify -log "${WORK}/falco.log" rules/tests/*.json
