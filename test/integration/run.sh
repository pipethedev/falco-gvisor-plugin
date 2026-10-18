#!/usr/bin/env bash
#
# End-to-end tests on a Linux host with Docker, runsc and the plugin image.
#
# Prerequisites (CI installs them):
#   - runsc registered as Docker runtime "runsc" with
#     --pod-init-config=/etc/falco/gvisor-pod-init.json
#   - /etc/falco/gvisor-pod-init.json from deploy/
#   - the plugin image built as $IMAGE (make image)
#
# Scenarios (SPEC section 10):
#   detections   miner, reverse shell, drop-and-execute and cloud metadata
#                fire with container metadata; benign workloads stay quiet
#   fail-open    with Falco stopped, gVisor containers still start
#   re-attach    a sandbox started before a Falco restart is monitored again
#   reload       a rules change (Falco reopens the plugin) does not leave
#                running sandboxes unmonitored
#   restart      restarting Falco under load causes no workload errors and
#                drops are reported
set -euo pipefail

IMAGE="${IMAGE:-falco-gvisor:0.1.0}"
RUNTIME="${RUNTIME:-runsc}"
RUNSC_ROOT="${RUNSC_ROOT:-/run/docker/runtime-runc/moby}"
RUNSC_BIN="${RUNSC_BIN:-$(command -v runsc)}"
FALCO_EXTRA_ARGS="${FALCO_EXTRA_ARGS:-}"
FALCO="falco-gvisor-it"
PREFIX="gvisor-it-$$"
ALERT_TIMEOUT=30
STARTUP_TIMEOUT=90
ATTACH_INTERVAL=5
LOAD_SECONDS=20
FAILURES=0
WORK="$(mktemp -d)"

log() { printf '\n==> %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  docker rm -f "${FALCO}" >/dev/null 2>&1 || true
  docker ps -aq --filter "name=${PREFIX}" | xargs -r docker rm -f >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

write_config() {
  cat > "${WORK}/gvisor.yaml" <<EOF
plugins:
  - name: gvisor
    library_path: /usr/share/falco/plugins/libgvisor.so
    init_config:
      runscRoot: ${RUNSC_ROOT}
      attachIntervalSeconds: ${ATTACH_INTERVAL}
      statsIntervalSeconds: 5
load_plugins: [gvisor]
json_output: true
json_include_output_property: true
EOF
}

start_falco() {
  docker rm -f "${FALCO}" >/dev/null 2>&1 || true
  sudo mkdir -p /run/falco
  # shellcheck disable=SC2086
  docker run -d --name "${FALCO}" --privileged --pid=host \
    -e HOST_ROOT=/host \
    -v /run/falco:/run/falco \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/run/docker.sock:/host/var/run/docker.sock \
    -v "${RUNSC_BIN}:/usr/local/bin/runsc:ro" \
    -v "${RUNSC_ROOT}:${RUNSC_ROOT}" \
    -v /proc:/host/proc:ro \
    -v /etc:/host/etc:ro \
    -v "${WORK}/gvisor.yaml:/etc/falco/config.d/gvisor.yaml:ro" \
    "${IMAGE}" falco ${FALCO_EXTRA_ARGS} >/dev/null
  for _ in $(seq "${STARTUP_TIMEOUT}"); do
    if docker logs "${FALCO}" 2>&1 | grep -q "listening on /run/falco/gvisor.sock"; then
      return 0
    fi
    sleep 1
  done
  docker logs "${FALCO}" 2>&1 | tail -50
  echo "falco did not start" >&2
  exit 1
}

stop_falco() {
  docker stop -t 10 "${FALCO}" >/dev/null
}

# wait_alert RULE CONTAINER_NAME: waits for an alert of RULE whose
# container.name is CONTAINER_NAME.
wait_alert() {
  local rule="$1" name="$2"
  for _ in $(seq "${ALERT_TIMEOUT}"); do
    if docker logs "${FALCO}" 2>/dev/null | grep -F "\"rule\":\"${rule}\"" | grep -qF "\"container.name\":\"${name}\""; then
      return 0
    fi
    sleep 1
  done
  return 1
}

alerts_for() {
  docker logs "${FALCO}" 2>/dev/null | grep -F '"source":"gvisor"' | grep -cF "\"container.name\":\"$1\"" || true
}

expect_alert() {
  local what="$1" rule="$2" name="$3"
  if wait_alert "${rule}" "${name}"; then pass "${what}"; else fail "${what}: no '${rule}' alert for ${name}"; fi
}

grun() {
  local name="$1"; shift
  docker run --rm --runtime="${RUNTIME}" --name "${PREFIX}-${name}" "$@"
}

scenario_detections() {
  log "detections"
  grun miner alpine:3.20 sh -c \
    'cp /bin/busybox /tmp/xmrig && /tmp/xmrig --donate-level 1 -o stratum+tcp://example.invalid:3333' || true
  expect_alert "miner binary with container metadata" "gVisor Crypto Miner Executed" "${PREFIX}-miner"

  grun revshell alpine:3.20 sh -c 'sh -c "echo bash -i >& /dev/tcp/127.0.0.1/9 0>&1"' || true
  expect_alert "reverse shell command line" "gVisor Reverse Shell Command Line" "${PREFIX}-revshell"

  grun dropexec alpine:3.20 sh -c 'cp /bin/busybox /tmp/update && /tmp/update true' || true
  expect_alert "drop and execute" "gVisor Dropped Binary Executed From Temp Directory" "${PREFIX}-dropexec"

  grun imds alpine:3.20 sh -c 'nc -w 1 169.254.169.254 80 </dev/null' || true
  expect_alert "cloud metadata connect" "gVisor Connection to Cloud Metadata Service" "${PREFIX}-imds"

  log "benign workloads"
  docker run -d --runtime="${RUNTIME}" --name "${PREFIX}-nginx" -p 18081:80 nginx:1.27-alpine >/dev/null
  for _ in $(seq 30); do curl -fsS -o /dev/null http://127.0.0.1:18081/ 2>/dev/null && break; sleep 1; done
  for _ in $(seq 50); do curl -fsS -o /dev/null http://127.0.0.1:18081/ || true; done
  grun python python:3.12-alpine python -c 'import json, urllib.parse; print(json.dumps({"ok": 1}))' >/dev/null
  grun shell alpine:3.20 sh -c 'ls / >/dev/null; cat /etc/os-release >/dev/null; apk --version >/dev/null'
  sleep 5
  docker rm -f "${PREFIX}-nginx" >/dev/null
  for name in nginx python shell; do
    count=$(alerts_for "${PREFIX}-${name}")
    if [ "${count}" -eq 0 ]; then pass "benign ${name}: no alerts"; else fail "benign ${name}: ${count} alerts"; fi
  done
}

scenario_fail_open() {
  log "fail-open"
  stop_falco
  if docker run --rm --runtime="${RUNTIME}" alpine:3.20 true; then
    pass "gVisor container starts with Falco stopped"
  else
    fail "gVisor container failed to start with Falco stopped"
  fi
  start_falco
}

scenario_reattach() {
  log "re-attach"
  docker run -d --runtime="${RUNTIME}" --name "${PREFIX}-longrun" alpine:3.20 sleep 600 >/dev/null
  sleep 2
  docker restart -t 10 "${FALCO}" >/dev/null
  for _ in $(seq "${STARTUP_TIMEOUT}"); do
    docker logs --since 30s "${FALCO}" 2>&1 | grep -q "attached trace session" && break
    sleep 1
  done
  docker exec "${PREFIX}-longrun" sh -c 'cp /bin/busybox /tmp/xmrig && /tmp/xmrig --donate-level 1 true' || true
  expect_alert "alert from sandbox started before Falco restart" "gVisor Crypto Miner Executed" "${PREFIX}-longrun"
  docker rm -f "${PREFIX}-longrun" >/dev/null
}

scenario_reload() {
  log "reload"
  docker run -d --runtime="${RUNTIME}" --name "${PREFIX}-reload" alpine:3.20 sleep 600 >/dev/null
  sleep 2
  local before
  before=$(docker logs "${FALCO}" 2>&1 | grep -c "listening on /run/falco/gvisor.sock")
  docker exec "${FALCO}" sh -c 'echo "# reload probe" >> /etc/falco/rules.d/gvisor_rules.yaml'
  for _ in $(seq "${STARTUP_TIMEOUT}"); do
    [ "$(docker logs "${FALCO}" 2>&1 | grep -c "listening on /run/falco/gvisor.sock")" -gt "${before}" ] && break
    sleep 1
  done
  sleep "${ATTACH_INTERVAL}"
  docker exec "${PREFIX}-reload" sh -c 'cp /bin/busybox /tmp/xmrig && /tmp/xmrig --donate-level 1 true' || true
  expect_alert "alert from running sandbox after a rules reload" "gVisor Crypto Miner Executed" "${PREFIX}-reload"
  docker rm -f "${PREFIX}-reload" >/dev/null
}

scenario_restart_under_load() {
  log "restart under load"
  docker run -d --runtime="${RUNTIME}" --name "${PREFIX}-load" alpine:3.20 \
    sh -c "end=\$((\$(date +%s) + ${LOAD_SECONDS})); while [ \$(date +%s) -lt \$end ]; do /bin/true; done; echo done" >/dev/null
  sleep 3
  docker restart -t 5 "${FALCO}" >/dev/null
  status=$(docker wait "${PREFIX}-load")
  output=$(docker logs "${PREFIX}-load" 2>&1)
  docker rm -f "${PREFIX}-load" >/dev/null
  if [ "${status}" = "0" ] && [ "${output}" = "done" ]; then
    pass "workload unaffected by Falco restart"
  else
    fail "workload exited ${status}: ${output}"
  fi
  sleep 6
  if docker logs "${FALCO}" 2>&1 | grep -q 'gvisor-plugin\] stats: .*drops='; then
    pass "drops reported in stats"
  else
    fail "no stats line with drop counters"
  fi
}

write_config
start_falco
scenario_detections
scenario_fail_open
scenario_reattach
scenario_reload
scenario_restart_under_load

if [ "${FAILURES}" -gt 0 ]; then
  log "${FAILURES} check(s) failed; Falco log tail:"
  docker logs "${FALCO}" 2>&1 | tail -40
  exit 1
fi
log "all integration checks passed"
