#!/usr/bin/env bash
#
# Runs real gVisor sandboxes next to Falco with the plugin, inside one
# privileged container, so it works on any Docker host (including Docker
# Desktop/OrbStack) without configuring runsc as a Docker runtime.
#
# Checks:
#   fail-open    a sandbox with the pod-init session starts while nothing
#                listens on the plugin socket
#   attach       a sandbox started without monitoring is attached by the plugin
#   idle         an attached sandbox that stays idle keeps its session and is
#                not attached again by later sweeps
#   detect       a binary dropped in /tmp (the tmpfs runsc mounts over an empty
#                image /tmp) and executed raises an alert
#   reload       after a rules change Falco reopens the plugin, the sandbox is
#                re-attached and a /dev/shm exec raises an alert
#
# Requires the plugin image (make image) and network access to fetch runsc.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE:-falco-gvisor:0.1.0}"
BUILDER_IMAGE="${BUILDER_IMAGE:-golang:1.27-bookworm}"
RUNSC_DIR="${RUNSC_DIR:-${ROOT}/dist/runsc}"
NAME="falco-gvisor-sandbox-test-$$"
WORK="$(mktemp -d)"
STARTUP_TIMEOUT=60
ALERT_TIMEOUT=60
IDLE_SECONDS=25
FAILURES=0

pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

fetch_runsc() {
  if [ -x "${RUNSC_DIR}/usr/bin/runsc" ]; then
    return
  fi
  mkdir -p "${RUNSC_DIR}"
  local arch
  arch=$(docker image inspect -f '{{.Architecture}}' "${IMAGE}")
  docker run --rm --platform "linux/${arch}" -v "${RUNSC_DIR}:/out" "${BUILDER_IMAGE}" sh -c '
    set -e
    curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
    apt-get update -qq >/dev/null
    cd /tmp && apt-get download -qq runsc >/dev/null
    dpkg -x /tmp/runsc_*.deb /out'
}

cat > "${WORK}/falco.yaml" <<'EOF'
plugins:
  - name: gvisor
    library_path: /usr/share/falco/plugins/libgvisor.so
    init_config:
      metadataProvider: none
      runscPath: /usr/local/bin/runsc
      runscRoot: /run/gvtest
      attachOnOpen: true
      attachIntervalSeconds: 2
      statsIntervalSeconds: 5
      requireRunscPeer: true
load_plugins: [gvisor]
rules_files: [/etc/falco/rules.d/gvisor_rules.yaml]
json_output: true
watch_config_files: true
stdout_output:
  enabled: true
EOF


falco_log() {
  cat "${WORK}/falco.log" 2>/dev/null || true
}

# wait_alert RULE TEXT: waits for an alert of RULE whose line contains TEXT.
wait_alert() {
  local rule="$1" text="$2"
  for _ in $(seq "${ALERT_TIMEOUT}"); do
    if falco_log | grep -F "\"rule\":\"${rule}\"" | grep -F "${text}" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

listening_count() {
  falco_log | grep -c "listening on /run/falco/gvisor.sock" || true
}

wait_log() {
  local pattern="$1" min="$2"
  for _ in $(seq "${ALERT_TIMEOUT}"); do
    if [ "$(falco_log | grep -c "${pattern}" || true)" -ge "${min}" ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

fetch_runsc

docker run -d --name "${NAME}" --privileged -e HOST_ROOT=/ \
  -v "${RUNSC_DIR}/usr/bin:/opt/runsc:ro" \
  -v "${WORK}:/work" \
  -v "${WORK}/falco.yaml:/etc/falco/falco.yaml:ro" \
  --entrypoint sleep "${IMAGE}" infinity >/dev/null
docker exec "${NAME}" sh -c 'mkdir -p /usr/local/bin /run/gvtest /run/bundle && cp -a /opt/runsc/. /usr/local/bin/'

if out=$(docker exec "${NAME}" sh -c 'timeout 60 runsc --network=none --ignore-cgroups --pod-init-config=/etc/falco/gvisor-pod-init.json do /bin/true' 2>&1); then
  pass "fail-open: sandbox starts with monitoring enabled and no plugin listening"
else
  fail "fail-open: sandbox failed to start with no plugin listening: ${out}"
fi

docker exec -d "${NAME}" sh -c 'exec falco -c /etc/falco/falco.yaml --disable-source=syscall > /work/falco.log 2>&1'
for _ in $(seq "${STARTUP_TIMEOUT}"); do
  falco_log | grep "listening on" >/dev/null && break
  sleep 1
done

docker exec "${NAME}" sh -c '
  cd /run/bundle && runsc spec -- /bin/sleep 600
  sed -i "s#\"path\": \"rootfs\"#\"path\": \"/\"#; s#\"terminal\": true#\"terminal\": false#; s#\"readonly\": true#\"readonly\": false#" config.json'
docker exec -d "${NAME}" sh -c 'runsc --root /run/gvtest --network=none --ignore-cgroups --overlay2=root:memory run -bundle /run/bundle sandbox1 > /work/sandbox.log 2>&1'

if wait_log "attached trace session to sandbox sandbox1" 1; then pass "attach: unmonitored sandbox attached"; else fail "attach: sandbox1 was never attached"; fi
sleep "${IDLE_SECONDS}"
attaches=$(falco_log | grep -c "attached trace session to sandbox sandbox1" || true)
if [ "${attaches}" -eq 1 ]; then
  pass "idle: idle sandbox kept its session for ${IDLE_SECONDS}s"
else
  fail "idle: idle sandbox1 attached ${attaches} times in ${IDLE_SECONDS}s"
fi
sandbox_exec() {
  docker exec "${NAME}" runsc --root /run/gvtest exec sandbox1 /bin/sh -c "$1" >/dev/null 2>&1 || true
}

sandbox_exec 'cp /bin/true /tmp/update && /tmp/update'
if wait_alert "gVisor Dropped Binary Executed From Temp Directory" "/tmp/update"; then
  pass "detect: /tmp drop-and-execute alert"
else
  fail "detect: no alert for /tmp/update"
fi

before=$(listening_count)
docker exec "${NAME}" sh -c 'echo "# reload probe" >> /etc/falco/rules.d/gvisor_rules.yaml'
if wait_log "listening on /run/falco/gvisor.sock" $((before + 1)) && wait_log "attached trace session to sandbox sandbox1" 2; then
  pass "reload: plugin reopened and re-attached sandbox1"
else
  fail "reload: sandbox1 not re-attached after the rules change"
fi
sandbox_exec 'cp /bin/true /dev/shm/update2 && /dev/shm/update2'
if wait_alert "gVisor Dropped Binary Executed From Temp Directory" "/dev/shm/update2"; then
  pass "reload: /dev/shm exec detected after re-attach"
else
  fail "reload: no alert for /dev/shm/update2"
fi

if [ "${FAILURES}" -gt 0 ]; then
  echo "--- falco log tail"
  tail -40 "${WORK}/falco.log"
  echo "--- sandbox log"
  cat "${WORK}/sandbox.log" 2>/dev/null || true
  exit 1
fi
