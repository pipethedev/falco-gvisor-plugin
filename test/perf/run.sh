#!/usr/bin/env bash
#
# Measures the cost of gVisor monitoring (docs/perf.md).
#
#   test/perf/run.sh RUNTIME...
#
# Each RUNTIME is a Docker runtime name from /etc/docker/daemon.json, e.g.:
#   runsc        plain gVisor (baseline)
#   runsc-lean   runtimeArgs: --pod-init-config=/etc/falco/gvisor-pod-init.json
#   runsc-full   runtimeArgs: --pod-init-config=/etc/falco/pod-init-full.json
# Falco with the gvisor plugin must be running for the monitored runtimes.
#
# Prints a markdown table: container start time and HTTP latency (p50/p99)
# per runtime, plus Falco CPU/RSS and plugin drop counters.
set -euo pipefail

RUNS="${RUNS:-30}"
REQUESTS="${REQUESTS:-2000}"
IMAGE_START="${IMAGE_START:-alpine:3.20}"
IMAGE_HTTP="${IMAGE_HTTP:-nginx:1.27-alpine}"
HTTP_PORT="${HTTP_PORT:-18080}"
FALCO_CONTAINER="${FALCO_CONTAINER:-falco}"
WARMUP_REQUESTS=100
READY_TIMEOUT=30

percentile() {
  sort -n | awk -v p="$1" '{a[NR]=$1} END {if (NR==0) {print "n/a"; exit} i=int((NR*p+99)/100); if (i<1) i=1; printf "%.2f", a[i]}'
}

start_times() {
  local rt="$1"
  for _ in $(seq "${RUNS}"); do
    local t0 t1
    t0=$(date +%s%N)
    docker run --rm --runtime="${rt}" "${IMAGE_START}" true >/dev/null
    t1=$(date +%s%N)
    echo $(( (t1 - t0) / 1000000 ))
  done
}

http_latencies() {
  local rt="$1" name="perf-http-$$"
  docker run -d --rm --name "${name}" --runtime="${rt}" -p "${HTTP_PORT}:80" "${IMAGE_HTTP}" >/dev/null
  for _ in $(seq "${READY_TIMEOUT}"); do
    curl -fsS -o /dev/null "http://127.0.0.1:${HTTP_PORT}/" 2>/dev/null && break
    sleep 1
  done
  for _ in $(seq "${WARMUP_REQUESTS}"); do curl -fsS -o /dev/null "http://127.0.0.1:${HTTP_PORT}/"; done
  for _ in $(seq "${REQUESTS}"); do
    curl -fsS -o /dev/null -w '%{time_total}\n' "http://127.0.0.1:${HTTP_PORT}/" | awk '{printf "%.3f\n", $1*1000}'
  done
  docker rm -f "${name}" >/dev/null
}

falco_usage() {
  if ! docker inspect "${FALCO_CONTAINER}" >/dev/null 2>&1; then
    echo "n/a n/a"
    return
  fi
  docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' "${FALCO_CONTAINER}" | awk '{print $1, $2}'
}

falco_drops() {
  docker logs "${FALCO_CONTAINER}" 2>&1 | grep 'gvisor-plugin\] stats:' | tail -1 | sed -E 's/.*drops=([0-9]+).*/\1/' || echo "n/a"
}

echo "| runtime | start p50 (ms) | start p99 (ms) | http p50 (ms) | http p99 (ms) | falco cpu | falco mem | drops |"
echo "|---|---|---|---|---|---|---|---|"
for rt in "$@"; do
  starts=$(start_times "${rt}")
  lat=$(http_latencies "${rt}")
  read -r cpu mem <<<"$(falco_usage)"
  printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "${rt}" \
    "$(percentile 50 <<<"${starts}")" "$(percentile 99 <<<"${starts}")" \
    "$(percentile 50 <<<"${lat}")" "$(percentile 99 <<<"${lat}")" \
    "${cpu}" "${mem}" "$(falco_drops)"
done
