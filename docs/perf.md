# Performance

gVisor already pays for intercepting syscalls; monitoring adds the cost of serializing each enabled trace point and writing it to the plugin socket. The default session is deliberately lean: process lifecycle points plus `connect`, `socket`, `execve`, `execveat` and `ptrace` exits. File opens, the most frequent syscalls in most workloads, are left to the optional full profile.

## Status

**Not yet measured.** The numbers below need a Linux host with Docker, runsc and Falco; they have not been collected yet. Run the benchmark below and fill in the table before treating the acceptance criteria as met.

## Method

`test/perf/run.sh` compares Docker runtimes that differ only in their monitoring config:

```json
{
  "runtimes": {
    "runsc":      { "path": "/usr/local/bin/runsc" },
    "runsc-lean": { "path": "/usr/local/bin/runsc", "runtimeArgs": ["--pod-init-config=/etc/falco/gvisor-pod-init.json"] },
    "runsc-full": { "path": "/usr/local/bin/runsc", "runtimeArgs": ["--pod-init-config=/etc/falco/pod-init-full.json"] }
  }
}
```

With Falco (plugin enabled) running as the `falco` container:

```sh
RUNS=30 REQUESTS=2000 test/perf/run.sh runsc runsc-lean runsc-full
```

For each runtime it reports:

- **Container start time:** `docker run --rm alpine true`, at least 30 runs, p50/p99.
- **Request latency:** p50/p99 over 2000 sequential requests to nginx, after a warmup.
- **Falco CPU and memory:** from `docker stats`.
- **Drops:** from the plugin's last `stats` line (`drops=`, the sum of all drop reasons).

Run on an otherwise idle host and repeat each configuration at least three times.

## Acceptance (lean profile)

- Start time and p99 latency regress by less than 5% against plain `runsc`.
- About zero drops at steady state.

## Results

| runtime | start p50 (ms) | start p99 (ms) | http p50 (ms) | http p99 (ms) | falco cpu | falco mem | drops |
|---|---|---|---|---|---|---|---|
| runsc (baseline) | — | — | — | — | — | — | — |
| runsc-lean | — | — | — | — | — | — | — |
| runsc-full (openat) | — | — | — | — | — | — | — |

Host: — (CPU, kernel, gVisor version, platform `systrap`/`kvm`, Falco version)

## Expected costs and knobs

- **The openat profile** emits one point per file open. Request-serving workloads that open files per request (static file servers, interpreters loading modules) will see the largest difference. Measure before enabling it fleet-wide.
- **The sink write path** never blocks the workload. With `retries: 3`, `backoff: 50us` and `backoff_max: 1ms`, a burst that fills the socket buffer costs at most about 0.35 ms of backoff per point (50 + 100 + 200 µs) before the point is dropped (`drops_sandbox`).
- **Plugin side:** decoding and enrichment run on one goroutine per sandbox. Events wait for Falco in a queue bounded by `maxQueueBytes` (64 MiB by default) and are dropped (`drops_channel_full`) instead of blocking; `gvisor.stats.queue_bytes` shows its depth. Size Falco's memory limit with this budget in mind.
- **Metadata** lookups are cached per container (`metadataCacheTTLSeconds`) and never block event processing.
