# gvisor plugin

Runtime threat detection for [gVisor](https://gvisor.dev)-sandboxed containers in [Falco](https://falco.org).

gVisor runs containers on a user-space kernel, so host-kernel sensors (Falco's `modern_ebpf`/`kmod`, Tetragon, Tracee) cannot see processes, execs or file activity inside a sandbox. Falco's built-in gVisor engine was removed in Falco 0.44. This plugin brings that visibility back as an event source, built on gVisor [Runtime Monitoring](https://gvisor.dev/docs/user_guide/runtime_monitoring/): each sandbox streams trace points to the plugin over a Unix socket, and the plugin turns them into Falco events with process ancestry and container metadata.

| | |
|---|---|
| Name | `gvisor` |
| Event source | `gvisor` |
| Capabilities | event sourcing, field extraction |
| Plugin ID | `999` (development id; an official id is being requested in the [registry](https://github.com/falcosecurity/plugins/blob/main/registry.yaml)) |
| Falco | 0.45 or later (plugin API 3.11) |
| gVisor | `runsc` releases from 2023 onward |
| License | Apache-2.0 |

## How it works

```
 workload ──syscall──▶ gVisor Sentry ──trace points──▶ /run/falco/gvisor.sock (unixpacket)
                                                             │
 ┌──────────────────────────── Falco ────────────────────────┴──────────────────────┐
 │  source: syscall (modern_ebpf)   host + non-gVisor containers                    │
 │  source: gvisor  (libgvisor.so)                                                  │
 │     ├─ server: one connection per sandbox → per-sandbox process table            │
 │     ├─ attacher: runsc trace create --force for running, unmonitored sandboxes   │
 │     └─ metadata: container id → name/image/labels (Docker API or CRI)            │
 │  rules: gvisor_rules.yaml (source: gvisor) + your syscall rules                  │
 └──────────────────────────────────▶ outputs (stdout / json / http / sidekick)     │
```

- **Server.** Accepts one connection per sandbox, performs the remote-sink handshake, and keeps a per-sandbox process table built from `container/start`, `sentry/clone`, `sentry/execve` and `sentry/task_exit`. Every event carries an immutable snapshot of the process and up to 8 ancestors.
- **Attacher.** gVisor sinks connect only when a sandbox is created and never reconnect. On startup and every `attachIntervalSeconds`, the plugin runs `runsc trace create --force` for every running sandbox without a live connection. Sandboxes started before Falco, or before Falco restarted, are monitored again automatically.
- **Metadata.** Container name, image and labels (and the pod name, namespace and labels under CRI) are fetched asynchronously and cached. The shipped sessions never request environment variables; if a custom session does, they are stripped on receipt and never stored, logged or passed to Falco.

### Fail-open by design

- Every shipped session config sets `"ignore_setup_error": true`, so a sandbox starts when Falco is down or its socket is missing. One case is not covered: if Falco is hung (for example stopped or frozen) while its socket still accepts connections, gVisor waits for the handshake reply without a timeout and sandbox creation blocks until Falco recovers ([upstream issue draft](docs/upstream-issues.md)).
- The gVisor remote sink writes without blocking and drops points instead of stalling the workload.
- The plugin never blocks on Falco: events wait in a queue bounded by `maxQueueBytes`, and when it is full they are dropped and counted (`gvisor_stats`), so a burst from a sandbox cannot exhaust Falco's memory.

## Quick start (Docker host)

1. Build or pull the image (Falco 0.45 with the plugin, rules and configs):

   ```sh
   make image            # or: docker build -t falco-gvisor .
   ```

2. Install the trace session config on the host and enable it for the gVisor runtime:

   ```sh
   sudo install -D -m 0644 deploy/gvisor-pod-init.json /etc/falco/gvisor-pod-init.json
   # add "--pod-init-config=/etc/falco/gvisor-pod-init.json" to the runsc runtimeArgs
   # in /etc/docker/daemon.json (see deploy/docker/daemon.json), then:
   sudo dockerd --validate --config-file /etc/docker/daemon.json && sudo systemctl reload docker
   ```

3. Run Falco (see `deploy/docker/docker-compose.yaml` for the full set of mounts):

   ```sh
   docker compose -f deploy/docker/docker-compose.yaml up -d
   ```

4. Trigger a detection:

   ```sh
   docker run --rm --runtime=runsc alpine sh -c \
     'cp /bin/busybox /tmp/xmrig && /tmp/xmrig --donate-level 1 -o stratum+tcp://example.invalid:3333'
   ```

New containers are monitored from their first instruction. Containers that were already running are attached within `attachIntervalSeconds`, or immediately when Falco restarts.

Guides for containerd/Kubernetes (Helm values, runsc shim config), Nomad and host installs are in [`deploy/`](deploy) and [`docs/runbook.md`](docs/runbook.md).

## Configuration

Add the plugin with [`deploy/falco.config.d/gvisor.yaml`](deploy/falco.config.d/gvisor.yaml). It is additive to an existing `falco.yaml`, including one running `modern_ebpf` with the `container` plugin. `init_config` is validated against a JSON schema with `additionalProperties: false`.

| Key | Default | Meaning |
|---|---|---|
| `socketPath` | `/run/falco/gvisor.sock` | Listener; must match the sink `endpoint` |
| `maxEventSize` | `65536` | Max message size; larger messages are dropped and counted |
| `runscPath` | `runsc` | runsc binary used by the attacher (resolved via `PATH`) |
| `runscRoot` | `/run/docker/runtime-runc/moby` | runsc state root (containerd/Kubernetes: `/run/containerd/runsc/k8s.io`) |
| `sessionConfigPath` | `/etc/falco/gvisor-session.json` | Trace session used when attaching |
| `attachOnOpen` | `true` | Attach running sandboxes when the source opens |
| `attachIntervalSeconds` | `300` | Periodic sweep for unmonitored sandboxes; `0` disables |
| `metadataProvider` | `docker` | `docker`, `cri` or `none` |
| `dockerSocket` | `/var/run/docker.sock` | For the `docker` provider |
| `criSocket` | `/run/containerd/containerd.sock` | For the `cri` provider |
| `labelAllowlist` | `[]` (all) | Labels to fetch and expose |
| `metadataCacheTTLSeconds` | `600` | Metadata cache lifetime |
| `maxTrackedProcesses` | `4096` | Per-sandbox process table cap |
| `statsIntervalSeconds` | `60` | Emit a `gvisor_stats` event and log counters; `0` disables |
| `metadataWaitMillis` | `200` | On a container's first event, how long its sandbox connection waits for metadata before emitting; `0` disables |
| `maxQueueBytes` | `67108864` (64 MiB) | Byte budget for events waiting for Falco; beyond it events are dropped and counted (`drops_channel_full`) |

### Trace sessions

| File | Use |
|---|---|
| `deploy/gvisor-pod-init.json` | `--pod-init-config` for new sandboxes (lean profile) |
| `deploy/gvisor-session.json` | `sessionConfigPath` for the attacher (same session, bare format) |
| `deploy/pod-init-full.json`, `deploy/gvisor-session-full.json` | Lean profile plus `syscall/openat` with `fd_path` |

The lean profile traces `container/start`, `sentry/clone`, `sentry/execve` (with binary info, SHA-256, stdio fd info and the process feeding stdin through a pipe), `sentry/task_exit`, and the exits of `connect`, `socket`, `execve`, `execveat` and `ptrace`. File-based rules (cron/authorized_keys writes, service account tokens, sysrq, `/sys/kernel`) need the full profile, which costs more ([`docs/perf.md`](docs/perf.md)). Every session is named `Default`: gVisor accepts no other name (it logs `only a single "Default" session is supported` and the sandbox runs unmonitored), and `trace create --force` then replaces the pod-init session instead of adding a second one.

## Fields and rules

- Fields: [`docs/fields.md`](docs/fields.md). Falco's standard names (`proc.*`, `fd.*`, `evt.type`, `container.*`, `k8s.*`) are used wherever the meaning matches, plus `gvisor.*` fields.
- Rules: [`rules/gvisor_rules.yaml`](rules/gvisor_rules.yaml), all `source: gvisor`:
  - crypto mining (miner binaries, miner arguments, stratum ports, known pool IPs)
  - network abuse (scanners, raw sockets, SMTP from non-mail workloads)
  - sandbox escape and host probing (runtime sockets, sysrq, `/sys/kernel`, ptrace, `nsenter`/`unshare`/`mount`)
  - drop-and-execute (temp-dir binaries from the upper layer, memfd, `curl | sh`)
  - reverse shells and persistence
  - credential access (cloud metadata, service account tokens)

  Each rule has an `*_allowlist` override macro, and generic shells and package managers do not alert. `rules/tools/pool_ips.sh` resolves mining pool domains into an IP macro.
- Rule tests: `make rules-test` runs Falco 0.45 in Docker and replays the fixtures in [`rules/tests`](rules/tests) into the plugin as a fake sandbox. Each attack fixture must fire exactly its expected rules, and the benign Node, Python, Go, nginx and exec-session workloads must fire none.

## Validation status

- **Falco 0.45.0** (arm64) loads the plugin next to the `container` plugin, and every rule fixture passes against it (`make rules-test`).
- **gVisor runsc release-20261012.0** (arm64, systrap) was run against the plugin with the shipped pod-init session. Execs, clones, exits, pipes and upper-layer detection were observed end to end, and the drop-and-execute rule fired on a binary written to `/tmp`. This run found the `Default` session requirement and the `proc.name` handling of symlinked binaries.
- **Not yet run:** the Docker and Kubernetes integration tests (`test/integration/run.sh`) and the benchmarks (`docs/perf.md`) need a Linux host with Docker and runsc; amd64 has been built in CI only.

## Building and testing

```sh
make build          # libgvisor.so for the host
make build-linux    # dist/{amd64,arm64}/libgvisor.so via docker
make test           # go test -race ./...
make test-linux     # Linux-only tests from macOS, in a container
make rules-test     # rules against a real Falco
make test-integration  # needs a Linux host with Docker, runsc and Falco
make generate       # syscall tables and docs/fields.md
make lint
```

The gVisor module is `gvisor.dev/gvisor` from its `go` branch (see `go.mod` for the exact pseudo-version). The decoder uses the official `points_go_proto` and remote-sink `wire` packages.

## Limitations

- gVisor drops, without counting them, trace points whose string fields (argv, binary path, process name, working directory) are not valid UTF-8, because protobuf refuses to marshal them. Such activity is invisible to the plugin and to `gvisor_stats`. This must be fixed in gVisor ([upstream issue draft](docs/upstream-issues.md)).

- Visibility is limited to the configured trace points; the lean profile does not trace file opens.
- `proc.pid` values are sandbox-internal.
- Container metadata is fetched asynchronously. A new container's first event waits up to `metadataWaitMillis` for it; if the runtime answers slower, early events carry only `container.id`.
- Sandboxes are re-attached by polling (`attachIntervalSeconds`), not in real time, after a Falco restart.
- Responding to alerts (stopping containers) is out of scope; consume Falco's output with a separate responder.

## License

Apache-2.0. See [LICENSE](LICENSE).
