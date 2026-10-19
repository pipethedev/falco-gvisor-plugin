# Configuration

Add the plugin to Falco with [`deploy/falco.config.d/gvisor.yaml`](../deploy/falco.config.d/gvisor.yaml). It works alongside an existing `falco.yaml`, including one that already runs `modern_ebpf` and the `container` plugin.

All settings go in `init_config`. Unknown keys are rejected. The plugin takes no open parameters (`open_params` must be empty).

## Settings

### Connection

| Key | Default | Meaning |
|---|---|---|
| `socketPath` | `/run/falco/gvisor.sock` | Socket the sandboxes connect to. Must match the `endpoint` in the trace session files. |
| `maxConnections` | `1024` | Maximum sandboxes connected at once. Extra connections are refused, logged and counted (`connections_rejected`), and the health rule fires. |
| `requireRunscPeer` | `false` | Only accept connections from an executable named `runsc` (checked through `/proc/<pid>/exe`, so Falco must share the host PID namespace). The shipped `deploy/falco.config.d/gvisor.yaml`, used by the Docker, Nomad and host setups, turns it on; the Kubernetes values leave it off because the Falco chart doesn't use the host PID namespace. Connections are always limited to root or Falco's own user. |

### Attaching to running sandboxes

gVisor connects to the plugin only when a sandbox starts, and never reconnects. To cover sandboxes that started before Falco (or before Falco restarted), the plugin runs `runsc trace create --force` on any running sandbox that isn't connected.

| Key | Default | Meaning |
|---|---|---|
| `attachOnOpen` | `true` | Attach running sandboxes when Falco starts. |
| `attachIntervalSeconds` | `300` | How often to look for unmonitored sandboxes. `0` disables it. |
| `runscPath` | `runsc` | The runsc binary (looked up in `PATH`). |
| `runscRoot` | `/run/docker/runtime-runc/moby` | runsc's state directory. For containerd/Kubernetes use `/run/containerd/runsc/k8s.io`. See the [runbook](runbook.md#finding-the-runsc-state-root). |
| `sessionConfigPath` | `/etc/falco/gvisor-session.json` | Trace session used when attaching. |

### Container metadata

| Key | Default | Meaning |
|---|---|---|
| `metadataProvider` | `docker` | Where container names, images and labels come from: `docker`, `cri` or `none`. Use `cri` on Kubernetes: only then does the attacher trust the CRI annotations that group a pod's containers into one sandbox (under Docker, any user can set annotations). |
| `dockerSocket` | `/var/run/docker.sock` | Used by the `docker` provider. |
| `criSocket` | `/run/containerd/containerd.sock` | Used by the `cri` provider (also gives pod name, namespace and labels). |
| `labelAllowlist` | `[]` (all) | Only fetch these labels. |
| `metadataCacheTTLSeconds` | `600` | How long metadata is cached. |
| `metadataWaitMillis` | `200` | How long a new container's first events wait for its metadata. Events are held in order and the socket keeps being read meanwhile. Held events use at most `maxQueueBytes` across all sandboxes; beyond that they are passed on without waiting. `0` disables waiting. |

Environment variables are never requested. If a custom session asks for them, they are stripped on arrival and never stored, logged or passed to Falco.

### Limits and privacy

| Key | Default | Meaning |
|---|---|---|
| `captureArgs` | `true` | Forward process arguments. With `false` only `argv[0]` is kept, and the rules that match on arguments (miner arguments, reverse shells, `curl \| sh`) can no longer fire. |
| `maxEventSize` | `1048576` (1 MiB) | Largest message accepted from gVisor. Larger ones are dropped, logged and counted (`drops_truncated`). gVisor itself can't send messages larger than its socket send buffer (about 208 KiB by default); those are counted as `drops_sandbox`. |
| `maxQueueBytes` | `67108864` (64 MiB) | Memory for events waiting for Falco. Each sandbox gets an equal share; beyond it, its events are dropped and counted (`drops_queue_share`, `drops_channel_full`). |
| `maxTrackedProcesses` | `4096` | Processes remembered per sandbox. Whatever this is set to, a sandbox's process table is also limited to about 16 MiB, and once all sandboxes' tables together pass 256 MiB, each table above 1 MiB drops its least recently used processes. |
| `statsIntervalSeconds` | `60` | How often to emit a `gvisor_stats` health event. `0` disables it. |

## Trace sessions

A trace session tells gVisor which events to send. Every session must be named `Default`: gVisor rejects any other name and the sandbox then runs unmonitored.

| File | Used for |
|---|---|
| `deploy/gvisor-pod-init.json` | New sandboxes, via runsc's `--pod-init-config` flag. |
| `deploy/gvisor-session.json` | The same session, in the format `runsc trace create` (the attacher) expects. |
| `deploy/pod-init-full.json`, `deploy/gvisor-session-full.json` | The full profile: the above plus file opens. |

The default (lean) profile sends container starts, process clone/exec/exit, and the results of `connect`, `socket`, `execve`, `execveat`, `ptrace` and the `setuid` family. Rules about files (writes to cron or `authorized_keys`, service account tokens, `/sys/kernel`) need the full profile, which costs more CPU. See [perf.md](perf.md).

## Fail-open behaviour

Monitoring never stops a sandbox from working:

- Every shipped session sets `"ignore_setup_error": true`, so sandboxes start even when Falco is down. One exception: if Falco is frozen while its socket still accepts connections, gVisor waits for its handshake with no timeout, and sandbox creation blocks until Falco recovers ([upstream issue draft](upstream-issues.md)).
- gVisor drops events rather than slowing the workload when the plugin can't keep up.
- The plugin drops and counts events rather than growing Falco's memory without limit.
