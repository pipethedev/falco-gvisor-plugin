# gvisor plugin for Falco

Detect threats inside [gVisor](https://gvisor.dev) sandboxes with [Falco](https://falco.org).

## Why

gVisor runs each container on its own user-space kernel. That isolates the container well, but it also hides it: host-level security tools (Falco's eBPF and kernel-module drivers, Tetragon, Tracee) can't see what happens inside the sandbox. Falco used to have built-in gVisor support, but it was removed in Falco 0.44.

This plugin brings that visibility back. gVisor's [Runtime Monitoring](https://gvisor.dev/docs/user_guide/runtime_monitoring/) sends the plugin a stream of events from every sandbox (processes started, network connections, privilege changes, …). The plugin passes them to Falco as the `gvisor` event source, so Falco rules can alert on them like on any other event.

```
container in gVisor ──events──▶ gvisor plugin ──▶ Falco rules ──▶ alerts
```

## What it detects

The shipped rules ([`rules/gvisor_rules.yaml`](rules/gvisor_rules.yaml)) cover:

| Threat | Examples |
|---|---|
| Crypto mining | Known miner binaries and arguments, connections to mining pool ports and IPs |
| Drop and execute | Binaries written to `/tmp` or `/dev/shm` and run, programs run from memory, `curl \| sh` |
| Reverse shells | `/dev/tcp` tricks, `nc -e`, shells wired to a network socket |
| Sandbox escape attempts | Container runtime sockets, `nsenter`/`unshare`/`mount`, `ptrace`, host kernel files |
| Network abuse | Port scanners, raw sockets, SMTP from non-mail workloads |
| Privilege changes | Non-root processes becoming root |
| Persistence and credentials | Writes to cron and `authorized_keys`, reads of credential files |

Four rules that need tuning for each environment ship disabled: shells in `kubectl exec` sessions, unexpected outbound connections, cloud metadata access, and service account token reads. Every rule has an allowlist macro you can override. See the [runbook](docs/runbook.md#tuning-rules).

The plugin also reports on its own health: the **gVisor Monitoring Degraded** rule alerts if sandboxes go unmonitored or events are being dropped.

## Requirements

- Falco 0.45 or later (the rules need Falco's rules engine 0.65.0, which is what 0.45.0 ships)
- gVisor (`runsc`) from 2023 or later
- Linux, amd64 or arm64

## Quick start (Docker)

1. **Build the image.** It's Falco with the plugin, the rules and example configs.

   ```sh
   make image
   ```

2. **Turn on monitoring in gVisor.** Copy the trace session file to the host, and tell Docker's `runsc` runtime to use it:

   ```sh
   sudo install -D -m 0644 deploy/gvisor-pod-init.json /etc/falco/gvisor-pod-init.json
   ```

   In `/etc/docker/daemon.json`, add `"--pod-init-config=/etc/falco/gvisor-pod-init.json"` to the runsc `runtimeArgs` (example: [`deploy/docker/daemon.json`](deploy/docker/daemon.json)), then reload Docker:

   ```sh
   sudo dockerd --validate --config-file /etc/docker/daemon.json && sudo systemctl reload docker
   ```

3. **Start Falco.**

   ```sh
   docker compose -f deploy/docker/docker-compose.yaml up -d
   ```

4. **Try it.** Run a fake crypto miner in a gVisor container:

   ```sh
   docker run --rm --runtime=runsc alpine sh -c \
     'cp /bin/busybox /tmp/xmrig && /tmp/xmrig --donate-level 1 -o stratum+tcp://example.invalid:3333'
   ```

   Falco's output should show a `gVisor Crypto Miner Executed` alert.

New containers are monitored from their first instruction. Containers that were already running are picked up automatically within a few minutes, or immediately when Falco restarts.

If gVisor can't reach Falco (Falco is down, say), sandboxes still start normally; they just aren't monitored until Falco is back.

**Other platforms:** for containerd and Kubernetes (Helm values and runsc config), Nomad and plain hosts, see [`deploy/`](deploy) and the [runbook](docs/runbook.md).

## Install with falcoctl

This plugin is being prepared for the [falcosecurity/plugins](https://github.com/falcosecurity/plugins) repository, and the index below lives there. Until it is merged, build it from source (`make image`, or `make build-linux` for the library).

Once it is published:

```sh
falcoctl index add gvisor https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/gvisor/deploy/falcoctl/index.yaml
falcoctl artifact install gvisor-rules:0.1.0   # also installs the matching plugin
```

Releases also ship tarballs: `gvisor-<version>-linux-{x86_64,aarch64}.tar.gz` for the plugin and `gvisor-rules-<version>.tar.gz` for the rules.

## Documentation

| Page | What's in it |
|---|---|
| [Configuration](docs/configuration.md) | Every setting, the trace session profiles, fail-open behaviour |
| [Runbook](docs/runbook.md) | Installing, verifying, troubleshooting, tuning rules, upgrades |
| [Fields](docs/fields.md) | Every field you can use in rules (`proc.*`, `fd.*`, `container.*`, `gvisor.*`, …) |
| [Performance](docs/perf.md) | Costs of the lean and full profiles |
| [Development](docs/development.md) | Building, testing, how the plugin works, what has been validated |
| [Event format](docs/payload.md) | Byte layout of events, for tools that read Falco captures |

## Limitations

- **Only what gVisor reports is visible.** The default profile does not include file opens; file-based rules need the [full profile](docs/configuration.md#trace-sessions), which costs more.
- **Some events can be lost silently.** gVisor drops events whose text (arguments, paths, names) isn't valid UTF-8 without counting them. This needs a fix in gVisor ([issue draft](docs/upstream-issues.md)).
- **Dropped exec events lose detail.** If gVisor drops an exec event under load, exec rules still fire on the process's next event, but rules that need details about the binary (where it came from, its hash) can't, and an exec of a program with the same name as the old one (say `sh` running `sh -c …`) is missed.
- **Running sandboxes are picked up by polling**, every `attachIntervalSeconds` (5 minutes by default), not instantly.
- **Process IDs are the sandbox's own**, not the host's.
- **No response actions.** The plugin detects; to stop containers, use a separate responder on Falco's output.

## Plugin details

| | |
|---|---|
| Name and event source | `gvisor` |
| Capabilities | event sourcing, field extraction |
| Plugin ID | `999`, a development ID until the [plugin registry](https://github.com/falcosecurity/plugins/blob/main/registry.yaml) assigns one ([draft entry](docs/registry-entry.yaml)) |
| Plugin API | 3.11 |

## License

Apache-2.0. See [LICENSE](LICENSE).
