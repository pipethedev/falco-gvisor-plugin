# gvisor plugin runbook

## Prerequisites and privileges

Falco needs:

- **The plugin socket directory on the host** (`/run/falco` by default). Sandboxes connect to the socket from the host mount namespace, so in a container deployment `/run/falco` must be a host bind mount.
- **The runsc binary and state root** for the attacher, at the same paths as on the host (for example `/usr/local/bin/runsc` and `/run/docker/runtime-runc/moby`).
- **The host PID namespace** (`pid: host`, `hostPID: true`). runsc checks sandbox processes by their host PIDs.
- **The runtime socket** for metadata: the Docker socket (`metadataProvider: docker`) or the CRI socket (`cri`).
- **Root**, or permission to connect to the runsc control sockets and run `runsc trace create`.

The listening socket is created with mode `0660`, owned by Falco's user and group. The plugin refuses to listen if the socket directory is a symlink, is writable by other users, is group-writable with a group other than root, or is owned by a user other than root or Falco's. Use a `0750` (or `0755`) directory owned by root. It also rejects connections from processes running as any user other than root or Falco's (checked with `SO_PEERCRED`), counted in `gvisor.stats.peer_rejected`. runsc creates sandboxes as root, so rootless runsc is not supported.

## Finding the runsc state root

The root depends on how runsc is invoked:

| Setup | Typical root |
|---|---|
| Docker (containerd shim) | `/run/docker/runtime-runc/moby` |
| containerd / Kubernetes (`io.containerd.runsc.v1`) | `/run/containerd/runsc/k8s.io` |
| Custom `--root` in runtimeArgs | that value |

Confirm by listing state files while a gVisor container runs:

```sh
ls /run/docker/runtime-runc/moby/*.state
sudo runsc --root /run/docker/runtime-runc/moby list
```

Set `runscRoot` to the directory that contains the `.state` files.

## Enabling monitoring

### Docker

1. Install the session files: `deploy/gvisor-pod-init.json` and `deploy/gvisor-session.json` into `/etc/falco/`.
2. Add `"--pod-init-config=/etc/falco/gvisor-pod-init.json"` to every gVisor runtime's `runtimeArgs` in `/etc/docker/daemon.json`, keeping the existing args.
3. Validate and apply:

   ```sh
   sudo dockerd --validate --config-file /etc/docker/daemon.json
   sudo systemctl reload docker
   ```

New containers are monitored at creation. Existing ones are attached by the plugin.

### containerd and Kubernetes

1. Install `/etc/falco/gvisor-pod-init.json` on every gVisor node.
2. Point the runsc shim at it via `deploy/containerd/runsc.toml` (`[runsc_config] pod-init-config = ...`) and reference that file from containerd's runtime options (`deploy/containerd/config.toml`). Restart containerd.
3. Deploy Falco with `deploy/kubernetes/values-gvisor.yaml`: `runscRoot: /run/containerd/runsc/k8s.io`, `metadataProvider: cri`.
4. Use the `gvisor` RuntimeClass (`deploy/kubernetes/runtimeclass.yaml`) for workloads.

## Verifying

1. **Falco loaded the plugin:** `falco --list-plugins` shows `gvisor`, and the logs show `[gvisor-plugin] listening on /run/falco/gvisor.sock`.
2. **Sandboxes are connected:** the periodic log line `[gvisor-plugin] stats: connections=N ...` should match the number of running gVisor sandboxes.
3. **A sandbox has the session:**

   ```sh
   sudo runsc --root <root> trace list <sandbox-id>     # shows session "Default"
   sudo runsc --root <root> trace metadata              # points and sinks this runsc supports
   ```

4. **End to end:** run the quick-start miner command from the README and look for `gVisor Crypto Miner Executed`.

## Troubleshooting

| Symptom | Check |
|---|---|
| `connections` above 0 but no events | The session is not named `Default`: runsc logs `unable to configure event session: only a single "Default" session is supported` while the sink stays connected. Use the shipped session files. |
| `connections=0` but sandboxes run | Socket path in the session `endpoint` must equal `socketPath`; `/run/falco` must be a host mount. runsc logs `Ignoring sink setup failure` when it cannot connect (by design the container still starts). |
| New sandboxes monitored, old ones not | The attacher needs runsc and the state root: look for `attacher:` / `attach sandbox` errors and `attach_failures` in stats. Verify `runscRoot`: runsc lists no sandboxes, without an error, for a directory that doesn't exist, so the plugin logs `attacher: runsc state root: ... check runscRoot` instead. |
| Attach fails with permission errors | Run Falco as root with host PID; mount the state root read-write. |
| `container.name` empty | Metadata is fetched asynchronously, so the first events of a new container have none. If it stays empty, check the `container metadata for ...` log lines and the runtime socket mount. Use `metadataProvider: cri` under Kubernetes. |
| `drops_channel_full` grows | Falco is not consuming fast enough: reduce the traced points, check Falco CPU and output back-pressure (slow http outputs). |
| `drops_queue_share` grows | One sandbox is producing events faster than Falco consumes them and has used its share of `maxQueueBytes`. Other sandboxes keep their share. The plugin logs `sandbox connection N (containers ...) dropped M events` when that connection closes. |
| `drops_sandbox` grows | The sandbox could not write to the socket in time. Raise `retries`/`backoff_max` in the session (costs workload latency on bursts) or reduce points. |
| `drops_truncated` grows | Messages exceed `maxEventSize` (very long argv); raise it. |
| `handshake_rejected` | A sandbox speaks an unsupported wire version: upgrade the plugin to match runsc. |
| `peer_rejected` grows, log says `peer executable is not runsc` | `requireRunscPeer` is on and the connecting process isn't a binary named `runsc`: either your runtime calls runsc under another name or through a wrapper, or Falco can't see the host's processes (no host PID namespace). Fix that, or set `requireRunscPeer: false`. |
| File rules never fire | They need the full profile (`pod-init-full.json`, `gvisor-session-full.json`). |
| Only one alert for an event matching two rules | Falco's default `rule_matching: first`. Set `rule_matching: all` to get every match. |

The `gVisor Monitoring Dropping Events` rule alerts when events are dropped.

## Restarts and reloads

gVisor sinks connect once, when a sandbox is created, and never reconnect. Whenever Falco closes the plugin, every sandbox connection is lost. That happens on a restart, on `SIGHUP`, and on any change to a watched config or rules file (`watch_config_files`, on by default). Coverage then depends on the attacher re-attaching each running sandbox with `runsc trace create`, immediately when `attachOnOpen` is set, otherwise within `attachIntervalSeconds`.

- Points emitted between the reload and the re-attach are lost.
- If runsc or its state root is unreachable from Falco, sandboxes stay unmonitored. The default-enabled rule **gVisor Sandboxes Not Monitored** fires on every `gvisor_stats` event while `gvisor.stats.attacher_failed` is true or `gvisor.stats.unmonitored_sandboxes` is above zero. Treat it as a monitoring outage.
- Disabling both `attachOnOpen` and periodic sweeps (`attachIntervalSeconds: 0`) means a single rules edit leaves every running sandbox unmonitored until it is recreated.

## Tuning rules

Override the allowlist macros in a file that loads after `gvisor_rules.yaml`. Files in `rules.d` load alphabetically, so name it for example `gvisor_rules_local.yaml`:

```yaml
- macro: gvisor_metadata_allowlist
  condition: (container.image startswith "registry.example.com/aws-sdk-app")
  override:
    condition: replace

- macro: gvisor_mail_server_workloads
  condition: (proc.name in (postfix, master, my-mailer))
  override:
    condition: replace
```

Other tuning hooks:

- `gvisor_miner_sha256` and `gvisor_network_tool_sha256`: override with `(proc.sha256 in (...))` to catch renamed tool binaries by hash.
- `gvisor_expected_outbound_ports` / `gvisor_expected_outbound`: define normal egress before enabling **gVisor Unexpected Outbound Connection**.
- `gvisor_sensitive_file_readers`: tools allowed to read their own credential files.
- Enable rules that are off by default from `falco.yaml`:

  ```yaml
  rules:
    - enable:
        rule: gVisor Terminal Shell in Container
  ```

Each rule's override macro is named in its condition (`gvisor_*_allowlist`, plus `gvisor_mail_server_workloads` and `gvisor_raw_socket_allowlist`).

### Mining pool IPs

Hostnames cannot be matched reliably in conditions, so pool domains are resolved to IPs:

```sh
rules/tools/pool_ips.sh > /etc/falco/rules.d/gvisor_rules_pools.yaml
```

Pool addresses rotate, so regenerate the file daily (cron or a CI job), review `rules/tools/mining_pools.txt` periodically, and reload Falco (`SIGHUP`, or `watch_config_files: true`). If nothing resolves, the generated file leaves the rule inactive.

## Rollback

1. Remove `--pod-init-config` from the runtime config and reload Docker or restart containerd.
2. Stop Falco or remove the plugin config.

Because every sink sets `ignore_setup_error`, the order of these steps does not matter to workloads. Running sandboxes keep their session until they exit; it is harmless once nothing listens.

## Upgrades

- Keep the session name `Default`. gVisor rejects any other name, and the attacher's `--force` relies on it to replace the pod-init session.
- The runsc Debian package ships its own `/etc/containerd/runsc.toml`; merge the `pod-init-config` line into it rather than replacing the file, and recheck it after runsc upgrades.
- Sessions set `ignore_missing`, so a session written for a newer runsc works on older ones; unsupported points and fields are skipped.
- After upgrading Falco or the plugin, running sandboxes are re-attached automatically on startup.
