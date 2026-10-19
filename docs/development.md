# Development

## Building and testing

```sh
make build             # libgvisor.so for this machine
make build-linux       # dist/{amd64,arm64}/libgvisor.so, built in Docker
make test              # unit tests with the race detector
make test-linux        # Linux-only unit tests, from macOS, in a container
make rules-test        # the rules against a real Falco, using fake sandbox traffic
make test-gvisor       # real gVisor sandboxes next to Falco (needs privileged Docker)
make test-integration  # needs a Linux host with Docker, runsc and Falco
make generate          # syscall tables and docs/fields.md
make lint
```

The Go module path, `github.com/falcosecurity/plugins/plugins/gvisor`, is where the plugin will live once it is merged into the falcosecurity plugins repository, so it can't be fetched with `go get` from this repository; clone it and build locally.

The plugin uses gVisor's own decoding packages (`points_go_proto` and the remote sink's `wire`) from the `gvisor.dev/gvisor` module's `go` branch; `go.mod` pins the exact version.

### Rule tests

`make rules-test` starts Falco 0.45 in Docker and replays the fixtures in [`rules/tests`](../rules/tests) into the plugin as if they came from sandboxes. Each `attack_*` fixture must fire exactly the rules it lists, and each `benign_*` fixture (Node, Python, Go, nginx, exec sessions, …) must fire none. Fixtures in `rules/tests/defaults/` run with only the rules enabled by default. `rules/tests/captures/` holds traffic recorded from a real runsc sandbox.

## How it works

```
 workload ──syscall──▶ gVisor Sentry ──trace points──▶ /run/falco/gvisor.sock
                                                             │
 ┌──────────────────────────── Falco ────────────────────────┴───────────────┐
 │  source: syscall (modern_ebpf)   host and non-gVisor containers            │
 │  source: gvisor  (libgvisor.so)                                            │
 │     ├─ server: one connection per sandbox, each with its process table     │
 │     ├─ attacher: runsc trace create --force for unmonitored sandboxes      │
 │     └─ metadata: container id → name/image/labels (Docker API or CRI)      │
 │  rules: gvisor_rules.yaml (source: gvisor) + your syscall rules            │
 └──────────────────────────────────▶ outputs (stdout / json / http / …)     │
```

- **Server:** accepts one connection per sandbox, does gVisor's handshake, and tracks each sandbox's processes from its container start, clone, exec and exit events. Every Falco event carries a snapshot of the process and up to 8 ancestors.
- **Attacher:** finds running sandboxes with no connection and attaches a trace session to them.
- **Metadata:** looks up container names, images and labels in the background and caches them.

The byte format of the events the plugin hands Falco is in [payload.md](payload.md).

## Validation status

- **Unit tests** pass with the race detector on macOS, Linux arm64 and Linux amd64 (amd64 under emulation). golangci-lint is clean and the decoders are fuzzed.
- **Rules:** all 46 checks pass against Falco 0.45.0 on arm64 and amd64, including the recorded runsc traffic and a pass with the default rules that must stay silent on routine pod behaviour.
- **Real gVisor** (runsc release-20261012.0, arm64, systrap), in `make test-gvisor` and CI. It checks that:
  - a sandbox with monitoring enabled starts while nothing is listening
  - the plugin attaches an unmonitored sandbox
  - an idle attached sandbox is not attached again
  - binaries dropped in `/tmp` and `/dev/shm` are detected
  - sandboxes are re-attached after a Falco rules reload

  The same checks pass with `requireRunscPeer` enabled.
- **Packaging:** the release's falcoctl commands were rehearsed against a local OCI registry for `linux/amd64` and `linux/arm64`.
- **Not yet run:** the Docker-runtime and Kubernetes integration tests (`test/integration/run.sh`), end-to-end benchmarks ([perf.md](perf.md) has the microbenchmarks), runsc on amd64, and the CRI provider against a real containerd.
