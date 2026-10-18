# Upstream issue drafts (gVisor)

Problems found while building and auditing this plugin that can only be fixed in gVisor. They have not been filed yet.

## Remote sink silently drops points that contain invalid UTF-8

**Component:** `pkg/sentry/seccheck/sinks/remote` (and the point protos)

**Problem:** the point messages use proto3 `string` fields for values that come straight from the workload: argv, binary path, process name, working directory. Go's protobuf runtime refuses to marshal a proto3 string that is not valid UTF-8. `remote.write` handles the marshal error by logging at debug level and returning (`remote.go`, `write`), without incrementing `droppedCount`. The point is lost, and the consumer cannot see that it was lost.

**Impact:** a monitoring consumer such as Falco loses visibility of any process whose identifying strings are not valid UTF-8, and nothing reports the loss.

**Suggested fixes (any of):**
- Sanitize strings before building points (for example `strings.ToValidUTF8`), or carry them as `bytes`.
- At minimum, count marshal failures in `droppedCount` so consumers can detect the loss.

## Remote sink setup can block sandbox creation indefinitely

**Component:** `pkg/sentry/seccheck/sinks/remote`, `setup()`

**Problem:** `setup()` connects, sends the handshake and then blocks in `Read` for the reply with no timeout. It only switches to non-blocking mode afterwards. If the consumer process is alive enough for the kernel to accept the connection into the listen backlog but does not answer (stopped, frozen or wedged), sandbox creation hangs. `ignore_setup_error` does not help, because no error is ever returned.

**Impact:** monitoring can prevent workloads from starting, which contradicts the sink's otherwise fail-open design.

**Suggested fix:** bound the handshake with a deadline (for example a few seconds, configurable through the sink config) and treat the timeout as a setup error, which `ignore_setup_error` already covers.

## Session name must be "Default" but the failure is only a warning

**Component:** `pkg/sentry/seccheck/config.go`, `Create`; `runsc/boot/loader.go`

**Problem:** any session not named `Default` is rejected, but at boot this is logged as a warning while the sink connection stays open. A consumer sees a healthy connection that never carries points.

**Suggested fix:** fail the session (or close the sink) when it cannot be configured, and document the naming requirement in the Runtime Monitoring guide; its examples use other names.
