# gvisor plugin event payload

Every event the plugin hands to Falco is an opaque byte payload with plugin ID 999 and source `gvisor`. The payload starts with a 4-byte magic that identifies its kind and format version. Captures (`.scap` files) store these payloads verbatim, so this format is what a capture reader or another extractor has to decode.

## Point events (`GVP1`)

| Offset | Size | Content |
|---|---|---|
| 0 | 4 | ASCII `GVP1` |
| 4 | 4 | Context length `N`, unsigned little-endian |
| 8 | N | Context, UTF-8 JSON (below) |
| 8 + N | rest | The gVisor remote-sink packet as received: 8-byte wire header (`HeaderSize`, `MessageType`, `DroppedCount`, native byte order) followed by the protobuf payload |

The packet is passed through unchanged, with two exceptions. If it carried environment variables (only possible with a custom session that requests `env`/`envv`), they are removed and the packet is re-encoded. If `captureArgs` is `false`, argv is cut to `argv[0]` and the packet is re-encoded. A `GVP1` payload therefore never contains environment variables.

**Timestamp:** Falco's event timestamp is the point's `context_data.time_ns`, the sandbox clock in nanoseconds since the Unix epoch. It falls back to the time of receipt only when the session does not request the `time` context field.

### Context JSON

```json
{
  "proc": { "pid": 42, "ppid": 1, "exepath": "/tmp/xmrig", "argv": ["/tmp/xmrig", "--donate-level", "1"],
            "cwd": "/", "comm": "xmrig", "uid": 0, "gid": 0, "creds": true, "start": 1700000000000000000,
            "execsess": false, "sha256": "…", "upper": true, "lower": false, "memfd": false,
            "stdin": "pipe", "stdout": "file", "stderr": "file", "tty": 0, "stdinpipe": "curl" },
  "anc":  [ { "pid": 1, "comm": "sh", "exepath": "/bin/sh", "argv": ["sh", "-c", "…"] }, { "pid": 0, "comm": "init" } ],
  "prevuid": 1000,
  "ctr":  { "id": "<64 hex>", "name": "web", "image": "nginx:1.27", "labels": {"app": "web"},
            "pod": "web-0", "ns": "prod", "podlabels": {"tier": "front"} },
  "arch": "arm64"
}
```

- `proc`: snapshot of the process that emitted the point, taken when the event was built, so extraction never depends on later state.
- `anc`: up to 8 ancestors, nearest first. Only the parent (`anc[0]`) keeps `argv`, since no field reads older ancestors' argv.
- `prevuid`: present only on setuid-family events for processes seen before; the effective uid before the call.
- `ctr`: container metadata from Docker or CRI, absent until resolved. It never contains environment variables.
- `arch`: the sandbox's architecture, used to map syscall numbers to names. Events without it are decoded with the reader's architecture.
- Fields with zero or empty values are omitted (`omitempty`). `creds` tells an unknown uid/gid apart from uid 0.

**Size cap:** the context is limited to 32 KiB. If it would be larger, the plugin removes, in order: ancestors' argv, then the farthest ancestors one at a time, then container and pod labels, then the process's arguments after `argv[0]`. An event whose context still does not fit is dropped and counted in `gvisor.stats.drops_context_size`.

## Stats events (`GVS1`)

| Offset | Size | Content |
|---|---|---|
| 0 | 4 | ASCII `GVS1` |
| 4 | rest | UTF-8 JSON of the stats snapshot (`connections`, `events`, `events_per_second`, the `drops_*` counters, `queue_bytes`, `unmonitored_sandboxes`, `attacher_failed`, `peer_rejected`, `panics`, `time_ns`, …) |

These events have `evt.type = gvisor_stats` and expose the `gvisor.stats.*` fields.

## Versioning

- New JSON keys may be added to the context or stats at any time. Readers must ignore unknown keys and treat missing keys as unknown.
- Any change that existing readers would misinterpret (layout, meaning or type of an existing key, byte order) gets a new magic (`GVP2`, `GVS2`). The extractor rejects payloads whose magic it does not know, rather than guessing.
- The embedded gVisor packet follows gVisor's own wire versioning: the handshake version and the header's `HeaderSize`.
