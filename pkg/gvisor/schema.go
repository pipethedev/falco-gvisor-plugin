package gvisor

const initSchema = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": ["object", "null"],
  "additionalProperties": false,
  "properties": {
    "socketPath": {"type": "string", "default": "/run/falco/gvisor.sock", "description": "Unix seqpacket socket the gVisor remote sink connects to; must match the sink endpoint"},
    "maxEventSize": {"type": "integer", "minimum": 1024, "maximum": 16777216, "default": 1048576, "description": "Maximum gVisor message size; larger messages are dropped, counted and logged. gVisor cannot send a message larger than its socket send buffer (about 208 KiB by default), so the default leaves headroom"},
    "runscPath": {"type": "string", "default": "runsc", "description": "runsc binary used by the attacher"},
    "runscRoot": {"type": "string", "default": "/run/docker/runtime-runc/moby", "description": "runsc state root"},
    "sessionConfigPath": {"type": "string", "default": "/etc/falco/gvisor-session.json", "description": "Trace session config used when attaching to running sandboxes"},
    "attachOnOpen": {"type": "boolean", "default": true, "description": "Attach running, unmonitored sandboxes when the source opens"},
    "attachIntervalSeconds": {"type": "integer", "minimum": 0, "default": 300, "description": "Periodic sweep for unmonitored sandboxes; 0 disables"},
    "metadataProvider": {"type": "string", "enum": ["docker", "cri", "none"], "default": "docker", "description": "Container metadata source"},
    "dockerSocket": {"type": "string", "default": "/var/run/docker.sock", "description": "Docker Engine API socket"},
    "criSocket": {"type": "string", "default": "/run/containerd/containerd.sock", "description": "CRI runtime socket"},
    "labelAllowlist": {"type": "array", "items": {"type": "string"}, "default": [], "description": "Labels to fetch and expose; empty means all"},
    "metadataCacheTTLSeconds": {"type": "integer", "minimum": 0, "default": 600, "description": "Container metadata cache lifetime"},
    "maxTrackedProcesses": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 4096, "description": "Per-sandbox process table cap"},
    "statsIntervalSeconds": {"type": "integer", "minimum": 0, "default": 60, "description": "Interval for gvisor_stats events; 0 disables"},
    "metadataWaitMillis": {"type": "integer", "minimum": 0, "maximum": 5000, "default": 200, "description": "How long a new container's first events are held, in order, for its metadata; the connection keeps reading meanwhile. 0 disables"},
    "maxConnections": {"type": "integer", "minimum": 1, "maximum": 65536, "default": 1024, "description": "Maximum concurrent sandbox connections; further connections are refused and counted"},
    "captureArgs": {"type": "boolean", "default": true, "description": "Forward process arguments; when false only argv[0] is kept, and argument-based rules stop matching"},
    "maxQueueBytes": {"type": "integer", "minimum": 1048576, "maximum": 4294967296, "default": 67108864, "description": "Byte budget for events waiting for Falco; events beyond it are dropped and counted"}
  }
}`

// InitSchema returns the JSON schema of the init config.
func InitSchema() string {
	return initSchema
}
