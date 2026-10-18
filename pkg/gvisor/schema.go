package gvisor

const initSchema = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "socketPath": {"type": "string", "default": "/run/falco/gvisor.sock", "description": "Unix seqpacket socket the gVisor remote sink connects to; must match the sink endpoint"},
    "maxEventSize": {"type": "integer", "minimum": 1024, "maximum": 4194304, "default": 65536, "description": "Maximum message size; larger messages are dropped and counted"},
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
    "statsIntervalSeconds": {"type": "integer", "minimum": 0, "default": 60, "description": "Interval for gvisor_stats events; 0 disables"}
  }
}`

// InitSchema returns the JSON schema of the init config.
func InitSchema() string {
	return initSchema
}
