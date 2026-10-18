package gvisor

// PluginVersion is overridden at build time with -ldflags -X.
var PluginVersion = "0.1.0"

// MaxPluginEventSize is the largest plugin event the source can produce.
func MaxPluginEventSize(cfg Config) uint32 {
	return uint32(cfg.MaxEventSize + envelopeHdrSize + maxContextBytes)
}
