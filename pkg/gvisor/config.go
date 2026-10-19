package gvisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

const (
	defaultSocketPath         = "/run/falco/gvisor.sock"
	defaultMaxEventSize       = 1 << 20
	defaultRunscPath          = "runsc"
	defaultRunscRoot          = "/run/docker/runtime-runc/moby"
	defaultSessionConfigPath  = "/etc/falco/gvisor-session.json"
	defaultAttachInterval     = 300
	defaultDockerSocket       = "/var/run/docker.sock"
	defaultCRISocket          = "/run/containerd/containerd.sock"
	defaultMetadataCacheTTL   = 600
	defaultMaxTrackedProcess  = 4096
	defaultStatsInterval      = 60
	defaultMaxQueueBytes      = 64 << 20
	defaultMetadataWaitMillis = 200
	defaultMaxConnections     = 1024
	maxMaxConnections         = 65536
	maxMetadataWaitMillis     = 5000
	minMaxQueueBytes          = 1 << 20
	maxMaxQueueBytes          = 4 << 30
	minMaxEventSize           = 1024
	maxMaxEventSize           = 16 << 20
	maxMaxTrackedProcesses    = 1 << 20
	providerDocker            = "docker"
	providerCRI               = "cri"
	providerNone              = "none"
	errInvalidConfigPrefix    = "invalid init config"
	errFieldMustBeAbsoluteFmt = "%s: %s must be an absolute path"
)

// Config is the plugin init configuration.
type Config struct {
	SocketPath              string   `json:"socketPath"`
	MaxEventSize            int      `json:"maxEventSize"`
	RunscPath               string   `json:"runscPath"`
	RunscRoot               string   `json:"runscRoot"`
	SessionConfigPath       string   `json:"sessionConfigPath"`
	AttachOnOpen            bool     `json:"attachOnOpen"`
	AttachIntervalSeconds   int      `json:"attachIntervalSeconds"`
	MetadataProvider        string   `json:"metadataProvider"`
	DockerSocket            string   `json:"dockerSocket"`
	CRISocket               string   `json:"criSocket"`
	LabelAllowlist          []string `json:"labelAllowlist"`
	MetadataCacheTTLSeconds int      `json:"metadataCacheTTLSeconds"`
	MaxTrackedProcesses     int      `json:"maxTrackedProcesses"`
	StatsIntervalSeconds    int      `json:"statsIntervalSeconds"`
	MaxQueueBytes           int      `json:"maxQueueBytes"`
	MetadataWaitMillis      int      `json:"metadataWaitMillis"`
	CaptureArgs             bool     `json:"captureArgs"`
	MaxConnections          int      `json:"maxConnections"`
	RequireRunscPeer        bool     `json:"requireRunscPeer"`
}

// DefaultConfig returns the configuration used for keys absent from the init config.
func DefaultConfig() Config {
	return Config{
		SocketPath:              defaultSocketPath,
		MaxEventSize:            defaultMaxEventSize,
		RunscPath:               defaultRunscPath,
		RunscRoot:               defaultRunscRoot,
		SessionConfigPath:       defaultSessionConfigPath,
		AttachOnOpen:            true,
		AttachIntervalSeconds:   defaultAttachInterval,
		MetadataProvider:        providerDocker,
		DockerSocket:            defaultDockerSocket,
		CRISocket:               defaultCRISocket,
		LabelAllowlist:          []string{},
		MetadataCacheTTLSeconds: defaultMetadataCacheTTL,
		MaxTrackedProcesses:     defaultMaxTrackedProcess,
		StatsIntervalSeconds:    defaultStatsInterval,
		MaxQueueBytes:           defaultMaxQueueBytes,
		MetadataWaitMillis:      defaultMetadataWaitMillis,
		CaptureArgs:             true,
		MaxConnections:          defaultMaxConnections,
	}
}

// ParseConfig decodes and validates an init config, applying defaults.
func ParseConfig(raw string) (Config, error) {
	cfg := DefaultConfig()
	if len(bytes.TrimSpace([]byte(raw))) > 0 {
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("%s: %w", errInvalidConfigPrefix, err)
		}
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var errs []error
	for name, path := range map[string]string{
		"socketPath":        c.SocketPath,
		"runscRoot":         c.RunscRoot,
		"sessionConfigPath": c.SessionConfigPath,
		"dockerSocket":      c.DockerSocket,
		"criSocket":         c.CRISocket,
	} {
		if !filepath.IsAbs(path) {
			errs = append(errs, fmt.Errorf(errFieldMustBeAbsoluteFmt, errInvalidConfigPrefix, name))
		}
	}
	if c.RunscPath == "" {
		errs = append(errs, fmt.Errorf("%s: runscPath must not be empty", errInvalidConfigPrefix))
	}
	if c.MaxEventSize < minMaxEventSize || c.MaxEventSize > maxMaxEventSize {
		errs = append(errs, fmt.Errorf("%s: maxEventSize must be in [%d, %d]", errInvalidConfigPrefix, minMaxEventSize, maxMaxEventSize))
	}
	if c.MaxQueueBytes < minMaxQueueBytes || c.MaxQueueBytes > maxMaxQueueBytes || c.MaxQueueBytes < 2*c.MaxEventSize {
		errs = append(errs, fmt.Errorf("%s: maxQueueBytes must be in [%d, %d] and at least twice maxEventSize", errInvalidConfigPrefix, minMaxQueueBytes, maxMaxQueueBytes))
	}
	if c.MetadataWaitMillis < 0 || c.MetadataWaitMillis > maxMetadataWaitMillis {
		errs = append(errs, fmt.Errorf("%s: metadataWaitMillis must be in [0, %d]", errInvalidConfigPrefix, maxMetadataWaitMillis))
	}
	if c.MaxConnections < 1 || c.MaxConnections > maxMaxConnections {
		errs = append(errs, fmt.Errorf("%s: maxConnections must be in [1, %d]", errInvalidConfigPrefix, maxMaxConnections))
	}
	if c.MaxTrackedProcesses < 1 || c.MaxTrackedProcesses > maxMaxTrackedProcesses {
		errs = append(errs, fmt.Errorf("%s: maxTrackedProcesses must be in [1, %d]", errInvalidConfigPrefix, maxMaxTrackedProcesses))
	}
	for name, v := range map[string]int{
		"attachIntervalSeconds":   c.AttachIntervalSeconds,
		"metadataCacheTTLSeconds": c.MetadataCacheTTLSeconds,
		"statsIntervalSeconds":    c.StatsIntervalSeconds,
	} {
		if v < 0 {
			errs = append(errs, fmt.Errorf("%s: %s must not be negative", errInvalidConfigPrefix, name))
		}
	}
	switch c.MetadataProvider {
	case providerDocker, providerCRI, providerNone:
	default:
		errs = append(errs, fmt.Errorf("%s: metadataProvider must be one of %q, %q, %q", errInvalidConfigPrefix, providerDocker, providerCRI, providerNone))
	}
	return errors.Join(errs...)
}

func (c Config) attachInterval() time.Duration {
	return time.Duration(c.AttachIntervalSeconds) * time.Second
}

func (c Config) metadataCacheTTL() time.Duration {
	return time.Duration(c.MetadataCacheTTLSeconds) * time.Second
}

func (c Config) metadataWait() time.Duration {
	return time.Duration(c.MetadataWaitMillis) * time.Millisecond
}

func (c Config) statsInterval() time.Duration {
	return time.Duration(c.StatsIntervalSeconds) * time.Second
}
