//go:build linux

package gvisor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	_ "gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote"
)

const (
	deployDir          = "../../deploy"
	sessionName        = "falco"
	remoteSink         = "remote"
	sinkEndpointKey    = "endpoint"
	envFieldMarker     = "env"
	podInitSuffix      = "pod-init"
	podInitFullFile    = "pod-init-full.json"
	podInitLeanFile    = "gvisor-pod-init.json"
	sessionLeanFile    = "gvisor-session.json"
	sessionFullFile    = "gvisor-session-full.json"
	expectedConfigsLen = 4
	syscallPointPrefix = "syscall"
	syscallPointParts  = 3
)

type podInitConfig struct {
	TraceSession seccheck.SessionConfig `json:"trace_session"`
}

func decodeStrict(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func loadSession(t *testing.T, name string) seccheck.SessionConfig {
	t.Helper()
	path := filepath.Join(deployDir, name)
	if strings.Contains(name, podInitSuffix) {
		var cfg podInitConfig
		decodeStrict(t, path, &cfg)
		return cfg.TraceSession
	}
	var cfg seccheck.SessionConfig
	decodeStrict(t, path, &cfg)
	return cfg
}

func fieldNames(fields []seccheck.FieldDesc) map[string]bool {
	names := map[string]bool{}
	for _, f := range fields {
		names[f.Name] = true
	}
	return names
}

func TestShippedSessionConfigs(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(deployDir, "*.json"))
	if err != nil || len(files) != expectedConfigsLen {
		t.Fatalf("expected %d session configs in %s, found %v (%v)", expectedConfigsLen, deployDir, files, err)
	}
	for _, path := range files {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(`"`+envFieldMarker)) {
				t.Error("session must never request environment variables")
			}
			session := loadSession(t, name)
			if session.Name != sessionName {
				t.Errorf("session name %q must be %q so attach --force replaces the pod-init session", session.Name, sessionName)
			}
			if !session.IgnoreMissing {
				t.Error("ignore_missing must be true so older runsc versions accept the config")
			}
			checkSinks(t, session.Sinks)
			checkPoints(t, session.Points)
		})
	}
}

func checkSinks(t *testing.T, sinks []seccheck.SinkConfig) {
	t.Helper()
	if len(sinks) == 0 {
		t.Fatal("no sinks")
	}
	for _, sink := range sinks {
		if sink.Name != remoteSink {
			t.Errorf("unexpected sink %q", sink.Name)
		}
		if _, ok := seccheck.Sinks[sink.Name]; !ok {
			t.Errorf("sink %q is not registered in gVisor", sink.Name)
		}
		if !sink.IgnoreSetupError {
			t.Error("ignore_setup_error must be true: otherwise sandboxes fail to start when Falco is down")
		}
		if sink.Config[sinkEndpointKey] != DefaultConfig().SocketPath {
			t.Errorf("endpoint %v does not match the plugin default socket", sink.Config[sinkEndpointKey])
		}
	}
}

func syscallMissingOnArch(point string) bool {
	parts := strings.Split(point, "/")
	if len(parts) != syscallPointParts || parts[0] != syscallPointPrefix {
		return false
	}
	_, ok := SyscallNumber(parts[1])
	return !ok
}

func checkPoints(t *testing.T, points []seccheck.PointConfig) {
	t.Helper()
	seccheck.Initialize()
	for _, pt := range points {
		if syscallMissingOnArch(pt.Name) {
			continue
		}
		desc, ok := seccheck.Points[pt.Name]
		if !ok {
			t.Errorf("point %q does not exist in gVisor", pt.Name)
			continue
		}
		optional, context := fieldNames(desc.OptionalFields), fieldNames(desc.ContextFields)
		for _, f := range pt.OptionalFields {
			if !optional[f] {
				t.Errorf("point %q has no optional field %q", pt.Name, f)
			}
		}
		for _, f := range pt.ContextFields {
			if !context[f] {
				t.Errorf("point %q has no context field %q", pt.Name, f)
			}
		}
	}
}

func TestSessionVariantsMatch(t *testing.T) {
	pairs := [][2]string{{podInitLeanFile, sessionLeanFile}, {podInitFullFile, sessionFullFile}}
	for _, pair := range pairs {
		if a, b := loadSession(t, pair[0]), loadSession(t, pair[1]); !reflect.DeepEqual(a, b) {
			t.Errorf("%s and %s define different sessions", pair[0], pair[1])
		}
	}
	lean, full := loadSession(t, sessionLeanFile), loadSession(t, sessionFullFile)
	if len(full.Points) <= len(lean.Points) || !reflect.DeepEqual(full.Points[:len(lean.Points)], lean.Points) {
		t.Error("full profile must extend the lean profile")
	}
}
