package main

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/falcosecurity/plugin-sdk-go/pkg/loader"
)

func buildPlugin(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the shared library")
	}
	out := filepath.Join(t.TempDir(), "libgvisor.so")
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", out, ".")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, msg)
	}
	return out
}

func TestPluginLoads(t *testing.T) {
	p, err := loader.NewValidPlugin(buildPlugin(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Unload)

	info := p.Info()
	if info.Name != pluginName || info.EventSource != pluginSource || info.ID != pluginID || info.RequiredAPIVersion != requiredAPIVersion {
		t.Errorf("unexpected info %+v", info)
	}
	if !p.HasCapSourcing() || !p.HasCapExtraction() {
		t.Error("plugin must provide sourcing and extraction")
	}
	if p.InitSchema() == nil || p.InitSchema().Schema == "" {
		t.Error("missing init schema")
	}
	if len(p.Fields()) == 0 {
		t.Error("no fields exported")
	}
	if err := p.Init(`{"metadataProvider":"none","attachOnOpen":false}`); err != nil {
		t.Errorf("init with valid config: %v", err)
	}
}

func TestPluginRejectsBadConfig(t *testing.T) {
	p, err := loader.NewValidPlugin(buildPlugin(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Unload)
	if err := p.Init(`{"unknownKey":true}`); err == nil {
		t.Error("init accepted an unknown key")
	}
}
