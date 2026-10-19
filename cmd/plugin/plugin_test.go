package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
)

// Loading libgvisor.so into a Go test binary would put two Go runtimes in
// one process, which Go does not support and which hangs intermittently.
// These tests exercise the plugin methods directly; loading the built
// library is covered by running it in Falco (make rules-test, make
// test-gvisor).

func TestPluginInfo(t *testing.T) {
	info := (&gvisorPlugin{}).Info()
	if info.Name != pluginName || info.EventSource != pluginSource || info.ID != pluginID || info.RequiredAPIVersion != requiredAPIVersion {
		t.Errorf("unexpected info %+v", info)
	}
	if len(info.ExtractEventSources) != 1 || info.ExtractEventSources[0] != pluginSource {
		t.Errorf("extract event sources = %v, want only %q", info.ExtractEventSources, pluginSource)
	}
}

func TestPluginInitSchemaAndConfig(t *testing.T) {
	p := &gvisorPlugin{}
	var schema map[string]any
	if err := json.Unmarshal([]byte(p.InitSchema().Schema), &schema); err != nil {
		t.Fatalf("init schema is not JSON: %v", err)
	}
	if err := p.Init(`{"metadataProvider":"none","attachOnOpen":false}`); err != nil {
		t.Errorf("init with valid config: %v", err)
	}
	if err := p.Init(`{"unknownKey":true}`); err == nil {
		t.Error("init accepted an unknown key")
	}
}

func TestPluginFieldsMirrorDefinitions(t *testing.T) {
	entries := (&gvisorPlugin{}).Fields()
	defs := gvisor.Fields()
	if len(entries) != len(defs) {
		t.Fatalf("%d SDK fields for %d definitions", len(entries), len(defs))
	}
	for i, d := range defs {
		e := entries[i]
		if e.Name != d.Name || e.Type != d.Type || e.IsList != d.IsList || e.Desc != d.Desc {
			t.Errorf("field %s not mirrored: %+v", d.Name, e)
		}
		if e.Arg.IsIndex != (d.Arg == gvisor.ArgIndex) || e.Arg.IsKey != (d.Arg == gvisor.ArgKey) || e.Arg.IsRequired != (d.Arg != gvisor.ArgNone) {
			t.Errorf("field %s argument spec %+v does not match %v", d.Name, e.Arg, d.Arg)
		}
	}
}

func TestValidateOpenParams(t *testing.T) {
	for _, ok := range []string{"", "  "} {
		if err := validateOpenParams(ok); err != nil {
			t.Errorf("open params %q rejected: %v", ok, err)
		}
	}
	if err := validateOpenParams("socket=/tmp/x"); !errors.Is(err, errOpenParams) {
		t.Errorf("non-empty open params accepted: %v", err)
	}
}

func TestRecoverInto(t *testing.T) {
	run := func() (err error) {
		defer recoverInto(&err, "test")
		panic("boom")
	}
	if err := run(); err == nil {
		t.Error("panic not converted into an error")
	}
}
