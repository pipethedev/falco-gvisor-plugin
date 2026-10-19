package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"

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

func TestBatchSizeBoundsMemory(t *testing.T) {
	cases := map[uint32]uint32{64 << 10: maxBatchSize, 1<<20 + 40<<10: 30, 64 << 20: 1}
	for eventSize, want := range cases {
		if got := batchSize(eventSize); got != want || uint64(got)*uint64(eventSize) > batchMemoryBudget && got != 1 {
			t.Errorf("batchSize(%d) = %d, want %d", eventSize, got, want)
		}
	}
}

func TestOpenResetsEventCache(t *testing.T) {
	p := &gvisorPlugin{}
	dir, err := os.MkdirTemp("", "gv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := fmt.Sprintf(`{"socketPath":%q,"metadataProvider":"none","attachOnOpen":false,"attachIntervalSeconds":0}`, filepath.Join(dir, "s.sock"))
	if err := p.Init(cfg); err != nil {
		t.Fatal(err)
	}
	stale := &gvisor.Event{}
	p.cache = newEventCache()
	_, _ = p.cache.get(1, func() (*gvisor.Event, error) { return stale, nil })
	if inst, err := p.Open(""); err == nil {
		if c, ok := inst.(sdk.Closer); ok {
			c.Close()
		}
	}
	evt, _ := p.cache.get(1, func() (*gvisor.Event, error) { return &gvisor.Event{}, nil })
	if evt == stale {
		t.Error("an event decoded in a previous capture was returned after Open")
	}
}
