package gvisor

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseConfigDefaults(t *testing.T) {
	for _, raw := range []string{"", "  ", "{}", "null"} {
		cfg, err := ParseConfig(raw)
		if err != nil {
			t.Fatalf("ParseConfig(%q): %v", raw, err)
		}
		if !reflect.DeepEqual(cfg, DefaultConfig()) {
			t.Errorf("ParseConfig(%q) = %+v, want defaults", raw, cfg)
		}
	}
}

func TestParseConfigOverrides(t *testing.T) {
	cfg, err := ParseConfig(`{"socketPath":"/tmp/x.sock","metadataProvider":"cri","attachOnOpen":false,"labelAllowlist":["app"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SocketPath != "/tmp/x.sock" || cfg.MetadataProvider != providerCRI || cfg.AttachOnOpen || len(cfg.LabelAllowlist) != 1 {
		t.Errorf("unexpected config %+v", cfg)
	}
	if cfg.MaxEventSize != defaultMaxEventSize {
		t.Errorf("unset key lost its default: %d", cfg.MaxEventSize)
	}
}

func TestParseConfigRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":        `{"bogus":1}`,
		"relative socket":    `{"socketPath":"gvisor.sock"}`,
		"tiny event size":    `{"maxEventSize":10}`,
		"zero processes":     `{"maxTrackedProcesses":0}`,
		"negative interval":  `{"attachIntervalSeconds":-1}`,
		"bad provider":       `{"metadataProvider":"podman"}`,
		"no connections":     `{"maxConnections":0}`,
		"tiny queue":         `{"maxQueueBytes":1024}`,
		"long metadata wait": `{"metadataWaitMillis":60000}`,
		"queue below events": `{"maxEventSize":4194304,"maxQueueBytes":4194304}`,
		"empty runsc":        `{"runscPath":""}`,
		"not json":           `{`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig(raw); err == nil {
				t.Errorf("ParseConfig(%s) succeeded", raw)
			}
		})
	}
}

func TestSchemaMatchesConfig(t *testing.T) {
	var schema struct {
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal([]byte(initSchema), &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if schema.AdditionalProperties {
		t.Error("schema must set additionalProperties to false")
	}
	var schemaKeys []string
	for k := range schema.Properties {
		schemaKeys = append(schemaKeys, k)
	}
	var configKeys []string
	typ := reflect.TypeFor[Config]()
	for field := range typ.Fields() {
		configKeys = append(configKeys, strings.Split(field.Tag.Get("json"), ",")[0])
	}
	sort.Strings(schemaKeys)
	sort.Strings(configKeys)
	if !reflect.DeepEqual(schemaKeys, configKeys) {
		t.Errorf("schema keys %v != config keys %v", schemaKeys, configKeys)
	}
}
