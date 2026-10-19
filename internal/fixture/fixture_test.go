package fixture

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
)

const rulesTestsDir = "../../rules/tests"

func TestRepositoryFixturesEncode(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(rulesTestsDir, "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	defaults, err := filepath.Glob(filepath.Join(rulesTestsDir, "defaults", "*.json"))
	if err != nil || len(defaults) == 0 {
		t.Fatalf("no default-rules fixtures found: %v", err)
	}
	paths = append(paths, defaults...)
	ids := map[string]string{}
	for _, path := range paths {
		f, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := ids[f.ContainerID[:shortIDLen]]; dup {
			t.Errorf("%s and %s share a short container id", f.Name, other)
		}
		ids[f.ContainerID[:shortIDLen]] = f.Name
		benign := strings.HasPrefix(f.Name, "benign_")
		if benign != (len(f.Expect) == 0) {
			t.Errorf("%s: benign fixtures must expect nothing and attack fixtures something", f.Name)
		}
		packets, err := f.Packets()
		if err != nil {
			t.Fatal(err)
		}
		for i, pkt := range packets {
			p, err := gvisor.DecodePoint(pkt)
			if err != nil {
				t.Fatalf("%s packet %d: %v", f.Name, i, err)
			}
			if p.Context().GetContainerId() != f.ContainerID {
				t.Errorf("%s packet %d: container id not set", f.Name, i)
			}
		}
	}
}

func TestPacketsRejectUnknownValues(t *testing.T) {
	cases := map[string]Event{
		"point":   {Point: "sentry/mmap"},
		"flag":    {Point: pointOpenat, Flags: "O_BOGUS"},
		"domain":  {Point: pointSocket, Domain: "AF_X25", Type: "SOCK_RAW"},
		"request": {Point: pointPtrace, Request: "PTRACE_NOPE"},
		"address": {Point: pointConnect, Addr: "not-an-address"},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			f := Fixture{Name: name, ContainerID: strings.Repeat("a", 64), Events: []Event{e}}
			if _, err := f.Packets(); err == nil {
				t.Error("expected error")
			}
		})
	}
	f := Fixture{Name: "x", ContainerID: strings.Repeat("a", 64), Events: []Event{{Point: "nope"}}}
	if _, err := f.Packets(); !errors.Is(err, errUnknownPoint) {
		t.Errorf("err = %v", err)
	}
}

func TestVerify(t *testing.T) {
	a := Fixture{Name: "attack", Expect: []string{"Rule A", "Rule B"}, ContainerID: "aaaaaaaaaaaa" + strings.Repeat("0", 52)}
	b := Fixture{Name: "benign", ContainerID: "bbbbbbbbbbbb" + strings.Repeat("0", 52)}
	log := strings.Join([]string{
		"2026-10-18T00:00:00+0000: Falco initialized",
		`{"rule":"Rule A","source":"gvisor","output_fields":{"container.id":"aaaaaaaaaaaa"}}`,
		`{"rule":"Rule A","source":"gvisor","output_fields":{"container.id":"aaaaaaaaaaaa"}}`,
		`{"rule":"Rule C","source":"gvisor","output_fields":{"container.id":"bbbbbbbbbbbb"}}`,
		`{"not":"an alert"}`,
		`{broken json`,
	}, "\n")
	results, err := Verify([]Fixture{a, b}, strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	if results[0].OK() || len(results[0].Missing) != 1 || results[0].Missing[0] != "Rule B" {
		t.Errorf("attack result %+v", results[0])
	}
	if results[1].OK() || len(results[1].Unexpected) != 1 || results[1].Unexpected[0] != "Rule C" {
		t.Errorf("benign result %+v", results[1])
	}
	if !strings.HasPrefix(results[0].String(), "FAIL attack") {
		t.Errorf("string = %q", results[0].String())
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected error for missing file")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("expected error for invalid json")
	}
}
