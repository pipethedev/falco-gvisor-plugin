package main

import (
	"os"
	"strings"
	"testing"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
)

const fieldsDoc = "../../docs/fields.md"

func TestFieldsDocUpToDate(t *testing.T) {
	current, err := os.ReadFile(fieldsDoc)
	if err != nil {
		t.Fatalf("%v (run make generate)", err)
	}
	if string(current) != render() {
		t.Error("docs/fields.md is stale; run make generate")
	}
}

func TestEveryFieldDocumented(t *testing.T) {
	doc := render()
	for _, d := range gvisor.Fields() {
		if !strings.Contains(doc, "`"+d.Name) {
			t.Errorf("field %s missing from docs", d.Name)
		}
	}
}
