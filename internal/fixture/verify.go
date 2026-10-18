package fixture

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
)

const (
	containerIDField = "container.id"
	shortIDLen       = 12
	maxAlertLine     = 1 << 20
)

type falcoAlert struct {
	Rule         string         `json:"rule"`
	Source       string         `json:"source"`
	OutputFields map[string]any `json:"output_fields"`
}

// Result compares the rules that fired for one fixture with its expectations.
type Result struct {
	Fixture    string
	Missing    []string
	Unexpected []string
}

// OK reports whether the fixture fired exactly the expected rules.
func (r Result) OK() bool {
	return len(r.Missing) == 0 && len(r.Unexpected) == 0
}

func (r Result) String() string {
	if r.OK() {
		return "PASS " + r.Fixture
	}
	return fmt.Sprintf("FAIL %s: missing=%v unexpected=%v", r.Fixture, r.Missing, r.Unexpected)
}

// Verify reads Falco JSON output and checks every fixture fired exactly its
// expected rules. Non-JSON lines are ignored.
func Verify(fixtures []Fixture, falcoOutput io.Reader) ([]Result, error) {
	fired, err := alertsByContainer(falcoOutput)
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(fixtures))
	for _, f := range fixtures {
		got := fired[f.ContainerID[:shortIDLen]]
		res := Result{Fixture: f.Name}
		for _, rule := range f.Expect {
			if !slices.Contains(got, rule) {
				res.Missing = append(res.Missing, rule)
			}
		}
		for _, rule := range got {
			if !slices.Contains(f.Expect, rule) {
				res.Unexpected = append(res.Unexpected, rule)
			}
		}
		results = append(results, res)
	}
	return results, nil
}

func alertsByContainer(r io.Reader) (map[string][]string, error) {
	fired := map[string][]string{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, maxAlertLine), maxAlertLine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var alert falcoAlert
		if err := json.Unmarshal([]byte(line), &alert); err != nil || alert.Rule == "" {
			continue
		}
		id, _ := alert.OutputFields[containerIDField].(string)
		if !slices.Contains(fired[id], alert.Rule) {
			fired[id] = append(fired[id], alert.Rule)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read falco output: %w", err)
	}
	for id := range fired {
		sort.Strings(fired[id])
	}
	return fired, nil
}
