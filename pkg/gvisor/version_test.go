package gvisor

import (
	"regexp"
	"testing"
)

var semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$`)

func TestPluginVersionIsSemver(t *testing.T) {
	if !semverPattern.MatchString(PluginVersion) {
		t.Errorf("PluginVersion %q is not semver; Falco refuses to load the plugin", PluginVersion)
	}
}
