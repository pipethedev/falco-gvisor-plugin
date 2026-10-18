package gvisor

import (
	"fmt"
	"testing"
)

func TestSandboxConnContainerIDsBounded(t *testing.T) {
	sc := &sandboxConn{containerIDs: map[string]struct{}{}}
	for i := range maxConnContainers + 10 {
		if !sc.addContainer(fmt.Sprintf("c%d", i)) {
			t.Fatalf("container %d not reported as new", i)
		}
	}
	if sc.addContainer(fmt.Sprintf("c%d", maxConnContainers+9)) {
		t.Error("a known container was reported as new")
	}
	if n := len(sc.info().ContainerIDs); n != maxConnContainers {
		t.Errorf("tracking %d container ids, cap %d", n, maxConnContainers)
	}
	if !sc.addContainer("c0") {
		t.Error("the oldest container id was not evicted")
	}
}
