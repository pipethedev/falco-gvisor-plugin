package gvisor

import (
	"fmt"
	"runtime/debug"
)

// errPanic wraps a panic recovered at a goroutine or callback boundary.
var errPanic = fmt.Errorf("recovered panic")

// guard runs fn and turns a panic into a counted, logged error, so a bug in
// one sandbox's processing cannot crash Falco.
func guard(stats *Stats, what string, fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stats.Panics.Add(1)
			logger.Printf("recovered panic in %s: %v\n%s", what, r, debug.Stack())
			err = fmt.Errorf("%w in %s: %v", errPanic, what, r)
		}
	}()
	fn()
	return nil
}
