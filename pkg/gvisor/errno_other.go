//go:build !linux

package gvisor

import "strconv"

func errnoName(errno int64) string {
	return errnoPrefix + strconv.FormatInt(errno, 10)
}
