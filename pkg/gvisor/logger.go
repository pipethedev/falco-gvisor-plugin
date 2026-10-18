package gvisor

import (
	"log"
	"os"
)

const logPrefix = "[gvisor-plugin] "

var logger = log.New(os.Stderr, logPrefix, log.LstdFlags|log.Lmsgprefix)
