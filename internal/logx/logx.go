// Package logx is the exporter's levelled logger.
package logx

import (
	"fmt"
	"log"
	"sync/atomic"
)

var levels = map[string]int32{"ERROR": 1, "WARN": 2, "INFO": 3, "DEBUG": 4}

var current atomic.Int32

func init() { current.Store(levels["INFO"]) }

// SetLevel sets the level by name (ERROR, WARN, INFO, DEBUG). An empty or
// unknown name keeps INFO.
func SetLevel(name string) {
	if name == "" {
		name = "INFO"
	}
	if v, ok := levels[name]; ok {
		current.Store(v)
	}
}

// Printf logs at level if the current level includes it.
func Printf(level string, format string, args ...any) {
	if levels[level] <= current.Load() {
		log.Printf("[%s] %s", level, fmt.Sprintf(format, args...))
	}
}
