package logx

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestLevels(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
		SetLevel("INFO")
	})

	tests := []struct {
		level string
		want  []string
	}{
		{"ERROR", []string{"[ERROR] e"}},
		{"WARN", []string{"[ERROR] e", "[WARN] w"}},
		{"INFO", []string{"[ERROR] e", "[WARN] w", "[INFO] i"}},
		{"", []string{"[ERROR] e", "[WARN] w", "[INFO] i"}},
		{"DEBUG", []string{"[ERROR] e", "[WARN] w", "[INFO] i", "[DEBUG] d"}},
	}
	for _, tt := range tests {
		buf.Reset()
		SetLevel("INFO")
		SetLevel(tt.level)
		Printf("ERROR", "e")
		Printf("WARN", "w")
		Printf("INFO", "i")
		Printf("DEBUG", "d")
		if got := strings.Split(strings.TrimSpace(buf.String()), "\n"); strings.Join(got, "|") != strings.Join(tt.want, "|") {
			t.Errorf("level %q logged %q, want %q", tt.level, got, tt.want)
		}
	}
}

// An unknown level keeps the previous one, like before the restructuring.
func TestUnknownLevel(t *testing.T) {
	t.Cleanup(func() { SetLevel("INFO") })
	SetLevel("ERROR")
	SetLevel("verbose")
	if current.Load() != levels["ERROR"] {
		t.Errorf("unknown level changed the level to %d", current.Load())
	}
}
