package main_test

// Exporter health: adguard_exporter_up is 1 only if every API call of a loop
// succeeded, and every failed call is a scrape error.

import (
	"fmt"
	"testing"
	"time"

	"github.com/znand-dev/adguardexporter/internal/adguardtest"
)

func TestExporterUp(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	up := func() float64 { return sum(t, e.scrape(), "adguard_exporter_up", nil) }
	errs := func() float64 { return sum(t, e.scrape(), "adguard_exporter_scrape_errors_total", nil) }

	if got := up(); got != 1 {
		t.Errorf("up = %v with a healthy API, want 1", got)
	}

	// One failing endpoint is enough for up to be 0.
	fake.Fail(adguardtest.PathStatus, -1)
	e.loop()
	if got := up(); got != 0 {
		t.Errorf("up = %v with /control/status failing, want 0", got)
	}
	e.loop()
	if got := errs(); got != 2 {
		t.Errorf("scrape_errors_total = %v after two loops with one failing call, want 2", got)
	}

	fake.Fail(adguardtest.PathStatus, 0)
	e.loop()
	e.loop()
	if got := up(); got != 1 {
		t.Errorf("up = %v after recovery, want 1", got)
	}
}

func TestScrapeErrorsPerFailedCall(t *testing.T) {
	fake := newFake(t)
	for _, p := range []string{adguardtest.PathStats, adguardtest.PathStatus, adguardtest.PathQueryLog} {
		fake.Fail(p, -1)
	}
	e := start(t, fake, options{})
	e.loop()
	e.loop()

	body := e.scrape()
	if got := sum(t, body, "adguard_exporter_up", nil); got != 0 {
		t.Errorf("up = %v, want 0", got)
	}
	if got := sum(t, body, "adguard_exporter_scrape_errors_total", nil); got != 6 {
		t.Errorf("scrape_errors_total = %v after two loops with three failing calls, want 6", got)
	}
}

func TestExporterUpUnreachable(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{env: map[string]string{
		"ADGUARD_HOST": fmt.Sprintf("http://127.0.0.1:%d", freePort(t)),
	}})

	deadline := time.Now().Add(10 * time.Second)
	for sum(t, e.scrape(), "adguard_exporter_up", nil) != 0 || !has(t, e.scrape(), "adguard_exporter_up") {
		if time.Now().After(deadline) {
			t.Fatalf("up did not become 0 with an unreachable AdGuard Home:\n%s", e.scrape())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
