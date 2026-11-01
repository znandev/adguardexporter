package main_test

// Characterisation tests of the exporter as it behaves today. They pin the
// metric output and the configuration handling, so a restructuring can show
// that nothing changed.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/znand-dev/adguardexporter/internal/adguardtest"
)

const quad9 = "https://dns.quad9.net:443/dns-query"

func baseStats() map[string]any {
	return map[string]any{
		"num_dns_queries":         1234,
		"num_blocked_filtering":   56,
		"num_replaced_parental":   7,
		"avg_processing_time":     0.0123,
		"top_queried_domains":     []map[string]float64{{"example.com": 100}, {"example.org": 50}},
		"top_blocked_domains":     []map[string]float64{{"ads.example": 20}},
		"top_clients":             []map[string]float64{{"192.168.1.10": 300}},
		"top_upstreams_responses": []map[string]float64{{quad9: 900}},
		"top_upstreams_avg_time":  []map[string]float64{{quad9: 0.021}},
	}
}

func baseStatus() map[string]any {
	return map[string]any{
		"version":                      "v0.107.70",
		"language":                     "en",
		"dns_addresses":                []string{"192.168.1.2"},
		"dns_port":                     53,
		"http_port":                    3000,
		"protection_disabled_duration": 0,
		"protection_enabled":           true,
		"dhcp_available":               false,
		"running":                      true,
	}
}

// baseEntries covers private, loopback and public clients, blocked and
// allowed reasons, WHOIS data, an empty upstream and an elapsed time that does
// not parse. Times are relative to now, so they are newer than the exporter's
// start; entries are written oldest first.
func baseEntries() []adguardtest.Entry {
	now := time.Now()
	at := func(ms int) time.Time { return now.Add(-time.Duration(ms) * time.Millisecond) }
	return []adguardtest.Entry{
		{Time: at(6), Client: "198.51.100.20", Name: "example.com", Type: "A", Reason: "NotFilteredNotFound", Elapsed: "n/a", Upstream: quad9},
		{Time: at(5), Client: "127.0.0.1", Name: "localhost.example", Type: "HTTPS", Reason: "Rewrite", Elapsed: "0.05"},
		{Time: at(4), Client: "203.0.113.7", Name: "tracker.example", Type: "A", Reason: "FilteredBlackList", Elapsed: "0.2", WhoisCountry: "DE", WhoisOrg: "Example ISP"},
		{Time: at(3), Client: "203.0.113.7", Name: "example.org", Type: "AAAA", Reason: "NotFilteredNotFound", Elapsed: "12.5", Upstream: quad9, WhoisCountry: "DE", WhoisOrg: "Example ISP"},
		{Time: at(2), Client: "192.168.1.10", Name: "ads.example", Type: "A", Reason: "FilteredBlackList", Elapsed: "0.1"},
		{Time: at(1), Client: "192.168.1.10", Name: "example.com", Type: "A", Reason: "NotFilteredNotFound", Elapsed: "3.2", Upstream: quad9},
	}
}

func newFake(t *testing.T) *adguardtest.Server {
	t.Helper()
	fake := adguardtest.New(t)
	fake.SetStats(baseStats())
	fake.SetStatus(baseStatus())
	return fake
}

// The query log is empty in the first loop and filled before the second, so
// the snapshot only contains entries newer than the exporter's start.
func TestGoldenBasic(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})

	e.loop()
	fake.AddEntries(baseEntries()...)
	e.loop()

	assertGolden(t, "basic", adguardMetrics(e.scrape()))
}

func TestGoldenWithoutGeoDB(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{env: map[string]string{"GEOIP_DB": filepath.Join(t.TempDir(), "missing.mmdb")}})

	e.loop()
	fake.AddEntries(baseEntries()...)
	e.loop()

	assertGolden(t, "without-geodb", adguardMetrics(e.scrape()))
	if !strings.Contains(e.logs.String(), "geo metrics disabled") {
		t.Errorf("no warning about the missing GeoIP database in:\n%s", e.logs.String())
	}
}

// Without GEOIP_DB the exporter looks for GeoLite2-City.mmdb in its working
// directory.
func TestGeoDBDefaultPath(t *testing.T) {
	db, err := os.ReadFile(geoDBPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "GeoLite2-City.mmdb"), db, 0o644); err != nil {
		t.Fatal(err)
	}

	fake := newFake(t)
	e := start(t, fake, options{dir: dir, unset: []string{"GEOIP_DB"}})

	e.loop()
	fake.AddEntries(baseEntries()...)
	e.loop()

	if got := sum(t, e.scrape(), "adguard_client_geo_queries", map[string]string{"country": geoCountry}); got != 2 {
		t.Errorf("geo queries for %s = %v, want 2", geoCountry, got)
	}
}

// All API calls fail. Today the exporter still reports itself as up.
func TestGoldenAdGuardErrors(t *testing.T) {
	fake := newFake(t)
	for _, p := range []string{adguardtest.PathStats, adguardtest.PathStatus, adguardtest.PathQueryLog} {
		fake.Fail(p, -1)
	}
	e := start(t, fake, options{})
	e.loop()
	e.loop()

	assertGolden(t, "adguard-errors", adguardMetrics(e.scrape()))
}

// Entries that stay in the returned window are counted once.
func TestEntriesCountedOnceAcrossLoops(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})

	e.loop()
	fake.AddEntries(baseEntries()...)
	e.loop()
	e.loop()
	e.loop()

	if got, want := counted(t, e.scrape()), float64(len(baseEntries())); got != want {
		t.Errorf("counted %v entries, want %v", got, want)
	}
}

func TestTopListsReplacedEachLoop(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	stats := baseStats()
	stats["top_queried_domains"] = []map[string]float64{{"new.example": 5}}
	fake.SetStats(stats)
	e.loop()

	body := e.scrape()
	if got := sum(t, body, "adguard_top_queried_domain_total", map[string]string{"domain": "new.example"}); got != 5 {
		t.Errorf("new.example = %v, want 5", got)
	}
	if got := sum(t, body, "adguard_top_queried_domain_total", map[string]string{"domain": "example.com"}); got != 0 {
		t.Errorf("example.com still exported with %v", got)
	}
}

// adguard_version_info keeps the series of earlier versions.
func TestVersionInfoKeepsOldVersions(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	status := baseStatus()
	status["version"] = "v0.107.71"
	fake.SetStatus(status)
	e.loop()

	body := e.scrape()
	for _, v := range []string{"v0.107.70", "v0.107.71"} {
		if got := sum(t, body, "adguard_version_info", map[string]string{"version": v}); got != 1 {
			t.Errorf("version_info{version=%q} = %v, want 1", v, got)
		}
	}
}

func TestPassFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"plain", "secret"},
		{"trailing newline", "secret\n"},
		{"trailing CRLF", "secret\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pass")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			fake := newFake(t)
			// ADGUARD_PASS is wrong; the file takes precedence.
			e := start(t, fake, options{env: map[string]string{
				"ADGUARD_PASS":      "wrong",
				"ADGUARD_PASS_FILE": path,
			}})
			e.loop()

			if got := sum(t, e.scrape(), "adguard_dns_queries_total", nil); got != 1234 {
				t.Errorf("dns_queries_total = %v, want 1234", got)
			}
		})
	}
}

// The password file is read for every request, so a rotated secret is picked
// up without a restart.
func TestPassFileReread(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := newFake(t)
	e := start(t, fake, options{env: map[string]string{"ADGUARD_PASS_FILE": path}})
	e.loop()

	fake.SetPass("rotated")
	if err := os.WriteFile(path, []byte("rotated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stats := baseStats()
	stats["num_dns_queries"] = 2000
	fake.SetStats(stats)
	// The held stats request still carries the old password, so the loop
	// after it is the first one with the rotated secret.
	e.loop()
	e.loop()

	if got := sum(t, e.scrape(), "adguard_dns_queries_total", nil); got != 2000 {
		t.Errorf("dns_queries_total = %v, want 2000 after rotation", got)
	}
}

func TestPassFileMissing(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{env: map[string]string{
		"ADGUARD_PASS_FILE": filepath.Join(t.TempDir(), "missing"),
	}})

	waitLog(t, e, "failed to read ADGUARD_PASS_FILE")
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("exporter sent %d requests without a password", n)
	}
}

func TestWrongPassword(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{env: map[string]string{"ADGUARD_PASS": "wrong"}})
	e.loop()

	if has(t, e.scrape(), "adguard_dns_queries_total") &&
		sum(t, e.scrape(), "adguard_dns_queries_total", nil) != 0 {
		t.Error("stats exported with a wrong password")
	}
}

// A .env file in the working directory is loaded; real environment
// variables take precedence over it.
func TestDotEnv(t *testing.T) {
	fake := newFake(t)
	dir := t.TempDir()
	env := "ADGUARD_PASS=" + fake.Pass() + "\nADGUARD_USER=nobody\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	e := start(t, fake, options{dir: dir, unset: []string{"ADGUARD_PASS"}})
	e.loop()

	if got := sum(t, e.scrape(), "adguard_dns_queries_total", nil); got != 1234 {
		t.Errorf("dns_queries_total = %v, want 1234 with ADGUARD_PASS from .env", got)
	}
}

func TestScrapeIntervalDefault(t *testing.T) {
	for _, v := range []string{"", "abc", "0", "-5"} {
		t.Run(v, func(t *testing.T) {
			e := start(t, newFake(t), options{env: map[string]string{"SCRAPE_INTERVAL": v}})
			waitLog(t, e, "Scrape interval set to 15s")
		})
	}
}

func TestLogLevel(t *testing.T) {
	e := start(t, newFake(t), options{env: map[string]string{"LOG_LEVEL": "ERROR"}})
	e.loop()
	if logs := e.logs.String(); strings.Contains(logs, "[INFO]") || strings.Contains(logs, "[DEBUG]") {
		t.Errorf("LOG_LEVEL=ERROR still logs INFO or DEBUG:\n%s", logs)
	}

	e = start(t, newFake(t), options{env: map[string]string{"LOG_LEVEL": "DEBUG"}})
	e.loop()
	if logs := e.logs.String(); !strings.Contains(logs, "[DEBUG] Fetched stats:") {
		t.Errorf("LOG_LEVEL=DEBUG does not log fetched stats:\n%s", logs)
	}
}

func waitLog(t *testing.T, e *exporter, s string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(e.logs.String(), s) {
		if time.Now().After(deadline) {
			t.Fatalf("log line %q not found in:\n%s", s, e.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
