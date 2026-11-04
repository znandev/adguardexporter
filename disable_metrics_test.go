package main_test

// DISABLE_METRICS turns off single metrics, named without the adguard_
// prefix and the _total suffix. The default keeps every metric.

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// withoutFamilies drops the given metric families from a golden snapshot.
func withoutFamilies(s string, families ...string) string {
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		name := line
		if strings.HasPrefix(line, "# ") {
			name = strings.Fields(line)[2]
		} else if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		drop := false
		for _, f := range families {
			if name == f || name == f+"_bucket" || name == f+"_sum" || name == f+"_count" {
				drop = true
				break
			}
		}
		if !drop {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func basicGolden(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "basic.golden"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var geoCacheRe = regexp.MustCompile(`(?m)^(adguard_exporter_geo_cache_size )\d+$`)

func TestDisableMetrics(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		families []string
		// geoCache is the expected GeoIP cache size: without geo metrics,
		// no client is looked up.
		geoCache string
	}{
		{"empty", "", nil, ""},
		{"counter", "query_domain", []string{"adguard_query_domain_total"}, ""},
		{"list with spaces", " query_domain , query_isp ", []string{"adguard_query_domain_total", "adguard_query_isp_total"}, ""},
		{"histogram", "query_elapsed_ms", []string{"adguard_query_elapsed_ms"}, ""},
		{"geo", "client_geo_queries,blocked_geo_queries", []string{"adguard_client_geo_queries", "adguard_blocked_geo_queries"}, "0"},
		{"gauge", "top_queried_domain", []string{"adguard_top_queried_domain_total"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFake(t)
			e := start(t, fake, options{env: map[string]string{"DISABLE_METRICS": tt.value}})
			e.loop()
			fake.AddEntries(baseEntries()...)
			e.loop()

			got := adguardMetrics(e.scrape())
			want := withoutFamilies(basicGolden(t), tt.families...)
			if tt.geoCache != "" {
				want = geoCacheRe.ReplaceAllString(want, "${1}"+tt.geoCache)
			}
			if got != want {
				t.Errorf("metrics with DISABLE_METRICS=%q differ:\n%s", tt.value, diffLines(want, got))
			}
		})
	}
}

// An unknown name stops the exporter, so a typo does not silently keep a
// high-cardinality metric enabled.
func TestDisableMetricsUnknownName(t *testing.T) {
	e := launch(t, newFake(t), options{env: map[string]string{"DISABLE_METRICS": "query_domain,query_domian"}})
	if code := e.waitExit(10 * time.Second); code == 0 {
		t.Errorf("exporter exited with 0 for an unknown metric name")
	}
	if logs := e.logs.String(); !strings.Contains(logs, "query_domian") {
		t.Errorf("error does not name the unknown metric:\n%s", logs)
	}
}

// waitExit waits for the exporter to exit and returns its exit code.
func (e *exporter) waitExit(timeout time.Duration) int {
	e.t.Helper()
	select {
	case <-e.done:
		return e.cmd.ProcessState.ExitCode()
	case <-time.After(timeout):
		e.t.Fatalf("exporter still running after %s:\n%s", timeout, e.logs.String())
		return -1
	}
}
