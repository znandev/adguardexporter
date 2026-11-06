package collector

import (
	"context"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/oschwald/geoip2-golang/v2"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/znand-dev/adguardexporter/internal/adguard"
	"github.com/znand-dev/adguardexporter/internal/geo"
)

var fqName = regexp.MustCompile(`fqName: "([^"]+)"`)

// names returns the full names of the metrics a collector describes.
func names(c prometheus.Collector) []string {
	ch := make(chan *prometheus.Desc, 1)
	go func() {
		c.Describe(ch)
		close(ch)
	}()
	var out []string
	for d := range ch {
		out = append(out, fqName.FindStringSubmatch(d.String())[1])
	}
	return out
}

// Every metric except the exporter's own is optional, under its full name
// without adguard_ and _total.
func TestOptionalMetricNames(t *testing.T) {
	m := newMetrics()
	optional := map[string]bool{}
	for _, o := range m.optional() {
		full := names(o.collector)
		if len(full) != 1 || shortName(full[0]) != o.name {
			t.Errorf("optional metric %q describes %v", o.name, full)
		}
		optional[o.name] = true
	}
	for _, c := range m.collectors() {
		full := names(c)[0]
		own := strings.HasPrefix(full, "adguard_exporter_")
		if own == optional[shortName(full)] {
			t.Errorf("%s: optional = %v, want %v", full, optional[shortName(full)], !own)
		}
	}
}

func TestDisableInvalidNames(t *testing.T) {
	tests := []struct {
		names []string
		want  []string
	}{
		{[]string{"query_domian"}, []string{"query_domian: unknown metric", "valid names: dns_queries, "}},
		{[]string{"exporter_up"}, []string{"exporter_up: the exporter's own metrics cannot be disabled"}},
		{[]string{"adguard_exporter_querylog_gaps_total"}, []string{"adguard_exporter_querylog_gaps_total: the exporter's own metrics cannot be disabled"}},
		{[]string{"adguard_query_domain_total"}, []string{"adguard_query_domain_total: use the short name query_domain"}},
		{[]string{"query_domain", "QUERY_ISP", "geo"}, []string{"QUERY_ISP: unknown metric", "geo: unknown metric"}},
	}
	for _, tt := range tests {
		_, err := New(emptyAPI(), geo.New(nil), prometheus.NewRegistry(), Options{QueryLog: testOpts, DisableMetrics: tt.names})
		if err == nil {
			t.Errorf("%q: no error", tt.names)
			continue
		}
		for _, w := range tt.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%q: error %q does not contain %q", tt.names, err, w)
			}
		}
	}
}

// A disabled metric is neither registered nor updated, so it keeps no
// series in memory either.
func TestDisabledMetricsCollectNothing(t *testing.T) {
	api := emptyAPI()
	api.stats = &adguard.Stats{
		NumDNSQueries:     10,
		TopClients:        []map[string]float64{{"192.168.1.10": 4}},
		TopQueriedDomains: []map[string]float64{{"a.example": 4}},
	}
	api.status = &adguard.Status{Version: "v0.107.79"}
	reg := prometheus.NewRegistry()
	disabled := []string{"dns_queries", "top_client", "version_info", "query_domain", "query_elapsed_ms", "query_isp"}
	c, err := New(api, geo.New(nil), reg, Options{QueryLog: testOpts, DisableMetrics: disabled})
	if err != nil {
		t.Fatal(err)
	}
	c.RunOnce(context.Background())
	e := entry(t0, "192.168.1.10", "a.example", "NotFilteredNotFound", "2500")
	e.ClientInfo.Whois.OrgName = "Example ISP"
	api.write(e)
	c.RunOnce(context.Background())

	if c.m.dnsQueries != nil || c.m.topClients != nil || c.m.versionInfo != nil ||
		c.m.queryCountByDomain != nil || c.m.queryHistogramByClient != nil || c.m.queryCountByISP != nil {
		t.Error("a disabled metric is still set")
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range families {
		got = append(got, f.GetName())
	}
	for _, name := range disabled {
		for _, full := range []string{"adguard_" + name, "adguard_" + name + "_total"} {
			if slices.Contains(got, full) {
				t.Errorf("%s is still exposed", full)
			}
		}
	}
	for _, want := range []string{"adguard_query_reason_total", "adguard_top_queried_domain_total", "adguard_exporter_up"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s is missing", want)
		}
	}
	if n := len(c.m.collectors()); n != 31-len(disabled) {
		t.Errorf("%d collectors, want %d", n, 31-len(disabled))
	}
}

type countingDB struct{ calls int }

func (d *countingDB) City(netip.Addr) (*geoip2.City, error) {
	d.calls++
	return &geoip2.City{}, nil
}

// GeoIP lookups are skipped when both geo metrics are disabled.
func TestGeoLookupSkippedWhenDisabled(t *testing.T) {
	tests := []struct {
		disabled []string
		lookups  int
	}{
		{nil, 1},
		{[]string{"blocked_geo_queries"}, 1},
		{[]string{"client_geo_queries", "blocked_geo_queries"}, 0},
	}
	for _, tt := range tests {
		api := emptyAPI()
		db := &countingDB{}
		c, err := New(api, geo.New(db), prometheus.NewRegistry(), Options{QueryLog: testOpts, DisableMetrics: tt.disabled})
		if err != nil {
			t.Fatal(err)
		}
		c.RunOnce(context.Background())
		api.write(entry(t0, "203.0.113.7", "a.example", "NotFilteredNotFound", "1"))
		c.RunOnce(context.Background())
		if db.calls != tt.lookups {
			t.Errorf("DISABLE_METRICS=%q: %d lookups, want %d", tt.disabled, db.calls, tt.lookups)
		}
	}
}

// With every optional metric disabled, only the exporter's own metrics are
// left, and a loop with stats, status and query log entries still works.
func TestDisableAllOptionalMetrics(t *testing.T) {
	var all []string
	for _, o := range newMetrics().optional() {
		all = append(all, o.name)
	}
	api := emptyAPI()
	api.stats = &adguard.Stats{TopQueriedDomains: []map[string]float64{{"a.example": 4}}}
	reg := prometheus.NewRegistry()
	c, err := New(api, geo.New(&countingDB{}), reg, Options{QueryLog: testOpts, DisableMetrics: all})
	if err != nil {
		t.Fatal(err)
	}
	c.RunOnce(context.Background())
	e := entry(t0, "203.0.113.7", "a.example", "FilteredBlackList", "1")
	e.Upstream = "1.1.1.1:53"
	e.ClientInfo.Whois.OrgName = "Example ISP"
	api.write(e)
	c.RunOnce(context.Background())

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if !strings.HasPrefix(f.GetName(), "adguard_exporter_") {
			t.Errorf("%s is still exposed", f.GetName())
		}
	}
	if len(families) != 7 {
		t.Errorf("%d families, want the 7 exporter metrics", len(families))
	}
}
