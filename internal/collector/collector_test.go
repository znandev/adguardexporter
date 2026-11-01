package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/znand-dev/adguardexporter/internal/adguard"
	"github.com/znand-dev/adguardexporter/internal/geo"
)

type fakeAPI struct {
	stats    *adguard.Stats
	status   *adguard.Status
	log      *adguard.QueryLog
	statsErr error
}

func (f *fakeAPI) Stats(context.Context) (*adguard.Stats, error) {
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	return f.stats, nil
}

func (f *fakeAPI) Status(context.Context) (*adguard.Status, error) { return f.status, nil }

func (f *fakeAPI) QueryLog(context.Context) (*adguard.QueryLog, error) { return f.log, nil }

func entry(client, name, reason, elapsed string) adguard.QueryLogEntry {
	var e adguard.QueryLogEntry
	e.Client = client
	e.Question.Name = name
	e.Question.Type = "A"
	e.Reason = reason
	e.Elapsed = elapsed
	return e
}

func newCollector(t *testing.T, api *fakeAPI) (*Collector, *time.Time) {
	t.Helper()
	c := New(api, geo.New(nil), prometheus.NewRegistry())
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	return c, &now
}

func emptyAPI() *fakeAPI {
	return &fakeAPI{stats: &adguard.Stats{}, status: &adguard.Status{}, log: &adguard.QueryLog{}}
}

func TestRegistersEveryMetricOnce(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := New(emptyAPI(), geo.New(nil), reg)
	c.RunOnce(context.Background())
	if _, err := reg.Gather(); err != nil {
		t.Fatal(err)
	}
	if n := len(c.m.collectors()); n != 30 {
		t.Errorf("%d collectors, want 30", n)
	}
}

func TestStatsAndStatus(t *testing.T) {
	api := emptyAPI()
	api.stats = &adguard.Stats{
		NumDNSQueries:     100,
		TopQueriedDomains: []map[string]float64{{"a.example": 2}, {"b.example": 1}},
	}
	api.status = &adguard.Status{Version: "v1", Running: true, ProtectionEnabled: false, ProtectionDisabledDuration: 30}
	c, _ := newCollector(t, api)
	c.RunOnce(context.Background())

	if got := testutil.ToFloat64(c.m.dnsQueries); got != 100 {
		t.Errorf("dns_queries = %v", got)
	}
	if got := testutil.CollectAndCount(c.m.topQueriedDomains); got != 2 {
		t.Errorf("%d top domains, want 2", got)
	}
	if testutil.ToFloat64(c.m.statusRunning) != 1 || testutil.ToFloat64(c.m.statusProtectionEnabled) != 0 ||
		testutil.ToFloat64(c.m.statusDisabledDuration) != 30 {
		t.Error("status gauges wrong")
	}

	// A failed stats call keeps the previous values.
	api.statsErr = errors.New("down")
	c.RunOnce(context.Background())
	if got := testutil.ToFloat64(c.m.dnsQueries); got != 100 {
		t.Errorf("dns_queries = %v after a failed call, want 100", got)
	}
	// Today exporter_up is 1 regardless.
	if got := testutil.ToFloat64(c.m.exporterUp); got != 1 {
		t.Errorf("exporter_up = %v", got)
	}
}

// The current deduplication drops identical entries within QueryTTL and
// counts them again afterwards.
func TestQueryLogDedupTTL(t *testing.T) {
	api := emptyAPI()
	api.log = &adguard.QueryLog{Data: []adguard.QueryLogEntry{
		entry("192.168.1.10", "a.example", "NotFilteredNotFound", "1"),
		entry("192.168.1.10", "a.example", "NotFilteredNotFound", "1"),
		entry("192.168.1.10", "b.example", "FilteredBlackList", "1"),
	}}
	c, now := newCollector(t, api)
	reason := func(r string) float64 { return testutil.ToFloat64(c.m.queryCountByReason.WithLabelValues(r)) }

	c.RunOnce(context.Background())
	if reason("NotFilteredNotFound") != 1 || reason("FilteredBlackList") != 1 {
		t.Errorf("first loop: allowed %v blocked %v, want 1 and 1", reason("NotFilteredNotFound"), reason("FilteredBlackList"))
	}
	if got := testutil.ToFloat64(c.m.exporterDedupHits); got != 1 {
		t.Errorf("dedup hits = %v, want 1", got)
	}

	*now = now.Add(QueryTTL - time.Second)
	c.RunOnce(context.Background())
	if reason("NotFilteredNotFound") != 1 {
		t.Errorf("counted again within the TTL")
	}
	if got := testutil.ToFloat64(c.m.exporterQueryCacheSize); got != 2 {
		t.Errorf("query cache size = %v, want 2", got)
	}

	*now = now.Add(time.Second)
	c.RunOnce(context.Background())
	if reason("NotFilteredNotFound") != 2 || reason("FilteredBlackList") != 2 {
		t.Errorf("after the TTL: allowed %v blocked %v, want 2 and 2", reason("NotFilteredNotFound"), reason("FilteredBlackList"))
	}
}

func TestQueryLogCacheCleanup(t *testing.T) {
	api := emptyAPI()
	api.log = &adguard.QueryLog{Data: []adguard.QueryLogEntry{entry("192.168.1.10", "a.example", "Rewrite", "1")}}
	c, now := newCollector(t, api)
	c.RunOnce(context.Background())

	api.log = &adguard.QueryLog{}
	*now = now.Add(QueryTTL + time.Second)
	c.RunOnce(context.Background())
	if got := testutil.ToFloat64(c.m.exporterQueryCacheSize); got != 0 {
		t.Errorf("query cache size = %v after the TTL, want 0", got)
	}
}

func TestQueryLogMetrics(t *testing.T) {
	api := emptyAPI()
	e := entry("192.168.1.10", "a.example", "NotFilteredNotFound", "2500")
	e.Upstream = "1.1.1.1:53"
	e.ClientInfo.Whois.OrgName = "Example ISP"
	e.ClientInfo.Whois.Country = "DE"
	bad := entry("192.168.1.11", "b.example", "NotFilteredNotFound", "n/a")
	api.log = &adguard.QueryLog{Data: []adguard.QueryLogEntry{e, bad}}
	c, _ := newCollector(t, api)
	c.RunOnce(context.Background())

	if got := testutil.ToFloat64(c.m.queryCountByISP.WithLabelValues("Example ISP", "DE")); got != 1 {
		t.Errorf("isp = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(c.m.queryHistogramByClient); got != 1 {
		t.Errorf("%d elapsed histograms, want 1 (unparsable elapsed is skipped)", got)
	}
	if got := testutil.CollectAndCount(c.m.upstreamLatencyHistogram); got != 1 {
		t.Errorf("%d upstream histograms, want 1", got)
	}
	if got := testutil.CollectAndCount(c.m.clientGeoQueries); got != 0 {
		t.Errorf("%d geo series without a database, want 0", got)
	}
}

func TestRunStops(t *testing.T) {
	c, _ := newCollector(t, emptyAPI())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx, time.Hour)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
