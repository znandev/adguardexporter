package collector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/znand-dev/adguardexporter/internal/adguard"
	"github.com/znand-dev/adguardexporter/internal/geo"
)

// fakeAPI answers query log requests like AdGuard Home: the limit most
// recently written entries, sorted by time, newest first.
type fakeAPI struct {
	stats    *adguard.Stats
	status   *adguard.Status
	written  []adguard.QueryLogEntry
	statsErr error
	logErr   error
	limits   []int
	// onQueryLog runs before the n-th query log request (1-based) is
	// answered.
	onQueryLog func(n int)
}

func (f *fakeAPI) Stats(context.Context) (*adguard.Stats, error) {
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	return f.stats, nil
}

func (f *fakeAPI) Status(context.Context) (*adguard.Status, error) { return f.status, nil }

func (f *fakeAPI) QueryLog(_ context.Context, limit int) (*adguard.QueryLog, error) {
	f.limits = append(f.limits, limit)
	if f.onQueryLog != nil {
		f.onQueryLog(len(f.limits))
	}
	if f.logErr != nil {
		return nil, f.logErr
	}
	start := max(len(f.written)-limit, 0)
	data := slices.Clone(f.written[start:])
	slices.Reverse(data)
	slices.SortStableFunc(data, func(a, b adguard.QueryLogEntry) int { return -a.Time.Compare(b.Time) })
	return &adguard.QueryLog{Data: data}, nil
}

// write appends entries to the query log in write order.
func (f *fakeAPI) write(e ...adguard.QueryLogEntry) { f.written = append(f.written, e...) }

// t0 is the reference time of the unit tests.
var t0 = time.Unix(1_700_000_000, 0)

// entry returns an entry whose ID is derived from its fields, like the
// client's.
func entry(at time.Time, client, name, reason, elapsed string) adguard.QueryLogEntry {
	var e adguard.QueryLogEntry
	e.Time = at
	e.Client = client
	e.Question.Name = name
	e.Question.Type = "A"
	e.Reason = reason
	e.Elapsed = elapsed
	e.ID = fmt.Sprintf("%s|%s|%s|%s|%s", at.Format(time.RFC3339Nano), client, name, reason, elapsed)
	return e
}

// simple returns an entry at t0+d named after d.
func simple(d time.Duration) adguard.QueryLogEntry {
	return entry(t0.Add(d), "192.168.1.10", d.String()+".example", "NotFilteredNotFound", "1")
}

var testOpts = QueryLogOptions{Overlap: time.Minute, MaxEntries: 20000}

func newCollector(t *testing.T, api *fakeAPI, opts QueryLogOptions) *Collector {
	t.Helper()
	c, err := New(api, geo.New(nil), prometheus.NewRegistry(), Options{QueryLog: opts})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func emptyAPI() *fakeAPI {
	return &fakeAPI{stats: &adguard.Stats{}, status: &adguard.Status{}}
}

func TestRegistersEveryMetricOnce(t *testing.T) {
	reg := prometheus.NewRegistry()
	c, err := New(emptyAPI(), geo.New(nil), reg, Options{QueryLog: testOpts})
	if err != nil {
		t.Fatal(err)
	}
	c.RunOnce(context.Background())
	if _, err := reg.Gather(); err != nil {
		t.Fatal(err)
	}
	if n := len(c.m.collectors()); n != 31 {
		t.Errorf("%d collectors, want 31", n)
	}
}

func TestStatsAndStatus(t *testing.T) {
	api := emptyAPI()
	api.stats = &adguard.Stats{
		NumDNSQueries:     100,
		TopQueriedDomains: []map[string]float64{{"a.example": 2}, {"b.example": 1}},
	}
	api.status = &adguard.Status{Version: "v1", Running: true, ProtectionEnabled: false, ProtectionDisabledDuration: 30}
	c := newCollector(t, api, testOpts)
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
	if got := testutil.ToFloat64(c.m.exporterUp); got != 0 {
		t.Errorf("exporter_up = %v after a failed call, want 0", got)
	}
	if got := testutil.ToFloat64(c.m.exporterErrors); got != 1 {
		t.Errorf("scrape_errors_total = %v, want 1", got)
	}

	api.statsErr = nil
	c.RunOnce(context.Background())
	if got := testutil.ToFloat64(c.m.exporterUp); got != 1 {
		t.Errorf("exporter_up = %v after recovery, want 1", got)
	}
}

func TestQueryLogMetrics(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	c.RunOnce(context.Background())

	e := entry(t0, "192.168.1.10", "a.example", "NotFilteredNotFound", "2500")
	e.Upstream = "1.1.1.1:53"
	e.ClientInfo.Whois.OrgName = "Example ISP"
	e.ClientInfo.Whois.Country = "DE"
	bad := entry(t0, "192.168.1.11", "b.example", "NotFilteredNotFound", "n/a")
	api.write(e, bad)
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
	c := newCollector(t, emptyAPI(), testOpts)
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
