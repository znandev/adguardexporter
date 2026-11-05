// Package collector turns AdGuard Home API responses into Prometheus
// metrics.
package collector

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/znand-dev/adguardexporter/internal/adguard"
	"github.com/znand-dev/adguardexporter/internal/geo"
	"github.com/znand-dev/adguardexporter/internal/logx"
)

// adguardDefaultLimit is AdGuard Home's default number of query log entries
// per request.
const adguardDefaultLimit = 500

// API is the part of the AdGuard Home API the collector reads.
type API interface {
	Stats(ctx context.Context) (*adguard.Stats, error)
	Status(ctx context.Context) (*adguard.Status, error)
	QueryLog(ctx context.Context, limit int) (*adguard.QueryLog, error)
}

// Collector updates the metrics in a loop. Its methods are not safe for
// concurrent use; the loop runs in a single goroutine.
type Collector struct {
	api    API
	geo    *geo.Resolver
	m      *metrics
	cursor *queryLogCursor
}

// QueryLogOptions configure how the query log is read.
type QueryLogOptions struct {
	// Overlap is the longest expected time between a query's start and the
	// moment AdGuard Home writes it to the query log (QUERYLOG_OVERLAP).
	Overlap time.Duration
	// MaxEntries caps the entries requested in one loop
	// (QUERYLOG_MAX_ENTRIES).
	MaxEntries int
}

// Options configure the collector.
type Options struct {
	QueryLog QueryLogOptions
	// DisableMetrics names the metrics to turn off (DISABLE_METRICS).
	DisableMetrics []string
}

// New returns a collector whose enabled metrics are registered with reg. It
// fails if DisableMetrics holds a name that is not an optional metric.
func New(api API, resolver *geo.Resolver, reg prometheus.Registerer, opts Options) (*Collector, error) {
	c := &Collector{
		api:    api,
		geo:    resolver,
		m:      newMetrics(),
		cursor: newQueryLogCursor(opts.QueryLog.Overlap, opts.QueryLog.MaxEntries),
	}
	if err := c.m.disable(opts.DisableMetrics); err != nil {
		return nil, err
	}
	reg.MustRegister(c.m.collectors()...)
	return c, nil
}

// Run updates the metrics every interval until ctx is done.
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	for {
		c.RunOnce(ctx)

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// RunOnce runs one loop: stats, status and query log. The exporter is up
// only if every call of the loop succeeded; each failed call counts as one
// scrape error.
func (c *Collector) RunOnce(ctx context.Context) {
	start := time.Now()

	up := true
	for _, update := range []func(context.Context) error{c.updateStats, c.updateStatus, c.updateQueryLog} {
		if err := update(ctx); err != nil {
			up = false
			c.m.exporterErrors.Inc()
		}
	}

	duration := time.Since(start).Seconds()

	c.m.exporterScrapeDuration.Set(duration)
	c.m.exporterUp.Set(boolValue(up))

	c.m.exporterGeoCacheSize.Set(float64(c.geo.CacheSize()))

	logx.Printf(
		"DEBUG",
		"Exporter caches: querylog_window_entries=%d geo_cache_entries=%d",
		len(c.cursor.window),
		c.geo.CacheSize(),
	)

	logx.Printf("DEBUG", "Scrape finished in %.3fs", duration)
}

func (c *Collector) updateStats(ctx context.Context) error {
	stats, err := c.api.Stats(ctx)
	if err != nil {
		logx.Printf("ERROR", "Failed fetch stats: %v", err)
		return err
	}

	setGauge(c.m.dnsQueries, stats.NumDNSQueries)
	setGauge(c.m.blockedFiltering, stats.NumBlockedFiltering)
	setGauge(c.m.replacedParental, stats.NumReplacedParental)
	setGauge(c.m.avgProcessingTime, stats.AvgProcessingTime)

	setTop(c.m.topQueriedDomains, stats.TopQueriedDomains)
	setTop(c.m.topBlockedDomains, stats.TopBlockedDomains)
	setTop(c.m.topClients, stats.TopClients)
	setTop(c.m.topUpstreams, stats.TopUpstream)
	setTop(c.m.topUpstreamTime, stats.TopUpstreamTime)

	logx.Printf(
		"DEBUG",
		"Fetched stats: queries=%.0f blocked=%.0f replaced=%.0f avgTime=%.2fms topDomains=%d",
		stats.NumDNSQueries,
		stats.NumBlockedFiltering,
		stats.NumReplacedParental,
		stats.AvgProcessingTime,
		len(stats.TopQueriedDomains),
	)

	return nil
}

// setTop replaces the series of a top list.
func setTop(g *prometheus.GaugeVec, top []map[string]float64) {
	if g == nil {
		return
	}
	g.Reset()
	for _, item := range top {
		for label, v := range item {
			g.WithLabelValues(label).Set(v)
		}
	}
}

func (c *Collector) updateStatus(ctx context.Context) error {
	status, err := c.api.Status(ctx)
	if err != nil {
		logx.Printf("ERROR", "Failed fetch status: %v", err)
		return err
	}

	setGauge(c.m.statusRunning, boolValue(status.Running))
	setGauge(c.m.statusProtectionEnabled, boolValue(status.ProtectionEnabled))
	setGauge(c.m.statusDHCPAvailable, boolValue(status.DHCPAvailable))
	setGauge(c.m.statusDisabledDuration, float64(status.ProtectionDisabledDuration))

	if c.m.versionInfo != nil {
		c.m.versionInfo.WithLabelValues(status.Version).Set(1)
	}

	logx.Printf(
		"DEBUG",
		"Fetched status: running=%v protection=%v DHCP=%v version=%s",
		status.Running,
		status.ProtectionEnabled,
		status.DHCPAvailable,
		status.Version,
	)

	return nil
}

// setGauge, inc and observe update a metric unless DISABLE_METRICS turned it
// off.
func setGauge(g prometheus.Gauge, v float64) {
	if g != nil {
		g.Set(v)
	}
}

func inc(v *prometheus.CounterVec, labels ...string) {
	if v != nil {
		v.WithLabelValues(labels...).Inc()
	}
}

func observe(h *prometheus.HistogramVec, v float64, labels ...string) {
	if h != nil {
		h.WithLabelValues(labels...).Observe(v)
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// updateQueryLog counts the entries written since the previous loop. A
// failed request leaves the cursor unchanged, so the next loop counts them.
func (c *Collector) updateQueryLog(ctx context.Context) error {
	requests := 0
	c.cursor.begin()
	entries, limit, complete, err := c.fetchQueryLog(ctx, c.cursor.limit, &requests)
	if err != nil {
		return err
	}

	fresh, gaps, vanished := c.cursor.advance(entries, complete)
	c.cursor.nextLimit(entries, limit)

	geoResolved := 0
	for _, q := range fresh {
		if c.count(q) {
			geoResolved++
		}
	}

	for _, gap := range gaps {
		c.m.exporterQueryLogGaps.WithLabelValues(gap).Inc()
		logx.Printf("WARN", "Query log gap (%s): entries may have been missed", gap)
	}
	if len(gaps) == 0 && vanished > 0 {
		logx.Printf("DEBUG", "Querylog: %d counted entries vanished from the query log (memory buffer overflow in AdGuard Home)", vanished)
	}

	logx.Printf("DEBUG",
		"Querylog: requests=%d limit=%d scanned=%d new=%d geoip=%d",
		requests,
		limit,
		len(entries),
		len(fresh),
		geoResolved,
	)

	return nil
}

// fetchQueryLog requests limit entries and doubles the limit until the
// response is complete or MaxEntries is reached.
func (c *Collector) fetchQueryLog(ctx context.Context, limit int, requests *int) ([]adguard.QueryLogEntry, int, bool, error) {
	for {
		logData, err := c.api.QueryLog(ctx, limit)
		if err != nil {
			logx.Printf("ERROR", "Failed querylog: %v", err)
			return nil, limit, false, err
		}
		*requests++
		complete := c.cursor.complete(logData.Data, limit)
		if complete || limit >= c.cursor.maxEntries {
			return logData.Data, limit, complete, nil
		}
		limit = min(2*limit, c.cursor.maxEntries)
	}
}

// count adds one entry to the query metrics and reports whether its client
// was resolved by GeoIP.
func (c *Collector) count(q *adguard.QueryLogEntry) bool {
	inc(c.m.queryCountByReason, q.Reason)
	inc(c.m.queryCountByType, q.Question.Type)

	if elapsedMs, err := strconv.ParseFloat(q.Elapsed, 64); err == nil {
		observe(c.m.queryHistogramByClient, elapsedMs, q.Client)
		if q.Upstream != "" {
			observe(c.m.upstreamLatencyHistogram, elapsedMs/1000, q.Upstream)
		}
	}

	inc(c.m.queryCountByUpstream, q.Upstream)
	inc(c.m.queryCountByDomain, q.Question.Name)
	inc(c.m.queryCountClientReason, q.Client, q.Reason)

	resolved := false
	if c.m.clientGeoQueries != nil || c.m.blockedGeoQueries != nil {
		var loc geo.Location
		loc, resolved = c.geo.Lookup(q.Client)
		if resolved {
			lat := fmt.Sprintf("%f", loc.Lat)
			lon := fmt.Sprintf("%f", loc.Lon)
			inc(c.m.clientGeoQueries, q.Client, loc.Country, lat, lon)

			if q.Reason == "FilteredBlackList" ||
				q.Reason == "FilteredSafeBrowsing" ||
				q.Reason == "FilteredParental" {
				inc(c.m.blockedGeoQueries, q.Client, loc.Country, lat, lon)
			}
		}
	}

	if isp := q.ClientInfo.Whois.OrgName; isp != "" {
		inc(c.m.queryCountByISP, isp, q.ClientInfo.Whois.Country)
	}

	return resolved
}
