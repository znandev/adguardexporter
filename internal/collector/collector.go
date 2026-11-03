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

// New returns a collector whose metrics are registered with reg.
func New(api API, resolver *geo.Resolver, reg prometheus.Registerer, opts QueryLogOptions) *Collector {
	c := &Collector{
		api:    api,
		geo:    resolver,
		m:      newMetrics(),
		cursor: newQueryLogCursor(opts.Overlap, opts.MaxEntries),
	}
	reg.MustRegister(c.m.collectors()...)
	return c
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

	c.m.dnsQueries.Set(stats.NumDNSQueries)
	c.m.blockedFiltering.Set(stats.NumBlockedFiltering)
	c.m.replacedParental.Set(stats.NumReplacedParental)
	c.m.avgProcessingTime.Set(stats.AvgProcessingTime)

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

	c.m.statusRunning.Set(boolValue(status.Running))
	c.m.statusProtectionEnabled.Set(boolValue(status.ProtectionEnabled))
	c.m.statusDHCPAvailable.Set(boolValue(status.DHCPAvailable))
	c.m.statusDisabledDuration.Set(float64(status.ProtectionDisabledDuration))

	c.m.versionInfo.WithLabelValues(status.Version).Set(1)

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
	entries, limit, complete, err := c.fetchQueryLog(ctx, c.cursor.limit, &requests)
	if err != nil {
		return err
	}

	fresh, gap, vanished := c.cursor.advance(entries, complete)
	if gap == gapReset {
		// The cursor moved to a new reference time; read until the response
		// covers its counting window, so the window holds every entry in it.
		entries, limit, complete, err = c.fetchQueryLog(ctx, limit, &requests)
		if err != nil {
			c.cursor.restart()
		} else {
			c.cursor.reset(entries, c.cursor.newest)
			if !complete {
				gap = gapLimit
			}
		}
	}
	if err == nil {
		c.cursor.nextLimit(entries, limit)
	}

	geoResolved := 0
	for _, q := range fresh {
		if c.count(q) {
			geoResolved++
		}
	}

	if gap != "" {
		c.m.exporterQueryLogGaps.WithLabelValues(gap).Inc()
		logx.Printf("WARN", "Query log gap (%s): entries may have been missed", gap)
	} else if vanished > 0 {
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

	return err
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
	c.m.queryCountByReason.WithLabelValues(q.Reason).Inc()
	c.m.queryCountByType.WithLabelValues(q.Question.Type).Inc()

	if elapsedMs, err := strconv.ParseFloat(q.Elapsed, 64); err == nil {
		c.m.queryHistogramByClient.WithLabelValues(q.Client).Observe(elapsedMs)
		if q.Upstream != "" {
			c.m.upstreamLatencyHistogram.WithLabelValues(q.Upstream).Observe(elapsedMs / 1000)
		}
	}

	c.m.queryCountByUpstream.WithLabelValues(q.Upstream).Inc()
	c.m.queryCountByDomain.WithLabelValues(q.Question.Name).Inc()
	c.m.queryCountClientReason.WithLabelValues(q.Client, q.Reason).Inc()

	loc, resolved := c.geo.Lookup(q.Client)
	if resolved {
		lat := fmt.Sprintf("%f", loc.Lat)
		lon := fmt.Sprintf("%f", loc.Lon)
		c.m.clientGeoQueries.WithLabelValues(q.Client, loc.Country, lat, lon).Inc()

		if q.Reason == "FilteredBlackList" ||
			q.Reason == "FilteredSafeBrowsing" ||
			q.Reason == "FilteredParental" {
			c.m.blockedGeoQueries.WithLabelValues(q.Client, loc.Country, lat, lon).Inc()
		}
	}

	if isp := q.ClientInfo.Whois.OrgName; isp != "" {
		c.m.queryCountByISP.WithLabelValues(isp, q.ClientInfo.Whois.Country).Inc()
	}

	return resolved
}
