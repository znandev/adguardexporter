package collector

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics holds every metric the exporter exposes.
type metrics struct {
	dnsQueries        prometheus.Gauge
	blockedFiltering  prometheus.Gauge
	replacedParental  prometheus.Gauge
	avgProcessingTime prometheus.Gauge

	statusProtectionEnabled prometheus.Gauge
	statusRunning           prometheus.Gauge
	statusDHCPAvailable     prometheus.Gauge
	statusDisabledDuration  prometheus.Gauge
	versionInfo             *prometheus.GaugeVec

	topQueriedDomains *prometheus.GaugeVec
	topBlockedDomains *prometheus.GaugeVec
	topClients        *prometheus.GaugeVec
	topUpstreams      *prometheus.GaugeVec
	topUpstreamTime   *prometheus.GaugeVec

	queryCountByReason       *prometheus.CounterVec
	queryCountByType         *prometheus.CounterVec
	queryHistogramByClient   *prometheus.HistogramVec
	queryCountByUpstream     *prometheus.CounterVec
	queryCountByDomain       *prometheus.CounterVec
	queryCountClientReason   *prometheus.CounterVec
	clientGeoQueries         *prometheus.CounterVec
	blockedGeoQueries        *prometheus.CounterVec
	upstreamLatencyHistogram *prometheus.HistogramVec
	queryCountByISP          *prometheus.CounterVec

	exporterUp             prometheus.Gauge
	exporterScrapeDuration prometheus.Gauge
	exporterErrors         prometheus.Counter
	exporterGeoCacheSize   prometheus.Gauge
	exporterQueryLogGaps   *prometheus.CounterVec

	// disabled holds the names of the optional metrics turned off by
	// DISABLE_METRICS.
	disabled map[string]bool
}

func newMetrics() *metrics {
	return &metrics{
		dnsQueries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_dns_queries_total", Help: "Total DNS queries received",
		}),
		blockedFiltering: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_blocked_filtering_total", Help: "Total DNS queries blocked",
		}),
		replacedParental: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_replaced_parental", Help: "Total parental replaced queries",
		}),
		avgProcessingTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_avg_processing_time", Help: "Avg DNS processing time",
		}),

		statusProtectionEnabled: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_protection_enabled", Help: "Protection enabled (1/0)",
		}),
		statusRunning: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_running", Help: "AdGuard running",
		}),
		statusDHCPAvailable: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_dhcp_available", Help: "DHCP available",
		}),
		statusDisabledDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_protection_disabled_duration_seconds",
			Help: "Time since protection disabled",
		}),
		versionInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "adguard_version_info",
			Help: "AdGuard version",
		}, []string{"version"}),

		topQueriedDomains: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "adguard_top_queried_domain_total",
			Help: "Top queried domains",
		}, []string{"domain"}),
		topBlockedDomains: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "adguard_top_blocked_domain_total",
			Help: "Top blocked domains",
		}, []string{"domain"}),
		topClients: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "adguard_top_client_total",
			Help: "Top client IPs",
		}, []string{"client"}),
		topUpstreams: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "adguard_top_upstream_total",
			Help: "Top upstream servers",
		}, []string{"upstream"}),
		topUpstreamTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "adguard_upstream_avg_response_time_seconds",
			Help: "Avg response time per upstream",
		}, []string{"upstream"}),

		queryCountByReason: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "adguard_query_reason_total",
			Help: "Queries by reason",
		}, []string{"reason"}),
		queryCountByType: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "adguard_query_type_total",
			Help: "Queries by DNS type",
		}, []string{"type"}),
		queryHistogramByClient: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "adguard_query_elapsed_ms",
			Help:    "Query duration by client",
			Buckets: prometheus.LinearBuckets(1, 5, 10),
		}, []string{"client"}),
		queryCountByUpstream: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "adguard_query_upstream_total",
			Help: "Queries per upstream",
		}, []string{"upstream"}),
		queryCountByDomain: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "adguard_query_domain_total",
			Help: "Queries per domain",
		}, []string{"domain"}),
		queryCountClientReason: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "adguard_query_client_reason_total",
			Help: "Queries per client per reason",
		}, []string{"client", "reason"}),
		clientGeoQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "adguard_client_geo_queries",
			Help: "Queries per client with geographic info",
		}, []string{"client", "country", "lat", "lon"}),
		blockedGeoQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "adguard_blocked_geo_queries",
			Help: "Blocked DNS queries per client with geographic info",
		}, []string{"client", "country", "lat", "lon"}),
		upstreamLatencyHistogram: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "adguard_upstream_latency_seconds",
			Help: "Latency distribution per upstream DNS server",
			Buckets: prometheus.ExponentialBuckets(
				0.001, // 1ms
				2,
				10,
			),
		}, []string{"upstream"}),
		queryCountByISP: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "adguard_query_isp_total",
			Help: "DNS queries grouped by ISP organization",
		}, []string{"isp", "country"}),

		exporterUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_exporter_up",
			Help: "Exporter scrape success",
		}),
		exporterScrapeDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_exporter_scrape_duration_seconds",
			Help: "Exporter scrape duration",
		}),
		exporterErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "adguard_exporter_scrape_errors_total",
			Help: "Total exporter errors",
		}),
		exporterGeoCacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_exporter_geo_cache_size",
			Help: "Current number of cached GeoIP entries",
		}),
		exporterQueryLogGaps: newGaps(),
		disabled:             map[string]bool{},
	}
}

// newGaps returns adguard_exporter_querylog_gaps_total with every reason
// present from the start.
func newGaps() *prometheus.CounterVec {
	g := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "adguard_exporter_querylog_gaps_total",
		Help: "Loops in which query log entries may have been missed (reason: limit = more new entries than QUERYLOG_MAX_ENTRIES, reset = entries counted before vanished from the query log)",
	}, []string{"reason"})
	for _, r := range []string{gapLimit, gapReset} {
		g.WithLabelValues(r)
	}
	return g
}

// optional lists the metrics DISABLE_METRICS can turn off, named without the
// adguard_ prefix and the _total suffix. drop clears the field; the collector
// skips nil metrics, so a disabled metric collects no series at all.
func (m *metrics) optional() []optionalMetric {
	return []optionalMetric{
		{"dns_queries", m.dnsQueries, func() { m.dnsQueries = nil }},
		{"blocked_filtering", m.blockedFiltering, func() { m.blockedFiltering = nil }},
		{"replaced_parental", m.replacedParental, func() { m.replacedParental = nil }},
		{"avg_processing_time", m.avgProcessingTime, func() { m.avgProcessingTime = nil }},
		{"protection_enabled", m.statusProtectionEnabled, func() { m.statusProtectionEnabled = nil }},
		{"running", m.statusRunning, func() { m.statusRunning = nil }},
		{"dhcp_available", m.statusDHCPAvailable, func() { m.statusDHCPAvailable = nil }},
		{"protection_disabled_duration_seconds", m.statusDisabledDuration, func() { m.statusDisabledDuration = nil }},
		{"version_info", m.versionInfo, func() { m.versionInfo = nil }},
		{"top_queried_domain", m.topQueriedDomains, func() { m.topQueriedDomains = nil }},
		{"top_blocked_domain", m.topBlockedDomains, func() { m.topBlockedDomains = nil }},
		{"top_client", m.topClients, func() { m.topClients = nil }},
		{"top_upstream", m.topUpstreams, func() { m.topUpstreams = nil }},
		{"upstream_avg_response_time_seconds", m.topUpstreamTime, func() { m.topUpstreamTime = nil }},
		{"query_reason", m.queryCountByReason, func() { m.queryCountByReason = nil }},
		{"query_type", m.queryCountByType, func() { m.queryCountByType = nil }},
		{"query_elapsed_ms", m.queryHistogramByClient, func() { m.queryHistogramByClient = nil }},
		{"query_upstream", m.queryCountByUpstream, func() { m.queryCountByUpstream = nil }},
		{"query_domain", m.queryCountByDomain, func() { m.queryCountByDomain = nil }},
		{"query_client_reason", m.queryCountClientReason, func() { m.queryCountClientReason = nil }},
		{"client_geo_queries", m.clientGeoQueries, func() { m.clientGeoQueries = nil }},
		{"blocked_geo_queries", m.blockedGeoQueries, func() { m.blockedGeoQueries = nil }},
		{"upstream_latency_seconds", m.upstreamLatencyHistogram, func() { m.upstreamLatencyHistogram = nil }},
		{"query_isp", m.queryCountByISP, func() { m.queryCountByISP = nil }},
	}
}

type optionalMetric struct {
	name      string
	collector prometheus.Collector
	drop      func()
}

// disable turns off the named optional metrics. It reports every name that
// is not one of them, so a typo does not silently keep a metric enabled.
func (m *metrics) disable(names []string) error {
	optional := m.optional()
	byName := make(map[string]optionalMetric, len(optional))
	for _, o := range optional {
		byName[o.name] = o
	}

	var problems []string
	for _, name := range names {
		o, ok := byName[name]
		switch {
		case ok:
			o.drop()
			m.disabled[name] = true
		case strings.HasPrefix(name, "exporter_") || strings.HasPrefix(name, "adguard_exporter_"):
			problems = append(problems, fmt.Sprintf("%s: the exporter's own metrics cannot be disabled", name))
		case byName[shortName(name)].name != "":
			problems = append(problems, fmt.Sprintf("%s: use the short name %s", name, shortName(name)))
		default:
			problems = append(problems, fmt.Sprintf("%s: unknown metric", name))
		}
	}
	if len(problems) > 0 {
		valid := make([]string, 0, len(optional))
		for _, o := range optional {
			valid = append(valid, o.name)
		}
		return fmt.Errorf("DISABLE_METRICS: %s (valid names: %s)", strings.Join(problems, "; "), strings.Join(valid, ", "))
	}
	return nil
}

// shortName strips the adguard_ prefix and the _total suffix of a full
// metric name.
func shortName(name string) string {
	return strings.TrimSuffix(strings.TrimPrefix(name, "adguard_"), "_total")
}

// collectors lists every enabled metric for registration.
func (m *metrics) collectors() []prometheus.Collector {
	var cs []prometheus.Collector
	for _, o := range m.optional() {
		if !m.disabled[o.name] {
			cs = append(cs, o.collector)
		}
	}
	return append(cs,
		m.exporterUp,
		m.exporterScrapeDuration,
		m.exporterErrors,
		m.exporterGeoCacheSize,
		m.exporterQueryLogGaps,
	)
}
