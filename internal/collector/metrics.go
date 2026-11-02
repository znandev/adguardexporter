package collector

import "github.com/prometheus/client_golang/prometheus"

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
	exporterQueryCacheSize prometheus.Gauge
	exporterGeoCacheSize   prometheus.Gauge
	exporterDedupHits      prometheus.Counter
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
		exporterQueryCacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_exporter_query_cache_size",
			Help: "Current number of entries in query deduplication cache",
		}),
		exporterGeoCacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "adguard_exporter_geo_cache_size",
			Help: "Current number of cached GeoIP entries",
		}),
		exporterDedupHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "adguard_exporter_dedup_hits_total",
			Help: "Total number of duplicate queries skipped by deduplication",
		}),
	}
}

// collectors lists every metric for registration.
func (m *metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.dnsQueries,
		m.blockedFiltering,
		m.replacedParental,
		m.avgProcessingTime,
		m.statusProtectionEnabled,
		m.statusRunning,
		m.statusDHCPAvailable,
		m.statusDisabledDuration,
		m.versionInfo,
		m.topQueriedDomains,
		m.topBlockedDomains,
		m.topClients,
		m.topUpstreams,
		m.topUpstreamTime,
		m.queryCountByReason,
		m.queryCountByType,
		m.queryHistogramByClient,
		m.queryCountByUpstream,
		m.queryCountByDomain,
		m.queryCountClientReason,
		m.clientGeoQueries,
		m.blockedGeoQueries,
		m.exporterUp,
		m.exporterScrapeDuration,
		m.exporterErrors,
		m.upstreamLatencyHistogram,
		m.exporterQueryCacheSize,
		m.exporterGeoCacheSize,
		m.exporterDedupHits,
		m.queryCountByISP,
	}
}
