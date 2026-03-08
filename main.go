package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

/*
 📦 AdGuard Exporter for Prometheus
 ----------------------------------
 Author   : @znand-dev
 License  : MIT
 Repo     : https://github.com/znand-dev/adguardexporter

 This Go application fetches stats from AdGuard Home via API endpoints
 and exposes them as Prometheus metrics at `/metrics`.

 Required ENV variables:
 - ADGUARD_HOST        : AdGuard Home base URL (e.g. http://192.168.1.1:3000)
 - ADGUARD_USER        : API username (your adguard user)
 - ADGUARD_PASS        : API password (your adguard pass)
 - EXPORTER_PORT       : Port to expose metrics (default: 9617)
 - SCRAPE_INTERVAL     : Interval (in seconds) to fetch new stats (default: 15)
 - LOG_LEVEL           : Logging level (options: DEBUG, INFO, WARN, ERROR — default: INFO)
 - GEOIP_DB            : GeoLite2-City.mmdb
*/

var logLevelMap = map[string]int{"ERROR": 1, "WARN": 2, "INFO": 3, "DEBUG": 4}
var currentLogLevel = 3

func initLogger() {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "INFO"
	}
	if val, ok := logLevelMap[level]; ok {
		currentLogLevel = val
	}
}

func logX(level string, format string, args ...interface{}) {
	if logLevelMap[level] <= currentLogLevel {
		log.Printf("[%s] %s", level, fmt.Sprintf(format, args...))
	}
}

//function hash query
func buildQueryKey(client, domain, upstream, reason, elapsed string) string {
	return client + "|" + domain + "|" + upstream + "|" + reason + "|" + elapsed
}

type GeoCache struct {
	Country string
	Lat     float64
	Lon     float64
	TS      int64
}

var (
	geoDB    *geoip2.Reader
	geoCache = map[string]GeoCache{}
	geoMutex sync.RWMutex
	// cache query hash
	querySeen   = map[string]int64{}
	queryMutex  sync.Mutex
	queryTTL    = int64(300) // 5 menit
	geoTTL      = int64(86400) // 24 jam
	dedupHits   int64
)

type AdGuardStats struct {
	NumDNSQueries       float64              `json:"num_dns_queries"`
	NumBlockedFiltering float64              `json:"num_blocked_filtering"`
	NumReplacedParental float64              `json:"num_replaced_parental"`
	AvgProcessingTime   float64              `json:"avg_processing_time"`
	TopQueriedDomains   []map[string]float64 `json:"top_queried_domains"`
	TopBlockedDomains   []map[string]float64 `json:"top_blocked_domains"`
	TopClients          []map[string]float64 `json:"top_clients"`
	TopUpstream         []map[string]float64 `json:"top_upstreams_responses"`
	TopUpstreamTime     []map[string]float64 `json:"top_upstreams_avg_time"`
}

type AdGuardStatus struct {
	Version                    string   `json:"version"`
	Language                   string   `json:"language"`
	DNSAddresses               []string `json:"dns_addresses"`
	DNSPort                    int      `json:"dns_port"`
	HTTPPort                   int      `json:"http_port"`
	ProtectionDisabledDuration int      `json:"protection_disabled_duration"`
	ProtectionEnabled          bool     `json:"protection_enabled"`
	DHCPAvailable              bool     `json:"dhcp_available"`
	Running                    bool     `json:"running"`
}

type AdGuardQueryLog struct {
	Data []struct {
		Question struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"question"`
		Answer   []interface{} `json:"answer"`
		Reason   string        `json:"reason"`
		Client   string        `json:"client"`
		Elapsed  string        `json:"elapsedMs"`
		Upstream string        `json:"upstream"`
	} `json:"data"`
}

var (

	dnsQueries = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "adguard_dns_queries_total", Help: "Total DNS queries received",
	})

	blockedFiltering = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "adguard_blocked_filtering_total", Help: "Total DNS queries blocked",
	})

	replacedParental = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "adguard_replaced_parental", Help: "Total parental replaced queries",
	})

	avgProcessingTime = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "adguard_avg_processing_time", Help: "Avg DNS processing time",
	})

	statusProtectionEnabled = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "adguard_protection_enabled", Help: "Protection enabled (1/0)",
	})

	statusRunning = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "adguard_running", Help: "AdGuard running",
	})

	statusDHCPAvailable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "adguard_dhcp_available", Help: "DHCP available",
	})

	statusDisabledDuration = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "adguard_protection_disabled_duration_seconds",
		Help: "Time since protection disabled",
	})

	versionInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "adguard_version_info",
			Help: "AdGuard version",
		},
		[]string{"version"},
	)

	topQueriedDomains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "adguard_top_queried_domain_total",
			Help: "Top queried domains",
		},
		[]string{"domain"},
	)

	topBlockedDomains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "adguard_top_blocked_domain_total",
			Help: "Top blocked domains",
		},
		[]string{"domain"},
	)

	topClients = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "adguard_top_client_total",
			Help: "Top client IPs",
		},
		[]string{"client"},
	)

	topUpstreams = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "adguard_top_upstream_total",
			Help: "Top upstream servers",
		},
		[]string{"upstream"},
	)

	topUpstreamTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "adguard_upstream_avg_response_time_seconds",
			Help: "Avg response time per upstream",
		},
		[]string{"upstream"},
	)

	queryCountByReason = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "adguard_query_reason_total",
			Help: "Queries by reason",
		},
		[]string{"reason"},
	)

	queryCountByType = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "adguard_query_type_total",
			Help: "Queries by DNS type",
		},
		[]string{"type"},
	)

	queryHistogramByClient = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "adguard_query_elapsed_ms",
			Help:    "Query duration by client",
			Buckets: prometheus.LinearBuckets(1, 5, 10),
		},
		[]string{"client"},
	)

	queryCountByUpstream = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "adguard_query_upstream_total",
			Help: "Queries per upstream",
		},
		[]string{"upstream"},
	)

	queryCountByDomain = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "adguard_query_domain_total",
			Help: "Queries per domain",
		},
		[]string{"domain"},
	)

	queryCountClientReason = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "adguard_query_client_reason_total",
			Help: "Queries per client per reason",
		},
		[]string{"client", "reason"},
	)

	clientGeoQueries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "adguard_client_geo_queries",
			Help: "Queries per client with geographic info",
		},
		[]string{"client", "country", "lat", "lon"},
	)

    blockedGeoQueries = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "adguard_blocked_geo_queries",
            Help: "Blocked DNS queries per client with geographic info",
        },
        []string{"client", "country", "lat", "lon"},
    )
    
    upstreamLatencyHistogram = prometheus.NewHistogramVec(
	    prometheus.HistogramOpts{
		    Name: "adguard_upstream_latency_seconds",
		    Help: "Latency distribution per upstream DNS server",
		    Buckets: prometheus.ExponentialBuckets(
			    0.001, // 1ms
			    2,
			    10,
		    ),
	    },
	    []string{"upstream"},
    )

	exporterUp = prometheus.NewGauge(
	    prometheus.GaugeOpts{
		    Name: "adguard_exporter_up",
		    Help: "Exporter scrape success",
	    },
    )

    exporterScrapeDuration = prometheus.NewGauge(
	    prometheus.GaugeOpts{
		    Name: "adguard_exporter_scrape_duration_seconds",
		    Help: "Exporter scrape duration",
	   },
    )

    exporterErrors = prometheus.NewCounter(
	    prometheus.CounterOpts{
		    Name: "adguard_exporter_scrape_errors_total",
		    Help: "Total exporter errors",
	   },
    )

	exporterQueryCacheSize = prometheus.NewGauge(
	    prometheus.GaugeOpts{
		    Name: "adguard_exporter_query_cache_size",
		    Help: "Current number of entries in query deduplication cache",
	    },
    )

    exporterGeoCacheSize = prometheus.NewGauge(
	    prometheus.GaugeOpts{
		    Name: "adguard_exporter_geo_cache_size",
		    Help: "Current number of cached GeoIP entries",
	    },
    )

    exporterDedupHits = prometheus.NewCounter(
	    prometheus.CounterOpts{
		    Name: "adguard_exporter_dedup_hits_total",
		    Help: "Total number of duplicate queries skipped by deduplication",
	   },
    )
)

func init() {
	_ = godotenv.Load()
	initLogger()

	prometheus.MustRegister(
		dnsQueries,
		blockedFiltering,
		replacedParental,
		avgProcessingTime,
		statusProtectionEnabled,
		statusRunning,
		statusDHCPAvailable,
		statusDisabledDuration,
		versionInfo,
		topQueriedDomains,
		topBlockedDomains,
		topClients,
		topUpstreams,
		topUpstreamTime,
		queryCountByReason,
		queryCountByType,
		queryHistogramByClient,
		queryCountByUpstream,
		queryCountByDomain,
		queryCountClientReason,
		clientGeoQueries,
        blockedGeoQueries,
		exporterUp,
        exporterScrapeDuration,
        exporterErrors,
		upstreamLatencyHistogram,
		exporterQueryCacheSize,
        exporterGeoCacheSize,
        exporterDedupHits,
	)
}

func resolveGeo(ipStr string) (GeoCache, bool) {

	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() {
		return GeoCache{}, false
	}

	now := time.Now().Unix()

	geoMutex.RLock()
	if val, ok := geoCache[ipStr]; ok {

		// cache valid
		if now-val.TS < geoTTL {
			geoMutex.RUnlock()
			return val, true
		}

	}
	geoMutex.RUnlock()

	record, err := geoDB.City(ip)
	if err != nil {
		return GeoCache{}, false
	}

	cache := GeoCache{
		Country: record.Country.IsoCode,
		Lat:     record.Location.Latitude,
		Lon:     record.Location.Longitude,
		TS:      now,
	}

	geoMutex.Lock()
	geoCache[ipStr] = cache
	geoMutex.Unlock()

	return cache, true
}

func fetchQueryLog() (*AdGuardQueryLog, error) {

	host := os.Getenv("ADGUARD_HOST")
	user := os.Getenv("ADGUARD_USER")
	pass := os.Getenv("ADGUARD_PASS")

	url := host + "/control/querylog"

	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(user, pass)

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

        defer func() {
            if err := resp.Body.Close(); err != nil {
                logX("WARN", "failed to close response body: %v", err)
            }
        }()

	body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

	var logData AdGuardQueryLog

	err = json.Unmarshal(body, &logData)

	return &logData, err
}

func fetchStats() (*AdGuardStats, error) {

	host := os.Getenv("ADGUARD_HOST")
	user := os.Getenv("ADGUARD_USER")
	pass := os.Getenv("ADGUARD_PASS")

	url := host + "/control/stats"

	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(user, pass)

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logX("WARN", "failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

	var stats AdGuardStats

	err = json.Unmarshal(body, &stats)

	return &stats, err
}

func fetchStatus() (*AdGuardStatus, error) {

	host := os.Getenv("ADGUARD_HOST")
	user := os.Getenv("ADGUARD_USER")
	pass := os.Getenv("ADGUARD_PASS")

	url := host + "/control/status"

	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(user, pass)

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logX("WARN", "failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

	var status AdGuardStatus

	err = json.Unmarshal(body, &status)

	return &status, err
}

func updateStatsMetrics() {

	stats, err := fetchStats()

	if err != nil {
		logX("ERROR", "Failed fetch stats: %v", err)
		return
	}

	dnsQueries.Set(stats.NumDNSQueries)
	blockedFiltering.Set(stats.NumBlockedFiltering)
	replacedParental.Set(stats.NumReplacedParental)
	avgProcessingTime.Set(stats.AvgProcessingTime)

	// reset gauge vectors
	topQueriedDomains.Reset()
	topBlockedDomains.Reset()
	topClients.Reset()
	topUpstreams.Reset()
	topUpstreamTime.Reset()

	// top queried domains
	for _, d := range stats.TopQueriedDomains {
		for domain, count := range d {
			topQueriedDomains.WithLabelValues(domain).Set(count)
		}
	}

	// top blocked domains
	for _, d := range stats.TopBlockedDomains {
		for domain, count := range d {
			topBlockedDomains.WithLabelValues(domain).Set(count)
		}
	}

	// top clients
	for _, c := range stats.TopClients {
		for client, count := range c {
			topClients.WithLabelValues(client).Set(count)
		}
	}

	// upstream responses
	for _, u := range stats.TopUpstream {
		for upstream, count := range u {
			topUpstreams.WithLabelValues(upstream).Set(count)
		}
	}

	// upstream avg response time
	for _, u := range stats.TopUpstreamTime {
		for upstream, time := range u {
			topUpstreamTime.WithLabelValues(upstream).Set(time)
		}
	}

	logX(
		"DEBUG",
		"Fetched stats: queries=%.0f blocked=%.0f replaced=%.0f avgTime=%.2fms topDomains=%d",
		stats.NumDNSQueries,
		stats.NumBlockedFiltering,
		stats.NumReplacedParental,
		stats.AvgProcessingTime,
		len(stats.TopQueriedDomains),
	)
}

func updateStatusMetrics() {

	status, err := fetchStatus()

	if err != nil {
		logX("ERROR", "Failed fetch status: %v", err)
		return
	}

	if status.Running {
		statusRunning.Set(1)
	} else {
		statusRunning.Set(0)
	}

	if status.ProtectionEnabled {
		statusProtectionEnabled.Set(1)
	} else {
		statusProtectionEnabled.Set(0)
	}

	if status.DHCPAvailable {
		statusDHCPAvailable.Set(1)
	} else {
		statusDHCPAvailable.Set(0)
	}

	statusDisabledDuration.Set(float64(status.ProtectionDisabledDuration))

	versionInfo.WithLabelValues(status.Version).Set(1)

	logX(
		"DEBUG",
		"Fetched status: running=%v protection=%v DHCP=%v version=%s",
		status.Running,
		status.ProtectionEnabled,
		status.DHCPAvailable,
		status.Version,
	)
}

func updateQueryLogMetrics() {
    
    scanned := 0
    processed := 0
    skipped := 0
	geoResolved := 0
	processed := 0
	skipped := 0
	dedupHits := 0

	logData, err := fetchQueryLog()

	if err != nil {
		logX("ERROR", "Failed querylog: %v", err)
		return
	}

	for _, q := range logData.Data {

		scanned++

		// dedup logic
		key := buildQueryKey(
			q.Client,
			q.Question.Name,
			q.Upstream,
			q.Reason,
			q.Elapsed,
		)

		now := time.Now().Unix()

		queryMutex.Lock()

		if ts, exists := querySeen[key]; exists {

			if now-ts < queryTTL {
				queryMutex.Unlock()
				skipped++
				exporterDedupHits.Inc()
				dedupHits++
				continue
			}

		}

		querySeen[key] = now
		queryMutex.Unlock()
		
		processed++

		processed++
		
		queryCountByReason.WithLabelValues(q.Reason).Inc()
		queryCountByType.WithLabelValues(q.Question.Type).Inc()

		elapsedMs, err := strconv.ParseFloat(q.Elapsed, 64)

		if err == nil {

			queryHistogramByClient.WithLabelValues(q.Client).Observe(elapsedMs)

			if q.Upstream != "" {
				upstreamLatencyHistogram.WithLabelValues(q.Upstream).Observe(elapsedMs / 1000)
			}

		}

		queryCountByUpstream.WithLabelValues(q.Upstream).Inc()
		queryCountByDomain.WithLabelValues(q.Question.Name).Inc()
		queryCountClientReason.WithLabelValues(q.Client, q.Reason).Inc()

		geo, ok := resolveGeo(q.Client)

		if ok {

			geoResolved++

			clientGeoQueries.WithLabelValues(
				q.Client,
				geo.Country,
				fmt.Sprintf("%f", geo.Lat),
				fmt.Sprintf("%f", geo.Lon),
			).Inc()

			if q.Reason == "FilteredBlackList" ||
			   q.Reason == "FilteredSafeBrowsing" ||
			   q.Reason == "FilteredParental" {

				blockedGeoQueries.WithLabelValues(
					q.Client,
					geo.Country,
					fmt.Sprintf("%f", geo.Lat),
					fmt.Sprintf("%f", geo.Lon),
				).Inc()

			}
		}
	}

	logX("DEBUG",
	    "Querylog: scanned=%d new=%d skipped=%d geoip=%d",
	    len(logData.Data),
	    processed,
	    skipped,
	    geoResolved,
    )
}

//cleanup memory
func cleanupQueryCache() {

	now := time.Now().Unix()

	queryMutex.Lock()

	for k, v := range querySeen {

		if now-v > queryTTL {
			delete(querySeen, k)
		}

	}

	queryMutex.Unlock()
}

func main() {

	dbPath := os.Getenv("GEOIP_DB")

	if dbPath == "" {
		dbPath = "GeoLite2-City.mmdb"
	}

	db, err := geoip2.Open(dbPath)

	if err != nil {
		log.Fatalf("Failed open GeoIP DB: %v", err)
	}

	geoDB = db
	logX("INFO", "GeoIP database loaded")

	scrapeIntervalStr := os.Getenv("SCRAPE_INTERVAL")
	port := os.Getenv("EXPORTER_PORT")

	if port == "" {
		port = "9617"
	}

	interval, err := strconv.Atoi(scrapeIntervalStr)

	if err != nil || interval < 1 {
		interval = 15
	}
    
    logX("INFO", "Scrape interval set to %ds", interval)

	go func() {

        for {

            start := time.Now()

            updateStatsMetrics()
            updateStatusMetrics()
            updateQueryLogMetrics()

            cleanupQueryCache()

            duration := time.Since(start).Seconds()

            exporterScrapeDuration.Set(duration)
            exporterUp.Set(1)

			exporterQueryCacheSize.Set(float64(len(querySeen)))
            exporterGeoCacheSize.Set(float64(len(geoCache)))
            
            logX(
                "DEBUG",
                "Exporter caches: query_cache_entries=%d geo_cache_entries=%d dedup_hits_total=%d",
                len(querySeen),
                len(geoCache),
                dedupHits,
            )

			logX("DEBUG", "Scrape finished in %.3fs", duration)

            time.Sleep(time.Duration(interval) * time.Second)

        }

    }()

	http.Handle("/metrics", promhttp.Handler())

	logX("INFO", "Starting exporter at :%s ..", port)

	err = http.ListenAndServe(":"+port, nil)

	if err != nil {
		logX("ERROR", "Server failed: %v", err)
		os.Exit(1)
	}

}
