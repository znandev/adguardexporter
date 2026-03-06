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

type GeoCache struct {
	Country string
	Lat     float64
	Lon     float64
}

var (
	geoDB    *geoip2.Reader
	geoCache = map[string]GeoCache{}
	geoMutex sync.RWMutex
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
	)
}

func resolveGeo(ipStr string) (GeoCache, bool) {

	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() {
		return GeoCache{}, false
	}

	geoMutex.RLock()
	if val, ok := geoCache[ipStr]; ok {
		geoMutex.RUnlock()
		return val, true
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

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var logData AdGuardQueryLog

	err = json.Unmarshal(body, &logData)

	return &logData, err
}

func updateQueryLogMetrics() {

	logData, err := fetchQueryLog()

	if err != nil {
		logX("ERROR", "Failed querylog: %v", err)
		return
	}

	for _, q := range logData.Data {

		queryCountByReason.WithLabelValues(q.Reason).Inc()
		queryCountByType.WithLabelValues(q.Question.Type).Inc()

		elapsedMs, err := strconv.ParseFloat(q.Elapsed, 64)

		if err == nil {
			queryHistogramByClient.WithLabelValues(q.Client).Observe(elapsedMs)
		}

		queryCountByUpstream.WithLabelValues(q.Upstream).Inc()
		queryCountByDomain.WithLabelValues(q.Question.Name).Inc()
		queryCountClientReason.WithLabelValues(q.Client, q.Reason).Inc()

		geo, ok := resolveGeo(q.Client)

		if ok {

			clientGeoQueries.WithLabelValues(
				q.Client,
				geo.Country,
				fmt.Sprintf("%f", geo.Lat),
				fmt.Sprintf("%f", geo.Lon),
			).Inc()

		}

	}

	logX("DEBUG", "Processed %d querylog entries", len(logData.Data))

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

	scrapeIntervalStr := os.Getenv("SCRAPE_INTERVAL")
	port := os.Getenv("EXPORTER_PORT")

	if port == "" {
		port = "9617"
	}

	interval, err := strconv.Atoi(scrapeIntervalStr)

	if err != nil || interval < 1 {
		interval = 15
	}

	go func() {

		for {

			updateQueryLogMetrics()

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
