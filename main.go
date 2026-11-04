package main

import (
	"context"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/znand-dev/adguardexporter/internal/adguard"
	"github.com/znand-dev/adguardexporter/internal/collector"
	"github.com/znand-dev/adguardexporter/internal/config"
	"github.com/znand-dev/adguardexporter/internal/geo"
	"github.com/znand-dev/adguardexporter/internal/logx"
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
 - ADGUARD_PASS_FILE   : Path to a file containing the API password (takes precedence over ADGUARD_PASS)
 - EXPORTER_PORT       : Port to expose metrics (default: 9617)
 - SCRAPE_INTERVAL     : Interval (in seconds) to fetch new stats (default: 15)
 - LOG_LEVEL           : Logging level (options: DEBUG, INFO, WARN, ERROR — default: INFO)
 - GEOIP_DB            : GeoLite2-City.mmdb
 - QUERYLOG_OVERLAP    : Longest time between a query's start and its query log write (default: 1m)
 - QUERYLOG_MAX_ENTRIES: Maximum query log entries requested per loop (default: 20000, at most 50000)

 Layout:
 - internal/config     : environment parsing
 - internal/adguard    : AdGuard Home API client
 - internal/collector  : metrics and the update loop
 - internal/geo        : GeoIP lookup and cache
 - internal/logx       : levelled logging
*/

func main() {
	_ = godotenv.Load()
	cfg := config.Load(os.Getenv)
	logx.SetLevel(cfg.LogLevel)

	resolver, err := geo.Open(cfg.GeoIPDB)
	if err != nil {
		logx.Printf("WARN", "GeoIP DB not found (%v) — geo metrics disabled", err)
	} else {
		logx.Printf("INFO", "GeoIP database loaded")
	}

	logx.Printf("INFO", "Scrape interval set to %ds", int(cfg.Interval.Seconds()))
	logx.Printf("INFO", "Query log overlap %s, at most %d entries per loop", cfg.QueryLogOverlap, cfg.QueryLogMaxEntries)

	client := adguard.New(cfg.Host, cfg.User, cfg.Password)
	c := collector.New(client, resolver, prometheus.DefaultRegisterer, collector.QueryLogOptions{
		Overlap:    cfg.QueryLogOverlap,
		MaxEntries: cfg.QueryLogMaxEntries,
	})
	go c.Run(context.Background(), cfg.Interval)

	http.Handle("/metrics", promhttp.Handler())

	logx.Printf("INFO", "Starting exporter at :%s ..", cfg.Port)

	err = http.ListenAndServe(":"+cfg.Port, nil)
	if err != nil {
		logx.Printf("ERROR", "Server failed: %v", err)
		os.Exit(1)
	}
}
