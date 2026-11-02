// Package config reads the exporter's configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults for optional settings.
const (
	DefaultPort     = "9617"
	DefaultInterval = 15 * time.Second
	DefaultGeoIPDB  = "GeoLite2-City.mmdb"
)

// Config is the exporter configuration.
type Config struct {
	Host     string // ADGUARD_HOST
	User     string // ADGUARD_USER
	Port     string // EXPORTER_PORT
	Interval time.Duration
	LogLevel string // LOG_LEVEL
	GeoIPDB  string // GEOIP_DB

	pass     string // ADGUARD_PASS
	passFile string // ADGUARD_PASS_FILE
}

// Load reads the configuration with getenv, usually os.Getenv.
func Load(getenv func(string) string) Config {
	c := Config{
		Host:     getenv("ADGUARD_HOST"),
		User:     getenv("ADGUARD_USER"),
		Port:     getenv("EXPORTER_PORT"),
		LogLevel: getenv("LOG_LEVEL"),
		GeoIPDB:  getenv("GEOIP_DB"),
		pass:     getenv("ADGUARD_PASS"),
		passFile: getenv("ADGUARD_PASS_FILE"),
	}
	if c.Port == "" {
		c.Port = DefaultPort
	}
	if c.GeoIPDB == "" {
		c.GeoIPDB = DefaultGeoIPDB
	}

	c.Interval = DefaultInterval
	if s, err := strconv.Atoi(getenv("SCRAPE_INTERVAL")); err == nil && s >= 1 {
		c.Interval = time.Duration(s) * time.Second
	}

	return c
}

// Password returns the AdGuard Home password. ADGUARD_PASS_FILE takes
// precedence over ADGUARD_PASS and is read on every call, so a rotated
// secret is picked up without a restart.
//
// ADGUARD_PASS_FILE support by Guillaume Kulakowski (@llaumgui), #104:
// https://github.com/znand-dev/adguardexporter/commit/d23ef392faa006b04a1c12d5540a506ea6425bc6
// https://github.com/znand-dev/adguardexporter/commit/117f4ff43efde193e5e21bcc63bbb6b9912da2b3
func (c Config) Password() (string, error) {
	if c.passFile != "" {
		password, err := os.ReadFile(c.passFile)
		if err != nil {
			return "", fmt.Errorf("failed to read ADGUARD_PASS_FILE: %w", err)
		}
		return strings.TrimRight(string(password), "\r\n"), nil
	}

	return c.pass, nil
}
