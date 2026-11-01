package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c := Load(env(nil))
	if c.Port != DefaultPort {
		t.Errorf("Port = %q, want %q", c.Port, DefaultPort)
	}
	if c.Interval != DefaultInterval {
		t.Errorf("Interval = %v, want %v", c.Interval, DefaultInterval)
	}
	if c.GeoIPDB != DefaultGeoIPDB {
		t.Errorf("GeoIPDB = %q, want %q", c.GeoIPDB, DefaultGeoIPDB)
	}
}

func TestLoad(t *testing.T) {
	c := Load(env(map[string]string{
		"ADGUARD_HOST":    "http://adguard:3000",
		"ADGUARD_USER":    "exporter",
		"EXPORTER_PORT":   "9200",
		"SCRAPE_INTERVAL": "30",
		"LOG_LEVEL":       "DEBUG",
		"GEOIP_DB":        "/data/city.mmdb",
	}))
	want := Config{
		Host:     "http://adguard:3000",
		User:     "exporter",
		Port:     "9200",
		Interval: 30 * time.Second,
		LogLevel: "DEBUG",
		GeoIPDB:  "/data/city.mmdb",
	}
	if c != want {
		t.Errorf("Load = %+v, want %+v", c, want)
	}
}

func TestLoadInvalidInterval(t *testing.T) {
	for _, v := range []string{"", "abc", "0", "-5", "1.5"} {
		if got := Load(env(map[string]string{"SCRAPE_INTERVAL": v})).Interval; got != DefaultInterval {
			t.Errorf("SCRAPE_INTERVAL=%q: Interval = %v, want %v", v, got, DefaultInterval)
		}
	}
	if got := Load(env(map[string]string{"SCRAPE_INTERVAL": "1"})).Interval; got != time.Second {
		t.Errorf("SCRAPE_INTERVAL=1: Interval = %v, want 1s", got)
	}
}

func TestPassword(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tests := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr bool
	}{
		{"env", map[string]string{"ADGUARD_PASS": "secret"}, "secret", false},
		{"unset", nil, "", false},
		{"file wins", map[string]string{"ADGUARD_PASS": "env", "ADGUARD_PASS_FILE": write("a", "file")}, "file", false},
		{"trailing LF", map[string]string{"ADGUARD_PASS_FILE": write("b", "file\n")}, "file", false},
		{"trailing CRLF", map[string]string{"ADGUARD_PASS_FILE": write("c", "file\r\n\n")}, "file", false},
		{"inner spaces kept", map[string]string{"ADGUARD_PASS_FILE": write("d", " a b \n")}, " a b ", false},
		{"missing file", map[string]string{"ADGUARD_PASS": "env", "ADGUARD_PASS_FILE": filepath.Join(dir, "missing")}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(env(tt.env)).Password()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Password = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPasswordReadEachCall(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Load(env(map[string]string{"ADGUARD_PASS_FILE": p}))
	if got, _ := c.Password(); got != "one" {
		t.Fatalf("Password = %q, want one", got)
	}
	if err := os.WriteFile(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Password(); got != "two" {
		t.Errorf("Password after rotation = %q, want two", got)
	}
}
