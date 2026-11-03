// Package adguard is a client for the parts of the AdGuard Home HTTP API the
// exporter reads.
package adguard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/znand-dev/adguardexporter/internal/logx"
)

// Timeout applies to every API request.
const Timeout = 10 * time.Second

// Stats is the response of /control/stats.
type Stats struct {
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

// Status is the response of /control/status.
type Status struct {
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

// QueryLog is the response of /control/querylog.
type QueryLog struct {
	Data []QueryLogEntry `json:"data"`
}

// QueryLogEntry is one entry of the query log.
type QueryLogEntry struct {
	Question struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"question"`
	Answer   []any  `json:"answer"`
	Reason   string `json:"reason"`
	Client   string `json:"client"`
	Elapsed  string `json:"elapsedMs"`
	Upstream string `json:"upstream"`

	ClientInfo struct {
		Whois struct {
			Country string `json:"country"`
			OrgName string `json:"orgname"`
		} `json:"whois"`
	} `json:"client_info"`
}

// Client talks to one AdGuard Home instance.
type Client struct {
	host     string
	user     string
	password func() (string, error)
	http     *http.Client
}

// New returns a client for the AdGuard Home at host (e.g.
// http://192.168.1.1:3000). password is called for every request.
func New(host, user string, password func() (string, error)) *Client {
	return &Client{
		host:     host,
		user:     user,
		password: password,
		http:     &http.Client{Timeout: Timeout},
	}
}

// Stats fetches /control/stats.
func (c *Client) Stats(ctx context.Context) (*Stats, error) {
	var v Stats
	return &v, c.get(ctx, "/control/stats", &v)
}

// Status fetches /control/status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var v Status
	return &v, c.get(ctx, "/control/status", &v)
}

// QueryLog fetches /control/querylog with AdGuard Home's default parameters.
func (c *Client) QueryLog(ctx context.Context) (*QueryLog, error) {
	var v QueryLog
	return &v, c.get(ctx, "/control/querylog", &v)
}

// get decodes the body of path into v. A status other than 200 is an error.
func (c *Client) get(ctx context.Context, path string, v any) error {
	pass, err := c.password()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(c.user, pass)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logx.Printf("WARN", "failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}

	return json.Unmarshal(body, v)
}
