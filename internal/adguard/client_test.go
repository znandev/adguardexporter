package adguard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/znand-dev/adguardexporter/internal/adguardtest"
)

func newClient(fake *adguardtest.Server, pass string) *Client {
	return New(fake.URL, fake.User, func() (string, error) { return pass, nil })
}

func TestStatsAndStatus(t *testing.T) {
	fake := adguardtest.New(t)
	fake.SetStats(map[string]any{
		"num_dns_queries":     10,
		"top_queried_domains": []map[string]float64{{"example.com": 3}},
	})
	fake.SetStatus(map[string]any{"version": "v0.107.70", "running": true})
	c := newClient(fake, fake.Pass())

	stats, err := c.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.NumDNSQueries != 10 || stats.TopQueriedDomains[0]["example.com"] != 3 {
		t.Errorf("Stats = %+v", stats)
	}

	status, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Version != "v0.107.70" || !status.Running {
		t.Errorf("Status = %+v", status)
	}
}

func TestQueryLog(t *testing.T) {
	fake := adguardtest.New(t)
	now := time.Now()
	fake.AddEntries(adguardtest.Entry{
		Time: now, Client: "203.0.113.7", Name: "example.org", Type: "AAAA",
		Reason: "NotFilteredNotFound", Elapsed: "12.5", Upstream: "1.1.1.1:53",
		WhoisCountry: "DE", WhoisOrg: "Example ISP",
	})
	c := newClient(fake, fake.Pass())

	log, err := c.QueryLog(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(log.Data) != 1 {
		t.Fatalf("got %d entries, want 1", len(log.Data))
	}
	e := log.Data[0]
	if e.Client != "203.0.113.7" || e.Question.Name != "example.org" || e.Question.Type != "AAAA" ||
		e.Reason != "NotFilteredNotFound" || e.Elapsed != "12.5" || e.Upstream != "1.1.1.1:53" ||
		e.ClientInfo.Whois.Country != "DE" || e.ClientInfo.Whois.OrgName != "Example ISP" {
		t.Errorf("entry = %+v", e)
	}

	if !e.Time.Equal(now) {
		t.Errorf("time = %v, want %v", e.Time, now)
	}
	if len(e.ID) != 32 {
		t.Errorf("ID has %d bytes, want 32", len(e.ID))
	}

	reqs := fake.Requests()
	if q := reqs[len(reqs)-1].Query; len(q) != 1 || len(q["limit"]) != 1 || q["limit"][0] != "20" {
		t.Errorf("query log requested with parameters %v, want only limit=20", q)
	}
}

// The ID covers every stored field but not client_info, which AdGuard Home
// fills in on each request.
func TestQueryLogEntryID(t *testing.T) {
	decode := func(s string) QueryLogEntry {
		t.Helper()
		var e QueryLogEntry
		if err := json.Unmarshal([]byte(s), &e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	base := decode(`{"time":"2026-11-01T10:00:00.000001Z","client":"192.168.1.10","question":{"name":"a.example","type":"A"},"client_info":{"name":"laptop"}}`)

	same := []string{
		`{"time":"2026-11-01T10:00:00.000001Z","client":"192.168.1.10","question":{"name":"a.example","type":"A"}}`,
		`{"client_info":{"name":"renamed","whois":{"country":"DE"}},"question":{"type":"A","name":"a.example"},"client":"192.168.1.10","time":"2026-11-01T10:00:00.000001Z"}`,
		"{ \"time\": \"2026-11-01T10:00:00.000001Z\",\n \"client\": \"192.168.1.10\", \"question\": {\"name\": \"a.example\", \"type\": \"A\"} }",
	}
	for _, s := range same {
		if decode(s).ID != base.ID {
			t.Errorf("ID differs for %s", s)
		}
	}

	different := []string{
		`{"time":"2026-11-01T10:00:00.000002Z","client":"192.168.1.10","question":{"name":"a.example","type":"A"}}`,
		`{"time":"2026-11-01T10:00:00.000001Z","client":"192.168.1.11","question":{"name":"a.example","type":"A"}}`,
		`{"time":"2026-11-01T10:00:00.000001Z","client":"192.168.1.10","question":{"name":"a.example","type":"AAAA"}}`,
		`{"time":"2026-11-01T10:00:00.000001Z","client":"192.168.1.10","question":{"name":"a.example","type":"A"},"elapsedMs":"1"}`,
	}
	for _, s := range different {
		if decode(s).ID == base.ID {
			t.Errorf("ID equal for %s", s)
		}
	}
}

func TestErrors(t *testing.T) {
	fake := adguardtest.New(t)

	if _, err := newClient(fake, "wrong").Stats(context.Background()); err == nil {
		t.Error("no error with a wrong password")
	}

	fake.Fail(adguardtest.PathStatus, 1)
	if _, err := newClient(fake, fake.Pass()).Status(context.Background()); err == nil {
		t.Error("no error on status 500")
	}

	// An error status is an error even if the body is valid JSON.
	jsonErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("{}"))
	}))
	defer jsonErr.Close()
	if _, err := New(jsonErr.URL, "u", func() (string, error) { return "p", nil }).Stats(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "503") {
		t.Errorf("err = %v, want the 503 status", err)
	}

	pwErr := errors.New("no password")
	c := New(fake.URL, fake.User, func() (string, error) { return "", pwErr })
	before := len(fake.Requests())
	if _, err := c.Stats(context.Background()); !errors.Is(err, pwErr) {
		t.Errorf("err = %v, want the password error", err)
	}
	if len(fake.Requests()) != before {
		t.Error("request sent although the password could not be read")
	}

	bad := New("http://[::1", "u", func() (string, error) { return "p", nil })
	if _, err := bad.Stats(context.Background()); err == nil {
		t.Error("no error for an invalid host")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newClient(fake, fake.Pass()).QueryLog(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestPasswordPerRequest(t *testing.T) {
	fake := adguardtest.New(t)
	calls := 0
	c := New(fake.URL, fake.User, func() (string, error) {
		calls++
		return fake.Pass(), nil
	})
	for range 3 {
		if _, err := c.Stats(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Errorf("password read %d times for 3 requests, want 3", calls)
	}
}
