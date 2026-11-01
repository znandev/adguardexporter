// Package adguardtest provides a fake AdGuard Home API for tests.
//
// The query log endpoint follows AdGuard Home's internal/querylog package,
// checked against AdGuard Home v0.107.79:
//
//   - Entries are kept in write order. An entry's time is when the query
//     started, but it is written when the query finishes, so write order and
//     time order can differ.
//   - limit (default 500) and offset select the most recently written
//     entries; the selection is then sorted by time, newest first, and offset
//     is dropped from its start.
//   - older_than (RFC 3339) is exclusive and has to be the exact time of an
//     entry, as returned in "oldest": AdGuard Home seeks the log file for that
//     timestamp and silently returns no file entries if it is not found. Only
//     entries written before the entry found are considered. A time after the
//     last written entry reads from the end of the file but skips that entry. The fake models
//     the log file only, not AdGuard Home's in-memory buffer, which filters
//     by time alone.
//   - "oldest" is the time of the last returned entry, or "" if none.
package adguardtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Endpoint paths served by the fake.
const (
	PathStats    = "/control/stats"
	PathStatus   = "/control/status"
	PathQueryLog = "/control/querylog"
)

// DefaultQueryLogLimit is AdGuard Home's default page size.
const DefaultQueryLogLimit = 500

// Entry is one query log entry.
type Entry struct {
	Time     time.Time
	Client   string
	Name     string
	Type     string
	Reason   string
	Elapsed  string
	Upstream string

	// WhoisCountry and WhoisOrg fill client_info.whois when either is set.
	WhoisCountry string
	WhoisOrg     string
}

// Request is a request the fake received.
type Request struct {
	Path  string
	Query map[string][]string
}

// Server is a fake AdGuard Home API.
type Server struct {
	*httptest.Server

	// User is the API user; it does not change.
	User string

	mu       sync.Mutex
	pass     string
	stats    any
	status   any
	entries  []Entry
	maxPage  int
	failures map[string]int
	requests []Request
	counts   map[string]int
	gate     *gate
	onQuery  func(n int)
}

type gate struct {
	path    string
	at      int
	reached chan struct{}
	release chan struct{}
}

// New starts a fake server that is closed when the test ends.
func New(t testing.TB) *Server {
	t.Helper()

	s := &Server{
		User:     "exporter",
		pass:     "secret",
		stats:    map[string]any{},
		status:   map[string]any{},
		failures: map[string]int{},
		counts:   map[string]int{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(func() {
		s.ReleaseAll()
		s.Close()
	})

	return s
}

// Pass returns the API password.
func (s *Server) Pass() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pass
}

// SetPass changes the API password.
func (s *Server) SetPass(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pass = p
}

// SetStats sets the JSON body of /control/stats.
func (s *Server) SetStats(v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats = v
}

// SetStatus sets the JSON body of /control/status.
func (s *Server) SetStatus(v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = v
}

// AddEntries writes entries to the query log, in the given order.
func (s *Server) AddEntries(e ...Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e...)
}

// ClearEntries empties the query log, like a rotation or a manual clear.
func (s *Server) ClearEntries() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = nil
}

// SetMaxPage caps the number of entries per query log response, whatever
// limit the client asks for. Zero means no cap. AdGuard Home has no such cap;
// tests use it to force page boundaries.
func (s *Server) SetMaxPage(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxPage = n
}

// Fail makes the next n requests to path answer with status 500. A negative n
// fails all requests until Fail(path, 0) is called.
func (s *Server) Fail(path string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[path] = n
}

// OnQueryLog registers a hook that runs before the n-th query log request
// (1-based) is answered. It may call AddEntries.
func (s *Server) OnQueryLog(f func(n int)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onQuery = f
}

// Requests returns all requests received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// Count returns how many requests path has received.
func (s *Server) Count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[path]
}

// HoldAt blocks the at-th request (1-based) to path until Release is called.
// It returns a channel that is closed once that request has arrived.
func (s *Server) HoldAt(path string, at int) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gate != nil {
		close(s.gate.release)
	}
	s.gate = &gate{
		path:    path,
		at:      at,
		reached: make(chan struct{}),
		release: make(chan struct{}),
	}
	return s.gate.reached
}

// Release lets a request held by HoldAt continue.
func (s *Server) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gate != nil {
		close(s.gate.release)
		s.gate = nil
	}
}

// ReleaseAll is Release under another name, for cleanup.
func (s *Server) ReleaseAll() { s.Release() }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.counts[r.URL.Path]++
	n := s.counts[r.URL.Path]
	s.requests = append(s.requests, Request{Path: r.URL.Path, Query: r.URL.Query()})
	g := s.gate
	s.mu.Unlock()

	if g != nil && g.path == r.URL.Path && g.at == n {
		close(g.reached)
		select {
		case <-g.release:
		case <-r.Context().Done():
			return
		}
	}

	user, pass, ok := r.BasicAuth()
	if !ok || user != s.User || pass != s.Pass() {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	if f := s.failures[r.URL.Path]; f != 0 {
		if f > 0 {
			s.failures[r.URL.Path] = f - 1
		}
		s.mu.Unlock()
		http.Error(w, "injected failure", http.StatusInternalServerError)
		return
	}
	hook := s.onQuery
	s.mu.Unlock()

	switch r.URL.Path {
	case PathStats:
		s.mu.Lock()
		v := s.stats
		s.mu.Unlock()
		writeJSON(w, v)
	case PathStatus:
		s.mu.Lock()
		v := s.status
		s.mu.Unlock()
		writeJSON(w, v)
	case PathQueryLog:
		if hook != nil {
			hook(n)
		}
		s.queryLog(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) queryLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var olderThan time.Time
	if v := q.Get("older_than"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			http.Error(w, "parsing params: "+err.Error(), http.StatusBadRequest)
			return
		}
		olderThan = t
	}

	limit := DefaultQueryLogLimit
	if v, err := strconv.ParseInt(q.Get("limit"), 10, 64); err == nil {
		limit = int(v)
	}
	offset := 0
	if v, err := strconv.ParseInt(q.Get("offset"), 10, 64); err == nil {
		offset = int(v)
	}

	s.mu.Lock()
	if s.maxPage > 0 && limit > s.maxPage {
		limit = s.maxPage
	}
	// Candidates in reverse write order, starting before the sought entry.
	end := len(s.entries)
	if !olderThan.IsZero() {
		end = -1
		for i := len(s.entries) - 1; i >= 0; i-- {
			if s.entries[i].Time.Equal(olderThan) {
				end = i
				break
			}
		}
		// A time after the last written entry makes AdGuard Home read from
		// the end of the file, skipping that last entry.
		if n := len(s.entries); end < 0 && n > 0 && olderThan.After(s.entries[n-1].Time) {
			end = n - 1
		}
	}
	var matched []Entry
	for i := end - 1; i >= 0 && limit > 0 && len(matched) < offset+limit; i-- {
		e := s.entries[i]
		if !olderThan.IsZero() && !e.Time.Before(olderThan) {
			continue
		}
		matched = append(matched, e)
	}
	s.mu.Unlock()

	// Newest first, reverse write order kept for equal timestamps.
	slices.SortStableFunc(matched, func(a, b Entry) int { return -a.Time.Compare(b.Time) })

	if offset > len(matched) {
		offset = len(matched)
	}
	matched = matched[offset:]

	data := make([]map[string]any, 0, len(matched))
	for _, e := range matched {
		data = append(data, e.json())
	}
	oldest := ""
	if len(matched) > 0 {
		oldest = matched[len(matched)-1].Time.Format(time.RFC3339Nano)
	}

	writeJSON(w, map[string]any{"data": data, "oldest": oldest})
}

func (e Entry) json() map[string]any {
	m := map[string]any{
		"answer":    []any{},
		"cached":    false,
		"client":    e.Client,
		"elapsedMs": e.Elapsed,
		"question": map[string]any{
			"class": "IN",
			"name":  e.Name,
			"type":  e.Type,
		},
		"reason":   e.Reason,
		"status":   "NOERROR",
		"time":     e.Time.Format(time.RFC3339Nano),
		"upstream": e.Upstream,
	}
	info := map[string]any{"name": "", "disallowed_rule": "", "disallowed": false}
	if e.WhoisCountry != "" || e.WhoisOrg != "" {
		info["whois"] = map[string]any{"country": e.WhoisCountry, "orgname": e.WhoisOrg}
	}
	m["client_info"] = info

	return m
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(fmt.Sprintf("adguardtest: encoding response: %v", err))
	}
}
