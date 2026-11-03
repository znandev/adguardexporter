package main_test

// Query log counting: every entry is counted exactly once, across limit
// cuts, identical timestamps, restarts and API failures. The cursor's edge
// cases are covered in more detail by the unit tests in internal/collector.

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/znand-dev/adguardexporter/internal/adguardtest"
)

// entries returns n distinct entries, the newest at newest, one millisecond
// apart, in write order (oldest first).
func entries(n int, newest time.Time, prefix string) []adguardtest.Entry {
	out := make([]adguardtest.Entry, 0, n)
	for i := n - 1; i >= 0; i-- {
		out = append(out, adguardtest.Entry{
			Time:     newest.Add(-time.Duration(i) * time.Millisecond),
			Client:   "192.168.1.10",
			Name:     fmt.Sprintf("%s%d.example", prefix, i),
			Type:     "A",
			Reason:   "NotFilteredNotFound",
			Elapsed:  "1.5",
			Upstream: quad9,
		})
	}
	return out
}

// grouped returns entries in groups that share one timestamp per group, in
// write order (oldest group first).
func grouped(sizes []int, newest time.Time) []adguardtest.Entry {
	var out []adguardtest.Entry
	for g := len(sizes) - 1; g >= 0; g-- {
		size := sizes[g]
		ts := newest.Add(-time.Duration(g) * time.Millisecond)
		for i := range size {
			out = append(out, adguardtest.Entry{
				Time:   ts,
				Client: "192.168.1.10",
				Name:   fmt.Sprintf("g%d-%d.example", g, i),
				Type:   "A",
				Reason: "NotFilteredNotFound",
			})
		}
	}
	return out
}

// gaps sums adguard_exporter_querylog_gaps_total, for one reason if given.
func gaps(t *testing.T, body string, reason ...string) float64 {
	t.Helper()
	var match map[string]string
	if len(reason) > 0 {
		match = map[string]string{"reason": reason[0]}
	}
	return sum(t, body, "adguard_exporter_querylog_gaps_total", match)
}

// limits returns the limit of every query log request after the first n.
func limits(fake *adguardtest.Server, n int) []string {
	var out []string
	for _, r := range fake.Requests() {
		if r.Path != adguardtest.PathQueryLog {
			continue
		}
		if n > 0 {
			n--
			continue
		}
		out = append(out, strings.Join(r.Query["limit"], ","))
	}
	return out
}

// The limit doubles from AdGuard Home's default of 500 until the response
// covers everything since the previous loop.
func TestQueryLogMoreThanDefaultLimit(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	fake.AddEntries(entries(1200, time.Now(), "q")...)
	base := fake.Count(adguardtest.PathQueryLog)
	e.loop()
	if got, want := limits(fake, base), []string{"500", "1000", "2000"}; !slices.Equal(got, want) {
		t.Errorf("limits %v, want %v", got, want)
	}

	body := e.scrape()
	if got := counted(t, body); got != 1200 {
		t.Errorf("counted %v entries, want 1200", got)
	}
	if got := gaps(t, body); got != 0 {
		t.Errorf("gaps = %v, want 0", got)
	}
}

// Groups of entries that share a timestamp, cut by the first limit of 500.
func TestQueryLogSameTimestampAtCut(t *testing.T) {
	tests := []struct {
		name  string
		sizes []int
	}{
		{"group straddles the cut", []int{498, 5}},
		{"group ends at the cut", []int{500, 500}},
		{"group larger than the limit", []int{3, 700, 2}},
		{"many small groups", []int{1, 2, 4, 5, 3, 1, 5, 2, 490, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFake(t)
			e := start(t, fake, options{})
			e.loop()

			want := 0
			for _, s := range tt.sizes {
				want += s
			}
			fake.AddEntries(grouped(tt.sizes, time.Now())...)
			e.loop()
			e.loop()

			body := e.scrape()
			if got := counted(t, body); got != float64(want) {
				t.Errorf("counted %v entries, want %d", got, want)
			}
			if got := gaps(t, body); got != 0 {
				t.Errorf("gaps = %v, want 0", got)
			}
		})
	}
}

// More new entries than QUERYLOG_MAX_ENTRIES: the newest are counted, the
// rest is reported as a gap, and the next loop continues with new entries.
func TestQueryLogLimitGap(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{env: map[string]string{
		"QUERYLOG_MAX_ENTRIES": "1000",
		"QUERYLOG_OVERLAP":     "10ms",
	}})
	e.loop()

	fake.AddEntries(entries(1500, time.Now(), "backlog")...)
	e.loop()
	body := e.scrape()
	if got := counted(t, body); got != 1000 {
		t.Errorf("counted %v of 1500 entries, want the newest 1000", got)
	}
	if got := gaps(t, body, "limit"); got != 1 {
		t.Errorf("limit gaps = %v, want 1", got)
	}

	time.Sleep(5 * time.Millisecond)
	fake.AddEntries(entries(3, time.Now(), "new")...)
	e.loop()
	body = e.scrape()
	if got := counted(t, body); got != 1003 {
		t.Errorf("counted %v entries, want 1003", got)
	}
	if got := gaps(t, body); got != 1 {
		t.Errorf("gaps = %v after catching up, want 1", got)
	}
}

// Entries that were in the log before the exporter started are not counted.
func TestQueryLogRestartDoesNotReplay(t *testing.T) {
	fake := newFake(t)
	fake.AddEntries(entries(50, time.Now().Add(-time.Hour), "old")...)
	e := start(t, fake, options{})
	e.loop()

	if got := counted(t, e.scrape()); got != 0 {
		t.Errorf("counted %v existing entries on start, want 0", got)
	}

	fake.AddEntries(entries(3, time.Now(), "new")...)
	e.loop()
	if got := counted(t, e.scrape()); got != 3 {
		t.Errorf("counted %v new entries, want 3", got)
	}
}

// The start position comes from the query log, not from the exporter's
// clock, so an AdGuard Home clock that is behind loses nothing.
func TestQueryLogClockBehind(t *testing.T) {
	behind := time.Now().Add(-time.Hour)
	fake := newFake(t)
	fake.AddEntries(entries(5, behind.Add(-time.Minute), "old")...)
	e := start(t, fake, options{})
	e.loop()

	fake.AddEntries(entries(3, behind, "new")...)
	e.loop()
	if got := counted(t, e.scrape()); got != 3 {
		t.Errorf("counted %v entries, want 3", got)
	}
}

func TestQueryLogStartsEmpty(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()
	e.loop()

	fake.AddEntries(entries(4, time.Now(), "q")...)
	e.loop()
	if got := counted(t, e.scrape()); got != 4 {
		t.Errorf("counted %v entries, want 4", got)
	}
}

// Genuine repeated queries with the same client, domain, upstream, reason and
// elapsed time are separate queries.
func TestQueryLogIdenticalQueries(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	q := entries(1, time.Now(), "same")[0]
	for i := range 3 {
		r := q
		r.Time = q.Time.Add(-time.Duration(i) * time.Second)
		fake.AddEntries(r)
	}
	// Two entries that are identical in every field, timestamp included.
	fake.AddEntries(q)
	e.loop()

	if got := counted(t, e.scrape()); got != 4 {
		t.Errorf("counted %v entries, want 4", got)
	}
}

// A slow query is written after newer ones, with its start time. It is
// counted although the exporter has already counted newer entries.
func TestQueryLogLateWrittenEntry(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	now := time.Now()
	fake.AddEntries(entries(5, now, "fast")...)
	e.loop()
	slow := entries(1, now.Add(-2*time.Second), "slow")
	fake.AddEntries(slow...)
	e.loop()

	if got := counted(t, e.scrape()); got != 6 {
		t.Errorf("counted %v entries, want 6", got)
	}
}

// An entry written later than QUERYLOG_OVERLAP after its start is not
// counted; this is the documented limit of the overlap window.
func TestQueryLogWrittenAfterOverlap(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{env: map[string]string{"QUERYLOG_OVERLAP": "1s"}})
	e.loop()

	now := time.Now()
	fake.AddEntries(entries(1, now, "fast")...)
	e.loop()
	fake.AddEntries(entries(1, now.Add(-3*time.Second), "slow")...)
	e.loop()

	if got := counted(t, e.scrape()); got != 1 {
		t.Errorf("counted %v entries, want 1", got)
	}
}

// Entries written between two requests of one loop are counted.
func TestQueryLogNewEntriesWhileGrowing(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	fake.AddEntries(entries(700, time.Now(), "q")...)
	base := fake.Count(adguardtest.PathQueryLog)
	fake.OnQueryLog(func(n int) {
		if n == base+2 {
			fake.AddEntries(entries(4, time.Now().Add(time.Second), "late")...)
		}
	})
	e.loop()
	e.loop()

	body := e.scrape()
	if got := counted(t, body); got != 704 {
		t.Errorf("counted %v entries, want 704", got)
	}
	if got := gaps(t, body); got != 0 {
		t.Errorf("gaps = %v, want 0", got)
	}
}

// A request that fails while the limit grows does not lose or double count
// entries.
func TestQueryLogFailureWhileGrowing(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	fake.AddEntries(entries(700, time.Now(), "q")...)
	base := fake.Count(adguardtest.PathQueryLog)
	// The hook runs after the failure check, so this fails the second
	// request of the loop.
	fake.OnQueryLog(func(n int) {
		if n == base+1 {
			fake.Fail(adguardtest.PathQueryLog, 1)
		}
	})
	e.loop()
	body := e.scrape()
	if got := sum(t, body, "adguard_exporter_up", nil); got != 0 {
		t.Errorf("up = %v after a failed request, want 0", got)
	}
	if got := sum(t, body, "adguard_exporter_scrape_errors_total", nil); got < 1 {
		t.Errorf("scrape_errors_total = %v, want at least 1", got)
	}

	fake.OnQueryLog(nil)
	e.loop()
	e.loop()
	if got := counted(t, e.scrape()); got != 700 {
		t.Errorf("counted %v entries, want 700", got)
	}
}

// Clearing the query log does not stop counting; it is reported as a reset
// gap.
func TestQueryLogCleared(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()

	fake.AddEntries(entries(5, time.Now(), "a")...)
	e.loop()
	fake.ClearEntries()
	e.loop()
	time.Sleep(5 * time.Millisecond)
	fake.AddEntries(entries(2, time.Now(), "b")...)
	e.loop()

	body := e.scrape()
	if got := counted(t, body); got != 7 {
		t.Errorf("counted %v entries, want 7", got)
	}
	if got := gaps(t, body, "reset"); got != 1 {
		t.Errorf("reset gaps = %v, want 1", got)
	}
}

// The deduplication metrics stay for one release, are always 0 and say
// that they are deprecated. Both gap reasons are present from the start.
func TestDeprecatedDedupMetrics(t *testing.T) {
	fake := newFake(t)
	e := start(t, fake, options{})
	e.loop()
	fake.AddEntries(baseEntries()...)
	e.loop()
	e.loop()

	body := e.scrape()
	for _, name := range []string{"adguard_exporter_dedup_hits_total", "adguard_exporter_query_cache_size"} {
		if !has(t, body, name) {
			t.Errorf("%s is missing", name)
		}
		if got := sum(t, body, name, nil); got != 0 {
			t.Errorf("%s = %v, want 0", name, got)
		}
		if !strings.Contains(body, "# HELP "+name+" Deprecated:") {
			t.Errorf("%s help does not say it is deprecated", name)
		}
	}
	for _, reason := range []string{"limit", "reset"} {
		if !strings.Contains(body, `adguard_exporter_querylog_gaps_total{reason="`+reason+`"} 0`) {
			t.Errorf("querylog_gaps_total{reason=%q} is missing", reason)
		}
	}
}
