package collector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/znand-dev/adguardexporter/internal/adguard"
)

func counted(c *Collector) float64 {
	return testutil.ToFloat64(c.m.queryCountByReason.WithLabelValues("NotFilteredNotFound"))
}

func gaps(c *Collector, reason string) float64 {
	return testutil.ToFloat64(c.m.exporterQueryLogGaps.WithLabelValues(reason))
}

// series returns n distinct entries from t0+from, step apart, oldest first.
func series(n int, from, step time.Duration) []adguard.QueryLogEntry {
	out := make([]adguard.QueryLogEntry, 0, n)
	for i := range n {
		out = append(out, simple(from+time.Duration(i)*step))
	}
	return out
}

func run(c *Collector) { c.RunOnce(context.Background()) }

func TestCursorStartDoesNotCount(t *testing.T) {
	api := emptyAPI()
	api.write(series(3, 0, time.Millisecond)...)
	c := newCollector(t, api, testOpts)
	run(c)
	if got := counted(c); got != 0 {
		t.Errorf("counted %v entries written before the start, want 0", got)
	}

	api.write(series(2, time.Second, time.Millisecond)...)
	run(c)
	if got := counted(c); got != 2 {
		t.Errorf("counted %v, want 2", got)
	}
}

// The limit doubles until the response covers the counting window, and
// shrinks again when much less is needed.
func TestCursorLimit(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)

	api.write(series(1200, 0, time.Millisecond)...)
	run(c)
	if got := counted(c); got != 1200 {
		t.Errorf("counted %v, want 1200", got)
	}
	if want := []int{500, 500, 1000, 2000}; !slices.Equal(api.limits, want) {
		t.Errorf("limits %v, want %v", api.limits, want)
	}

	api.write(simple(3 * time.Minute))
	for range 3 {
		run(c)
	}
	if want := []int{500, 500, 1000, 2000, 2000, 1000, 500}; !slices.Equal(api.limits, want) {
		t.Errorf("limits %v, want %v", api.limits, want)
	}
	if got := counted(c); got != 1201 {
		t.Errorf("counted %v, want 1201", got)
	}
	if gaps(c, gapLimit)+gaps(c, gapReset) != 0 {
		t.Error("unexpected gap")
	}
}

func TestCursorComplete(t *testing.T) {
	c := newQueryLogCursor(time.Second, 100)
	c.started = true
	c.newest = t0
	resp := func(oldest time.Duration) []adguard.QueryLogEntry {
		return []adguard.QueryLogEntry{simple(0), simple(oldest)}
	}
	if c.complete(resp(-2*time.Second), 2) {
		t.Error("an entry exactly at newest-2W is not older than it")
	}
	if !c.complete(resp(-2*time.Second-time.Nanosecond), 2) {
		t.Error("an entry before newest-2W completes the response")
	}
	if !c.complete(resp(0), 3) {
		t.Error("a response shorter than the limit is the whole log")
	}
}

// An entry is counted if it starts at or after newest-W, however late it is
// written.
func TestCursorWindowEdge(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, QueryLogOptions{Overlap: time.Second, MaxEntries: 1000})
	run(c)
	api.write(simple(0))
	run(c)

	api.write(simple(-time.Second), simple(-time.Second-time.Nanosecond))
	run(c)
	if got := counted(c); got != 2 {
		t.Errorf("counted %v, want 2 (the entry before newest-W is not counted)", got)
	}
}

// Entries that are identical in every field share an ID and are counted
// as often as they appear, also when the copies are written in different
// loops.
func TestCursorIdenticalEntries(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)

	e := simple(0)
	api.write(e, e)
	run(c)
	if got := counted(c); got != 2 {
		t.Errorf("counted %v, want 2", got)
	}
	api.write(e)
	run(c)
	run(c)
	if got := counted(c); got != 3 {
		t.Errorf("counted %v, want 3", got)
	}
}

// Groups of entries with one timestamp, around the first limit of 500.
func TestCursorSameTimestampAtCut(t *testing.T) {
	for _, sizes := range [][]int{{498, 5}, {499, 1, 1}, {500, 500}, {3, 700, 2}} {
		t.Run(fmt.Sprint(sizes), func(t *testing.T) {
			api := emptyAPI()
			c := newCollector(t, api, testOpts)
			run(c)

			want := 0
			for g, size := range sizes {
				for i := range size {
					e := simple(time.Duration(g) * time.Millisecond)
					e.Question.Name = fmt.Sprintf("g%d-%d.example", g, i)
					e.ID += e.Question.Name
					api.write(e)
				}
				want += size
			}
			run(c)
			run(c)
			if got := counted(c); got != float64(want) {
				t.Errorf("counted %v, want %d", got, want)
			}
		})
	}
}

// More new entries than MaxEntries: the newest are counted and the loop
// reports a gap; the next loop continues normally.
func TestCursorLimitGap(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, QueryLogOptions{Overlap: 10 * time.Millisecond, MaxEntries: 1000})
	run(c)

	api.write(series(1500, 0, time.Millisecond)...)
	run(c)
	if got := counted(c); got != 1000 {
		t.Errorf("counted %v, want the newest 1000", got)
	}
	if got := gaps(c, gapLimit); got != 1 {
		t.Errorf("limit gaps = %v, want 1", got)
	}

	api.write(series(3, 2*time.Second, time.Millisecond)...)
	run(c)
	if got := counted(c); got != 1003 {
		t.Errorf("counted %v, want 1003", got)
	}
	if got := gaps(c, gapLimit); got != 1 {
		t.Errorf("limit gaps = %v after catching up, want 1", got)
	}
}

func TestCursorCleared(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)
	api.write(series(5, 0, time.Millisecond)...)
	run(c)

	api.written = nil
	run(c)
	if got := gaps(c, gapReset); got != 1 {
		t.Errorf("reset gaps = %v, want 1", got)
	}

	api.write(series(2, time.Second, time.Millisecond)...)
	run(c)
	if got := counted(c); got != 7 {
		t.Errorf("counted %v, want 7", got)
	}
	if got := gaps(c, gapReset); got != 1 {
		t.Errorf("reset gaps = %v, want 1", got)
	}
}

// Entries written after a clear but before the next loop are counted
// anyway (best effort), together with the reset gap.
func TestCursorClearedAndRefilled(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)
	api.write(series(5, 0, time.Millisecond)...)
	run(c)

	api.written = nil
	api.write(series(2, time.Second, time.Millisecond)...)
	run(c)
	if got := counted(c); got != 7 {
		t.Errorf("counted %v, want 7", got)
	}
	if got := gaps(c, gapReset); got != 1 {
		t.Errorf("reset gaps = %v, want 1", got)
	}
}

// AdGuard Home's clock steps back by an hour. Once the entries from before
// the step have left the newest entries, the cursor resynchronises and
// counts again.
func TestCursorClockStepBack(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, QueryLogOptions{Overlap: time.Second, MaxEntries: 1000})
	run(c)
	api.write(series(3, 0, time.Millisecond)...)
	run(c)

	api.write(series(600, -time.Hour, time.Millisecond)...)
	run(c)
	if got := gaps(c, gapReset); got != 1 {
		t.Errorf("reset gaps = %v, want 1", got)
	}

	before := counted(c)
	api.write(series(4, -time.Hour+time.Second, time.Millisecond)...)
	run(c)
	if got := counted(c) - before; got != 4 {
		t.Errorf("counted %v after resynchronising, want 4", got)
	}
}

// A failed request leaves the cursor unchanged, so the next loop counts the
// entries.
func TestCursorFailureWhileGrowing(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)

	api.write(series(700, 0, time.Millisecond)...)
	api.onQueryLog = func(n int) {
		if n == 3 {
			api.logErr = errors.New("down")
		}
	}
	run(c)
	if got := testutil.ToFloat64(c.m.exporterUp); got != 0 {
		t.Errorf("up = %v, want 0", got)
	}
	if got := counted(c); got != 0 {
		t.Errorf("counted %v in the failed loop, want 0", got)
	}

	api.onQueryLog, api.logErr = nil, nil
	run(c)
	if got := counted(c); got != 700 {
		t.Errorf("counted %v, want 700", got)
	}
}

// Entries written between two requests of one loop are in the last
// response and counted.
func TestCursorEntriesWhileGrowing(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)

	api.write(series(700, 0, time.Millisecond)...)
	api.onQueryLog = func(n int) {
		if n == 3 {
			api.write(series(4, time.Second, time.Millisecond)...)
		}
	}
	run(c)
	api.onQueryLog = nil
	run(c)
	if got := counted(c); got != 704 {
		t.Errorf("counted %v, want 704", got)
	}
}

// The deprecated metrics stay at 0.
func TestDeprecatedMetrics(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)
	api.write(simple(0), simple(0))
	run(c)
	if testutil.ToFloat64(c.m.exporterDedupHits) != 0 || testutil.ToFloat64(c.m.exporterQueryCacheSize) != 0 {
		t.Error("deprecated metrics are not 0")
	}
}

// If the request that refills the window after a reset fails, the next
// loop starts over instead of trusting a window that may be incomplete.
func TestCursorResyncFailure(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)
	api.write(series(5, 0, time.Millisecond)...)
	run(c)

	api.written = nil
	api.write(series(2, time.Second, time.Millisecond)...)
	base := len(api.limits)
	api.onQueryLog = func(n int) {
		if n == base+2 {
			api.logErr = errors.New("down")
		}
	}
	run(c)
	if got := testutil.ToFloat64(c.m.exporterUp); got != 0 {
		t.Errorf("up = %v, want 0", got)
	}
	if got := counted(c); got != 7 {
		t.Errorf("counted %v, want 7 (the fresh entries are still counted)", got)
	}

	api.onQueryLog, api.logErr = nil, nil
	api.write(simple(2 * time.Second))
	run(c)
	if got := counted(c); got != 7 {
		t.Errorf("counted %v in the restart loop, want 7", got)
	}
	api.write(simple(3 * time.Second))
	run(c)
	if got := counted(c); got != 8 {
		t.Errorf("counted %v, want 8", got)
	}
}

// AdGuard Home's memory buffer can overwrite entries under load before they
// reach the file. Entries that vanish while others of the window remain are
// not a gap, and counting goes on normally.
func TestCursorSingleEntriesVanish(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, testOpts)
	run(c)
	api.write(series(10, 0, time.Millisecond)...)
	run(c)

	api.written = slices.Delete(api.written, 2, 4)
	api.write(series(3, time.Second, time.Millisecond)...)
	run(c)
	if got := counted(c); got != 13 {
		t.Errorf("counted %v, want 13", got)
	}
	if gaps(c, gapLimit)+gaps(c, gapReset) != 0 {
		t.Error("vanished single entries reported as a gap")
	}
}

// After a limit gap the window can hold more entries than MaxEntries, so
// completeness cannot be shown by time. A response that still shares entries
// with the window has skipped nothing and is not another gap.
func TestCursorDenseWindowAfterLimitGap(t *testing.T) {
	api := emptyAPI()
	c := newCollector(t, api, QueryLogOptions{Overlap: time.Minute, MaxEntries: 1000})
	run(c)

	api.write(series(1500, 0, time.Millisecond)...)
	run(c)
	api.write(series(3, 2*time.Second, time.Millisecond)...)
	run(c)
	run(c)
	if got := counted(c); got != 1003 {
		t.Errorf("counted %v, want 1003", got)
	}
	if got := gaps(c, gapLimit); got != 1 {
		t.Errorf("limit gaps = %v, want 1", got)
	}
}
