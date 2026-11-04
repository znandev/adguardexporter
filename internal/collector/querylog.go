package collector

import (
	"time"

	"github.com/znand-dev/adguardexporter/internal/adguard"
)

// Reading the query log
//
// AdGuard Home's /control/querylog returns the limit most recently written
// entries, sorted by time. An entry's time is when the query started, but it
// is written when the query finishes, so write order and time order differ.
// Paging with older_than or offset does not give contiguous parts of the
// write order: older_than has to be the exact time of an entry, and offset
// is applied after sorting. The cursor therefore always reads the newest
// entries and grows the limit until the response reaches far enough back.
//
// Let newest be the latest entry time seen so far and W the overlap window.
// Assuming every entry is written within W of its start, a response that
// contains an entry older than newest-2W contains every entry with a time of
// at least newest-W (the counting window): such an entry was written after
// the older one. Both the previous and the current response then cover the
// counting window completely, so comparing them by entry ID, as a multiset,
// finds exactly the new entries, also when timestamps collide.
//
// AdGuard Home keeps the newest entries in a ring buffer of size_memory
// entries and writes it to the file asynchronously once it is full. Under
// load, entries that arrive before the write overwrite the oldest ones, which
// are then lost from the query log. The cursor has counted them already, so
// single vanished entries are expected and not a gap; only when every
// counted entry of the window is gone has the log been reset.

// gap reasons for adguard_exporter_querylog_gaps_total.
const (
	// gapLimit: the response did not reach back to the counting window
	// within QUERYLOG_MAX_ENTRIES and shares no entry with it, so new entries
	// were skipped.
	gapLimit = "limit"
	// gapReset: a response that covers the counting window holds none of
	// its counted entries, e.g. because the query log was cleared, AdGuard
	// Home's clock stepped back or client IP anonymisation was switched on or
	// off.
	gapReset = "reset"
)

// queryLogCursor remembers which query log entries have been counted.
type queryLogCursor struct {
	overlap    time.Duration
	maxEntries int

	// limit is the first limit requested in the next loop.
	limit   int
	started bool
	// newest is the latest time of a counted entry.
	newest time.Time
	// window holds the IDs of the entries in the counting window, with the
	// number of entries per ID.
	window map[string]int
	// resetting is set during a loop once a response showed that the log
	// was reset.
	resetting bool
}

func newQueryLogCursor(overlap time.Duration, maxEntries int) *queryLogCursor {
	return &queryLogCursor{
		overlap:    overlap,
		maxEntries: maxEntries,
		limit:      min(adguardDefaultLimit, maxEntries),
		window:     map[string]int{},
	}
}

// begin starts a loop.
func (c *queryLogCursor) begin() { c.resetting = false }

// complete reports whether entries, the response to limit, contains every
// entry of the counting window. A response that does so for the current
// window but holds none of its entries shows that the log was reset; from
// then on in this loop, the response has to cover the window around the
// time advance resynchronises on.
func (c *queryLogCursor) complete(entries []adguard.QueryLogEntry, limit int) bool {
	if !c.started {
		return covers(entries, limit, latest(entries), c.overlap)
	}
	if !c.resetting {
		if !covers(entries, limit, c.newest, c.overlap) {
			return false
		}
		if len(c.window) == 0 || overlaps(entries, c.window) {
			return true
		}
		c.resetting = true
	}
	return covers(entries, limit, c.resyncTime(entries), c.overlap)
}

// covers reports whether a response to limit contains every entry from
// ref-overlap on: it is the whole log, or it reaches an entry older than
// ref-2*overlap, which was written before all of them.
func covers(entries []adguard.QueryLogEntry, limit int, ref time.Time, overlap time.Duration) bool {
	if len(entries) < limit {
		return true
	}
	bound := ref.Add(-2 * overlap)
	for i := range entries {
		if entries[i].Time.Before(bound) {
			return true
		}
	}
	return false
}

// resyncTime is the reference time after a reset: the latest entry not
// counted before, or the current one if there is none. After AdGuard Home's
// clock stepped back, the old reference would keep the window in the future.
func (c *queryLogCursor) resyncTime(entries []adguard.QueryLogEntry) time.Time {
	if t, ok := latestUnseen(entries, c.window); ok {
		return t
	}
	return c.newest
}

// advance takes the final response of a loop, which was complete or reached
// maxEntries, and returns the entries to count, the gap reasons, if any, and
// how many counted entries of the window have vanished. Counting and the new
// window both come from this one response, so no entry written between two
// requests of the loop can be skipped.
func (c *queryLogCursor) advance(entries []adguard.QueryLogEntry, complete bool) (fresh []*adguard.QueryLogEntry, gaps []string, vanished int) {
	if !c.started {
		// The first response only sets the start; entries written before the
		// exporter started are not counted.
		c.started = true
		c.reset(entries, latest(entries))
		return nil, nil, 0
	}

	cut := c.newest.Add(-c.overlap)
	inResponse := map[string]int{}
	newest := c.newest
	for i := range entries {
		e := &entries[i]
		if e.Time.Before(cut) {
			continue
		}
		inResponse[e.ID]++
		if inResponse[e.ID] > c.window[e.ID] {
			fresh = append(fresh, e)
			if e.Time.After(newest) {
				newest = e.Time
			}
		}
	}

	for id, n := range c.window {
		if m := inResponse[id]; m < n {
			vanished += n - m
		}
	}
	if c.resetting {
		// The fresh entries are still counted (best effort).
		gaps = append(gaps, gapReset)
		newest = c.resyncTime(entries)
		c.resetting = false
	}
	if !complete && !overlaps(entries, c.window) {
		// The response is the newest written entries, a suffix of the write
		// order. Every window entry was written before the previous loop's
		// request, so if one of them is in the response, so is every entry
		// written since; nothing new was skipped even though completeness
		// could not be shown by time (the window holds more than maxEntries
		// entries). Without such an entry, new entries may be missing.
		gaps = append(gaps, gapLimit)
	}

	c.reset(entries, newest)
	return fresh, gaps, vanished
}

// reset makes newest the reference time and the counting window the entries
// of the response at or after newest-overlap.
func (c *queryLogCursor) reset(entries []adguard.QueryLogEntry, newest time.Time) {
	c.newest = newest
	cut := newest.Add(-c.overlap)
	c.window = map[string]int{}
	for i := range entries {
		if !entries[i].Time.Before(cut) {
			c.window[entries[i].ID]++
		}
	}
}

// nextLimit sets the first limit of the next loop from the limit that was
// enough in this one, halving it when much less was needed.
func (c *queryLogCursor) nextLimit(entries []adguard.QueryLogEntry, used int) {
	bound := c.newest.Add(-2 * c.overlap)
	needed := 0
	for i := range entries {
		if !entries[i].Time.Before(bound) {
			needed++
		}
	}
	limit := used
	if needed < used/4 {
		limit = used / 2
	}
	c.limit = max(limit, min(adguardDefaultLimit, c.maxEntries))
}

func overlaps(entries []adguard.QueryLogEntry, window map[string]int) bool {
	for i := range entries {
		if window[entries[i].ID] > 0 {
			return true
		}
	}
	return false
}

func latest(entries []adguard.QueryLogEntry) time.Time {
	var t time.Time
	for i := range entries {
		if entries[i].Time.After(t) {
			t = entries[i].Time
		}
	}
	return t
}

func latestUnseen(entries []adguard.QueryLogEntry, seen map[string]int) (time.Time, bool) {
	var t time.Time
	found := false
	for i := range entries {
		if seen[entries[i].ID] == 0 && (!found || entries[i].Time.After(t)) {
			t = entries[i].Time
			found = true
		}
	}
	return t, found
}
