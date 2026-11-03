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
	// gapReset: every entry counted in the window is missing from the
	// response, e.g. because the query log was cleared, AdGuard Home's clock
	// stepped back or client IP anonymisation was switched on or off.
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
}

func newQueryLogCursor(overlap time.Duration, maxEntries int) *queryLogCursor {
	return &queryLogCursor{
		overlap:    overlap,
		maxEntries: maxEntries,
		limit:      min(adguardDefaultLimit, maxEntries),
		window:     map[string]int{},
	}
}

// complete reports whether entries, the response to limit, contains every
// entry of the counting window.
func (c *queryLogCursor) complete(entries []adguard.QueryLogEntry, limit int) bool {
	if len(entries) < limit {
		return true
	}
	ref := c.newest
	if !c.started {
		ref = latest(entries)
	}
	bound := ref.Add(-2 * c.overlap)
	for i := range entries {
		if entries[i].Time.Before(bound) {
			return true
		}
	}
	return false
}

// advance takes the final response of a loop, which was complete or reached
// maxEntries, and returns the entries to count, the gap reason, if any, and
// how many counted entries of the window have vanished.
func (c *queryLogCursor) advance(entries []adguard.QueryLogEntry, complete bool) (fresh []*adguard.QueryLogEntry, gap string, vanished int) {
	if !c.started {
		// The first response only sets the start; entries written before the
		// exporter started are not counted.
		c.started = true
		c.reset(entries, latest(entries))
		return nil, "", 0
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

	windowSize := 0
	for id, n := range c.window {
		windowSize += n
		if m := inResponse[id]; m < n {
			vanished += n - m
		}
	}
	if windowSize > 0 && vanished == windowSize {
		gap = gapReset
		// Resynchronise on the entries not seen before: after AdGuard Home's
		// clock stepped back, the old newest would keep the window in the
		// future. The fresh entries are still counted (best effort). The
		// caller reads the log again to fill the new window.
		newest = c.newest
		if t, ok := latestUnseen(entries, c.window); ok {
			newest = t
		}
	}
	if !complete && !overlaps(entries, c.window) {
		// A response that contains an entry of the window is a suffix of
		// the write order reaching back before the previous loop, so nothing
		// was skipped even if completeness could not be shown by time (the
		// window holds more than maxEntries entries).
		gap = gapLimit
	}

	c.reset(entries, newest)
	return fresh, gap, vanished
}

// restart makes the next loop start over without counting, for when the
// counting window cannot be trusted.
func (c *queryLogCursor) restart() {
	c.started = false
	c.window = map[string]int{}
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
