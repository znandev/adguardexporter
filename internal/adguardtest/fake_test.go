package adguardtest

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type page struct {
	Data []struct {
		Time string `json:"time"`
	} `json:"data"`
	Oldest string `json:"oldest"`
}

func get(t *testing.T, s *Server, path string, q url.Values) (int, page) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.URL+path+"?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(s.User, s.Pass())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var p page
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, p
}

func times(p page) []string {
	out := make([]string, 0, len(p.Data))
	for _, d := range p.Data {
		out = append(out, d.Time)
	}
	return out
}

func TestQueryLogPaging(t *testing.T) {
	s := New(t)
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ts := func(i int) time.Time { return base.Add(time.Duration(i) * time.Millisecond) }
	// Written out of time order, with two entries sharing ts(2).
	s.AddEntries(
		Entry{Time: ts(1), Name: "a"},
		Entry{Time: ts(3), Name: "b"},
		Entry{Time: ts(2), Name: "c"},
		Entry{Time: ts(2), Name: "d"},
	)
	f := func(i int) string { return ts(i).Format(time.RFC3339Nano) }

	_, p := get(t, s, PathQueryLog, nil)
	if got, want := times(p), []string{f(3), f(2), f(2), f(1)}; !equal(got, want) {
		t.Errorf("all entries = %v, want %v", got, want)
	}
	if p.Oldest != f(1) {
		t.Errorf("oldest = %q, want %q", p.Oldest, f(1))
	}

	// limit takes the most recently written entries, not the newest ones.
	_, p = get(t, s, PathQueryLog, url.Values{"limit": {"2"}})
	if got, want := times(p), []string{f(2), f(2)}; !equal(got, want) {
		t.Errorf("limit 2 = %v, want %v", got, want)
	}
	if p.Oldest != f(2) {
		t.Errorf("oldest = %q, want %q", p.Oldest, f(2))
	}

	// older_than is exclusive: the second entry at ts(2) is skipped.
	_, p = get(t, s, PathQueryLog, url.Values{"limit": {"2"}, "older_than": {p.Oldest}})
	if got, want := times(p), []string{f(1)}; !equal(got, want) {
		t.Errorf("older_than ts(2) = %v, want %v", got, want)
	}

	_, p = get(t, s, PathQueryLog, url.Values{"older_than": {f(1)}})
	if len(p.Data) != 0 || p.Oldest != "" {
		t.Errorf("past the end = %v oldest %q, want empty", times(p), p.Oldest)
	}

	// older_than that is not the time of an entry finds nothing.
	_, p = get(t, s, PathQueryLog, url.Values{"older_than": {ts(1).Add(time.Nanosecond).Format(time.RFC3339Nano)}})
	if len(p.Data) != 0 {
		t.Errorf("older_than between entries = %v, want empty", times(p))
	}

	// older_than after the last written entry skips that entry.
	_, p = get(t, s, PathQueryLog, url.Values{"older_than": {ts(4).Format(time.RFC3339Nano)}})
	if got, want := times(p), []string{f(3), f(2), f(1)}; !equal(got, want) {
		t.Errorf("older_than after the last written entry = %v, want %v", got, want)
	}

	if code, _ := get(t, s, PathQueryLog, url.Values{"older_than": {"yesterday"}}); code != http.StatusBadRequest {
		t.Errorf("bad older_than: status %d, want 400", code)
	}
}

func TestQueryLogDefaultLimit(t *testing.T) {
	s := New(t)
	base := time.Now()
	for i := range 2*DefaultQueryLogLimit + 1 {
		s.AddEntries(Entry{Time: base.Add(time.Duration(i) * time.Microsecond)})
	}
	if _, p := get(t, s, PathQueryLog, nil); len(p.Data) != DefaultQueryLogLimit {
		t.Errorf("got %d entries, want %d", len(p.Data), DefaultQueryLogLimit)
	}
	if _, p := get(t, s, PathQueryLog, url.Values{"limit": {"2000"}}); len(p.Data) != 2*DefaultQueryLogLimit+1 {
		t.Errorf("limit 2000: got %d entries", len(p.Data))
	}
	s.SetMaxPage(7)
	if _, p := get(t, s, PathQueryLog, url.Values{"limit": {"2000"}}); len(p.Data) != 7 {
		t.Errorf("max page 7: got %d entries", len(p.Data))
	}
}

func TestAuthAndFailures(t *testing.T) {
	s := New(t)
	s.SetPass("other")
	req, _ := http.NewRequest(http.MethodGet, s.URL+PathStats, nil)
	req.SetBasicAuth(s.User, "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: status %d, want 401", resp.StatusCode)
	}

	s.Fail(PathStats, 1)
	if code, _ := get(t, s, PathStats, nil); code != http.StatusInternalServerError {
		t.Errorf("first request after Fail: status %d, want 500", code)
	}
	if code, _ := get(t, s, PathStats, nil); code != http.StatusOK {
		t.Errorf("second request after Fail: status %d, want 200", code)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
