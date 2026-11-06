package geo

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/oschwald/geoip2-golang/v2"
)

type fakeDB struct {
	calls int
	err   error
	// last is the address of the latest lookup.
	last netip.Addr
	// noCoordinates makes the record lack a location, as records in real
	// databases can.
	noCoordinates bool
}

func (f *fakeDB) City(ip netip.Addr) (*geoip2.City, error) {
	f.calls++
	f.last = ip
	if f.err != nil {
		return nil, f.err
	}
	if f.noCoordinates {
		var c geoip2.City
		c.Country.ISOCode = "DE"
		return &c, nil
	}
	var c geoip2.City
	c.Country.ISOCode = "DE"
	lat, lon := 52.52, 13.405
	c.Location.Latitude = &lat
	c.Location.Longitude = &lon
	return &c, nil
}

func TestLookup(t *testing.T) {
	db := &fakeDB{}
	r := New(db)

	loc, ok := r.Lookup("203.0.113.7")
	if !ok || loc != (Location{Country: "DE", Lat: 52.52, Lon: 13.405}) {
		t.Errorf("Lookup = %+v, %v", loc, ok)
	}

	for _, ip := range []string{"192.168.1.10", "10.0.0.1", "fd00::1", "127.0.0.1", "::1", "not-an-ip", ""} {
		if _, ok := r.Lookup(ip); ok {
			t.Errorf("Lookup(%q) resolved, want skipped", ip)
		}
	}
	if db.calls != 1 {
		t.Errorf("database queried %d times, want 1", db.calls)
	}
}

// The database gets plain IPv4 addresses, also for IPv4-mapped input. Which
// addresses are skipped stays as net.ParseIP and net.IP decide it.
func TestLookupAddressForms(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"2001:db8::1", "2001:db8::1"},
		{"::ffff:10.0.0.1", ""},
		{"::ffff:127.0.0.1", ""},
		{"2001:db8::1%eth0", ""},
	}
	for _, tt := range tests {
		db := &fakeDB{}
		_, ok := New(db).Lookup(tt.ip)
		if tt.want == "" {
			if ok || db.calls != 0 {
				t.Errorf("Lookup(%q) = %v with %d queries, want skipped", tt.ip, ok, db.calls)
			}
			continue
		}
		if !ok || db.last != netip.MustParseAddr(tt.want) {
			t.Errorf("Lookup(%q) = %v, queried %v, want %s", tt.ip, ok, db.last, tt.want)
		}
	}
}

// A record without coordinates resolves with 0, 0, which keeps the geo
// metrics' lat and lon labels as they are for such records.
func TestLookupWithoutCoordinates(t *testing.T) {
	loc, ok := New(&fakeDB{noCoordinates: true}).Lookup("203.0.113.7")
	if !ok || loc != (Location{Country: "DE"}) {
		t.Errorf("Lookup = %+v, %v, want country only", loc, ok)
	}
}

func TestLookupWithoutDB(t *testing.T) {
	r := New(nil)
	if _, ok := r.Lookup("203.0.113.7"); ok {
		t.Error("resolved without a database")
	}
	if r.CacheSize() != 0 {
		t.Errorf("CacheSize = %d, want 0", r.CacheSize())
	}
}

func TestOpenMissing(t *testing.T) {
	r, err := Open("/nonexistent/GeoLite2-City.mmdb")
	if err == nil {
		t.Fatal("no error for a missing database")
	}
	if _, ok := r.Lookup("203.0.113.7"); ok {
		t.Error("resolver from a failed Open resolves")
	}
}

func TestLookupError(t *testing.T) {
	r := New(&fakeDB{err: errors.New("corrupt")})
	if _, ok := r.Lookup("203.0.113.7"); ok {
		t.Error("resolved although the database failed")
	}
	if r.CacheSize() != 0 {
		t.Errorf("failed lookup cached")
	}
}

func TestCacheTTL(t *testing.T) {
	db := &fakeDB{}
	r := New(db)
	now := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return now }

	r.Lookup("203.0.113.7")
	now = now.Add(TTL - time.Second)
	r.Lookup("203.0.113.7")
	if db.calls != 1 {
		t.Errorf("database queried %d times within the TTL, want 1", db.calls)
	}

	now = now.Add(time.Second)
	r.Lookup("203.0.113.7")
	if db.calls != 2 {
		t.Errorf("database queried %d times after the TTL, want 2", db.calls)
	}
	if r.CacheSize() != 1 {
		t.Errorf("CacheSize = %d, want 1", r.CacheSize())
	}
}
