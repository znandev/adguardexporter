package geo

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/oschwald/geoip2-golang"
)

type fakeDB struct {
	calls int
	err   error
}

func (f *fakeDB) City(ip net.IP) (*geoip2.City, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var c geoip2.City
	c.Country.IsoCode = "DE"
	c.Location.Latitude = 52.52
	c.Location.Longitude = 13.405
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
