// Package geo resolves client IPs to a country and coordinates with a
// GeoLite2 City database and caches the results.
package geo

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang/v2"
)

// TTL is how long a lookup stays cached.
const TTL = 24 * time.Hour

// Location is the result of a lookup.
type Location struct {
	Country string
	Lat     float64
	Lon     float64
}

// CityDB is the lookup a GeoLite2 City database provides.
type CityDB interface {
	City(ip netip.Addr) (*geoip2.City, error)
}

type cached struct {
	loc Location
	ts  int64
}

// Resolver looks up and caches locations. A Resolver without a database
// resolves nothing.
type Resolver struct {
	db  CityDB
	now func() time.Time

	mu    sync.RWMutex
	cache map[string]cached
}

// Open opens the database at path. On error it also returns a Resolver that
// resolves nothing.
func Open(path string) (*Resolver, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return New(nil), err
	}
	return New(db), nil
}

// New returns a Resolver for db, which may be nil.
func New(db CityDB) *Resolver {
	return &Resolver{db: db, now: time.Now, cache: map[string]cached{}}
}

// Lookup resolves a public IP. Private, loopback and unparsable addresses are
// not resolved.
func (r *Resolver) Lookup(ipStr string) (Location, bool) {
	if r.db == nil {
		return Location{}, false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() {
		return Location{}, false
	}

	now := r.now().Unix()

	r.mu.RLock()
	if val, ok := r.cache[ipStr]; ok && now-val.ts < int64(TTL/time.Second) {
		r.mu.RUnlock()
		return val.loc, true
	}
	r.mu.RUnlock()

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Location{}, false
	}
	record, err := r.db.City(addr.Unmap())
	if err != nil {
		return Location{}, false
	}

	loc := Location{
		Country: record.Country.ISOCode,
	}
	if record.Location.HasCoordinates() {
		loc.Lat = *record.Location.Latitude
		loc.Lon = *record.Location.Longitude
	}

	r.mu.Lock()
	r.cache[ipStr] = cached{loc: loc, ts: now}
	r.mu.Unlock()

	return loc, true
}

// CacheSize returns the number of cached lookups.
func (r *Resolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}
