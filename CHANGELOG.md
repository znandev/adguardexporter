# Changelog

## Unreleased
### 🗑 Removed
- `adguard_exporter_dedup_hits_total` and `adguard_exporter_query_cache_size`, deprecated in v1.3.0, where they were always 0. Dashboards and alerts that query them need updating.

### 🔁 Changed
- Moved to `github.com/oschwald/geoip2-golang/v2`. Lookups, metric names and labels are unchanged; records without coordinates still report `lat` and `lon` as 0.

### 🛠 Fixed
- CI checks with `go mod tidy -diff` that `go.mod` and `go.sum` are tidy. Before, it ran `go mod tidy` first, so a `go.mod` that could not build passed.

## v1.3.0 - 2026-11-06
### ✨ Added
- `adguard_exporter_querylog_gaps_total{reason}`: scrapes in which query log entries may have been missed (`limit`: more new entries than `QUERYLOG_MAX_ENTRIES`; `reset`: every entry counted in the overlap window vanished, e.g. the query log was cleared)
- `QUERYLOG_OVERLAP` (default `1m`) and `QUERYLOG_MAX_ENTRIES` (default `20000`, at most `50000`) configure how the query log is read
- `DISABLE_METRICS` turns off single metrics, e.g. `DISABLE_METRICS=query_domain,query_isp`. Disabled metrics are neither exposed nor kept in memory; without both geo metrics, GeoIP lookups are skipped. An unknown name stops the exporter. By default every metric stays enabled.

### 🔁 Changed
- Every query log entry is counted exactly once. Before, the exporter read only AdGuard Home's newest 500 entries per scrape, skipped genuine repeated queries within five minutes, counted entries again after five minutes and recounted up to 500 entries after a restart. Entries already in the log when the exporter starts are no longer counted.
- `adguard_exporter_up` is 1 only if every AdGuard Home API call of the scrape succeeded (it was always 1), and `adguard_exporter_scrape_errors_total` counts every failed call (it was never incremented)
- A response with a status other than 200 is reported as an error

### ⚠️ Deprecated
- `adguard_exporter_dedup_hits_total` and `adguard_exporter_query_cache_size` are always 0 and will be removed in the next release

### 🔄 Refactored
- Split `main.go` into `internal/config`, `internal/adguard`, `internal/collector`, `internal/geo` and `internal/logx`; `main.go` only wires them. Metric names, labels, environment variables and log lines are unchanged.

### 🛠 Fixed
- An invalid `ADGUARD_HOST` logs an error instead of crashing the exporter
- The DEBUG `dedupHits` log fields show the real count instead of always 0

### 🧪 Tests
- End-to-end tests run the exporter binary against a fake AdGuard Home API and compare `/metrics` with golden files in `testdata/` (`go test ./... -update` rewrites them)
- Unit tests for every internal package
- Query log tests for growing limits, identical timestamps at the cut and the window edge, restarts, gaps, clearing, clock steps and failures while reading
- `DISABLE_METRICS` tests for parsing, every metric name, invalid names, skipped updates and GeoIP lookups

## v1.1.0 - 2025-06-18
### ✨ Added
- `adguard_replaced_parental`: total queries replaced due to parental control
- `adguard_safe_search`: total queries forced into Safe Search (YouTube, Google, Bing)
- `adguard_safe_browsing`: total Safe Browsing protections triggered
- `adguard_top_upstreams`: top DNS upstreams based on query count
- `adguard_top_clients`: top client IPs querying AdGuard
- `adguard_top_queried_domains`: most frequently queried domains
- `adguard_upstream_avg_response_time_seconds`: average DNS upstream response time

### 🛠 Fixed
- Fixed: missing `upstream` and `client` labels due to empty maps or parsing errors
- Fixed: more reliable parsing of nested JSON from `/control/stats` and `/control/status`
- Fixed: exporter now exposes partial metrics even if part of the JSON fails

### 🔄 Refactored
- Cleaned up metric and label names to follow Prometheus naming conventions
- Fixed Dockerfile lint warning: unified casing of `FROM ... AS` keyword for best practices
