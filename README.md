# AdGuard Exporter for Prometheus

A lightweight Prometheus exporter written in Go that exposes detailed metrics from your AdGuard Home instance — including DNS statistics, blocked domains, upstreams, and client data.

---

## Features

| Category | Capabilities |
|----------|--------------|
| API Integration | • Authenticated access to AdGuard Home API<br>• Supports `/control/status`, `/control/stats`, and `/control/querylog` endpoints |
| DNS Analytics | • Total DNS queries metrics<br>• Blocked DNS queries tracking<br>• Upstream DNS statistics<br>• Per-client query statistics<br>• Query reason statistics<br>• DNS upstream latency histograms |
| Query Log Processing | • Real-time query log analysis<br>• Every query log entry counted exactly once<br>• Domain and query reason tracking |
| GeoIP Enrichment | • MaxMind GeoLite2 IP geolocation lookup<br>• DNS client geographic visualization (Grafana Geomap)<br>• DNS threat map for blocked queries<br>• GeoIP caching for improved performance |
| Traffic Analytics | • DNS queries grouped by ISP organization<br>• Country-level DNS traffic insights<br>• ISP-based DNS traffic monitoring |
| Exporter Monitoring | • Exporter health per scrape<br>• Query log gap counters<br>• GeoIP cache usage monitoring<br>• Exporter scrape performance metrics |
| Deployment | • Customizable scrape interval<br>• Lightweight single binary deployment<br>• Docker-friendly deployment |

---

## Built With

- [Go (Golang)](https://golang.org/)
- [Prometheus Client Library](https://github.com/prometheus/client_golang)
- [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)

---

## Prerequisites

Before running this exporter, make sure:

- AdGuard Home is up and running
- You have a valid AdGuard username & password (without special character (!,@,`,* etc.))
- Prometheus is configured to scrape this exporter
- Docker installed (or alternatively Go 1.20+ for building from source)
- Port `9617` is available on your system

To make sure the endpoint is valid, you can check the endpoints via curl:

```
curl -v -u <yourusername>:<yourpassword> <ADGUARD_URL>:<PORT>/control/stats
curl -v -u <yourusername>:<yourpassword> <ADGUARD_URL>:<PORT>/control/status
curl -v -u <yourusername>:<yourpassword> <ADGUARD_URL>:<PORT>/control/querylog
```
After that, you should got the output like this:

```
*   Trying 172.31.20.12:80...
* Connected to 172.31.20.12 (172.31.20.12) port 80 (#0)
* Server auth using Basic with user 'admin'
> GET /control/stats HTTP/1.1
> Host: 172.31.20.12
> Authorization: Basic Xxxxxxxxxxxxxxxxxxxxxxxxx
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Access-Control-Allow-Origin: http://172.31.20.12
< Content-Type: application/json
< Server: AdGuardHome/v0.107.62
< Vary: Origin
< Vary: Accept-Encoding
< Date: Tue, 08 Jul 2025 16:45:56 GMT
< Transfer-Encoding: chunked
<
```

---

## Environment Variables

| Variable         | Description                            | Required | Example                      |
|------------------|----------------------------   | -------------------|-------------------
| `ADGUARD_HOST`| AdGuard Home base URL            | ✅ |  `http://192.168.1.1:3000,`    |
| `ADGUARD_USER`| AdGuard Home username                 | ✅       | `admin`                      |
| `ADGUARD_PASS`| AdGuard Home password (used when `ADGUARD_PASS_FILE` is unset) | One of `ADGUARD_PASS` or `ADGUARD_PASS_FILE` | `secretpassword` |
| `ADGUARD_PASS_FILE` | Path to a file containing the AdGuard Home password (takes precedence over `ADGUARD_PASS`) | One of `ADGUARD_PASS` or `ADGUARD_PASS_FILE` | `/run/secrets/adguard_pass` |
| `EXPORTER_PORT`   | Port to expose metrics (default: 9617) | ❌       | `9200`                       |
| `SCRAPE_INTERVAL` | How often to scrape (default: `15` for 15s)    | ❌       | `30`                        |
| `LOG_LEVEL`       | Log Level to analyze, INFO, WARN, DEBUG | ❌      | `DEBUG`,`WARN`,`INFO`        |
| `QUERYLOG_OVERLAP` | Longest expected time between a query's start and AdGuard Home writing it to the query log (default: `1m`), see [How query log entries are counted](#how-query-log-entries-are-counted) | ❌ | `30s` |
| `QUERYLOG_MAX_ENTRIES` | Maximum query log entries requested per scrape (default: `20000`, at most `50000`) | ❌ | `5000` |
| `DISABLE_METRICS` | Comma-separated metrics to turn off, see [Disabling metrics](#disabling-metrics) (default: none) | ❌ | `query_domain,query_isp` |

---

## Quick Start

Run via Docker Compose

---

### 1. Create docker-compose.yml in your root dir

#### Without `secret`

```yaml
version: '3.8'

services:
  adguard-exporter:
    image: ghcr.io/znandev/adguardexporter:latest
    container_name: adguard_exporter
    restart: unless-stopped
    ports:
      - "9617:9617"
    volumes:
      - ./<path/to/your>/GeoLite2-City.mmdb:/GeoLite2-City.mmdb
    environment:
      ADGUARD_HOST: <YOUR_ADGUARD_URL>
      ADGUARD_USER: <YOUR_ADGUARD_USERNAME>
      ADGUARD_PASS: <YOUR_ADGUARD_PASSWORD>
      EXPORTER_PORT: 9617
      SCRAPE_INTERVAL: 15s
      LOG_LEVEL: DEBUG
```

#### With `secret`

```yaml
version: '3.8'

services:
  adguard-exporter:
    image: ghcr.io/znandev/adguardexporter:latest
    container_name: adguard_exporter
    restart: unless-stopped
    ports:
      - "9617:9617"
    volumes:
      - ./<path/to/your>/GeoLite2-City.mmdb:/GeoLite2-City.mmdb
    environment:
      ADGUARD_HOST: <YOUR_ADGUARD_URL>
      ADGUARD_USER: <YOUR_ADGUARD_USERNAME>
      ADGUARD_PASS_FILE: /run/secrets/adguard_pass
      EXPORTER_PORT: 9617
      SCRAPE_INTERVAL: 15s
      LOG_LEVEL: DEBUG
    secrets:
      - adguard_pass

secrets:
  adguard_pass:
    file: ./secrets/adguard_pass
```

Create `./secrets/adguard_pass` with the AdGuard password. The file is mounted into the container as a Docker secret; any trailing newline is ignored. To keep using an environment variable instead, set `ADGUARD_PASS` and remove `ADGUARD_PASS_FILE` and the Compose secret configuration.

---

### 2. Run with Docker Compose

```bash
docker-compose up -d
```

---

## Metrics Endpoint

Once running, your exporter will be available at:

```
http://<host>:9617/metrics
```

Ready to scrape by Prometheus!

---

## Example Prometheus Job

```yaml
- job_name: 'adguard-exporter'
  scrape_interval: 15s
  static_configs:
    - targets: ['adguard-exporter:9617']
```
---
## Available Prometheus Metrics

This exporter exposes the following metrics from AdGuard Home.

---

### Core Metrics

* `adguard_dns_queries_total`
  Total DNS queries processed by AdGuard Home.

* `adguard_blocked_filtering_total`
  Total DNS queries blocked by filtering rules.

* `adguard_replaced_parental`
  Queries replaced by parental filtering.

* `adguard_avg_processing_time`
  Average DNS query processing time in milliseconds.

---

### AdGuard Status

* `adguard_protection_enabled`
  Whether DNS filtering protection is enabled (1 = enabled, 0 = disabled).

* `adguard_running`
  Whether the AdGuard Home DNS service is running.

* `adguard_dhcp_available`
  Indicates if DHCP functionality is available.

* `adguard_protection_disabled_duration_seconds`
  Time since DNS protection was disabled.

---

### Top Queries

Metrics with labels:

* `adguard_top_queried_domain_total{domain="example.com"}`
* `adguard_top_blocked_domain_total{domain="ads.example.com"}`
* `adguard_top_client_total{client="192.168.1.2"}`
* `adguard_top_upstream_total{upstream="8.8.8.8"}`
* `adguard_upstream_avg_response_time_seconds{upstream="8.8.8.8"}`

---

### Query Log Metrics

Metrics generated from AdGuard query log analysis.

* `adguard_query_domain_total{domain="example.com"}`
* `adguard_query_reason_total{reason="FilteredBlackList"}`
* `adguard_query_type_total{type="A"}`
* `adguard_query_upstream_total{upstream="8.8.8.8"}`
* `adguard_query_client_reason_total{client="192.168.1.10",reason="FilteredBlackList"}`

#### How query log entries are counted

Every entry of AdGuard Home's query log is counted once. Entries that were already in the log when the exporter started are not counted.

AdGuard Home returns the most recently *written* entries, but an entry's time is when the query *started*, so a slow query is written after faster, newer ones. Each scrape therefore reads the newest entries, doubling the number requested from 500 until the response reaches back twice `QUERYLOG_OVERLAP` before the newest entry counted so far. Entries from the last `QUERYLOG_OVERLAP` are compared by their content with the previous scrape; everything else in that window is new. With a busy AdGuard Home, a scrape reads about (queries per second) × (2 × `QUERYLOG_OVERLAP` + `SCRAPE_INTERVAL`) entries.

Limitations:

* A query written to the log more than `QUERYLOG_OVERLAP` after it started is not counted. AdGuard Home's upstream timeout is 10 seconds by default.
* Queries answered while the exporter is not running are not counted.
* If more entries were written since the previous scrape than `QUERYLOG_MAX_ENTRIES`, the exporter counts only the newest and increases `adguard_exporter_querylog_gaps_total{reason="limit"}`.
* If every entry counted in the last `QUERYLOG_OVERLAP` vanishes from the log (the log was cleared, AdGuard Home's clock stepped back, or client IP anonymisation was switched), `adguard_exporter_querylog_gaps_total{reason="reset"}` increases. New entries are still counted, but switching anonymisation can count the last `QUERYLOG_OVERLAP` once more, and after a clock step the exporter counts again only once the entries from before the step have left the newest entries.
* Under load, AdGuard Home itself drops entries from its query log: it keeps the newest `querylog.size_memory` entries (default 1000) in a ring buffer and writes them to the file asynchronously, so entries that arrive before the write overwrite the oldest ones. The exporter usually sees these entries before they are dropped, so its counts can be slightly higher than the query log shows. This is not reported as a gap.

---

### Upstream Latency Metrics

Histogram metrics that track DNS upstream response time distribution.

* `adguard_upstream_latency_seconds`

This metric allows latency percentile calculations such as **p95 or p99 upstream DNS latency**.

Generated metrics:

* `adguard_upstream_latency_seconds_bucket`
* `adguard_upstream_latency_seconds_sum`
* `adguard_upstream_latency_seconds_count`

Example:

```
adguard_upstream_latency_seconds_bucket{upstream="1.1.1.1",le="0.005"} 50
```

---

### GeoIP Metrics

#### `adguard_client_geo_queries`

Total DNS queries per client enriched with geographic information.

Labels:

* `client` – Client IP address
* `country` – ISO country code
* `lat` – Latitude
* `lon` – Longitude

Example:

```
adguard_client_geo_queries{client="118.99.94.204",country="ID",lat="-2.969000",lon="104.744200"} 1000
```

---

#### `adguard_blocked_geo_queries`

Counts DNS queries that were blocked by filtering rules and enriches them with geographic information.

Labels:

* `client`
* `country`
* `lat`
* `lon`

Example:

```
adguard_blocked_geo_queries{client="118.99.94.204",country="ID",lat="-2.969000",lon="104.744200"} 306
```

---

### Exporter Health Metrics

Metrics used to monitor the exporter itself.

* `adguard_exporter_up` — 1 if every AdGuard Home API call of the last scrape succeeded, otherwise 0.
* `adguard_exporter_scrape_duration_seconds` — Time taken for the exporter to scrape AdGuard API data.
* `adguard_exporter_scrape_errors_total` — Number of failed AdGuard Home API calls.
* `adguard_exporter_querylog_gaps_total{reason="limit"|"reset"}` — Scrapes in which query log entries may have been missed, see [How query log entries are counted](#how-query-log-entries-are-counted).
* `adguard_exporter_geo_cache_size` — Number of cached GeoIP lookup entries.
* `adguard_exporter_query_cache_size` — **Deprecated**, always 0, will be removed in the next release.
* `adguard_exporter_dedup_hits_total` — **Deprecated**, always 0, will be removed in the next release.

---

### Disabling metrics

Some metrics have a series per domain, client or ISP and can grow large, e.g. `adguard_query_domain_total`. `DISABLE_METRICS` turns off single metrics, named without the `adguard_` prefix and the `_total` suffix:

```
DISABLE_METRICS=query_domain,query_isp
```

A disabled metric is neither exposed nor kept in memory. If both `client_geo_queries` and `blocked_geo_queries` are disabled, the exporter also skips the GeoIP lookups. An unknown name stops the exporter with an error that lists the valid names, so a typo does not leave a metric enabled. The exporter's own `adguard_exporter_*` metrics cannot be disabled.

| Name | Metric |
|---|---|
| `dns_queries` | `adguard_dns_queries_total` |
| `blocked_filtering` | `adguard_blocked_filtering_total` |
| `replaced_parental` | `adguard_replaced_parental` |
| `avg_processing_time` | `adguard_avg_processing_time` |
| `protection_enabled` | `adguard_protection_enabled` |
| `running` | `adguard_running` |
| `dhcp_available` | `adguard_dhcp_available` |
| `protection_disabled_duration_seconds` | `adguard_protection_disabled_duration_seconds` |
| `version_info` | `adguard_version_info` |
| `top_queried_domain` | `adguard_top_queried_domain_total` |
| `top_blocked_domain` | `adguard_top_blocked_domain_total` |
| `top_client` | `adguard_top_client_total` |
| `top_upstream` | `adguard_top_upstream_total` |
| `upstream_avg_response_time_seconds` | `adguard_upstream_avg_response_time_seconds` |
| `query_reason` | `adguard_query_reason_total` |
| `query_type` | `adguard_query_type_total` |
| `query_elapsed_ms` | `adguard_query_elapsed_ms` |
| `query_upstream` | `adguard_query_upstream_total` |
| `query_domain` | `adguard_query_domain_total` |
| `query_client_reason` | `adguard_query_client_reason_total` |
| `client_geo_queries` | `adguard_client_geo_queries` |
| `blocked_geo_queries` | `adguard_blocked_geo_queries` |
| `upstream_latency_seconds` | `adguard_upstream_latency_seconds` |
| `query_isp` | `adguard_query_isp_total` |
  
---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Screenshots

Grafana Dashboard Preview

[Live preview and monitoring, click here](https://stats.znand.my.id/public-dashboards/a0b05deb37464a17b01cbc69eb65ac5a?orgId=1&refresh=5s)

[Deploy yours here](https://grafana.com/grafana/dashboards/23579-adguard-metrics-statistics/)
— new dashboard.json for grafana will be uploaded soon

![dashboard1](./grafana/dashboard01.png)

![dashboard2](./grafana/dashboard02.png)

![dashboard3](./grafana/dashboard03.png)

![dashboard4](./grafana/dashboard04.png)

![dashboard5](./grafana/dashboard06.png)

---

## 💬 Feedback

Pull Requests, Issues, and Suggestions are always welcome!

**Made with ❤️ by [znanddev](https://github.com/znand-dev)**
