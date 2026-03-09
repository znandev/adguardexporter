# AdGuard Exporter for Prometheus

A lightweight Prometheus exporter written in Go that exposes detailed metrics from your AdGuard Home instance — including DNS statistics, blocked domains, upstreams, and client data.

---

## Features

| Category | Capabilities |
|----------|--------------|
| API Integration | • Authenticated access to AdGuard Home API<br>• Supports `/control/status`, `/control/stats`, and `/control/querylog` endpoints |
| DNS Analytics | • Total DNS queries metrics<br>• Blocked DNS queries tracking<br>• Upstream DNS statistics<br>• Per-client query statistics<br>• Query reason statistics<br>• DNS upstream latency histograms |
| Query Log Processing | • Real-time query log analysis<br>• Query deduplication to prevent metric inflation<br>• Domain and query reason tracking |
| GeoIP Enrichment | • MaxMind GeoLite2 IP geolocation lookup<br>• DNS client geographic visualization (Grafana Geomap)<br>• DNS threat map for blocked queries<br>• GeoIP caching for improved performance |
| Traffic Analytics | • DNS queries grouped by ISP organization<br>• Country-level DNS traffic insights<br>• ISP-based DNS traffic monitoring |
| Exporter Monitoring | • Deduplication cache metrics<br>• GeoIP cache usage monitoring<br>• Deduplication hit counters<br>• Exporter scrape performance metrics |
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

---
## Environment Variables

| Variable         | Description                            | Required | Example                      |
|------------------|----------------------------   | -------------------|-------------------
| `ADGUARD_HOST`| AdGuard Home base URL            | ✅ |  `http://192.168.1.1:3000,`    |
| `ADGUARD_USER`| AdGuard Home username                 | ✅       | `admin`                      |
| `ADGUARD_PASS`| AdGuard Home password                 | ✅       | `secretpassword`             |
| `EXPORTER_PORT`   | Port to expose metrics (default: 9617) | ❌       | `9200`                       |
| `SCRAPE_INTERVAL` | How often to scrape (default: 15s)    | ❌       | `30s`                        |
| `LOG_LEVEL`       | Log Level to analyze, INFO, WARN, DEBUG | ❌      | `DEBUG`,`WARN`,`INFO`        |

---

## Run via Docker

### Quick Start (Inline ENV)

```bash
docker run -d \
  --name adguard_exporter \
  --restart unless-stopped \
  -p 9617:9617 \
  -e ADGUARD_HOST=<YOUR_ADGUARD_URL> \
  -e ADGUARD_USER=<YOUR_ADGUARD_USERNAME> \
  -e ADGUARD_PASS=<YOUR_ADGUARD_PASSWORD> \
  -e EXPORTER_PORT=9617 \
  -e SCRAPE_INTERVAL=15s \
  -e LOG_LEVEL=DEBUG
  ghcr.io/znand-dev/adguardexporter:latest
```

---

## Run via Docker Compose

### 1. Create docker-compose.yml in your root dir

```yaml
version: '3.8'

services:
  adguard-exporter:
    image: ghcr.io/znand-dev/adguardexporter:latest
    container_name: adguard_exporter
    restart: unless-stopped
    ports:
      - "9617:9617"
    environment:
      - ADGUARD_HOST=<YOUR_ADGUARD_URL>
      - ADGUARD_USER=<YOUR_ADGUARD_USERNAME>
      - ADGUARD_PASS=<YOUR_ADGUARD_PASSWORD>
      - EXPORTER_PORT=9617
      - SCRAPE_INTERVAL=15s
      - LOG_LEVEL=DEBUG
```

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

* `adguard_exporter_up` — Indicates if the exporter successfully scraped the AdGuard API.
* `adguard_exporter_scrape_duration_seconds` — Time taken for the exporter to scrape AdGuard API data.
* `adguard_exporter_scrape_errors_total` — Total number of errors encountered during scraping.
* `adguard_exporter_query_cache_size` — Number of cached DNS query entries used for deduplication.
* `adguard_exporter_geo_cache_size` — Number of cached GeoIP lookup entries.
* `adguard_exporter_dedup_hits_total` — Total number of duplicate DNS queries skipped by the exporter.
  
---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Screenshots

Grafana Dashboard Preview

[Live preview and monitoring, click here](https://stats.znand.my.id/public-dashboards/a0b05deb37464a17b01cbc69eb65ac5a?orgId=1&refresh=5s)

[Deploy yours here](https://grafana.com/grafana/dashboards/23579-adguard-metrics-statistics/)
— new dashboard.json for grafana will be uploaded soon

![dashboard1](./grafana/dashboard1.png)

![dashboard2](./grafana/dashboard2.png)

![dashboard3](./grafana/dashboard3.png)

![dashboard4](./grafana/dashboard4.png)
---

## 💬 Feedback

Pull Requests, Issues, and Suggestions are always welcome!

**Made with ❤️ by [znanddev](https://github.com/znand-dev)**
