# 🧠 AdGuardExporter Project Board Template

## 🗂️ Columns:

### 1. 🧠 Feature Ideas / Wishlist
- Multi-server support (via .env list or CLI args)
- Support AdGuard Home running without filtering enabled
- Export per-client DNS stats with labels
- Add JSON-formatted Prometheus metric output (experimental)
- Add Grafana dashboard JSON preset

### 2. 🔧 In Progress
- Dockerfile + multi-arch GoReleaser config
- Histogram: DNS response time per upstream
- Custom labels per-domain (e.g., blocklist categories)

### 3. 🐞 Bugs / Issues
- Crash if `/control/status` not accessible
- Parsing error when AdGuard Home version < 0.107
- No fallback on invalid .env

### 4. 🧪 To Test
- Verify metrics in Prometheus + Grafana on:
  - Debian, Ubuntu, Alpine
  - Windows WSL
- Test with AdGuard Home v0.107 and latest
- Test with rate-limited or slow upstreams

### 5. ✅ Done
- Basic metrics: DNS queries, blocked count, protection status
- `.env` support for host, port, username, password
- Prometheus `/metrics` output endpoint
- Response time histogram (basic)

### 6. 🚀 Release Target
#### 🎯 v0.2.0
- [x] Metrics: Upstream stats
- [x] Response time histogram
- [ ] Basic unit test for `/metrics` handler
- [ ] Dockerfile + DockerHub push

#### 🎯 v1.0.0
- [ ] Multi-server support
- [ ] Improved error handling
- [ ] Documentation
