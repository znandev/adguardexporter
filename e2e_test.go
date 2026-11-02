package main_test

// End-to-end harness: every test builds and runs the real exporter binary
// against a fake AdGuard Home API and reads /metrics over HTTP. The tests only
// rely on the binary's interface (environment, logs, /metrics), so they hold
// across internal restructuring.

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"github.com/znand-dev/adguardexporter/internal/adguardtest"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata")

var (
	exporterBin string
	geoDBPath   string
)

func TestMain(m *testing.M) {
	flag.Parse()

	dir, err := os.MkdirTemp("", "adguard-exporter-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	code := func() int {
		defer func() { _ = os.RemoveAll(dir) }()

		exporterBin = filepath.Join(dir, "adguard-exporter")
		build := exec.Command("go", "build", "-o", exporterBin, ".")
		build.Stdout, build.Stderr = os.Stderr, os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "building exporter:", err)
			return 1
		}

		geoDBPath = filepath.Join(dir, "GeoLite2-City.mmdb")
		if err := writeGeoDB(geoDBPath); err != nil {
			fmt.Fprintln(os.Stderr, "writing GeoIP test database:", err)
			return 1
		}

		return m.Run()
	}()
	os.Exit(code)
}

// Addresses with a record in the GeoIP test database.
const (
	geoNet     = "203.0.113.0/24"
	geoCountry = "DE"
	geoLat     = 52.52
	geoLon     = 13.405
)

func writeGeoDB(path string) error {
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "GeoLite2-City",
		IncludeReservedNetworks: true,
	})
	if err != nil {
		return err
	}

	prefix := netip.MustParsePrefix(geoNet)
	record := mmdbtype.Map{
		"country": mmdbtype.Map{"iso_code": mmdbtype.String(geoCountry)},
		"location": mmdbtype.Map{
			"latitude":  mmdbtype.Float64(geoLat),
			"longitude": mmdbtype.Float64(geoLon),
		},
	}
	if err := w.Insert(&net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), 32)}, record); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := w.WriteTo(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// options configure one exporter run.
type options struct {
	// env overrides the defaults set by start.
	env map[string]string
	// unset removes default variables.
	unset []string
	// dir is the working directory; a fresh temp dir when empty.
	dir string
}

// exporter is a running exporter process.
type exporter struct {
	t    *testing.T
	fake *adguardtest.Server
	cmd  *exec.Cmd
	url  string
	logs *syncBuffer
	done chan struct{}

	loops int
	next  <-chan struct{}
}

// start runs the exporter against fake and waits until it serves /metrics.
// Loop synchronisation relies on the order inside one exporter loop (stats,
// status, query log): the stats request of loop n+1 is held until the test has
// looked at the state after loop n.
func start(t *testing.T, fake *adguardtest.Server, o options) *exporter {
	t.Helper()
	e := launch(t, fake, o)
	e.waitReady()
	return e
}

// launch runs the exporter without waiting for it, for tests that expect it
// to exit.
func launch(t *testing.T, fake *adguardtest.Server, o options) *exporter {
	t.Helper()

	port := freePort(t)
	env := map[string]string{
		"ADGUARD_HOST":    fake.URL,
		"ADGUARD_USER":    fake.User,
		"ADGUARD_PASS":    fake.Pass(),
		"EXPORTER_PORT":   strconv.Itoa(port),
		"SCRAPE_INTERVAL": "1",
		"LOG_LEVEL":       "DEBUG",
		"GEOIP_DB":        geoDBPath,
	}
	for _, k := range o.unset {
		delete(env, k)
	}
	for k, v := range o.env {
		env[k] = v
	}

	dir := o.dir
	if dir == "" {
		dir = t.TempDir()
	}

	e := &exporter{
		t:    t,
		fake: fake,
		url:  fmt.Sprintf("http://127.0.0.1:%d/metrics", port),
		logs: &syncBuffer{},
		done: make(chan struct{}),
	}
	e.next = fake.HoldAt(adguardtest.PathStats, 2)

	e.cmd = exec.Command(exporterBin)
	e.cmd.Dir = dir
	e.cmd.Env = make([]string, 0, len(env))
	for k, v := range env {
		e.cmd.Env = append(e.cmd.Env, k+"="+v)
	}
	e.cmd.Stdout = e.logs
	e.cmd.Stderr = e.logs
	if err := e.cmd.Start(); err != nil {
		t.Fatalf("starting exporter: %v", err)
	}
	go func() {
		_ = e.cmd.Wait()
		close(e.done)
	}()
	t.Cleanup(func() {
		fake.Release()
		_ = e.cmd.Process.Kill()
		<-e.done
		if t.Failed() {
			t.Logf("exporter output:\n%s", e.logs.String())
		}
	})

	return e
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func (e *exporter) waitReady() {
	e.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-e.done:
			e.t.Fatalf("exporter exited early:\n%s", e.logs.String())
		default:
		}
		resp, err := http.Get(e.url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("exporter did not serve /metrics:\n%s", e.logs.String())
}

// loop waits until the exporter has finished one more loop and holds it
// before the next one starts.
func (e *exporter) loop() {
	e.t.Helper()
	if e.loops > 0 {
		e.next = e.fake.HoldAt(adguardtest.PathStats, e.loops+2)
	}
	select {
	case <-e.next:
	case <-e.done:
		e.t.Fatalf("exporter exited:\n%s", e.logs.String())
	case <-time.After(20 * time.Second):
		e.t.Fatalf("exporter loop %d did not finish:\n%s", e.loops+1, e.logs.String())
	}
	e.loops++
}

// scrape returns the /metrics body.
func (e *exporter) scrape() string {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("scraping: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(body)
}

// adguardMetrics keeps the adguard_* lines of a /metrics body, without the
// scrape duration, which is not deterministic.
func adguardMetrics(body string) string {
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		name := line
		if strings.HasPrefix(line, "# ") {
			f := strings.Fields(line)
			if len(f) < 3 {
				continue
			}
			name = f[2]
		}
		if !strings.HasPrefix(name, "adguard_") ||
			strings.HasPrefix(name, "adguard_exporter_scrape_duration_seconds") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file (run with -update to create it): %v", err)
	}
	if got != string(want) {
		t.Errorf("metrics differ from %s (run with -update to accept):\n%s", path, diffLines(string(want), got))
	}
}

// diffLines lists lines only in want (-) or only in got (+).
func diffLines(want, got string) string {
	count := func(s string) map[string]int {
		m := map[string]int{}
		for _, l := range strings.Split(s, "\n") {
			m[l]++
		}
		return m
	}
	w, g := count(want), count(got)
	var b strings.Builder
	for _, l := range strings.Split(want, "\n") {
		if g[l] < w[l] {
			fmt.Fprintf(&b, "- %s\n", l)
			w[l]--
		}
	}
	w = count(want)
	for _, l := range strings.Split(got, "\n") {
		if w[l] < g[l] {
			fmt.Fprintf(&b, "+ %s\n", l)
			g[l]--
		}
	}
	return b.String()
}

// sample is one parsed sample line.
type sample struct {
	name   string
	labels map[string]string
	value  float64
}

// samples parses the sample lines of a /metrics body. It handles the subset
// of the text format the exporter produces.
func samples(t *testing.T, body string) []sample {
	t.Helper()
	var out []sample
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			t.Fatalf("malformed sample line %q", line)
		}
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			t.Fatalf("malformed value in %q: %v", line, err)
		}
		s := sample{labels: map[string]string{}, value: v}
		head := line[:i]
		if j := strings.IndexByte(head, '{'); j >= 0 {
			s.name = head[:j]
			s.labels = parseLabels(t, head[j+1:len(head)-1])
		} else {
			s.name = head
		}
		out = append(out, s)
	}
	return out
}

func parseLabels(t *testing.T, s string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for s != "" {
		eq := strings.IndexByte(s, '=')
		if eq < 0 || len(s) < eq+2 || s[eq+1] != '"' {
			t.Fatalf("malformed labels %q", s)
		}
		key := s[:eq]
		rest := s[eq+2:]
		var val strings.Builder
		k := 0
		for ; k < len(rest); k++ {
			c := rest[k]
			if c == '\\' && k+1 < len(rest) {
				k++
				switch rest[k] {
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(rest[k])
				}
				continue
			}
			if c == '"' {
				break
			}
			val.WriteByte(c)
		}
		m[key] = val.String()
		s = strings.TrimPrefix(rest[k+1:], ",")
	}
	return m
}

// sum adds up all samples of name whose labels contain match.
func sum(t *testing.T, body, name string, match map[string]string) float64 {
	t.Helper()
	var total float64
	for _, s := range samples(t, body) {
		if s.name != name {
			continue
		}
		ok := true
		for k, v := range match {
			if s.labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			total += s.value
		}
	}
	return total
}

// has reports whether body contains any sample of name.
func has(t *testing.T, body, name string) bool {
	t.Helper()
	for _, s := range samples(t, body) {
		if s.name == name {
			return true
		}
	}
	return false
}

// counted is the number of query log entries the exporter has counted.
func counted(t *testing.T, body string) float64 {
	t.Helper()
	return sum(t, body, "adguard_query_reason_total", nil)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
