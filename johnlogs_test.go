package johnlogs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/john-avenue/john-logs-sdk/wire"
)

// gateway is a fake john-logs gateway: it reads batches the way the real one
// does (package wire), keeps records and packs, and can be told to fail.
type gateway struct {
	t       *testing.T
	mu      sync.Mutex
	records []map[string]any
	packs   map[string][]byte
	seen    map[string]int // batch id -> deliveries
	reqs    int
	headers []http.Header
	// fail, when set, answers request n (from 1) itself and returns true.
	fail func(n int, w http.ResponseWriter) bool
}

func newGateway(t *testing.T) (*gateway, *httptest.Server) {
	g := &gateway{t: t, packs: map[string][]byte{}, seen: map[string]int{}}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return g, srv
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	g.reqs++
	n := g.reqs
	g.headers = append(g.headers, r.Header.Clone())
	fail := g.fail
	g.mu.Unlock()
	if r.URL.Path != "/v2/ingest" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if fail != nil && fail(n, w) {
		return
	}
	b, err := wire.ParseBatch(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Header.Get("X-Johnlogs-Batch") != b.Header.ID {
		g.t.Errorf("batch header %q, id %q", r.Header.Get("X-Johnlogs-Batch"), b.Header.ID)
	}
	var recs []map[string]any
	err = b.ReadRecords(func(line []byte) error {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return err
		}
		recs = append(recs, m)
		return nil
	})
	if err != nil || len(recs) != b.Header.Records {
		http.Error(w, fmt.Sprintf("records: %v (%d of %d)", err, len(recs), b.Header.Records), http.StatusBadRequest)
		return
	}
	if err := wire.EachBlob(b.Pack, func(int64, []byte) error { return nil }); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen[b.Header.ID]++
	if g.seen[b.Header.ID] == 1 { // a retried batch is stored once
		g.records = append(g.records, recs...)
		g.packs[b.Header.ID] = append([]byte(nil), b.Pack...)
	}
	w.WriteHeader(http.StatusAccepted)
}

func (g *gateway) fetch(r wire.Ref) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.packs[r.Batch]
	if !ok || r.Off+r.Len > int64(len(p)) {
		return nil, fmt.Errorf("no blob %s", r)
	}
	return p[r.Off : r.Off+r.Len], nil
}

func (g *gateway) all() []map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]map[string]any(nil), g.records...)
}

func (g *gateway) body(t *testing.T, rec map[string]any, field string) []byte {
	t.Helper()
	ref, err := wire.ParseRef(fmt.Sprint(rec[field+"_ref"]))
	if err != nil {
		t.Fatalf("%s_ref: %v (%v)", field, err, rec)
	}
	b, err := wire.Open(ref, g.fetch)
	if err != nil {
		t.Fatalf("open %s: %v", ref, err)
	}
	return b
}

func flushed(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Fatalf("close: %v (stats %+v)", err, c.Stats())
	}
}

func TestShipping(t *testing.T) {
	g, srv := newGateway(t)
	var console bytes.Buffer
	c := New(Config{
		URL: srv.URL, Token: "tok", Service: "svc", Env: "test", Version: "v1",
		Level:   LevelTrace,
		Fields:  map[string]any{"instance": "i1"},
		Console: slog.NewTextHandler(&console, nil),
	})
	prev := slog.Default()
	slog.SetDefault(c.Logger())
	defer slog.SetDefault(prev)

	ctx, session := Session(context.Background(), "user", "a@b.c")
	ctx, end := Start(ctx, "checkout", "task_id", "t1")
	slog.Default().With("module", "tm").WithGroup("http").Log(ctx, LevelTrace, "GET /x",
		"status", 200, "headers", map[string]any{"Authorization": "Bearer x", "Accept": "*/*"},
		slog.Group("req", "password", "hunter2"))
	end(errors.New("sold out"))
	slog.InfoContext(context.Background(), "no context", "api_key", "k-123")
	flushed(t, c)

	if h := g.headers[0]; h.Get("Authorization") != "Bearer tok" || h.Get("X-Johnlogs-Sdk") != Version {
		t.Errorf("headers = %v", h)
	}
	got := g.all()
	if len(got) != 4 { // span start (debug), the trace line, span end, plain
		t.Fatalf("got %d records: %v", len(got), got)
	}
	r := got[1]
	for k, want := range map[string]any{
		"message": "GET /x", "level": "trace", "service": "svc", "env": "test", "version": "v1",
		"instance": "i1", "session_id": session, "user": "a@b.c", "task_id": "t1", "span": "checkout",
		"module": "tm", "http_status": float64(200), "http_req_password": "[redacted]",
	} {
		if r[k] != want {
			t.Errorf("%s = %v, want %v", k, r[k], want)
		}
	}
	if h := r["http_headers"].(map[string]any); h["Authorization"] != "[redacted]" || h["Accept"] != "*/*" {
		t.Errorf("headers = %v", h)
	}
	if r["trace_id"] == nil || r["span_id"] == nil || r["_timestamp"] == nil {
		t.Errorf("missing trace fields: %v", r)
	}
	if e := got[2]; e["level"] != "error" || e["error"] != "sold out" || e["trace_id"] != r["trace_id"] || e["duration_ms"] == nil {
		t.Errorf("span end = %v", e)
	}
	if got[3]["session_id"] != nil {
		t.Errorf("context leaked: %v", got[3])
	}
	if !bytes.Contains(console.Bytes(), []byte("no context")) || bytes.Contains(console.Bytes(), []byte("GET /x")) || bytes.Contains(console.Bytes(), []byte("k-123")) {
		t.Errorf("console should get info and up only, redacted:\n%s", console.String())
	}
}

func TestNested(t *testing.T) {
	ctx, end := Start(context.Background(), "outer")
	outer := Get(ctx, KeySpan)
	ctx2, _ := Start(ctx, "inner")
	if Get(ctx2, KeyParent) != outer || Get(ctx2, KeyTrace) != Get(ctx, KeyTrace) {
		t.Errorf("inner span not tied to outer: %v", Fields(ctx2))
	}
	end(nil)
}

func TestOffAndNil(t *testing.T) {
	var nilc *Client
	nilc.Send(map[string]any{"a": 1})
	nilc.Logger().Info("nothing")
	_ = nilc.Stats()
	off := New(Config{})
	off.Logger().Error("nothing")
	if off.Shipping() || off.Close(context.Background()) != nil {
		t.Error("an empty URL must not ship")
	}
}

// page is an HTML page that differs from its siblings only in a nonce and a
// timestamp, the way real pages do.
func page(i int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<!DOCTYPE html><html><head><title>Event &amp; Tickets</title><script nonce="%016x">window.__t=%d</script></head><body>`, i*7919+1, 1700000000+i)
	for j := range 2000 {
		fmt.Fprintf(&b, `<div class="row r%d"><span>Section %d</span><a href="/seat/%d">Seat</a></div>`, j%7, j, j)
	}
	b.WriteString(`<script src="https://geo.captcha-delivery.com/x.js"></script></body></html>`)
	return []byte(b.String())
}

func TestBodiesStoredWholeWithSearchKeys(t *testing.T) {
	g, srv := newGateway(t)
	c := New(Config{URL: srv.URL, Token: "tok", InlineBytes: 64})
	pages := [][]byte{page(1), page(2), page(3)}
	for i, p := range pages {
		c.Send(map[string]any{
			"message":   "GET https://example.com/event/{id}",
			"resp_body": Body{Data: p, Type: "text/html; charset=utf-8"},
			"req_body":  &Body{Data: []byte(fmt.Sprintf(`{"event":%d,"qty":2}`, i))},
		})
	}
	bin := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe")
	c.Send(map[string]any{"message": "GET https://example.com/logo.png", "resp_body": Body{Data: bin}})
	flushed(t, c)

	got := g.all()
	if len(got) != 4 {
		t.Fatalf("got %d records", len(got))
	}
	var shapes []any
	for i, p := range pages {
		r := got[i]
		if b := g.body(t, r, "resp_body"); !bytes.Equal(b, p) {
			t.Fatalf("page %d did not come back whole", i)
		}
		if r["resp_body_size"] != float64(len(p)) || r["resp_body_partial"] != true || len(r["resp_body"].(string)) > 64 {
			t.Errorf("inline: size=%v partial=%v len=%d", r["resp_body_size"], r["resp_body_partial"], len(r["resp_body"].(string)))
		}
		if r["resp_body_kind"] != "html" || r["resp_body_title"] != "Event & Tickets" || r["resp_body_markers"] != "datadome" {
			t.Errorf("keys: kind=%v title=%v markers=%v", r["resp_body_kind"], r["resp_body_title"], r["resp_body_markers"])
		}
		if r["req_body"] != fmt.Sprintf(`{"event":%d,"qty":2}`, i) || r["req_body_partial"] != nil || r["req_body_json_keys"] != "event,qty" || r["req_body_kind"] != "json" {
			t.Errorf("req body keys: %v", r)
		}
		shapes = append(shapes, r["resp_body_shape"])
	}
	if shapes[0] != shapes[1] || shapes[1] != shapes[2] {
		t.Errorf("pages differing by a nonce should share a shape: %v", shapes)
	}
	if got[0]["resp_body_sha256"] == got[1]["resp_body_sha256"] {
		t.Error("different bytes, same sha256")
	}
	// The second and third pages are deltas against the first: tiny.
	for i := 1; i < 3; i++ {
		ref, _ := wire.ParseRef(got[i]["resp_body_ref"].(string))
		raw, _ := g.fetch(ref)
		blob, _ := wire.ParseBlob(raw)
		if blob.Kind != wire.Delta || ref.Len > int64(len(pages[i])/50) {
			t.Errorf("page %d: kind %d, %d bytes stored for %d", i, blob.Kind, ref.Len, len(pages[i]))
		}
	}
	png := got[3]
	if png["resp_body"] != nil || png["resp_body_kind"] != "image" || !bytes.Equal(g.body(t, png, "resp_body"), bin) {
		t.Errorf("binary body: %v", png)
	}
}

func TestBatchLimits(t *testing.T) {
	g, srv := newGateway(t)
	c := New(Config{URL: srv.URL, Token: "tok", BatchSize: 10, FlushEvery: time.Hour})
	for i := range 95 {
		c.Send(map[string]any{"message": "m", "i": i})
	}
	flushed(t, c)
	if n := len(g.all()); n != 95 {
		t.Fatalf("got %d records", n)
	}
	if len(g.seen) < 10 {
		t.Errorf("95 records at 10 a batch went in %d batches", len(g.seen))
	}
}

// A gateway that throttles most requests loses nothing: every record arrives,
// once.
func TestThrottledGatewayLosesNothing(t *testing.T) {
	defer func(d time.Duration) { backoffBase = d }(backoffBase)
	backoffBase = 5 * time.Millisecond
	g, srv := newGateway(t)
	g.fail = func(n int, w http.ResponseWriter) bool {
		switch n % 4 {
		case 1:
			w.Header().Set("Retry-After", "0")
			http.Error(w, "MemoryTableOverflowError", http.StatusTooManyRequests)
			return true
		case 2:
			http.Error(w, "upstream", http.StatusBadGateway)
			return true
		}
		return false
	}
	c := New(Config{URL: srv.URL, Token: "tok", BatchSize: 50, FlushEvery: 20 * time.Millisecond})
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 250 {
				c.Send(map[string]any{"message": "GET https://example.com/p", "worker": w, "i": i, "resp_body": Body{Data: page(i % 5)}})
			}
		}()
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Fatalf("close: %v %+v", err, c.Stats())
	}
	got := g.all()
	seen := map[string]bool{}
	for _, r := range got {
		seen[fmt.Sprint(r["worker"], "/", r["i"])] = true
	}
	if len(got) != 2000 || len(seen) != 2000 || c.Dropped() != 0 {
		t.Fatalf("records %d, distinct %d, dropped %d", len(got), len(seen), c.Dropped())
	}
	for _, r := range got[:20] {
		if b := g.body(t, r, "resp_body"); !bytes.Equal(b, page(int(r["i"].(float64))%5)) {
			t.Fatal("body mismatch after retries")
		}
	}
}

// A dead gateway, then a restart: the next run sends what the last one could
// not.
func TestSpoolSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	c := New(Config{URL: down.URL, Token: "tok", Spool: dir, FlushEvery: 10 * time.Millisecond})
	for i := range 300 {
		c.Send(map[string]any{"message": "m", "i": i, "resp_body": Body{Data: page(i % 3)}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	_ = c.Close(ctx)
	cancel()
	if st := c.Stats(); st.PendingRecords != 300 || c.Dropped() != 0 {
		t.Fatalf("after a dead gateway: %+v dropped %d", st, c.Dropped())
	}
	if segs, _ := filepath.Glob(filepath.Join(dir, "0", "seg-*.jls")); len(segs) == 0 {
		t.Fatal("nothing on disk")
	}

	g, srv := newGateway(t)
	c2 := New(Config{URL: srv.URL, Token: "tok", Spool: dir})
	c2.Send(map[string]any{"message": "after restart"})
	flushed(t, c2)
	got := g.all()
	if len(got) != 301 {
		t.Fatalf("got %d records after restart", len(got))
	}
	for _, r := range got {
		if r["resp_body_ref"] != nil {
			if b := g.body(t, r, "resp_body"); !bytes.Equal(b, page(int(r["i"].(float64))%3)) {
				t.Fatal("body mismatch after restart")
			}
		}
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "0", "seg-*"))
	if len(segs) != 0 {
		t.Errorf("accepted segments left behind: %v", segs)
	}
}

func TestSpoolFull(t *testing.T) {
	for _, policy := range []FullPolicy{DropOldest, DropNewest} {
		t.Run(fmt.Sprint(policy), func(t *testing.T) {
			down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "down", http.StatusServiceUnavailable)
			}))
			defer down.Close()
			var states []State
			var mu sync.Mutex
			c := New(Config{
				URL: down.URL, Token: "tok", Spool: t.TempDir(), SpoolMax: 24 << 20, WhenFull: policy,
				FlushEvery: 10 * time.Millisecond, BatchSize: 20,
				OnState: func(s Stats) { mu.Lock(); states = append(states, s.State); mu.Unlock() },
			})
			junk := make([]byte, 64<<10)
			for i := range 1200 { // random bodies, ~75 MiB, three times the cap
				_, _ = rand.Read(junk)
				c.Send(map[string]any{"message": fmt.Sprint("m", i), "resp_body": Body{Data: junk}})
			}
			time.Sleep(1200 * time.Millisecond) // a tick of checkState
			st := c.Stats()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_ = c.Close(ctx)
			cancel()
			if c.Dropped() == 0 || st.SpoolUsed > 24<<20 || st.State != StateFull {
				t.Fatalf("dropped %d, %+v", c.Dropped(), st)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(states) == 0 || states[len(states)-1] != StateFull {
				t.Errorf("OnState saw %v", states)
			}
		})
	}
}

func TestMalformedIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	g, srv := newGateway(t)
	g.fail = func(n int, w http.ResponseWriter) bool {
		if n == 1 {
			http.Error(w, "bad batch", http.StatusBadRequest)
			return true
		}
		return false
	}
	c := New(Config{URL: srv.URL, Token: "tok", Spool: dir})
	c.Send(map[string]any{"message": "first"})
	time.Sleep(700 * time.Millisecond)
	c.Send(map[string]any{"message": "second"})
	flushed(t, c)
	if c.Stats().Quarantined != 1 || len(g.all()) != 1 {
		t.Fatalf("quarantined %d, delivered %d", c.Stats().Quarantined, len(g.all()))
	}
	dead, _ := os.ReadDir(filepath.Join(dir, "0", "dead"))
	if len(dead) != 1 {
		t.Errorf("dead/ has %d files", len(dead))
	}
}

func TestRefusedTokenRetriesInsteadOfDropping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Token: "bad"})
	c.Send(map[string]any{"message": "x"})
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	_ = c.Close(ctx)
	st := c.Stats()
	if c.Dropped() != 0 || c.Sent() != 0 || st.PendingRecords != 1 || !strings.Contains(st.LastError, "401") {
		t.Errorf("dropped %d sent %d %+v", c.Dropped(), c.Sent(), st)
	}
}

func TestStatusHeaders(t *testing.T) {
	g, srv := newGateway(t)
	c := New(Config{URL: srv.URL, Token: "tok", Service: "svc"})
	c.Send(map[string]any{"message": "x"})
	flushed(t, c)
	h := g.headers[0]
	for _, k := range []string{"X-Johnlogs-Client", "X-Johnlogs-State", "X-Johnlogs-Pending-Bytes", "X-Johnlogs-Spool-Max", "X-Johnlogs-Dropped"} {
		if h.Get(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
	if h.Get("X-Johnlogs-Service") != "svc" {
		t.Errorf("service header %q", h.Get("X-Johnlogs-Service"))
	}
}
