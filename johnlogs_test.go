package johnlogs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestShipping(t *testing.T) {
	var (
		mu   sync.Mutex
		got  []map[string]any
		auth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var batch []map[string]any
		if err := json.NewDecoder(zr).Decode(&batch); err != nil {
			t.Error(err)
		}
		mu.Lock()
		auth = r.Header.Get("Authorization")
		got = append(got, batch...)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

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
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	if auth != "Bearer tok" {
		t.Errorf("auth = %q", auth)
	}
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
	off := New(Config{})
	off.Logger().Error("nothing")
	if off.Shipping() || off.Close(context.Background()) != nil {
		t.Error("an empty URL must not ship")
	}
}

func TestRefusedIsDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Token: "bad"})
	c.Send(map[string]any{"message": "x"})
	c.Close(context.Background())
	if c.Dropped() != 1 || c.Sent() != 0 {
		t.Errorf("dropped %d sent %d", c.Dropped(), c.Sent())
	}
}
