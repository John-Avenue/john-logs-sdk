package johnlogs

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestShapeIgnoresWhatChangesEveryTime(t *testing.T) {
	a := shape([]byte(`<script nonce="Zm9vYmFyYmF6cXV4MTIz">var t=1700000000123;</script><a href="/e/77812">Buy</a>`))
	b := shape([]byte(`<script nonce="cXV4YmF6YmFyZm9vOTk5">var t=1700000099999;</script><a href="/e/10023">Buy</a>`))
	c := shape([]byte(`<script nonce="cXV4YmF6YmFyZm9vOTk5">var t=1700000099999;</script><a href="/e/10023">Sold out</a>`))
	if a != b {
		t.Error("nonce, timestamp and id should not change the shape")
	}
	if a == c {
		t.Error("different words should change the shape")
	}
	if shape([]byte(`{"status":"ok","id":123}`)) == shape([]byte(`{"status":"sold_out","id":456}`)) {
		t.Error("a JSON state word should change the shape")
	}
}

func TestJSONKeys(t *testing.T) {
	for in, want := range map[string]string{
		`{"a":1,"b":{"c":[1,{"d":2}]},"e":"x\"y","f":[]}`: "a,b,e,f",
		` {"errors":[{"code":"X"}],"data":null}`:          "errors,data",
		`[1,2]`:                                           "",
		`{"a":"}`:                                         "a",
		`not json`:                                        "",
		`{"k":"v"} `:                                      "k",
	} {
		if got := jsonKeys([]byte(in), 50); got != want {
			t.Errorf("jsonKeys(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestKindTitleInline(t *testing.T) {
	for _, c := range []struct{ ct, body, want string }{
		{"application/json", `{"a":1}`, "json"},
		{"", ` [1,2]`, "json"},
		{"text/html", `<p>x</p>`, "html"},
		{"", "<!DOCTYPE html><html>", "html"},
		{"application/javascript", `var a`, "js"},
		{"", "plain words", "text"},
		{"", "\xff\xfe\x00\x01", "binary"},
		{"application/x-protobuf", "\x0a\x03abc", "protobuf"},
	} {
		if got := kindOf(c.ct, []byte(c.body)); got != c.want {
			t.Errorf("kindOf(%q, %q) = %s, want %s", c.ct, c.body, got, c.want)
		}
	}
	if got := title([]byte("<html><HEAD><Title data-x=1>\n  Seats &amp; More \n</TITLE>")); got != "Seats & More" {
		t.Errorf("title = %q", got)
	}
	s, partial := inlineText([]byte("héllo wörld"), 2) // cut inside é
	if s != "h" || !partial {
		t.Errorf("inline = %q %v", s, partial)
	}
	if s, partial := inlineText([]byte("short"), 4096); s != "short" || partial {
		t.Errorf("inline = %q %v", s, partial)
	}
}

// The work a caller does in Send: hash, inspect, compress against a base,
// encode. A task pays this per body, on its own goroutine.
func BenchmarkSendPage(b *testing.B) {
	_, srv := newGateway(&testing.T{})
	c := New(Config{URL: srv.URL, Token: "tok", SpoolMax: 4 << 30})
	defer c.Close(context.Background())
	pages := make([][]byte, 16)
	for i := range pages {
		pages[i] = page(i)
	}
	b.SetBytes(int64(len(pages[0])))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		c.Send(map[string]any{"message": "GET https://example.com/event/{id}", "resp_body": Body{Data: pages[i%16], Type: "text/html"}, "http_status": 200})
	}
	b.StopTimer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.Flush(ctx)
}

func TestMarkersAreSpecific(t *testing.T) {
	normal := strings.Repeat("<div>regular page, nothing to see, maintenance window next week</div>", 100)
	if m := findMarkers([]byte(normal), DefaultMarkers); m != "" {
		t.Errorf("an ordinary page got markers %q", m)
	}
	dd := `<html><script>var dd={'rt':'c','cid':'x','host':'geo.captcha-delivery.com'}</script></html>`
	if m := findMarkers([]byte(dd), DefaultMarkers); m != "datadome" {
		t.Errorf("datadome page got %q", m)
	}
	_ = fmt.Sprint()
}

func TestScanAgrees(t *testing.T) {
	m := compileMarkers(DefaultMarkers)
	for _, b := range [][]byte{page(3), []byte(`{"status":"ok","id":12345,"tok":"abcdefghijklmnopqrstuvwxyz"}`), []byte("x"), nil, []byte("Access Denied 99")} {
		sh, mk := scan(b, m)
		if sh != shape(b) || mk != m.find(b) {
			t.Errorf("scan(%.30q) = %s %q, want %s %q", b, sh, mk, shape(b), m.find(b))
		}
	}
}
