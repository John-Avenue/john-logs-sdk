package har

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestWrite(t *testing.T) {
	records := []map[string]any{
		{"message": "session start", "session_seq": 1.0, "_timestamp": 1.7e15},
		{
			"http_method": "POST", "http_url": "https://api.example.com/v1/cart?x=1&y=a%20b", "http_proto": "h2",
			"http_status": 403.0, "duration_ms": 120.0, "ttfb_ms": 100.0, "tls_ms": 30.0, "connect_ms": 10.0,
			"_timestamp": 1.7e15 + 1e6, "session_seq": 2.0, "step": "cart", "step_idx": 3.0, "client_id": "c1",
			"req_headers":       `{"Content-Type":"application/json","User-Agent":"UA","Cookie":"a=1"}`,
			"req_header_order":  `["user-agent","content-type","cookie"]`,
			"req_cookies":       `{"a":"1"}`,
			"req_body":          `{"q":2}`,
			"req_body_size":     7.0,
			"resp_headers":      `{"Content-Type":"text/html","Set-Cookie":["dd=1; Path=/","x=2"]}`,
			"resp_header_order": `["content-type","set-cookie"]`,
			"resp_body":         "<html>first bytes",
			"resp_body_partial": true,
			"resp_body_ref":     "0123456789a-deadbeef-000001:0:100",
			"resp_body_size":    20.0,
			"h2_pseudo_order":   "m,a,s,p",
			"tls_version":       "TLS 1.3", "tls_alpn": "h2", "h2_settings": "1:65536",
			"proxy": "http://u:p@1.2.3.4:8080",
		},
		{
			"http_method": "GET", "http_url": "https://cdn.example.com/a.png", "http_proto": "h1", "http_status": 200.0,
			"duration_ms": 5.0, "_timestamp": 1.7e15 + 2e6, "resp_body_ref": "0123456789a-deadbeef-000001:100:50",
			"resp_headers": `{"Content-Type":"image/png"}`,
		},
		{"http_method": "GET", "http_url": "https://x.example/", "error": "dial tcp: refused", "duration_ms": 3.0, "_timestamp": 1.7e15 + 3e6},
	}
	open := func(ref string) ([]byte, error) {
		switch ref {
		case "0123456789a-deadbeef-000001:0:100":
			return []byte("<html>first bytes, then the rest</html>"), nil
		case "0123456789a-deadbeef-000001:100:50":
			return []byte{0x89, 'P', 'N', 'G', 0xff}, nil
		}
		return nil, errors.New("no such blob")
	}
	var buf bytes.Buffer
	if err := Write(&buf, records, open, Options{Comment: "session abc"}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Version string
			Comment string
			Entries []map[string]any
			Events  []map[string]any `json:"_events"`
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if doc.Log.Version != "1.3" || doc.Log.Comment != "session abc" || len(doc.Log.Entries) != 3 || len(doc.Log.Events) != 1 {
		t.Fatalf("log: %+v", doc.Log)
	}
	e := doc.Log.Entries[0]
	req := e["request"].(map[string]any)
	hs := req["headers"].([]any)
	names := []string{}
	for _, h := range hs {
		names = append(names, h.(map[string]any)["name"].(string))
	}
	want := []string{":method", ":authority", ":scheme", ":path", "user-agent", "content-type", "cookie"}
	if len(names) != len(want) {
		t.Fatalf("headers %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("header order %v, want %v", names, want)
		}
	}
	if hs[3].(map[string]any)["value"] != "/v1/cart?x=1&y=a%20b" || req["httpVersion"] != "HTTP/2" {
		t.Errorf(":path / version: %v %v", hs[3], req["httpVersion"])
	}
	if pd := req["postData"].(map[string]any); pd["text"] != `{"q":2}` || pd["mimeType"] != "application/json" {
		t.Errorf("postData %v", pd)
	}
	if q := req["queryString"].([]any); len(q) != 2 || q[1].(map[string]any)["value"] != "a b" {
		t.Errorf("query %v", q)
	}
	resp := e["response"].(map[string]any)
	if c := resp["content"].(map[string]any); c["text"] != "<html>first bytes, then the rest</html>" || c["mimeType"] != "text/html" {
		t.Errorf("content %v", c)
	}
	rh := resp["headers"].([]any)
	if len(rh) != 4 || rh[0].(map[string]any)["name"] != ":status" || rh[3].(map[string]any)["value"] != "x=2" {
		t.Errorf("response headers %v", rh)
	}
	tm := e["timings"].(map[string]any)
	if tm["wait"] != 60.0 || tm["receive"] != 20.0 || tm["ssl"] != 30.0 || tm["dns"] != -1.0 {
		t.Errorf("timings %v", tm)
	}
	if e["comment"] != "cart (step 3)" || e["_john"].(map[string]any)["proxy"] == nil || e["_tls"].(map[string]any)["version"] != "TLS 1.3" {
		t.Errorf("extensions: %v %v %v", e["comment"], e["_john"], e["_tls"])
	}
	png := doc.Log.Entries[1]["response"].(map[string]any)["content"].(map[string]any)
	if png["encoding"] != "base64" || png["text"] != "iVBOR/8=" {
		t.Errorf("binary content %v", png)
	}
	failed := doc.Log.Entries[2]["response"].(map[string]any)
	if failed["status"] != 0.0 || failed["comment"] != "no response: dial tcp: refused" {
		t.Errorf("failed trip %v", failed)
	}
}

func TestUnopenableBodyKeepsTheInlineText(t *testing.T) {
	var buf bytes.Buffer
	recs := []map[string]any{{"http_method": "GET", "http_url": "https://a/", "http_status": 200.0, "resp_body": "head", "resp_body_ref": "0123456789a-deadbeef-000001:0:100"}}
	_ = Write(&buf, recs, func(string) ([]byte, error) { return nil, errors.New("s3 down") }, Options{})
	if !bytes.Contains(buf.Bytes(), []byte(`"text":"head"`)) || !bytes.Contains(buf.Bytes(), []byte("s3 down")) {
		t.Fatal(buf.String())
	}
}
