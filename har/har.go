// Package har turns one session's log records back into an HTTP Archive, so a
// run can be opened in powhttp, Charles or a browser's devtools and its
// requests replayed.
//
// The records are john-logs' HTTP records (docs/conventions.md in john-logs):
// http_method, http_url, req_headers as JSON text, req_header_order,
// resp_body_ref, timings, tls_*, h2_*, … Every record without http_method —
// console lines, step changes, the session's start and end — goes into
// log._events, in order, so nothing the session logged is lost on the way.
//
// Version "1.3" (the default) is what powhttp recommends: HAR 1.2 plus
// postData.encoding, so a binary request body survives. "1.2" leaves that
// field out and carries a binary request body as base64 with a comment
// saying so — Charles reads 1.2.
//
// Header order is the wire's: req_header_order (and h2_pseudo_order for the
// HTTP/2 pseudo-headers, which go first, as Chrome's own HAR has them). What
// a HAR cannot carry natively — the TLS handshake, the HTTP/2 SETTINGS and
// priority, the proxy, the task and step — rides in _tls, _h2 and _john.
package har

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Open returns the whole body a ref names (wire.Open on the gateway).
type Open func(ref string) ([]byte, error)

// Options shape the archive.
type Options struct {
	Version string // "1.3" (default) or "1.2"
	Creator string // log.creator.name, default "john-logs"
	Comment string // log.comment
}

type nv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type entry struct {
	Started         string         `json:"startedDateTime"`
	Time            float64        `json:"time"`
	Request         request        `json:"request"`
	Response        response       `json:"response"`
	Cache           struct{}       `json:"cache"`
	Timings         timings        `json:"timings"`
	ServerIPAddress string         `json:"serverIPAddress,omitempty"`
	Connection      string         `json:"connection,omitempty"`
	Comment         string         `json:"comment,omitempty"`
	TLS             map[string]any `json:"_tls,omitempty"`
	H2              map[string]any `json:"_h2,omitempty"`
	John            map[string]any `json:"_john,omitempty"`
}

type request struct {
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	HTTPVersion string    `json:"httpVersion"`
	Cookies     []nv      `json:"cookies"`
	Headers     []nv      `json:"headers"`
	QueryString []nv      `json:"queryString"`
	PostData    *postData `json:"postData,omitempty"`
	HeadersSize int       `json:"headersSize"`
	BodySize    int       `json:"bodySize"`
}

type postData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type response struct {
	Status      int     `json:"status"`
	StatusText  string  `json:"statusText"`
	HTTPVersion string  `json:"httpVersion"`
	Cookies     []nv    `json:"cookies"`
	Headers     []nv    `json:"headers"`
	Content     content `json:"content"`
	RedirectURL string  `json:"redirectURL"`
	HeadersSize int     `json:"headersSize"`
	BodySize    int     `json:"bodySize"`
	Comment     string  `json:"comment,omitempty"`
}

type content struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type timings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
	SSL     float64 `json:"ssl"`
}

// Write writes the archive for records, which should be one session's, in
// order (session_seq). Bodies are opened one entry at a time, so memory is one
// body, not the session. A body that cannot be opened becomes a comment on
// its entry; the archive is still written.
func Write(w io.Writer, records []map[string]any, open Open, opt Options) error {
	i := 0
	return WriteFrom(w, func() (map[string]any, error) {
		if i == len(records) {
			return nil, io.EOF
		}
		i++
		return records[i-1], nil
	}, open, opt)
}

// WriteFrom is Write over records pulled one at a time — next returns io.EOF
// after the last — so a session of a hundred thousand records streams from
// the log to the archive without being held. Only the non-HTTP records
// (log._events) are kept until the end, and they are small.
func WriteFrom(w io.Writer, next func() (map[string]any, error), open Open, opt Options) error {
	if opt.Version == "" {
		opt.Version = "1.3"
	}
	if opt.Creator == "" {
		opt.Creator = "john-logs"
	}
	// Written by hand around the entries so they stream: the archive's
	// envelope, then each entry encoded and written as it is built.
	head := fmt.Sprintf(`{"log":{"version":%q,"creator":{"name":%q,"version":"1"},"pages":[],`, opt.Version, opt.Creator)
	if opt.Comment != "" {
		c, _ := json.Marshal(opt.Comment)
		head += `"comment":` + string(c) + `,`
	}
	if _, err := io.WriteString(w, head+`"entries":[`); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	var events []map[string]any
	n := 0
	for {
		rec, err := next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if str(rec, "http_method") == "" {
			events = append(events, rec)
			continue
		}
		e := build(rec, open, opt)
		// The step the request was made in, where powhttp and Charles show
		// an entry's note.
		if step := str(rec, "step"); step != "" {
			e.Comment = fmt.Sprintf("%s (step %d)", step, int(num(rec, "step_idx")))
		}
		if n > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := enc.Encode(e); err != nil {
			return err
		}
		n++
	}
	if _, err := io.WriteString(w, `],"_events":`); err != nil {
		return err
	}
	if events == nil {
		events = []map[string]any{}
	}
	if err := enc.Encode(events); err != nil {
		return err
	}
	_, err := io.WriteString(w, "}}\n")
	return err
}

func build(rec map[string]any, open Open, opt Options) entry {
	proto := httpVersion(str(rec, "http_proto"))
	dur := num(rec, "duration_ms")
	end := time.UnixMicro(int64(num(rec, "_timestamp")))
	started := end.Add(-time.Duration(dur * float64(time.Millisecond)))

	reqHeaders := headers(str(rec, "req_headers"), list(str(rec, "req_header_order")))
	respHeaders := headers(str(rec, "resp_headers"), list(str(rec, "resp_header_order")))
	u, _ := url.Parse(str(rec, "http_url"))
	if proto == "HTTP/2" && u != nil {
		reqHeaders = append(pseudo(str(rec, "h2_pseudo_order"), str(rec, "http_method"), u), reqHeaders...)
		if st := int(num(rec, "http_status")); st > 0 {
			respHeaders = append([]nv{{":status", fmt.Sprint(st)}}, respHeaders...)
		}
	}

	e := entry{
		Started:    started.UTC().Format("2006-01-02T15:04:05.000Z"),
		Time:       dur,
		Connection: connection(rec),
		Request: request{
			Method: str(rec, "http_method"), URL: str(rec, "http_url"), HTTPVersion: proto,
			Cookies: cookies(str(rec, "req_cookies")), Headers: reqHeaders, QueryString: query(u),
			HeadersSize: -1, BodySize: int(num(rec, "req_body_size")),
		},
		Response: response{
			Status: int(num(rec, "http_status")), HTTPVersion: proto,
			Cookies: cookies(str(rec, "resp_cookies")), Headers: respHeaders,
			RedirectURL: header(respHeaders, "location"), HeadersSize: -1,
			BodySize: int(num(rec, "resp_body_size")),
		},
		Timings: timing(rec, dur),
	}
	e.Response.StatusText = http.StatusText(e.Response.Status)
	if e.Response.Status == 0 {
		e.Response.HTTPVersion = ""
		e.Response.Comment = "no response: " + str(rec, "error")
	}

	if body, note := bodyOf(rec, "req_body", open); body != nil || note != "" {
		pd := &postData{MimeType: header(reqHeaders, "content-type"), Comment: note}
		if utf8.Valid(body) {
			pd.Text = string(body)
		} else {
			pd.Text = base64.StdEncoding.EncodeToString(body)
			if opt.Version == "1.2" {
				pd.Comment = strings.TrimSpace(pd.Comment + " binary body, base64")
			} else {
				pd.Encoding = "base64"
			}
		}
		e.Request.PostData = pd
	}
	body, note := bodyOf(rec, "resp_body", open)
	e.Response.Content = content{Size: len(body), MimeType: header(respHeaders, "content-type"), Comment: note}
	if body == nil {
		e.Response.Content.Size = int(num(rec, "resp_body_size"))
	} else if utf8.Valid(body) {
		e.Response.Content.Text = string(body)
	} else {
		e.Response.Content.Text, e.Response.Content.Encoding = base64.StdEncoding.EncodeToString(body), "base64"
	}
	if e.Response.Content.MimeType == "" {
		e.Response.Content.MimeType = "x-unknown"
	}
	if mt, _, err := mime.ParseMediaType(e.Response.Content.MimeType); err == nil && mt == "" {
		e.Response.Content.MimeType = "x-unknown"
	}

	e.TLS = pick(rec, map[string]string{
		"tls_preset": "preset", "tls_version": "version", "tls_cipher": "cipher", "tls_alpn": "alpn",
		"tls_sni": "sni", "tls_resumed": "resumed", "tls_ja3": "ja3", "tls_ja3_hash": "ja3_hash",
		"tls_ja4": "ja4", "tls_ja4_r": "ja4_r", "tls_client_hello": "client_hello",
	})
	e.H2 = pick(rec, map[string]string{
		"h2_settings": "settings", "h2_window_update": "window_update", "h2_priority": "priority",
		"h2_pseudo_order": "pseudo_order", "h2_stream_id": "stream_id",
	})
	e.John = pick(rec, map[string]string{
		"req_id": "req_id", "session_id": "session_id", "session_seq": "session_seq", "task_id": "task_id",
		"module": "module", "step": "step", "step_idx": "step_idx", "proxy": "proxy", "error": "error",
		"http_error_code": "error_code", "conn_reused": "conn_reused", "conn_id": "conn_id",
		"remote_addr": "remote_addr", "client_id": "client_id", "resp_body_markers": "markers",
		"resp_body_sha256": "resp_body_sha256", "req_body_sha256": "req_body_sha256",
	})
	if ip := str(rec, "server_ip"); ip != "" {
		e.ServerIPAddress = ip
	}
	return e
}

// connection is the entry's HAR connection: the transport's connection id,
// shared by every exchange it carried, or the HTTP client's id for records
// made before connections were named.
func connection(rec map[string]any) string {
	if id := num(rec, "conn_id"); id > 0 {
		return fmt.Sprintf("%.0f", id)
	}
	return str(rec, "client_id")
}

// bodyOf is a record's whole body: opened from its ref, or, for a record
// without one (shipped before bodies moved to packs, or small enough to be
// whole in the row), its inline text.
func bodyOf(rec map[string]any, field string, open Open) ([]byte, string) {
	if ref := str(rec, field+"_ref"); ref != "" && open != nil {
		b, err := open(ref)
		if err == nil {
			return b, ""
		}
		inline := str(rec, field)
		return []byte(inline), fmt.Sprintf("whole body unavailable (%v); this is the record's first %d bytes", err, len(inline))
	}
	inline, ok := rec[field].(string)
	if !ok {
		return nil, ""
	}
	if str(rec, field+"_encoding") == "base64" { // records from before packs
		if b, err := base64.StdEncoding.DecodeString(inline); err == nil {
			return b, ""
		}
	}
	if rec[field+"_partial"] == true {
		return []byte(inline), "only the record's first bytes; the whole body had no ref"
	}
	return []byte(inline), ""
}

func timing(rec map[string]any, dur float64) timings {
	t := timings{Blocked: -1, DNS: -1, Connect: -1, SSL: -1}
	if _, ok := rec["dns_ms"]; ok {
		t.DNS = num(rec, "dns_ms")
	}
	if _, ok := rec["connect_ms"]; ok {
		t.Connect = num(rec, "connect_ms")
	}
	if _, ok := rec["tls_ms"]; ok {
		t.SSL = num(rec, "tls_ms")
	}
	setup := max(t.DNS, 0) + max(t.Connect, 0) + max(t.SSL, 0)
	if _, ok := rec["ttfb_ms"]; ok && num(rec, "ttfb_ms") >= setup {
		ttfb := num(rec, "ttfb_ms")
		t.Wait = ttfb - setup
		t.Receive = max(dur-ttfb, 0)
	} else {
		t.Wait = max(dur-setup, 0)
	}
	return t
}

func httpVersion(proto string) string {
	switch proto {
	case "h2":
		return "HTTP/2"
	case "h3":
		return "HTTP/3"
	case "h1", "":
		return "HTTP/1.1"
	}
	return proto
}

// headers rebuilds a header block in wire order from the record's JSON text
// (a value is a string, or an array when the header repeated) and its order
// list; headers the order does not name follow, sorted.
func headers(jsonText string, order []string) []nv {
	if jsonText == "" {
		return []nv{}
	}
	var m map[string]any
	if json.Unmarshal([]byte(jsonText), &m) != nil {
		return []nv{}
	}
	byLower := map[string]string{}
	for k := range m {
		byLower[strings.ToLower(k)] = k
	}
	out := make([]nv, 0, len(m))
	done := map[string]bool{}
	emit := func(key, wireName string) {
		switch v := m[key].(type) {
		case string:
			out = append(out, nv{wireName, v})
		case []any:
			for _, x := range v {
				out = append(out, nv{wireName, fmt.Sprint(x)})
			}
		}
		done[key] = true
	}
	for _, name := range order {
		if key, ok := byLower[strings.ToLower(name)]; ok && !done[key] {
			emit(key, name)
		}
	}
	var rest []string
	for k := range m {
		if !done[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		emit(k, k)
	}
	return out
}

// pseudo is the HTTP/2 pseudo-headers in the order sent ("m,a,s,p").
func pseudo(order, method string, u *url.URL) []nv {
	if order == "" {
		order = "m,a,s,p"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	var out []nv
	for _, p := range strings.Split(order, ",") {
		switch strings.TrimSpace(p) {
		case "m":
			out = append(out, nv{":method", method})
		case "a":
			out = append(out, nv{":authority", u.Host})
		case "s":
			out = append(out, nv{":scheme", u.Scheme})
		case "p":
			out = append(out, nv{":path", path})
		}
	}
	return out
}

func cookies(jsonText string) []nv {
	if jsonText == "" {
		return []nv{}
	}
	var m map[string]string
	if json.Unmarshal([]byte(jsonText), &m) != nil {
		return []nv{}
	}
	out := make([]nv, 0, len(m))
	for k, v := range m {
		out = append(out, nv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func query(u *url.URL) []nv {
	out := []nv{}
	if u == nil || u.RawQuery == "" {
		return out
	}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		k, v, _ := strings.Cut(pair, "=")
		ku, err1 := url.QueryUnescape(k)
		vu, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			ku, vu = k, v
		}
		out = append(out, nv{ku, vu})
	}
	return out
}

func header(hs []nv, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func list(jsonText string) []string {
	var out []string
	_ = json.Unmarshal([]byte(jsonText), &out)
	return out
}

func pick(rec map[string]any, keys map[string]string) map[string]any {
	out := map[string]any{}
	for from, to := range keys {
		if v, ok := rec[from]; ok && v != nil && v != "" {
			out[to] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func str(rec map[string]any, k string) string {
	s, _ := rec[k].(string)
	return s
}

func num(rec map[string]any, k string) float64 {
	switch v := rec[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	}
	return 0
}
