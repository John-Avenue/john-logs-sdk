package johnlogs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Body is a request or response body to keep whole. Put one in a record
// under the field it belongs to — "resp_body", "req_body" — and the client
// stores the bytes in the batch's pack (S3, on the gateway) instead of in the
// log row, and puts small search keys in the row beside it:
//
//	resp_body          the first Config.InlineBytes as text (the whole body when it fits)
//	resp_body_partial  true when resp_body is only the start
//	resp_body_size     length in bytes
//	resp_body_sha256   hash of the exact bytes: the same body anywhere has the same hash
//	resp_body_ref      where the whole body is: GET /v1/body?ref=… on the gateway
//	resp_body_shape    hash with the parts that change every time (numbers, ids,
//	                   tokens) blanked: the same page with a new nonce has the same shape
//	resp_body_kind     html, json, js, css, xml, text, image, font, binary
//	resp_body_title    an HTML page's <title>
//	resp_body_markers  signatures found in it (datadome, cloudflare_challenge, …)
//	resp_body_json_keys a JSON object's top-level keys
//
// Nothing is cut: the row's text is a search aid and the pack holds every
// byte. The client copies Data, so the caller may reuse it after Send.
type Body struct {
	Data []byte
	// Type is the Content-Type, when known; it decides Kind before sniffing.
	Type string
	// Group is what bodies that resemble each other share — an endpoint,
	// "GET https://host/route". The client compresses a body against the last
	// one stored in its group, which is what makes the hundredth copy of a page
	// cost a few hundred bytes. Empty uses the record's "message".
	Group string
}

// Marker names a signature to look for in bodies: the marker is listed when
// any of the strings appears (case-sensitive) in the first 512 KiB.
type Marker struct {
	Name string
	Any  []string
}

// DefaultMarkers are the walls and states worth finding without opening a
// body. A marker says the body MENTIONS the thing — a page that loads a
// captcha script on every visit carries its marker on every visit.
var DefaultMarkers = []Marker{
	{"cloudflare_challenge", []string{"/cdn-cgi/challenge-platform/", "cf-chl-", "Just a moment..."}},
	{"turnstile", []string{"challenges.cloudflare.com/turnstile"}},
	{"datadome", []string{"captcha-delivery.com"}},
	{"kasada", []string{"KPSDK", "x-kpsdk", "/ips.js"}},
	{"akamai", []string{"/_sec/cp_challenge", "sec-if-cpt", "bm-verify"}},
	{"perimeterx", []string{"px-captcha", "_pxCaptcha", "perimeterx", "/px/client/main.min.js"}},
	{"incapsula", []string{"_Incapsula_Resource", "incap_ses_"}},
	{"queueit", []string{"queue-it.net", "queueit", "QueueIT"}},
	{"hcaptcha", []string{"hcaptcha.com", "h-captcha"}},
	{"recaptcha", []string{"google.com/recaptcha", "recaptcha/api.js", "grecaptcha"}},
	{"access_denied", []string{"Access Denied", "Access denied"}},
	{"rate_limited", []string{"Too Many Requests", "too many requests", "Rate limit exceeded", "rate limit exceeded"}},
}

const markerScan = 512 << 10

// inspected is what a body puts in its row, apart from where it is stored.
type inspected struct {
	sha     [32]byte
	inline  string
	partial bool
	shape   string
	kind    string
	title   string
	markers string
	keys    string
}

func inspect(b Body, inlineMax int, markers *markerSet) inspected {
	in := inspected{sha: sha256.Sum256(b.Data)}
	in.inline, in.partial = inlineText(b.Data, inlineMax)
	in.kind = kindOf(b.Type, b.Data)
	in.shape, in.markers = scan(b.Data, markers)
	if in.kind == "html" {
		in.title = title(b.Data)
	}
	if in.kind == "json" {
		in.keys = jsonKeys(b.Data, 50)
	}
	return in
}

// fields writes the row's keys for a body stored at ref under field.
func (in inspected) fields(rec map[string]any, field string, size int, ref string) {
	if in.inline != "" {
		rec[field] = in.inline
		if in.partial {
			rec[field+"_partial"] = true
		}
	}
	rec[field+"_size"] = size
	rec[field+"_sha256"] = hex.EncodeToString(in.sha[:])
	if ref != "" {
		rec[field+"_ref"] = ref
	}
	rec[field+"_shape"] = in.shape
	rec[field+"_kind"] = in.kind
	putStr(rec, field+"_title", in.title)
	putStr(rec, field+"_markers", in.markers)
	putStr(rec, field+"_json_keys", in.keys)
}

func putStr(rec map[string]any, k, v string) {
	if v != "" {
		rec[k] = v
	}
}

// inlineText is the start of a text body, cut on a rune boundary; nothing for
// a body that is not UTF-8, where the start would not be searchable text.
func inlineText(b []byte, n int) (string, bool) {
	if n <= 0 || len(b) == 0 {
		return "", false
	}
	cut := b
	if len(cut) > n {
		cut = cut[:n]
		for i := 0; i < utf8.UTFMax && len(cut) > 0 && !utf8.Valid(cut); i++ {
			cut = cut[:len(cut)-1]
		}
	}
	if !utf8.Valid(cut) {
		return "", false
	}
	return string(cut), len(cut) < len(b)
}

// shape hashes the body with every run of word characters that holds a digit
// or is 16+ long replaced by one '#': ids, timestamps, nonces, cache-busting
// hashes and tokens. Two copies of a page that differ only in those share a
// shape; a page whose words, markup or keys changed does not. A JSON body's
// values that are short words ("ok", "sold_out") stay, so its shape tells
// states apart as well as schemas.
func shape(b []byte) string {
	const prime = 1099511628211
	h := uint64(14695981039346656037) // FNV-1a, inlined: this runs over every byte of every body
	for i := 0; i < len(b); {
		c := b[i]
		if wordClass[c] == 0 {
			h = (h ^ uint64(c)) * prime
			i++
			continue
		}
		j, digit := i, false
		for j < len(b) && wordClass[b[j]] != 0 {
			digit = digit || wordClass[b[j]] == 2
			j++
		}
		if digit || j-i >= 16 {
			h = (h ^ '#') * prime
		} else {
			for _, w := range b[i:j] {
				h = (h ^ uint64(w)) * prime
			}
		}
		i = j
	}
	var out [8]byte
	for k := range out {
		out[k] = byte(h >> (56 - 8*k))
	}
	return hex.EncodeToString(out[:])
}

// scan is shape and markerSet.find in one pass: the two per-byte loops are
// independent, so run together the CPU overlaps them, and the body is read
// once. It must agree with both (TestScanAgrees).
func scan(b []byte, m *markerSet) (string, string) {
	if m == nil || len(m.names) == 0 {
		return shape(b), ""
	}
	const prime = 1099511628211
	h := uint64(14695981039346656037)
	var hit uint64
	st, next, mask := int32(0), m.next, m.mask
	scanTo := min(len(b), markerScan)
	run, digit := 0, false // the word run being read, and whether it holds a digit
	endRun := func(i int) {
		if run == 0 {
			return
		}
		if digit || run >= 16 {
			h = (h ^ '#') * prime
		} else {
			for _, w := range b[i-run : i] {
				h = (h ^ uint64(w)) * prime
			}
		}
		run, digit = 0, false
	}
	for i, c := range b {
		if i < scanTo {
			st = next[int(st)<<8|int(c)]
			hit |= mask[st]
		}
		switch wordClass[c] {
		case 0:
			endRun(i)
			h = (h ^ uint64(c)) * prime
		case 2:
			digit = true
			run++
		default:
			run++
		}
	}
	endRun(len(b))
	var out [8]byte
	for k := range out {
		out[k] = byte(h >> (56 - 8*k))
	}
	return hex.EncodeToString(out[:]), m.namesOf(hit)
}

func (m *markerSet) namesOf(hit uint64) string {
	if hit == 0 {
		return ""
	}
	var found []string
	for i, name := range m.names {
		if i < 64 && hit&(1<<i) != 0 {
			found = append(found, name)
		}
	}
	return strings.Join(found, ",")
}

// wordClass: 0 not a word byte, 1 word byte, 2 digit.
var wordClass = func() (t [256]byte) {
	for c := range 256 {
		switch {
		case c >= '0' && c <= '9':
			t[c] = 2
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= 0x80,
			c == '_', c == '-', c == '+', c == '/', c == '=', c == '%':
			t[c] = 1
		}
	}
	return t
}()

func kindOf(contentType string, b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case strings.Contains(mt, "json"):
		return "json"
	case strings.Contains(mt, "html"):
		return "html"
	case strings.Contains(mt, "javascript"), strings.Contains(mt, "ecmascript"):
		return "js"
	case strings.Contains(mt, "css"):
		return "css"
	case strings.Contains(mt, "xml"):
		return "xml"
	case strings.HasPrefix(mt, "image/"):
		return "image"
	case strings.HasPrefix(mt, "font/"), strings.Contains(mt, "font"):
		return "font"
	case strings.Contains(mt, "protobuf"), strings.Contains(mt, "grpc"):
		return "protobuf"
	}
	head := bytes.TrimLeft(b[:min(len(b), 1024)], " \t\r\n\xef\xbb\xbf")
	if len(head) > 0 && (head[0] == '{' || head[0] == '[') {
		return "json"
	}
	lower := bytes.ToLower(head[:min(len(head), 512)])
	if bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) || bytes.Contains(lower, []byte("<head")) {
		return "html"
	}
	switch sniff := http.DetectContentType(b[:min(len(b), 512)]); {
	case strings.HasPrefix(sniff, "image/"):
		return "image"
	case strings.HasPrefix(sniff, "font/"):
		return "font"
	case strings.HasPrefix(sniff, "text/xml"):
		return "xml"
	}
	if t, _ := inlineText(b, 4096); t != "" {
		return "text"
	}
	return "binary"
}

// title is an HTML page's <title>, entities decoded, at most 200 characters.
func title(b []byte) string {
	head := b[:min(len(b), 256<<10)]
	i := indexFold(head, "<title")
	if i < 0 {
		return ""
	}
	rest := head[i+len("<title"):]
	gt := bytes.IndexByte(rest, '>')
	if gt < 0 {
		return ""
	}
	rest = rest[gt+1:]
	end := indexFold(rest, "</title")
	if end < 0 {
		return ""
	}
	t := strings.Join(strings.Fields(html.UnescapeString(string(rest[:end]))), " ")
	if len(t) > 200 {
		t, _ = inlineText([]byte(t), 200)
	}
	return t
}

// indexFold finds a tag ("<title") case-insensitively.
func indexFold(b []byte, tag string) int {
	needle := []byte(tag)
	for i := 0; i+len(needle) <= len(b); {
		j := bytes.IndexByte(b[i:], '<')
		if j < 0 || i+j+len(needle) > len(b) {
			return -1
		}
		i += j
		if bytes.EqualFold(b[i:i+len(needle)], needle) {
			return i
		}
		i++
	}
	return -1
}

// markerSet finds every marker in one pass over a body (Aho-Corasick over
// bytes): a dozen markers by bytes.Contains was 40-odd scans of every body
// and the largest cost of logging one.
type markerSet struct {
	names []string
	next  []int32  // state*256+byte -> state
	out   [][]int  // state -> marker indexes that end here
	mask  []uint64 // out as a bit per marker (the first 64), read on every byte
}

func compileMarkers(ms []Marker) *markerSet {
	m := &markerSet{next: make([]int32, 256), out: [][]int{nil}}
	for i, mk := range ms {
		m.names = append(m.names, mk.Name)
		for _, pat := range mk.Any {
			st := int32(0)
			for k := 0; k < len(pat); k++ {
				c := int32(pat[k])
				if m.next[st*256+c] == 0 {
					m.next = append(m.next, make([]int32, 256)...)
					m.out = append(m.out, nil)
					m.next[st*256+c] = int32(len(m.out) - 1)
				}
				st = m.next[st*256+c]
			}
			m.out[st] = append(m.out[st], i)
		}
	}
	// Breadth-first: fail links folded into the table, outputs merged.
	fail := make([]int32, len(m.out))
	var queue []int32
	for c := range 256 {
		if s := m.next[c]; s != 0 {
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		st := queue[0]
		queue = queue[1:]
		m.out[st] = append(m.out[st], m.out[fail[st]]...)
		for c := int32(0); c < 256; c++ {
			nx := m.next[st*256+c]
			if nx != 0 {
				fail[nx] = m.next[fail[st]*256+c]
				queue = append(queue, nx)
			} else {
				m.next[st*256+c] = m.next[fail[st]*256+c]
			}
		}
	}
	m.mask = make([]uint64, len(m.out))
	for st, idx := range m.out {
		for _, i := range idx {
			if i < 64 {
				m.mask[st] |= 1 << i
			}
		}
	}
	return m
}

func (m *markerSet) find(b []byte) string {
	if m == nil || len(m.names) == 0 {
		return ""
	}
	head := b[:min(len(b), markerScan)]
	var hit uint64
	st, next, mask := int32(0), m.next, m.mask
	for _, c := range head {
		st = next[int(st)<<8|int(c)]
		hit |= mask[st]
	}
	return m.namesOf(hit)
}

func findMarkers(b []byte, ms []Marker) string { return compileMarkers(ms).find(b) }

// jsonKeys lists a JSON object's top-level keys in order, at most max, by a
// single scan that tracks depth and strings — a multi-megabyte catalogue is
// read once and nothing in it is decoded.
func jsonKeys(b []byte, maxKeys int) string {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	if i >= len(b) || b[i] != '{' {
		return ""
	}
	var keys []string
	depth := 0
	expectKey := false
	for ; i < len(b); i++ {
		switch c := b[i]; c {
		case '{', '[':
			depth++
			expectKey = depth == 1 && c == '{'
		case '}', ']':
			depth--
			if depth == 0 {
				return strings.Join(keys, ",")
			}
		case ',':
			expectKey = depth == 1
		case '"':
			j := i + 1
			for j < len(b) && b[j] != '"' {
				if b[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(b) {
				return strings.Join(keys, ",")
			}
			if depth == 1 && expectKey {
				keys = append(keys, string(b[i+1:j]))
				expectKey = false
				if len(keys) >= maxKeys {
					return strings.Join(keys, ",")
				}
			}
			i = j
		}
	}
	return strings.Join(keys, ",")
}
