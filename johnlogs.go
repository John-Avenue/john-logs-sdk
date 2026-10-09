// Package johnlogs ships structured logs to a john-logs gateway.
//
// It is a log/slog handler: log with the standard library, and records go to
// the console (optional) and to the gateway in gzipped batches. Shipping never
// blocks the caller and never fails loudly: a full buffer or a dead gateway
// drops records and counts them.
//
//	logs := johnlogs.New(johnlogs.FromEnv("my-app"))
//	defer logs.Close(context.Background())
//	slog.SetDefault(logs.Logger())
//
//	ctx, end := johnlogs.Start(ctx, "checkout", "task_id", id)
//	slog.InfoContext(ctx, "queue passed", "position", 12)
//	end(err)
//
// Every record carries the fields put on its context with [With] and [Start],
// so one session or one task can be pulled out of the logs by a single field.
package johnlogs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LevelTrace is below Debug: whole request and response bodies, every step.
// Check logger.Enabled(ctx, LevelTrace) before building anything expensive.
const LevelTrace = slog.Level(-8)

// Config says where records go and what every record carries.
type Config struct {
	// URL is the gateway base, e.g. https://logs.example.com. Empty turns
	// shipping off; the console handler still works.
	URL   string
	Token string // write-only ingest token

	Service string
	Env     string
	Version string
	Host    string         // defaults to os.Hostname
	Fields  map[string]any // added to every record (instance, user, …)

	// Level is the minimum level shipped. Defaults to Info. Pass a
	// *slog.LevelVar to change it while running.
	Level slog.Leveler
	// Console, when set, also receives every record (at its own level).
	Console slog.Handler
	// AddSource records the caller as "source" (file:line).
	AddSource bool

	// Secret says whether a field name holds a credential; its value is
	// replaced with "[redacted]" at any depth. Defaults to [Secret].
	Secret func(key string) bool

	MaxField   int           // longest string kept per field, default 256 KiB
	BatchSize  int           // records per request, default 500
	FlushEvery time.Duration // default 1s
	Buffer     int           // records held in memory, default 8192
	HTTPClient *http.Client
}

// FromEnv reads JOHN_LOGS_URL, JOHN_LOGS_TOKEN, JOHN_LOGS_ENV and
// JOHN_LOGS_LEVEL (trace, debug, info, warn, error).
func FromEnv(service string) Config {
	lv := new(slog.LevelVar)
	lv.Set(ParseLevel(os.Getenv("JOHN_LOGS_LEVEL")))
	return Config{
		URL:     os.Getenv("JOHN_LOGS_URL"),
		Token:   os.Getenv("JOHN_LOGS_TOKEN"),
		Env:     os.Getenv("JOHN_LOGS_ENV"),
		Service: service,
		Level:   lv,
	}
}

// ParseLevel reads trace, debug, info, warn or error. Anything else is Info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return LevelTrace
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// LevelName is the lowercase name a level ships as.
func LevelName(l slog.Level) string {
	switch {
	case l < slog.LevelDebug:
		return "trace"
	case l < slog.LevelInfo:
		return "debug"
	case l < slog.LevelWarn:
		return "info"
	case l < slog.LevelError:
		return "warn"
	}
	return "error"
}

// Client batches records to the gateway. The zero value and nil are valid
// and ship nothing.
type Client struct {
	cfg     Config
	base    map[string]any
	queue   chan map[string]any
	flushes chan chan struct{}
	done    chan struct{}
	closed  atomic.Bool
	dropped atomic.Int64
	sent    atomic.Int64
	wg      sync.WaitGroup
}

// New starts a client. Close it on shutdown so the last batch goes out.
func New(cfg Config) *Client {
	if cfg.Level == nil {
		cfg.Level = slog.LevelInfo
	}
	if cfg.Secret == nil {
		cfg.Secret = Secret
	}
	if cfg.MaxField <= 0 {
		cfg.MaxField = 256 << 10
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = time.Second
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = 8192
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.Host == "" {
		cfg.Host, _ = os.Hostname()
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	c := &Client{cfg: cfg, base: map[string]any{}}
	for k, v := range map[string]string{"service": cfg.Service, "env": cfg.Env, "version": cfg.Version, "host": cfg.Host} {
		if v != "" {
			c.base[k] = v
		}
	}
	for k, v := range cfg.Fields {
		c.base[k] = v
	}
	if cfg.URL == "" {
		return c
	}
	c.queue = make(chan map[string]any, cfg.Buffer)
	c.flushes = make(chan chan struct{})
	c.done = make(chan struct{})
	c.wg.Add(1)
	go c.run()
	return c
}

// Shipping reports whether records leave the process.
func (c *Client) Shipping() bool { return c != nil && c.queue != nil && !c.closed.Load() }

// Dropped is how many records were lost to a full buffer or a failed send.
func (c *Client) Dropped() int64 {
	if c == nil {
		return 0
	}
	return c.dropped.Load()
}

// Sent is how many records the gateway accepted.
func (c *Client) Sent() int64 {
	if c == nil {
		return 0
	}
	return c.sent.Load()
}

// Send ships one record as given, after redaction and clipping. service,
// env, version, host and the Config's Fields are filled in when absent;
// "_timestamp" (unix µs) defaults to now. Never blocks.
func (c *Client) Send(rec map[string]any) {
	if !c.Shipping() {
		return
	}
	defer func() { _ = recover() }() // a panicking String() must not take the caller down
	out := make(map[string]any, len(rec)+len(c.base)+2)
	for k, v := range c.base {
		out[k] = v
	}
	for k, v := range rec {
		out[k] = c.clean(k, v)
	}
	if _, ok := out["_timestamp"]; !ok {
		out["_timestamp"] = time.Now().UnixMicro()
	}
	select {
	case c.queue <- out:
	default:
		c.dropped.Add(1)
	}
}

// clean redacts secrets and clips long strings at any depth.
func (c *Client) clean(key string, v any) any {
	if c.cfg.Secret(key) {
		if v == nil || v == "" {
			return v
		}
		return "[redacted]"
	}
	switch x := v.(type) {
	case string:
		if len(x) > c.cfg.MaxField {
			return x[:c.cfg.MaxField] + fmt.Sprintf("…[+%d bytes]", len(x)-c.cfg.MaxField)
		}
	case []byte:
		return c.clean(key, string(x))
	case error:
		return x.Error()
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, vv := range x {
			m[k] = c.clean(k, vv)
		}
		return m
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, vv := range x {
			m[k] = c.clean(k, vv)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, vv := range x {
			s[i] = c.clean(key, vv)
		}
		return s
	case time.Duration:
		return x.Milliseconds()
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case fmt.Stringer:
		return x.String()
	}
	return v
}

// Flush waits until everything sent so far has been posted, or ctx ends.
func (c *Client) Flush(ctx context.Context) error {
	if !c.Shipping() {
		return nil
	}
	ack := make(chan struct{})
	select {
	case c.flushes <- ack:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close flushes and stops the client. Later records are dropped silently.
func (c *Client) Close(ctx context.Context) error {
	if !c.Shipping() || !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(c.done)
	wait := make(chan struct{})
	go func() { c.wg.Wait(); close(wait) }()
	select {
	case <-wait:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) run() {
	defer c.wg.Done()
	batch := make([]map[string]any, 0, c.cfg.BatchSize)
	tick := time.NewTicker(c.cfg.FlushEvery)
	defer tick.Stop()
	flush := func() {
		if len(batch) > 0 {
			c.post(batch)
			batch = batch[:0]
		}
	}
	drain := func() {
		for {
			select {
			case r := <-c.queue:
				batch = append(batch, r)
				if len(batch) >= c.cfg.BatchSize {
					flush()
				}
			default:
				flush()
				return
			}
		}
	}
	for {
		select {
		case r := <-c.queue:
			batch = append(batch, r)
			if len(batch) >= c.cfg.BatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		case ack := <-c.flushes:
			drain()
			close(ack)
		case <-c.done:
			drain()
			return
		}
	}
}

const maxRequest = 8 << 20 // uncompressed bytes per request; the gateway takes 64 MiB

// post sends a batch, split so no request is too large. A batch that cannot
// be delivered is dropped and counted; the count rides on the next record.
func (c *Client) post(batch []map[string]any) {
	if d := c.dropped.Swap(0); d > 0 {
		batch[0]["dropped_since_last"] = d
	}
	var part []json.RawMessage
	size := 0
	for _, r := range batch {
		b, err := json.Marshal(r)
		if err != nil {
			c.dropped.Add(1)
			continue
		}
		if len(part) > 0 && size+len(b) > maxRequest {
			c.deliver(part)
			part, size = nil, 0
		}
		part, size = append(part, b), size+len(b)+1
	}
	if len(part) > 0 {
		c.deliver(part)
	}
}

func (c *Client) deliver(records []json.RawMessage) {
	body, _ := json.Marshal(records)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(body)
	_ = zw.Close()
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * time.Second):
			case <-c.done: // shutting down: one last try, no waiting
			}
		}
		err := c.request(gz.Bytes())
		if err == nil {
			c.sent.Add(int64(len(records)))
			return
		}
		if errors.Is(err, errPermanent) {
			break
		}
	}
	c.dropped.Add(int64(len(records)))
}

var errPermanent = errors.New("refused")

func (c *Client) request(gz []byte) error {
	req, err := http.NewRequest(http.MethodPost, c.cfg.URL+"/v1/logs", bytes.NewReader(gz))
	if err != nil {
		return errPermanent
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	res, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	switch {
	case res.StatusCode < 300:
		return nil
	case res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("gateway %d", res.StatusCode)
	}
	return errPermanent // 4xx: a bad token or a bad batch will not improve
}

// Secret is the default credential check: names containing token, password,
// secret, cookie, authorization, api key, private key, or card fields.
func Secret(key string) bool {
	k := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(key))
	for _, s := range []string{"token", "password", "passwd", "secret", "cookie", "authorization", "apikey", "privatekey", "cardnumber", "cvv", "cvc", "mnemonic", "seedphrase"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}
