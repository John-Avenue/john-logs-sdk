// Package johnlogs ships structured logs to a john-logs gateway.
//
// It is a log/slog handler: log with the standard library, and records go to
// the console (optional) and to the gateway in batches. Shipping never blocks
// the caller and never panics it.
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
//
// Records are sealed into a batch every Config.FlushEvery, or sooner when a
// batch reaches Config.BatchSize records or Config.BatchBytes; what does not
// fit waits for the next batch. Sealed batches wait in the spool — on disk when
// Config.Spool is set — until the gateway accepts them, retried for as long as
// it takes. Request and response bodies ([Body]) are stored whole beside the
// records, compressed against the last similar body, and the records carry
// search keys for them. The format is package wire; PROTOCOL.md describes it.
package johnlogs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/john-avenue/john-logs-sdk/wire"
)

// Version is this SDK's version, sent with every batch.
const Version = "0.2.0"

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

	MaxField int // longest string kept per field (not Body), default 256 KiB

	// Batching. A batch is sealed every FlushEvery (default 500ms), or as soon
	// as it holds BatchSize records (default 2000) or BatchBytes of records
	// (default 8 MiB, uncompressed) or PackBytes of compressed bodies (default
	// 32 MiB). A record that would cross a limit opens the next batch.
	FlushEvery time.Duration
	BatchSize  int
	BatchBytes int
	PackBytes  int

	// Spool is a directory where sealed batches wait until the gateway takes
	// them. With it, nothing is lost to a slow or dead gateway, a crash or a
	// restart: the next run sends what the last one could not. Without it,
	// batches wait in memory and die with the process.
	Spool string
	// SpoolMax caps the spool: default 10 GiB on disk, 256 MiB in memory.
	SpoolMax int64
	// WhenFull is what happens at SpoolMax: DropOldest (default) or
	// DropNewest. Either way the loss is counted, reported by Stats and
	// OnState, and announced to the gateway.
	WhenFull FullPolicy
	// Uploads is how many batches may be on their way at once (default 4).
	// The client starts at 2 and backs off to 1 while the gateway struggles.
	Uploads int

	// InlineBytes is how much of a Body's text the record itself carries for
	// searching (default 4096; negative for none). The whole body is stored
	// regardless.
	InlineBytes int
	// Markers are the signatures looked for in bodies; nil is DefaultMarkers.
	Markers []Marker
	// BaseMemory caps the bodies kept as compression bases (default 64 MiB).
	BaseMemory int64

	// OnState is called, from a background goroutine, whenever Stats().State
	// changes — so an app can show "logs are 2 GB behind" while it matters.
	OnState func(Stats)
	// StatusEvery is how often the client logs its own state as a record,
	// "johnlogs status" (default 1m; negative turns it off).
	StatusEvery time.Duration

	HTTPClient *http.Client

	// Buffer is no longer used: memory is bounded by SpoolMax.
	Buffer int
}

// FromEnv reads JOHN_LOGS_URL, JOHN_LOGS_TOKEN, JOHN_LOGS_ENV,
// JOHN_LOGS_LEVEL (trace, debug, info, warn, error) and JOHN_LOGS_SPOOL.
func FromEnv(service string) Config {
	lv := new(slog.LevelVar)
	lv.Set(ParseLevel(os.Getenv("JOHN_LOGS_LEVEL")))
	return Config{
		URL:     os.Getenv("JOHN_LOGS_URL"),
		Token:   os.Getenv("JOHN_LOGS_TOKEN"),
		Env:     os.Getenv("JOHN_LOGS_ENV"),
		Spool:   os.Getenv("JOHN_LOGS_SPOOL"),
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
	cfg  Config
	base map[string]any
	id   string // this client, in batch ids and request headers

	spool   *spool
	bases   *bases
	markers *markerSet
	zenc    *zstd.Encoder

	mu          sync.Mutex // the open batch
	open        *openBatch
	seq         uint64
	lastRecs    int // the last batch's records length, to size the next
	seals       chan *openBatch
	sealsClosed bool // under mu: Close has closed seals

	wake     chan struct{}
	done     chan struct{}
	stopped  chan struct{}
	sealerWG sync.WaitGroup
	wg       sync.WaitGroup
	closed   atomic.Bool

	sent        atomic.Int64
	dropped     atomic.Int64 // since start
	unreported  atomic.Int64 // dropped and not yet in a batch header
	quarantined atomic.Int64
	sealing     atomic.Int64 // batches handed off and not yet in the spool
	lastDrop    atomic.Int64 // unix ns of the last record lost

	reqCtx    context.Context // cancelled by Close, so a stuck request cannot hold it
	cancelReq context.CancelFunc

	st upState
}

type openBatch struct {
	id      string
	seq     uint64
	gen     uint64
	recs    []byte
	n       int
	pack    []byte
	bodies  int
	bodyRaw int64
	created time.Time
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
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 500 * time.Millisecond
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 2000
	}
	if cfg.BatchBytes <= 0 {
		cfg.BatchBytes = 8 << 20
	}
	if cfg.PackBytes <= 0 {
		cfg.PackBytes = 32 << 20
	}
	if cfg.SpoolMax <= 0 {
		cfg.SpoolMax = 256 << 20
		if cfg.Spool != "" {
			cfg.SpoolMax = 10 << 30
		}
	}
	if cfg.Uploads <= 0 {
		cfg.Uploads = 4
	}
	if cfg.InlineBytes == 0 {
		cfg.InlineBytes = 4096
	}
	if cfg.Markers == nil {
		cfg.Markers = DefaultMarkers
	}
	if cfg.BaseMemory <= 0 {
		cfg.BaseMemory = 64 << 20
	}
	if cfg.StatusEvery == 0 {
		cfg.StatusEvery = time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.Host == "" {
		cfg.Host, _ = os.Hostname()
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	c := &Client{cfg: cfg, base: map[string]any{}, id: newHex(4)}
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
	sp, err := openSpool(spoolOpts{dir: cfg.Spool, max: cfg.SpoolMax, policy: cfg.WhenFull, segBytes: segBytes(cfg.SpoolMax), segAge: time.Minute})
	if err != nil {
		// A spool that will not open (read-only disk, every slot taken) must
		// not turn logging off: fall back to memory and say so.
		fmt.Fprintf(os.Stderr, "johnlogs: spool %s: %v; batches will wait in memory\n", cfg.Spool, err)
		c.st.setErr("spool: " + err.Error())
		sp, _ = openSpool(spoolOpts{max: 256 << 20, policy: cfg.WhenFull, segBytes: 32 << 20, segAge: time.Minute})
	}
	c.spool = sp
	c.bases = newBases(cfg.BaseMemory)
	c.markers = compileMarkers(cfg.Markers)
	c.zenc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(2), zstd.WithLowerEncoderMem(true))
	c.seals = make(chan *openBatch, 16)
	c.wake = make(chan struct{}, 1)
	c.done = make(chan struct{})
	c.stopped = make(chan struct{})
	c.st.cwnd = min(2, cfg.Uploads)
	c.reqCtx, c.cancelReq = context.WithCancel(context.Background())
	c.sealerWG.Add(1)
	go c.sealer()
	c.wg.Add(2)
	go c.ticker()
	go c.uploader()
	c.poke() // what an earlier run left in the spool
	return c
}

// segBytes is a spool segment's size: 1/16 of the cap, between 8 and 64 MiB,
// so dropping the oldest segment frees a useful amount without losing much.
func segBytes(spoolMax int64) int64 {
	return min(64<<20, max(8<<20, spoolMax/16))
}

func newHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Shipping reports whether records leave the process.
func (c *Client) Shipping() bool { return c != nil && c.spool != nil && !c.closed.Load() }

// Dropped is how many records were lost: the spool was full, or a record
// could not be encoded.
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
// "_timestamp" (unix µs) defaults to now. A [Body] value (or *Body) is stored
// whole in the batch's pack and replaced by its search keys — see Body. Never
// blocks.
func (c *Client) Send(rec map[string]any) {
	if !c.Shipping() {
		return
	}
	defer func() { _ = recover() }() // a panicking String() must not take the caller down
	out := make(map[string]any, len(rec)+len(c.base)+12)
	for k, v := range c.base {
		out[k] = v
	}
	var bodies []string
	for k, v := range rec {
		switch v.(type) {
		case Body, *Body:
			bodies = append(bodies, k)
			continue
		}
		out[k] = c.clean(k, v)
	}
	if _, ok := out["_timestamp"]; !ok {
		out["_timestamp"] = time.Now().UnixMicro()
	}
	for _, k := range bodies {
		var b Body
		switch x := rec[k].(type) {
		case Body:
			b = x
		case *Body:
			if x == nil {
				continue
			}
			b = *x
		}
		c.attach(out, k, b)
	}
	line, err := encodeLine(out)
	if err != nil {
		c.lose(1)
		return
	}
	c.appendRecord(line)
}

// attach stores a body in the open batch's pack and puts its keys in rec.
func (c *Client) attach(rec map[string]any, field string, b Body) {
	if len(b.Data) == 0 {
		return
	}
	in := inspect(b, c.cfg.InlineBytes, c.markers)
	group := b.Group
	if group == "" {
		group, _ = rec["message"].(string)
	}
	if group == "" {
		group = field
	}
	gen := c.batchGen()
	z := c.bases.compress(gen, field+" "+group, in.shape, in.sha, b.Data)
	ref := c.appendBlob(z.blob, len(b.Data))
	if z.register != nil {
		z.register(ref)
	}
	in.fields(rec, field, len(b.Data), ref.String())
}

var linePool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// encodeLine is one NDJSON line. HTML is not escaped: a page's every '<' would
// otherwise ship as six bytes.
func encodeLine(rec map[string]any) ([]byte, error) {
	buf := linePool.Get().(*bytes.Buffer)
	buf.Reset()
	defer linePool.Put(buf)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil { // Encode ends the line with '\n'
		return nil, err
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// batchGen opens a batch if none is open and returns its spool generation.
func (c *Client) batchGen() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.openLocked().gen
}

func (c *Client) openLocked() *openBatch {
	if c.open == nil {
		c.seq++
		now := time.Now()
		c.open = &openBatch{
			id:      fmt.Sprintf("%011x-%s-%06x", now.UnixMilli(), c.id, c.seq&0xffffff),
			seq:     c.seq,
			gen:     c.spool.nextGen(),
			created: now,
			recs:    make([]byte, 0, min(c.lastRecs+c.lastRecs/4, c.cfg.BatchBytes)),
		}
	}
	return c.open
}

func (c *Client) appendBlob(b wire.Blob, raw int) wire.Ref {
	c.mu.Lock()
	defer c.mu.Unlock()
	ob := c.openLocked()
	if len(ob.pack) > 0 && len(ob.pack)+len(b.Frame)+128 > c.cfg.PackBytes {
		c.sealLocked()
		ob = c.openLocked()
	}
	off := len(ob.pack)
	var n int
	ob.pack, n = wire.AppendBlob(ob.pack, b)
	ob.bodies++
	ob.bodyRaw += int64(raw)
	return wire.Ref{Batch: ob.id, Off: int64(off), Len: int64(n)}
}

func (c *Client) appendRecord(line []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ob := c.openLocked()
	if ob.n > 0 && (ob.n+1 > c.cfg.BatchSize || len(ob.recs)+len(line) > c.cfg.BatchBytes) {
		c.sealLocked()
		ob = c.openLocked()
	}
	ob.recs = append(ob.recs, line...)
	ob.n++
}

// sealLocked hands the open batch to the sealer. When the sealer is behind,
// the caller seals it itself rather than wait or drop.
func (c *Client) sealLocked() {
	ob := c.open
	c.open = nil
	if ob == nil || ob.n == 0 && len(ob.pack) == 0 {
		return
	}
	c.lastRecs = len(ob.recs)
	c.sealing.Add(1)
	if c.sealsClosed {
		c.mu.Unlock()
		c.seal(ob)
		c.mu.Lock()
		return
	}
	select {
	case c.seals <- ob:
	default:
		c.mu.Unlock()
		c.seal(ob)
		c.mu.Lock()
	}
}

func (c *Client) sealer() {
	defer c.sealerWG.Done()
	for ob := range c.seals {
		c.seal(ob)
	}
}

// seal compresses a batch and writes it to the spool.
func (c *Client) seal(ob *openBatch) {
	h := wire.Header{
		ID: ob.id, Records: ob.n, RecRaw: len(ob.recs), Bodies: ob.bodies, BodyRaw: ob.bodyRaw,
		Producer: c.id, Created: time.Now().UnixMicro(), Dropped: c.unreported.Swap(0),
	}
	defer c.sealing.Add(-1)
	recs := c.zenc.EncodeAll(ob.recs, make([]byte, 0, len(ob.recs)/4+64))
	batch, err := wire.AppendBatch(make([]byte, 0, len(recs)+len(ob.pack)+512), h, recs, ob.pack)
	if err != nil {
		c.lose(int64(ob.n))
		return
	}
	lost, err := c.spool.append(batch, ob.n, ob.gen)
	if lost > 0 {
		c.lose(lost)
	}
	if err != nil && err != errSpoolFull {
		c.st.setErr("spool: " + err.Error())
	}
	c.poke()
}

func (c *Client) lose(n int64) {
	c.dropped.Add(n)
	c.unreported.Add(n)
	c.lastDrop.Store(time.Now().UnixNano())
}

func (c *Client) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// ticker seals the open batch every FlushEvery, flushes the spool to disk
// every second, and logs the client's state every StatusEvery.
func (c *Client) ticker() {
	defer c.wg.Done()
	tick := time.NewTicker(c.cfg.FlushEvery)
	defer tick.Stop()
	lastSync, lastStatus := time.Now(), time.Now()
	for {
		select {
		case <-c.done:
			return
		case now := <-tick.C:
			c.mu.Lock()
			if c.open != nil && now.Sub(c.open.created) >= c.cfg.FlushEvery*9/10 {
				c.sealLocked()
			}
			c.mu.Unlock()
			if now.Sub(lastSync) >= time.Second {
				c.spool.sync()
				lastSync = now
			}
			c.checkState()
			if c.cfg.StatusEvery > 0 && now.Sub(lastStatus) >= c.cfg.StatusEvery {
				lastStatus = now
				c.sendStatus()
			}
		}
	}
}

// Flush waits until everything sent so far has been accepted by the gateway,
// or ctx ends.
func (c *Client) Flush(ctx context.Context) error {
	if !c.Shipping() {
		return nil
	}
	c.mu.Lock()
	c.sealLocked()
	c.mu.Unlock()
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		if c.sealing.Load() == 0 && c.spool.stats().pendingBytes == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.poke()
		}
	}
}

// Close seals the open batch, gives the gateway until ctx ends to take what
// is waiting, and stops. What it did not take stays in the spool for the next
// run (when Config.Spool is set). Later records are dropped silently.
func (c *Client) Close(ctx context.Context) error {
	if !c.Shipping() {
		return nil
	}
	err := c.Flush(ctx)
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.mu.Lock()
	c.sealLocked()
	c.sealsClosed = true
	close(c.seals)
	c.mu.Unlock()
	c.sealerWG.Wait()
	close(c.done)
	c.cancelReq()
	c.wg.Wait()
	c.spool.close()
	c.bases.close()
	c.zenc.Close()
	return err
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

var secretPunct = strings.NewReplacer("-", "", "_", "", ".", "")

// Secret is the default credential check: names containing token, password,
// secret, cookie, authorization, api key, private key, or card fields.
func Secret(key string) bool {
	k := strings.ToLower(secretPunct.Replace(key))
	for _, s := range []string{"token", "password", "passwd", "secret", "cookie", "authorization", "apikey", "privatekey", "cardnumber", "cvv", "cvc", "mnemonic", "seedphrase"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
