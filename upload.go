package johnlogs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/john-avenue/john-logs-sdk/wire"
)

// State is how the client is keeping up, worst first.
type State string

const (
	StateOK      State = "ok"      // batches are leaving as fast as they are made
	StateBehind  State = "behind"  // a backlog is building: the gateway is slow or throttling
	StateFailing State = "failing" // nothing has been accepted for a while
	StateFull    State = "full"    // the spool is at 90%+ of SpoolMax, or dropped records in the last minute
)

// Stats is the client's view of its own shipping, for an app to show and to
// alert on.
type Stats struct {
	State          State
	PendingBytes   int64 // batches waiting in the spool
	PendingRecords int64
	SpoolUsed      int64
	SpoolMax       int64
	OldestPending  time.Duration // how long the oldest waiting batch has waited
	Sent           int64         // records accepted since start
	Dropped        int64         // records lost since start (spool full, unencodable)
	Quarantined    int64         // batches the gateway refused as malformed, kept in the spool's dead/
	InFlight       int
	LastError      string
	LastErrorAt    time.Time
	LastSentAt     time.Time
}

// Stats reports the client's shipping. Cheap enough to poll every second.
func (c *Client) Stats() Stats {
	if c == nil || c.spool == nil {
		return Stats{State: StateOK}
	}
	sp := c.spool.stats()
	c.st.mu.Lock()
	s := Stats{
		PendingBytes: sp.pendingBytes, PendingRecords: sp.pendingRecords,
		SpoolUsed: sp.used, SpoolMax: sp.max,
		Sent: c.sent.Load(), Dropped: c.dropped.Load(), Quarantined: c.quarantined.Load(),
		InFlight: c.st.inflight, LastError: c.st.lastErr, LastErrorAt: c.st.lastErrAt, LastSentAt: c.st.lastOK,
	}
	failingSince := c.st.failingSince
	c.st.mu.Unlock()
	if !sp.oldest.IsZero() {
		s.OldestPending = time.Since(sp.oldest)
	}
	lastDrop := c.lastDrop.Load()
	switch {
	case sp.max > 0 && sp.used*10 >= sp.max*9, lastDrop > 0 && time.Since(time.Unix(0, lastDrop)) < time.Minute:
		s.State = StateFull
	case s.PendingBytes > 0 && !failingSince.IsZero() && time.Since(failingSince) >= 30*time.Second:
		s.State = StateFailing
	case s.PendingBytes > 64<<20 || s.OldestPending > 30*time.Second:
		s.State = StateBehind
	default:
		s.State = StateOK
	}
	return s
}

// upState is the uploader's bookkeeping, shared with Stats.
type upState struct {
	mu           sync.Mutex
	cwnd         int // batches allowed in flight
	inflight     int
	okStreak     int
	failures     int // consecutive
	pauseUntil   time.Time
	failingSince time.Time
	lastErr      string
	lastErrAt    time.Time
	lastOK       time.Time
	lastState    State
}

func (u *upState) setErr(msg string) {
	u.mu.Lock()
	u.lastErr, u.lastErrAt = msg, time.Now()
	u.mu.Unlock()
}

type result struct {
	f       *frame
	batch   []byte
	id      string
	records int
	outcome outcome
	wait    time.Duration // the gateway's Retry-After, when it sent one
	err     string
}

type outcome int

const (
	accepted  outcome = iota
	retry             // throttled, overloaded, unreachable: try again after a backoff
	refused           // token or endpoint refused: try again, slowly
	malformed         // the gateway will never take this batch
)

// uploader sends spooled batches, oldest first, with up to cwnd in flight.
// cwnd grows by one after every few acceptances and halves on every failure
// (additive increase, multiplicative decrease), so a struggling gateway sees
// fewer, not more, requests from every client at once.
func (c *Client) uploader() {
	defer c.wg.Done()
	results := make(chan result)
	inflight := 0
	for {
		c.st.mu.Lock()
		cwnd, pause := c.st.cwnd, time.Until(c.st.pauseUntil)
		c.st.mu.Unlock()
		for pause <= 0 && inflight < cwnd && !c.closing() {
			f, ok := c.spool.next()
			if !ok {
				break
			}
			inflight++
			c.setInflight(inflight)
			go func() { results <- c.upload(f) }()
		}
		var timer <-chan time.Time
		if pause > 0 {
			timer = time.After(pause)
		}
		select {
		case r := <-results:
			inflight--
			c.setInflight(inflight)
			c.settle(r)
		case <-c.wake:
		case <-timer:
		case <-c.done:
			for ; inflight > 0; inflight-- {
				c.settle(<-results)
			}
			c.setInflight(0)
			return
		}
	}
}

func (c *Client) closing() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *Client) setInflight(n int) {
	c.st.mu.Lock()
	c.st.inflight = n
	c.st.mu.Unlock()
}

func (c *Client) settle(r result) {
	now := time.Now()
	c.st.mu.Lock()
	defer c.st.mu.Unlock()
	switch r.outcome {
	case accepted:
		c.spool.ack(r.f)
		c.sent.Add(int64(r.records))
		c.st.lastOK, c.st.failures, c.st.failingSince = now, 0, time.Time{}
		if c.st.okStreak++; c.st.okStreak >= 4 && c.st.cwnd < c.cfg.Uploads {
			c.st.cwnd++
			c.st.okStreak = 0
		}
		return
	case malformed:
		c.spool.quarantine(r.f, r.batch, r.id)
		c.quarantined.Add(1)
		c.st.lastErr, c.st.lastErrAt = r.err, now
		return
	}
	c.spool.nack(r.f)
	if c.closing() {
		return // shutting down; the batch stays in the spool for the next run
	}
	c.st.okStreak = 0
	c.st.cwnd = max(1, c.st.cwnd/2)
	c.st.failures++
	if c.st.failingSince.IsZero() {
		c.st.failingSince = now
	}
	c.st.lastErr, c.st.lastErrAt = r.err, now
	wait := r.wait
	if wait <= 0 {
		wait = backoff(c.st.failures)
	}
	if r.outcome == refused {
		wait = max(wait, time.Minute)
	}
	if until := now.Add(wait); until.After(c.st.pauseUntil) {
		c.st.pauseUntil = until
	}
}

// backoffBase is the first retry's wait; tests shorten it.
var backoffBase = 500 * time.Millisecond

// backoff is 0.5s doubling to 30s, with jitter so a fleet does not retry in
// step.
func backoff(failures int) time.Duration {
	d := backoffBase << min(failures-1, 6)
	d = min(d, 30*time.Second)
	return d/2 + rand.N(d/2+1)
}

func (c *Client) upload(f *frame) result {
	r := result{f: f, records: f.records}
	batch, err := c.spool.read(f)
	if err != nil {
		if errors.Is(err, errCorruptFrame) {
			r.outcome, r.err, r.batch = malformed, "spooled batch is corrupt (disk)", batch
			return r
		}
		r.outcome, r.err = retry, "spool read: "+err.Error()
		return r
	}
	r.batch = batch
	if b, err := wire.ParseBatch(batch); err == nil {
		r.id = b.Header.ID
	}
	ctx, cancel := context.WithTimeout(c.reqCtx, c.cfg.HTTPClient.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL+"/v2/ingest", bytes.NewReader(batch))
	if err != nil {
		r.outcome, r.err = malformed, err.Error()
		return r
	}
	st := c.Stats()
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/x-johnlogs-batch")
	req.Header.Set("X-Johnlogs-Batch", r.id)
	req.Header.Set("X-Johnlogs-Client", c.id)
	req.Header.Set("X-Johnlogs-Sdk", Version)
	req.Header.Set("X-Johnlogs-Host", c.cfg.Host)
	req.Header.Set("X-Johnlogs-Service", c.cfg.Service)
	req.Header.Set("X-Johnlogs-State", string(st.State))
	req.Header.Set("X-Johnlogs-Pending-Bytes", itoa(st.PendingBytes))
	req.Header.Set("X-Johnlogs-Pending-Records", itoa(st.PendingRecords))
	req.Header.Set("X-Johnlogs-Spool-Used", itoa(st.SpoolUsed))
	req.Header.Set("X-Johnlogs-Spool-Max", itoa(st.SpoolMax))
	req.Header.Set("X-Johnlogs-Dropped", itoa(st.Dropped))
	req.Header.Set("X-Johnlogs-Oldest-Ms", itoa(st.OldestPending.Milliseconds()))
	res, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		r.outcome, r.err = retry, "gateway: "+err.Error()
		return r
	}
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	res.Body.Close()
	r.wait = retryAfter(res.Header.Get("Retry-After"))
	code := res.StatusCode
	switch {
	case code < 300:
		r.outcome = accepted
	case code == http.StatusRequestTimeout, code == http.StatusTooEarly, code == http.StatusTooManyRequests, code >= 500:
		r.outcome = retry
	case code == http.StatusUnauthorized, code == http.StatusForbidden:
		r.outcome = refused
	case code == http.StatusNotFound, code == http.StatusMethodNotAllowed:
		r.outcome = refused // a gateway without /v2/ingest; it will be upgraded
	default:
		r.outcome = malformed
	}
	if r.outcome != accepted {
		r.err = fmt.Sprintf("gateway %d: %s", code, bytes.TrimSpace(msg))
	}
	return r
}

// retryAfter reads Retry-After as seconds or an HTTP date, capped at 5 minutes.
func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return min(time.Duration(s)*time.Second, 5*time.Minute)
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(time.Until(t), 0), 5*time.Minute)
	}
	return 0
}

// checkState calls OnState when the state changed.
func (c *Client) checkState() {
	if c.cfg.OnState == nil {
		return
	}
	s := c.Stats()
	c.st.mu.Lock()
	changed := s.State != c.st.lastState
	c.st.lastState = s.State
	c.st.mu.Unlock()
	if changed {
		func() {
			defer func() { _ = recover() }()
			c.cfg.OnState(s)
		}()
	}
}

// sendStatus logs the client's own state as a record, so a dashboard can
// show every machine's backlog and losses without asking it.
func (c *Client) sendStatus() {
	s := c.Stats()
	level := "info"
	if s.State != StateOK || s.Dropped > 0 || s.Quarantined > 0 {
		level = "warn"
	}
	rec := map[string]any{
		"level": level, "message": "johnlogs status",
		"log_state": string(s.State), "log_pending_bytes": s.PendingBytes, "log_pending_records": s.PendingRecords,
		"log_spool_used": s.SpoolUsed, "log_spool_max": s.SpoolMax, "log_oldest_ms": s.OldestPending.Milliseconds(),
		"log_sent": s.Sent, "log_dropped": s.Dropped, "log_quarantined": s.Quarantined,
		"log_client": c.id, "log_sdk": Version,
	}
	if s.LastError != "" {
		rec["log_last_error"] = s.LastError
	}
	c.Send(rec)
}
