package johnlogs

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// settled waits until the gateway has taken everything sent so far.
func settled(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("flush: %v (stats %+v)", err, c.Stats())
	}
}

func spoolBytes(t *testing.T, dir string) (n int64) {
	t.Helper()
	names, _ := filepath.Glob(filepath.Join(dir, "*", "seg-*.jls"))
	for _, name := range names {
		if st, err := os.Stat(name); err == nil {
			n += st.Size()
		}
	}
	return n
}

// A session reads back whole from this machine's disk — the batches the
// gateway already took (kept by SpoolKeep, across segment rotations) and the
// ones still waiting — with every body, while another session's records
// stay out of it.
func TestHeldSessionReadsBackAcceptedAndWaiting(t *testing.T) {
	g, srv := newGateway(t)
	dir := t.TempDir()
	c := New(Config{URL: srv.URL, Token: "tok", Spool: dir, SpoolMax: 128 << 20, SpoolKeep: 64 << 20, FlushEvery: 10 * time.Millisecond, BatchSize: 20})
	var want [][]byte
	send := func(n int) {
		for range n {
			body := make([]byte, 64<<10) // random: ~20 MiB over the test, two segment rotations
			_, _ = rand.Read(body)
			if len(want)%3 == 0 {
				body = page(len(want)) // and pages, which are stored as deltas of each other
			}
			c.Send(map[string]any{"message": "GET", "session_id": "aaaa", "session_seq": len(want) + 1, "resp_body": Body{Data: body}})
			c.Send(map[string]any{"message": "GET", "session_id": "bbbb", "resp_body": Body{Data: body[:100]}})
			want = append(want, body)
		}
	}
	send(300)
	settled(t, c)
	if len(g.all()) != 600 {
		t.Fatalf("gateway has %d records", len(g.all()))
	}
	g.mu.Lock()
	g.fail = func(int, http.ResponseWriter) bool { panic(http.ErrAbortHandler) } // now it is down
	g.mu.Unlock()
	send(20)

	h := c.Hold()
	defer h.Close()
	got, err := h.Session("aaaa")
	if err != nil || len(got) != len(want) {
		t.Fatalf("read back %d of %d records: %v", len(got), len(want), err)
	}
	for i, rec := range got {
		if rec["session_seq"] != float64(i+1) {
			t.Fatalf("record %d is session_seq %v", i, rec["session_seq"])
		}
		body, err := h.Body(fmt.Sprint(rec["resp_body_ref"]))
		if err != nil || !bytes.Equal(body, want[i]) {
			t.Fatalf("body %d did not come back whole: %v", i, err)
		}
	}
	if st := c.Stats(); st.SpoolUsed > 16<<20 {
		t.Errorf("kept batches count as used: %+v", st)
	}
	h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = c.Close(ctx)
}

// Without SpoolKeep an accepted segment is deleted as before; with a small
// one, only that much stays; and what is kept never costs a waiting record
// its place.
func TestSpoolKeepIsBoundedAndGivesWay(t *testing.T) {
	junk := func(c *Client, n int) {
		body := make([]byte, 64<<10)
		for i := range n {
			_, _ = rand.Read(body)
			c.Send(map[string]any{"message": "m", "session_id": "aaaa", "session_seq": i, "resp_body": Body{Data: body}})
		}
	}
	for _, keep := range []int64{0, 12 << 20} {
		_, srv := newGateway(t)
		dir := t.TempDir()
		c := New(Config{URL: srv.URL, Token: "tok", Spool: dir, SpoolMax: 128 << 20, SpoolKeep: keep, FlushEvery: 10 * time.Millisecond, BatchSize: 20})
		junk(c, 600) // ~38 MiB, four rotations of an 8 MiB segment
		settled(t, c)
		h := c.Hold()
		got, _ := h.Session("aaaa")
		h.Close()
		// Up to one segment being written (8 MiB and a batch) on top of keep.
		if on := spoolBytes(t, dir); on > keep+10<<20 || len(got) == 600 || keep > 0 && on < keep/2 {
			t.Errorf("SpoolKeep %d: %d bytes on disk, %d of 600 records readable", keep, on, len(got))
		}
		flushed(t, c)
		if on := spoolBytes(t, dir); on != 0 {
			t.Errorf("SpoolKeep %d: %d bytes left after Close", keep, on)
		}
	}

	// Kept batches fill the spool to its cap; new ones still fit.
	_, srv := newGateway(t)
	c := New(Config{URL: srv.URL, Token: "tok", Spool: t.TempDir(), SpoolMax: 24 << 20, SpoolKeep: 24 << 20, FlushEvery: 10 * time.Millisecond, BatchSize: 20})
	for range 6 { // ~75 MiB through a 24 MiB spool, the gateway keeping up
		junk(c, 200)
		settled(t, c)
	}
	if st := c.Stats(); c.Dropped() != 0 || st.State != StateOK {
		t.Errorf("dropped %d, %+v", c.Dropped(), st)
	}
	flushed(t, c)
}

// A reader's files are not deleted under it: the spool lets go of them when
// it closes.
func TestHeldPinsWhatItReads(t *testing.T) {
	_, srv := newGateway(t)
	dir := t.TempDir()
	c := New(Config{URL: srv.URL, Token: "tok", Spool: dir, SpoolMax: 128 << 20, FlushEvery: 10 * time.Millisecond, BatchSize: 20})
	body := make([]byte, 64<<10)
	send := func(from, n int) {
		for i := range n {
			_, _ = rand.Read(body)
			c.Send(map[string]any{"message": "m", "session_id": "aaaa", "session_seq": from + i, "resp_body": Body{Data: append([]byte(nil), body...)}})
		}
	}
	send(0, 10)
	settled(t, c)
	h := c.Hold() // the first segment, accepted but still the one being written
	send(10, 400) // ~25 MiB: it rotates away and, with no SpoolKeep, is deleted
	settled(t, c)
	got, err := h.Session("aaaa")
	if err != nil || len(got) != 10 {
		t.Fatalf("the held segment read back %d of 10 records: %v", len(got), err)
	}
	if _, err := h.Body(fmt.Sprint(got[9]["resp_body_ref"])); err != nil {
		t.Fatalf("body under a hold: %v", err)
	}
	before := spoolBytes(t, dir)
	h.Close()
	if after := spoolBytes(t, dir); after >= before {
		t.Errorf("closing the hold freed nothing: %d then %d bytes", before, after)
	}
	flushed(t, c)
}
