package johnlogs

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/john-avenue/john-logs-sdk/wire"
)

// Reading back what this process logged, from its own spool: the batches
// still waiting for the gateway and the accepted ones Config.SpoolKeep keeps.
// The gateway's copy can be minutes behind during a burst — the upload is
// throttled, or the log has not indexed it yet — while every record is
// already here, compressed, on this disk.

// Held is a read-only view of the batches on disk. Nothing it can see is
// deleted until Close, so keep it open only as long as the read takes.
type Held struct {
	sp    *spool
	segs  []heldSeg
	packs map[string]heldPack // batch id -> where its bodies are
}

type heldSeg struct {
	f      *os.File
	frames []heldFrame
}

type heldFrame struct {
	off int64 // of the frame header
	n   int   // batch length
}

type heldPack struct {
	f   *os.File
	off int64
	n   int64
}

// Hold seals what is batched and pins the disk spool for reading. Nil when
// there is nothing on disk to read (not shipping, or the spool is in memory);
// Close on nil is fine.
func (c *Client) Hold() *Held {
	if !c.Shipping() || c.spool.dir == "" {
		return nil
	}
	c.mu.Lock()
	c.sealLocked()
	c.mu.Unlock()
	// The sealer writes within milliseconds; do not wait on a stuck disk.
	for until := time.Now().Add(2 * time.Second); c.sealing.Load() > 0 && time.Now().Before(until); {
		time.Sleep(5 * time.Millisecond)
	}
	return c.spool.hold()
}

func (s *spool) hold() *Held {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	h := &Held{sp: s, packs: map[string]heldPack{}}
	for _, seg := range s.segs {
		hs := heldSeg{f: seg.f, frames: make([]heldFrame, len(seg.frames))}
		for i, f := range seg.frames {
			hs.frames[i] = heldFrame{off: f.off, n: f.n}
		}
		h.segs = append(h.segs, hs)
	}
	s.readers++
	return h
}

// Close lets the spool delete what it was keeping for this reader.
func (h *Held) Close() {
	if h == nil || h.sp == nil {
		return
	}
	s := h.sp
	h.sp = nil
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readers--; s.readers == 0 && !s.closed {
		for _, seg := range s.doomed {
			s.deleteFiles(seg)
		}
		s.doomed = nil
	}
}

// Session returns the records on disk whose "session_id" is id, in the order
// they were logged, decoded as the log returns them (numbers are float64).
// It reads every held batch's records — not their bodies — so it costs about
// a second per few gigabytes of log; Body opens the bodies those records
// name. A batch that cannot be read is skipped and reported after the rest.
//
// ponytail: one pass over the whole spool per call, single-threaded. An index
// of session -> frames kept as batches are sealed is the upgrade if a 10 GiB
// spool makes this slow.
func (h *Held) Session(id string) ([]map[string]any, error) {
	if h == nil || h.sp == nil || id == "" {
		return nil, nil
	}
	var out []map[string]any
	var firstErr error
	needle := []byte(id)
	for _, seg := range h.segs {
		for _, fr := range seg.frames {
			err := h.readFrame(seg.f, fr, func(line []byte) error {
				if !bytes.Contains(line, needle) {
					return nil
				}
				var rec map[string]any
				if json.Unmarshal(line, &rec) == nil && rec["session_id"] == id {
					out = append(out, rec)
				}
				return nil
			})
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return out, firstErr
}

// readFrame reads one batch's header and records (never its pack), notes
// where the pack is, and calls fn with each record line.
func (h *Held) readFrame(f *os.File, fr heldFrame, fn func([]byte) error) error {
	var head [frameHead + 8]byte
	if _, err := f.ReadAt(head[:], fr.off); err != nil {
		return err
	}
	b := head[frameHead:]
	if string(head[:4]) != frameMagic || string(b[:4]) != wire.Magic {
		return errCorruptFrame
	}
	hn := int64(binary.BigEndian.Uint32(b[4:]))
	if hn > wire.MaxHeader || 8+hn > int64(fr.n) {
		return errCorruptFrame
	}
	hj := make([]byte, hn)
	if _, err := f.ReadAt(hj, fr.off+frameHead+8); err != nil {
		return err
	}
	var wh wire.Header
	if err := json.Unmarshal(hj, &wh); err != nil {
		return fmt.Errorf("johnlogs: spooled batch header: %w", err)
	}
	recAt := fr.off + frameHead + 8 + hn
	if wh.RecLen < 0 || wh.PackLen < 0 || 8+hn+int64(wh.RecLen)+int64(wh.PackLen) != int64(fr.n) {
		return errCorruptFrame
	}
	h.packs[wh.ID] = heldPack{f: f, off: recAt + int64(wh.RecLen), n: int64(wh.PackLen)}
	recs := make([]byte, wh.RecLen)
	if _, err := f.ReadAt(recs, recAt); err != nil {
		return err
	}
	return wire.Batch{Header: wh, Records: recs}.ReadRecords(fn)
}

// ErrNotHeld is a body whose batch is no longer on this disk: accepted long
// enough ago that SpoolKeep let it go. The gateway has it.
var ErrNotHeld = errors.New("johnlogs: that body is no longer on this disk")

// Body opens the body a record's req_body_ref or resp_body_ref names, whole.
// Only batches a Session call has passed are known, so call Session first.
func (h *Held) Body(ref string) ([]byte, error) {
	if h == nil || h.sp == nil {
		return nil, ErrNotHeld
	}
	r, err := wire.ParseRef(ref)
	if err != nil {
		return nil, err
	}
	return wire.Open(r, func(r wire.Ref) ([]byte, error) {
		p, ok := h.packs[r.Batch]
		if !ok || r.Off+r.Len > p.n {
			return nil, ErrNotHeld
		}
		b := make([]byte, r.Len)
		_, err := p.f.ReadAt(b, p.off+r.Off)
		return b, err
	})
}
