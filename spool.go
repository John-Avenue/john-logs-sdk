package johnlogs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The spool is where sealed batches wait for the gateway. On disk (Config.Spool)
// it survives a dead gateway, a throttled one, a crash and a restart: a batch
// leaves it only when the gateway has accepted it. In memory it survives
// nothing but a slow gateway.
//
// Disk layout, one directory per running client (a slot, "0", "1", … under
// Config.Spool, locked while in use so two processes never share one):
//
//	seg-<seq>.jls   frames, appended: "JLF1" | u32 len | u32 crc32c | u32 records | batch
//	seg-<seq>.ack   u64 offsets of the frames the gateway accepted
//	dead/<id>.jlb   batches the gateway refused as malformed, kept for a person
//
// A segment is deleted once every frame in it is accepted and it is no longer
// the one being written. Bodies in a segment are only ever compressed against
// bases in the same segment (see delta.go), so deleting the oldest segment to
// make room never breaks a newer one.

// FullPolicy is what the spool does when a new batch would take it past
// Config.SpoolMax.
type FullPolicy int

const (
	// DropOldest deletes the oldest waiting batches to make room: the log
	// keeps what is happening now. The default.
	DropOldest FullPolicy = iota
	// DropNewest refuses the new batch: the log keeps what happened first.
	DropNewest
)

const (
	frameHead  = 16
	frameMagic = "JLF1"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type frame struct {
	seg      *segment
	off      int64 // of the frame header
	n        int   // batch length
	records  int
	data     []byte // memory spool only
	inflight bool
	acked    bool
}

type segment struct {
	seq     uint64
	f       *os.File // nil in memory
	ackf    *os.File
	size    int64
	frames  []*frame
	opened  time.Time
	pending int // frames not acked
}

type spool struct {
	dir      string // "" in memory
	max      int64
	policy   FullPolicy
	segBytes int64
	segAge   time.Duration

	mu      sync.Mutex
	lock    *os.File
	segs    []*segment
	size    int64 // bytes held, on disk or in memory
	pendB   int64 // bytes not yet accepted
	pendR   int64 // records not yet accepted
	dirty   bool
	closed  bool
	nextSeq uint64
}

type spoolOpts struct {
	dir      string
	max      int64
	policy   FullPolicy
	segBytes int64
	segAge   time.Duration
}

func openSpool(o spoolOpts) (*spool, error) {
	s := &spool{max: o.max, policy: o.policy, segBytes: o.segBytes, segAge: o.segAge, nextSeq: 1}
	if o.dir == "" {
		return s, nil
	}
	dir, lock, err := claimSlot(o.dir)
	if err != nil {
		return nil, err
	}
	s.dir, s.lock = dir, lock
	if err := s.recover(); err != nil {
		unlockSlot(lock)
		return nil, err
	}
	return s, nil
}

// claimSlot locks the first free slot directory under root.
func claimSlot(root string) (string, *os.File, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", nil, err
	}
	for i := range 64 {
		dir := filepath.Join(root, strconv.Itoa(i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", nil, err
		}
		f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return "", nil, err
		}
		if lockFile(f) == nil {
			return dir, f, nil
		}
		f.Close()
	}
	return "", nil, errors.New("johnlogs: every spool slot is in use")
}

func unlockSlot(f *os.File) {
	if f != nil {
		unlockFile(f)
		f.Close()
	}
}

func segName(seq uint64) string { return fmt.Sprintf("seg-%016x", seq) }

// recover reads what an earlier run left: every frame, minus the accepted
// ones, is pending again. A torn frame at the end of a segment (the process
// died mid-write) is cut off.
func (s *spool) recover() error {
	names, err := filepath.Glob(filepath.Join(s.dir, "seg-*.jls"))
	if err != nil {
		return err
	}
	slices.Sort(names)
	for _, name := range names {
		seq, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(name), "seg-"), ".jls"), 16, 64)
		if err != nil {
			continue
		}
		f, err := os.OpenFile(name, os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		seg := &segment{seq: seq, f: f, opened: time.Now()}
		acked := readAcks(filepath.Join(s.dir, segName(seq)+".ack"))
		st, _ := f.Stat()
		var off int64
		var head [frameHead]byte
		for off+frameHead <= st.Size() {
			if _, err := f.ReadAt(head[:], off); err != nil || string(head[:4]) != frameMagic {
				break
			}
			n := int64(binary.BigEndian.Uint32(head[4:]))
			if off+frameHead+n > st.Size() {
				break
			}
			fr := &frame{seg: seg, off: off, n: int(n), records: int(binary.BigEndian.Uint32(head[12:])), acked: acked[off]}
			seg.frames = append(seg.frames, fr)
			if !fr.acked {
				seg.pending++
				s.pendB += n
				s.pendR += int64(fr.records)
			}
			off += frameHead + n
		}
		if off < st.Size() {
			_ = f.Truncate(off)
		}
		seg.size = off
		s.size += off
		s.nextSeq = max(s.nextSeq, seq+1)
		if seg.pending == 0 {
			s.removeFiles(seg)
			continue
		}
		s.segs = append(s.segs, seg)
	}
	return nil
}

func readAcks(path string) map[int64]bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := make(map[int64]bool, len(b)/8)
	for i := 0; i+8 <= len(b); i += 8 {
		out[int64(binary.BigEndian.Uint64(b[i:]))] = true
	}
	return out
}

func (s *spool) removeFiles(seg *segment) {
	if seg.f != nil {
		seg.f.Close()
		os.Remove(seg.f.Name())
	}
	if seg.ackf != nil {
		seg.ackf.Close()
	}
	if s.dir != "" {
		os.Remove(filepath.Join(s.dir, segName(seg.seq)+".ack"))
	}
	s.size -= seg.size
}

// cur is the segment being written, nil before the first append.
func (s *spool) curLocked() *segment {
	if len(s.segs) == 0 {
		return nil
	}
	return s.segs[len(s.segs)-1]
}

// nextGen is the segment the next batch will be written to. A batch's bodies
// are compressed against bases of that segment only.
func (s *spool) nextGen() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.curLocked()
	if cur == nil || cur.size >= s.segBytes || time.Since(cur.opened) >= s.segAge {
		return s.nextSeq
	}
	return cur.seq
}

// append stores a sealed batch in segment gen (from nextGen when the batch
// was opened). It returns how many records were dropped to keep under the
// cap — the batch's own, under DropNewest, or older ones under DropOldest.
func (s *spool) append(batch []byte, records int, gen uint64) (dropped int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return int64(records), errors.New("johnlogs: spool closed")
	}
	need := int64(frameHead + len(batch))
	if s.size+need > s.max {
		if s.policy == DropOldest {
			dropped = s.dropOldestLocked(s.size + need - s.max)
		}
		if s.size+need > s.max {
			return dropped + int64(records), errSpoolFull
		}
	}
	cur := s.curLocked()
	if cur == nil || gen > cur.seq {
		if cur, err = s.rotateLocked(max(gen, s.nextSeq)); err != nil {
			return dropped + int64(records), err
		}
	}
	fr := &frame{seg: cur, off: cur.size, n: len(batch), records: records}
	if s.dir == "" {
		fr.data = batch
	} else {
		var head [frameHead]byte
		copy(head[:], frameMagic)
		binary.BigEndian.PutUint32(head[4:], uint32(len(batch)))
		binary.BigEndian.PutUint32(head[8:], crc32.Checksum(batch, castagnoli))
		binary.BigEndian.PutUint32(head[12:], uint32(records))
		if _, err := cur.f.WriteAt(head[:], cur.size); err != nil {
			return dropped + int64(records), err
		}
		if _, err := cur.f.WriteAt(batch, cur.size+frameHead); err != nil {
			_ = cur.f.Truncate(cur.size)
			return dropped + int64(records), err
		}
		s.dirty = true
	}
	cur.frames = append(cur.frames, fr)
	cur.size += need
	cur.pending++
	s.size += need
	s.pendB += int64(len(batch))
	s.pendR += int64(records)
	return dropped, nil
}

var errSpoolFull = errors.New("johnlogs: spool full")

func (s *spool) rotateLocked(seq uint64) (*segment, error) {
	if old := s.curLocked(); old != nil && old.pending == 0 && !hasInflight(old) {
		s.removeFiles(old)
		s.segs = s.segs[:len(s.segs)-1]
	}
	seg := &segment{seq: seq, opened: time.Now()}
	if s.dir != "" {
		f, err := os.OpenFile(filepath.Join(s.dir, segName(seq)+".jls"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err
		}
		seg.f = f
	}
	s.segs = append(s.segs, seg)
	s.nextSeq = seq + 1
	return seg, nil
}

func hasInflight(seg *segment) bool {
	for _, f := range seg.frames {
		if f.inflight {
			return true
		}
	}
	return false
}

// dropOldestLocked deletes whole segments, oldest first, never the one being
// written or one with a batch on its way to the gateway, until want bytes are
// free. It returns the records lost.
func (s *spool) dropOldestLocked(want int64) (lost int64) {
	for i := 0; i < len(s.segs)-1 && want > 0; {
		seg := s.segs[i]
		if hasInflight(seg) {
			i++
			continue
		}
		for _, f := range seg.frames {
			if !f.acked {
				lost += int64(f.records)
				s.pendB -= int64(f.n)
				s.pendR -= int64(f.records)
			}
		}
		want -= seg.size
		s.removeFiles(seg)
		s.segs = slices.Delete(s.segs, i, i+1)
	}
	return lost
}

// next hands out the oldest batch not yet accepted or on its way.
func (s *spool) next() (*frame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, seg := range s.segs {
		if seg.pending == 0 {
			continue
		}
		for _, f := range seg.frames {
			if !f.acked && !f.inflight {
				f.inflight = true
				return f, true
			}
		}
	}
	return nil, false
}

var errCorruptFrame = errors.New("johnlogs: spooled batch is corrupt")

// read returns a batch's bytes.
func (s *spool) read(f *frame) ([]byte, error) {
	if f.data != nil {
		return f.data, nil
	}
	buf := make([]byte, frameHead+f.n)
	if _, err := f.seg.f.ReadAt(buf, f.off); err != nil && err != io.EOF {
		return nil, err
	}
	if string(buf[:4]) != frameMagic || crc32.Checksum(buf[frameHead:], castagnoli) != binary.BigEndian.Uint32(buf[8:]) {
		return buf[frameHead:], errCorruptFrame
	}
	return buf[frameHead:], nil
}

// ack marks a batch accepted; a segment with nothing left is deleted unless
// it is still being written.
func (s *spool) ack(f *frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.inflight = false
	if f.acked {
		return
	}
	f.acked = true
	f.data = nil
	seg := f.seg
	seg.pending--
	s.pendB -= int64(f.n)
	s.pendR -= int64(f.records)
	if s.dir != "" && !s.isGoneLocked(seg) {
		if seg.ackf == nil {
			seg.ackf, _ = os.OpenFile(filepath.Join(s.dir, segName(seg.seq)+".ack"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		}
		if seg.ackf != nil {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(f.off))
			_, _ = seg.ackf.Write(b[:])
		}
	}
	if s.dir == "" && !s.isGoneLocked(seg) {
		s.size -= int64(frameHead + f.n)
		seg.size -= int64(frameHead + f.n)
	}
	if seg.pending == 0 && seg != s.curLocked() && !hasInflight(seg) {
		if i := slices.Index(s.segs, seg); i >= 0 {
			s.removeFiles(seg)
			s.segs = slices.Delete(s.segs, i, i+1)
		}
	}
}

func (s *spool) isGoneLocked(seg *segment) bool { return !slices.Contains(s.segs, seg) }

// nack puts a batch back to be sent again.
func (s *spool) nack(f *frame) {
	s.mu.Lock()
	f.inflight = false
	s.mu.Unlock()
}

// quarantine keeps a batch the gateway refused as malformed where a person
// can find it, and takes it out of the queue.
func (s *spool) quarantine(f *frame, batch []byte, id string) {
	if s.dir != "" && batch != nil {
		dead := filepath.Join(s.dir, "dead")
		if os.MkdirAll(dead, 0o700) == nil {
			if id == "" {
				id = fmt.Sprintf("%s-%d", segName(f.seg.seq), f.off)
			}
			_ = os.WriteFile(filepath.Join(dead, id+".jlb"), batch, 0o600)
		}
	}
	s.ack(f)
}

type spoolStats struct {
	pendingBytes, pendingRecords, used, max int64
	oldest                                  time.Time
}

func (s *spool) stats() spoolStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := spoolStats{pendingBytes: s.pendB, pendingRecords: s.pendR, used: s.size, max: s.max}
	for _, seg := range s.segs {
		if seg.pending > 0 {
			st.oldest = seg.opened
			break
		}
	}
	return st
}

// sync flushes written batches to the disk. It is a plain fsync, not the
// F_FULLFSYNC that os.File.Sync is on macOS, which flushes the whole drive's
// cache and stalls every program writing to it.
func (s *spool) sync() {
	s.mu.Lock()
	if !s.dirty || s.closed {
		s.mu.Unlock()
		return
	}
	s.dirty = false
	var files []*os.File
	if cur := s.curLocked(); cur != nil && cur.f != nil {
		files = append(files, cur.f)
	}
	s.mu.Unlock()
	for _, f := range files {
		_ = fsync(f)
	}
}

func (s *spool) close() {
	s.sync()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, seg := range s.segs {
		if seg.f != nil {
			seg.f.Close()
		}
		if seg.ackf != nil {
			seg.ackf.Close()
		}
		if seg.pending == 0 && s.dir != "" {
			os.Remove(filepath.Join(s.dir, segName(seg.seq)+".jls"))
			os.Remove(filepath.Join(s.dir, segName(seg.seq)+".ack"))
		}
	}
	unlockSlot(s.lock)
}
