package johnlogs

import (
	"container/list"
	"runtime"
	"sync"

	"github.com/klauspost/compress/zstd"

	"github.com/john-avenue/john-logs-sdk/wire"
)

// Bodies are compressed against an earlier body from the same group, used as
// the zstd dictionary: two copies of a 150 KB page that differ by a nonce
// compress to about 2 KB this way, against 100+ KB on their own. Measured on
// john-logs' own tickets stream, 2026-10-23.
//
// A base is a whole body this client stored, and it is only ever a whole body
// — a delta never becomes a base — so reading any body back takes at most two
// blobs. Bases belong to one spool generation (a segment on disk): when the
// spool moves on, they are forgotten and the next body of each group is stored
// whole again, so the oldest segment can be deleted without breaking a delta
// in a newer one.

const (
	baseMin  = 1 << 10 // smaller bodies compress fine alone
	baseMax  = 2 << 20 // larger bases cost a 4 MiB+ window per encoder
	deltaWin = 4 << 20
	// A delta is kept when it is at most 1/deltaGain of the raw body.
	// Real deltas against a sibling page run 50x and better; a worse one
	// means the base is a different page and the body should start its own.
	deltaGain = 8
)

type base struct {
	key   string // group + "|" + shape
	group string
	reach int // longest body a delta against this base can still match across
	ref   wire.Ref
	sha   [32]byte
	enc   *zstd.Encoder
	cost  int64
	el    *list.Element
}

type bases struct {
	mu      sync.Mutex
	gen     uint64
	byKey   map[string]*base
	byGroup map[string]*base // the group's newest base
	lru     *list.List
	cost    int64
	budget  int64

	plain *zstd.Encoder // for bodies stored whole
}

func newBases(budget int64) *bases {
	plain, _ := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderConcurrency(min(4, runtime.GOMAXPROCS(0))),
		zstd.WithWindowSize(deltaWin),
		zstd.WithLowerEncoderMem(true),
		zstd.WithEncoderCRC(false))
	return &bases{byKey: map[string]*base{}, byGroup: map[string]*base{}, lru: list.New(), budget: budget, plain: plain}
}

// compressed is a body ready for the pack. When register is set the body is
// a new base; call it with the ref the blob got.
type compressed struct {
	blob     wire.Blob
	register func(wire.Ref)
}

// compress encodes body for spool generation gen.
func (bs *bases) compress(gen uint64, group, shape string, sha [32]byte, body []byte) compressed {
	key := group + "|" + shape
	bs.mu.Lock()
	if gen != bs.gen {
		bs.resetLocked(gen)
	}
	b := bs.byKey[key]
	if b == nil {
		b = bs.byGroup[group]
	}
	if b != nil {
		bs.lru.MoveToFront(b.el)
	}
	bs.mu.Unlock()

	if b != nil && len(body) <= b.reach {
		frame := b.enc.EncodeAll(body, make([]byte, 0, len(body)/deltaGain+64))
		if len(frame)*deltaGain <= len(body) {
			return compressed{blob: wire.Blob{Kind: wire.Delta, Sha: sha, Size: len(body), Base: b.ref, BaseSha: b.sha, Frame: frame}}
		}
	}
	out := compressed{blob: wire.Blob{Kind: wire.Whole, Sha: sha, Size: len(body), Frame: bs.plain.EncodeAll(body, nil)}}
	if len(body) >= baseMin && len(body) <= baseMax {
		dict := append([]byte(nil), body...)
		out.register = func(ref wire.Ref) { bs.add(gen, key, group, ref, sha, dict) }
	}
	return out
}

func (bs *bases) add(gen uint64, key, group string, ref wire.Ref, sha [32]byte, dict []byte) {
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderDictRaw(wire.DictID(sha), dict),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(window(len(dict))),
		zstd.WithLowerEncoderMem(true),
		zstd.WithEncoderCRC(false))
	if err != nil {
		return
	}
	w := window(len(dict))
	b := &base{key: key, group: group, reach: w - len(dict), ref: ref, sha: sha, enc: enc, cost: int64(len(dict)) + int64(w)*7/4}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if gen != bs.gen {
		return // the spool moved on while this body was being stored
	}
	if old := bs.byKey[key]; old != nil {
		bs.dropLocked(old)
	}
	b.el = bs.lru.PushFront(b)
	bs.byKey[key], bs.byGroup[group] = b, b
	bs.cost += b.cost
	for bs.cost > bs.budget && bs.lru.Len() > 1 {
		bs.dropLocked(bs.lru.Back().Value.(*base))
	}
}

// window fits the base and a body up to the same size again, so a delta can
// reach back across the whole dictionary.
func window(dict int) int {
	w := 1 << 18
	for w < 2*dict+(64<<10) && w < deltaWin {
		w <<= 1
	}
	return w
}

func (bs *bases) dropLocked(b *base) {
	bs.lru.Remove(b.el)
	if bs.byKey[b.key] == b {
		delete(bs.byKey, b.key)
	}
	if bs.byGroup[b.group] == b {
		delete(bs.byGroup, b.group)
	}
	bs.cost -= b.cost
	b.enc.Close()
}

func (bs *bases) resetLocked(gen uint64) {
	for e := bs.lru.Front(); e != nil; e = e.Next() {
		e.Value.(*base).enc.Close()
	}
	bs.byKey, bs.byGroup = map[string]*base{}, map[string]*base{}
	bs.lru.Init()
	bs.cost, bs.gen = 0, gen
}

func (bs *bases) close() {
	bs.mu.Lock()
	bs.resetLocked(bs.gen + 1)
	bs.mu.Unlock()
	bs.plain.Close()
}
