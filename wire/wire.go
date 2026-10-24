// Package wire is the john-logs batch format: what a client sends to
// POST /v2/ingest, what the gateway stores, and how a body is read back from
// a pack. The SDK writes it and the gateway reads it with this same code, so
// the two cannot drift. PROTOCOL.md at the repo root is the prose version.
//
// A batch is one request:
//
//	"JLB2" | u32 header length | header JSON | records | pack
//
// records is zstd-compressed NDJSON, one log record per line. pack is the
// bodies those records refer to, back to back, each one a blob:
//
//	u32 blob length | "JB" | kind | sha256 (32) | u32 size | [base] | zstd frame
//
// kind 0 is a whole body; kind 1 is a delta, compressed with a base body as
// its zstd dictionary, and [base] names it: u16 length | base ref | base sha256.
// A delta's base is always a whole body, so reading any body takes at most two
// blobs.
//
// A ref is "<batch id>:<offset>:<length>": the batch whose pack holds the
// blob, and the blob's place in that pack. Records carry refs, so the log
// itself is the index of where every body lives.
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Magic opens every batch.
const Magic = "JLB2"

// Batch limits the gateway enforces and the SDK stays under.
const (
	MaxHeader = 64 << 10
	MaxBatch  = 64 << 20 // whole request, compressed
)

// Header is a batch's JSON header.
type Header struct {
	ID       string `json:"id"`       // batch id, also the pack's name
	Records  int    `json:"n"`        // records in the batch
	RecLen   int    `json:"rec_len"`  // compressed records length
	RecRaw   int    `json:"rec_raw"`  // records length uncompressed
	PackLen  int    `json:"pack_len"` // pack length
	Bodies   int    `json:"bodies"`   // blobs in the pack
	BodyRaw  int64  `json:"body_raw"` // bodies' decoded bytes, for accounting
	Producer string `json:"producer"` // client id that made it
	Created  int64  `json:"created"`  // unix µs when it was sealed
	Dropped  int64  `json:"dropped"`  // records the producer lost before this batch, if any
}

// AppendBatch writes a batch: header, then the already-compressed records,
// then the pack.
func AppendBatch(dst []byte, h Header, records, pack []byte) ([]byte, error) {
	h.RecLen, h.PackLen = len(records), len(pack)
	hj, err := json.Marshal(h)
	if err != nil {
		return dst, err
	}
	if len(hj) > MaxHeader {
		return dst, errors.New("wire: header too large")
	}
	dst = append(dst, Magic...)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(hj)))
	dst = append(dst, hj...)
	dst = append(dst, records...)
	return append(dst, pack...), nil
}

// Batch is a parsed batch. Records and Pack alias the input.
type Batch struct {
	Header  Header
	Records []byte // zstd NDJSON
	Pack    []byte
}

// ParseBatch splits a batch into its parts. It checks lengths, not contents.
func ParseBatch(b []byte) (Batch, error) {
	if len(b) < 8 || string(b[:4]) != Magic {
		return Batch{}, errors.New("wire: not a JLB2 batch")
	}
	n := int(binary.BigEndian.Uint32(b[4:8]))
	if n > MaxHeader || 8+n > len(b) {
		return Batch{}, errors.New("wire: bad header length")
	}
	var h Header
	if err := json.Unmarshal(b[8:8+n], &h); err != nil {
		return Batch{}, fmt.Errorf("wire: header: %w", err)
	}
	if err := ValidID(h.ID); err != nil {
		return Batch{}, err
	}
	rest := b[8+n:]
	if h.RecLen < 0 || h.PackLen < 0 || h.RecLen+h.PackLen != len(rest) {
		return Batch{}, fmt.Errorf("wire: lengths %d+%d do not match %d bytes", h.RecLen, h.PackLen, len(rest))
	}
	return Batch{Header: h, Records: rest[:h.RecLen], Pack: rest[h.RecLen:]}, nil
}

// ReadRecords calls fn with each record line, decompressed. A line is only
// valid during the call.
func (b Batch) ReadRecords(fn func(line []byte) error) error {
	zr, err := zstd.NewReader(bytes.NewReader(b.Records), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256<<20))
	if err != nil {
		return err
	}
	defer zr.Close()
	return eachLine(zr, fn)
}

func eachLine(r io.Reader, fn func([]byte) error) error {
	buf := make([]byte, 0, 64<<10)
	chunk := make([]byte, 64<<10)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			if i > 0 {
				if ferr := fn(buf[:i]); ferr != nil {
					return ferr
				}
			}
			buf = buf[i+1:]
		}
		if err == io.EOF {
			if len(bytes.TrimSpace(buf)) > 0 {
				return fn(buf)
			}
			return nil
		}
		if err != nil {
			return err
		}
		// Keep the partial line at the front so buf does not creep forward.
		if cap(buf)-len(buf) < len(chunk) {
			buf = append(make([]byte, 0, max(2*len(buf), 64<<10)), buf...)
		}
	}
}

// ValidID accepts the ids the SDK makes: lowercase hex and dashes, so one is
// safe as a file name, an S3 key and a ref segment.
func ValidID(id string) error {
	if len(id) < 8 || len(id) > 64 {
		return fmt.Errorf("wire: bad batch id %q", id)
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == '-') {
			return fmt.Errorf("wire: bad batch id %q", id)
		}
	}
	return nil
}

// Ref names one blob: the pack (batch id) and its place in it.
type Ref struct {
	Batch    string
	Off, Len int64
}

func (r Ref) String() string {
	return r.Batch + ":" + strconv.FormatInt(r.Off, 10) + ":" + strconv.FormatInt(r.Len, 10)
}

// ParseRef reads "<batch>:<off>:<len>".
func ParseRef(s string) (Ref, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return Ref{}, fmt.Errorf("wire: bad ref %q", s)
	}
	off, err1 := strconv.ParseInt(parts[1], 10, 64)
	n, err2 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil || off < 0 || n < blobFixed || ValidID(parts[0]) != nil {
		return Ref{}, fmt.Errorf("wire: bad ref %q", s)
	}
	return Ref{Batch: parts[0], Off: off, Len: n}, nil
}

// Blob kinds.
const (
	Whole = 0
	Delta = 1
)

// u32 length, "JB", kind, sha256, u32 size
const blobFixed = 4 + 2 + 1 + 32 + 4

// Blob is one body as it sits in a pack.
type Blob struct {
	Kind    byte
	Sha     [32]byte // of the decoded body
	Size    int      // decoded length
	Base    Ref      // Delta only
	BaseSha [32]byte // Delta only
	Frame   []byte   // zstd frame
}

// AppendBlob writes b to a pack and returns the pack and the blob's length.
func AppendBlob(pack []byte, b Blob) ([]byte, int) {
	start := len(pack)
	pack = append(pack, 0, 0, 0, 0, 'J', 'B', b.Kind)
	pack = append(pack, b.Sha[:]...)
	pack = binary.BigEndian.AppendUint32(pack, uint32(b.Size))
	if b.Kind == Delta {
		ref := b.Base.String()
		pack = binary.BigEndian.AppendUint16(pack, uint16(len(ref)))
		pack = append(pack, ref...)
		pack = append(pack, b.BaseSha[:]...)
	}
	pack = append(pack, b.Frame...)
	n := len(pack) - start
	binary.BigEndian.PutUint32(pack[start:], uint32(n))
	return pack, n
}

// ParseBlob reads one blob; b is exactly the bytes a ref names.
func ParseBlob(b []byte) (Blob, error) {
	if len(b) < blobFixed || b[4] != 'J' || b[5] != 'B' {
		return Blob{}, errors.New("wire: not a blob")
	}
	if int(binary.BigEndian.Uint32(b)) != len(b) {
		return Blob{}, errors.New("wire: blob length mismatch")
	}
	out := Blob{Kind: b[6], Size: int(binary.BigEndian.Uint32(b[39:43]))}
	copy(out.Sha[:], b[7:39])
	p := b[blobFixed:]
	switch out.Kind {
	case Whole:
	case Delta:
		if len(p) < 2 {
			return Blob{}, errors.New("wire: short delta")
		}
		n := int(binary.BigEndian.Uint16(p))
		if len(p) < 2+n+32 {
			return Blob{}, errors.New("wire: short delta")
		}
		ref, err := ParseRef(string(p[2 : 2+n]))
		if err != nil {
			return Blob{}, err
		}
		out.Base = ref
		copy(out.BaseSha[:], p[2+n:2+n+32])
		p = p[2+n+32:]
	default:
		return Blob{}, fmt.Errorf("wire: unknown blob kind %d", out.Kind)
	}
	out.Frame = p
	return out, nil
}

// EachBlob walks a pack, calling fn with each blob's offset and bytes.
func EachBlob(pack []byte, fn func(off int64, blob []byte) error) error {
	for off := 0; off < len(pack); {
		if len(pack)-off < 4 {
			return errors.New("wire: torn pack")
		}
		n := int(binary.BigEndian.Uint32(pack[off:]))
		if n < blobFixed || off+n > len(pack) {
			return fmt.Errorf("wire: bad blob at %d", off)
		}
		if err := fn(int64(off), pack[off:off+n]); err != nil {
			return err
		}
		off += n
	}
	return nil
}

// DictID is the zstd dictionary id a delta's frame names for its base: the
// base's sha256, never zero.
func DictID(baseSha [32]byte) uint32 {
	id := binary.BigEndian.Uint32(baseSha[:4])
	if id == 0 {
		id = 1
	}
	return id
}

// Fetch reads the bytes a ref names. The gateway reads packs from disk or S3;
// tests read them from memory.
type Fetch func(Ref) ([]byte, error)

// ErrCorrupt is a body whose bytes do not hash to the sha256 it was stored
// under.
var ErrCorrupt = errors.New("wire: body does not match its sha256")

// Open returns the body a ref names, reading its base too when it is a delta,
// and checks it against its sha256.
func Open(ref Ref, fetch Fetch) ([]byte, error) {
	raw, err := fetch(ref)
	if err != nil {
		return nil, err
	}
	b, err := ParseBlob(raw)
	if err != nil {
		return nil, err
	}
	var body []byte
	switch b.Kind {
	case Whole:
		body, err = decode(b.Frame, b.Size, nil, 0)
	case Delta:
		var base []byte
		base, err = Open(b.Base, func(r Ref) ([]byte, error) {
			raw, err := fetch(r)
			if err == nil {
				if pb, perr := ParseBlob(raw); perr == nil && pb.Kind != Whole {
					return nil, errors.New("wire: a delta's base is itself a delta")
				}
			}
			return raw, err
		})
		if err == nil && sha256.Sum256(base) != b.BaseSha {
			err = ErrCorrupt
		}
		if err == nil {
			body, err = decode(b.Frame, b.Size, base, DictID(b.BaseSha))
		}
	}
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(body) != b.Sha {
		return nil, ErrCorrupt
	}
	return body, nil
}

func decode(frame []byte, size int, dict []byte, id uint32) ([]byte, error) {
	opts := []zstd.DOption{zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(max(size, 1)) + 1<<20)}
	if dict != nil {
		opts = append(opts, zstd.WithDecoderDictRaw(id, dict), zstd.WithDecoderMaxWindow(uint64(len(dict)+size)+1<<20))
	}
	d, err := zstd.NewReader(nil, opts...)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.DecodeAll(frame, make([]byte, 0, size))
}
