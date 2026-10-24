package wire

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestBatchRoundTrip(t *testing.T) {
	enc, _ := zstd.NewWriter(nil)
	recs := enc.EncodeAll([]byte("{\"a\":1}\n{\"a\":2}\n{\"a\":3}"), nil)
	b, err := AppendBatch(nil, Header{ID: "0123456789a-deadbeef-000001", Records: 3}, recs, []byte("pack"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBatch(b)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	if err := got.ReadRecords(func(l []byte) error { lines = append(lines, string(l)); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || lines[2] != `{"a":3}` || string(got.Pack) != "pack" || got.Header.Records != 3 {
		t.Fatalf("lines %q pack %q header %+v", lines, got.Pack, got.Header)
	}
	if _, err := ParseBatch(b[:len(b)-1]); err == nil {
		t.Error("a short batch parsed")
	}
	if _, err := ParseBatch(append([]byte("JLB1"), b[4:]...)); err == nil {
		t.Error("wrong magic parsed")
	}
}

func TestBlobsAndDeltas(t *testing.T) {
	base := bytes.Repeat([]byte("<div class=row>Section A Row 12 Seat 4</div>\n"), 3000)
	body := append([]byte(nil), base...)
	copy(body[777:], "nonce-abcdef0123456789")
	baseSha, bodySha := sha256.Sum256(base), sha256.Sum256(body)

	plain, _ := zstd.NewWriter(nil)
	var pack []byte
	pack, n := AppendBlob(pack, Blob{Kind: Whole, Sha: baseSha, Size: len(base), Frame: plain.EncodeAll(base, nil)})
	baseRef := Ref{Batch: "0123456789a-deadbeef-000001", Off: 0, Len: int64(n)}

	denc, _ := zstd.NewWriter(nil, zstd.WithEncoderDictRaw(DictID(baseSha), base))
	off := len(pack)
	pack, n = AppendBlob(pack, Blob{Kind: Delta, Sha: bodySha, Size: len(body), Base: baseRef, BaseSha: baseSha, Frame: denc.EncodeAll(body, nil)})
	bodyRef := Ref{Batch: baseRef.Batch, Off: int64(off), Len: int64(n)}
	if n > 400 {
		t.Errorf("delta is %d bytes", n)
	}

	fetch := func(r Ref) ([]byte, error) {
		if r.Batch != baseRef.Batch {
			return nil, fmt.Errorf("no pack %s", r.Batch)
		}
		return pack[r.Off : r.Off+r.Len], nil
	}
	for _, c := range []struct {
		ref  Ref
		want []byte
	}{{baseRef, base}, {bodyRef, body}} {
		got, err := Open(c.ref, fetch)
		if err != nil || !bytes.Equal(got, c.want) {
			t.Fatalf("open %s: %v", c.ref, err)
		}
	}
	r, err := ParseRef(bodyRef.String())
	if err != nil || r != bodyRef {
		t.Fatalf("ref round trip: %v %v", r, err)
	}
	var offs []int64
	if err := EachBlob(pack, func(o int64, _ []byte) error { offs = append(offs, o); return nil }); err != nil || len(offs) != 2 || offs[1] != bodyRef.Off {
		t.Fatalf("walk: %v %v", offs, err)
	}

	// A flipped byte in the base is caught, not handed back as the body.
	bad := append([]byte(nil), pack...)
	bad[int(baseRef.Len)-3] ^= 0xff
	if _, err := Open(bodyRef, func(r Ref) ([]byte, error) { return bad[r.Off : r.Off+r.Len], nil }); err == nil {
		t.Error("corrupt base opened")
	}
}

func TestParseRefRejects(t *testing.T) {
	for _, s := range []string{"", "a:1:2", "0123456789a-deadbeef:1", "0123456789a-deadbeef:-1:100", "0123456789A-deadbeef:0:100", "../../etc:0:100"} {
		if _, err := ParseRef(s); err == nil {
			t.Errorf("ParseRef(%q) accepted", s)
		}
	}
}
