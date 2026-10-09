package johnlogs

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
)

// Logger is a *slog.Logger that ships through c (and writes to Console).
func (c *Client) Logger() *slog.Logger { return slog.New(c.Handler()) }

// Handler is the slog.Handler behind Logger, for composing with others.
func (c *Client) Handler() slog.Handler {
	if c == nil {
		return &handler{c: c}
	}
	return &handler{c: c, con: c.cfg.Console}
}

type handler struct {
	c      *Client
	attrs  []slog.Attr  // from WithAttrs, already prefixed by their group
	prefix string       // open groups, "a_b_"
	con    slog.Handler // Config.Console with the same attrs and groups, or nil
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	if h.c == nil {
		return false
	}
	if h.c.Shipping() && l >= h.c.cfg.Level.Level() {
		return true
	}
	return h.con != nil && h.con.Enabled(ctx, l)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	if h.con != nil && h.con.Enabled(ctx, r.Level) {
		rr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
		r.Attrs(func(a slog.Attr) bool {
			rr.AddAttrs(h.redact(a))
			return true
		})
		for _, a := range Fields(ctx) {
			rr.AddAttrs(h.redact(a))
		}
		_ = h.con.Handle(ctx, rr)
	}
	if !h.c.Shipping() || r.Level < h.c.cfg.Level.Level() {
		return nil
	}
	rec := make(map[string]any, 8+len(h.attrs)+r.NumAttrs())
	// Context first, so a field set on the call itself wins.
	for _, a := range Fields(ctx) {
		put(rec, "", a)
	}
	for _, a := range h.attrs {
		put(rec, "", a)
	}
	r.Attrs(func(a slog.Attr) bool {
		put(rec, h.prefix, a)
		return true
	})
	rec["message"] = r.Message
	rec["level"] = LevelName(r.Level)
	if !r.Time.IsZero() {
		rec["_timestamp"] = r.Time.UnixMicro()
	}
	if h.c.cfg.AddSource && r.PC != 0 {
		f, _ := runtime.CallersFrames([]uintptr{r.PC}).Next()
		rec["source"] = fmt.Sprintf("%s:%d", trimPath(f.File), f.Line)
	}
	h.c.Send(rec)
	return nil
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(n.attrs[:len(n.attrs):len(n.attrs)], prefixed(h.prefix, as)...)
	if n.con != nil {
		red := make([]slog.Attr, len(as))
		for i, a := range as {
			red[i] = h.redact(a)
		}
		n.con = n.con.WithAttrs(red)
	}
	return &n
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	n := *h
	n.prefix += name + "_"
	if n.con != nil {
		n.con = n.con.WithGroup(name)
	}
	return &n
}

// redact applies the Secret check to console output, which the shipped copy
// gets from Client.Send.
func (h *handler) redact(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		g := a.Value.Group()
		out := make([]slog.Attr, len(g))
		for i, x := range g {
			out[i] = h.redact(x)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	}
	if a.Key != "" && h.c.cfg.Secret(a.Key) {
		return slog.String(a.Key, "[redacted]")
	}
	return a
}

// prefixed bakes the open group into attr keys, so WithAttrs inside a group
// ships as group_key while the record's own attrs get the prefix at Handle.
func prefixed(prefix string, as []slog.Attr) []slog.Attr {
	if prefix == "" {
		return as
	}
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = slog.Attr{Key: prefix + a.Key, Value: a.Value}
	}
	return out
}

// put flattens groups into "group_key", the shape OpenObserve stores anyway.
func put(rec map[string]any, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "_"
		}
		for _, g := range v.Group() {
			put(rec, p, g)
		}
		return
	}
	if a.Key == "" {
		return
	}
	rec[prefix+a.Key] = v.Any()
}

// trimPath keeps the last two path elements: pkg/file.go.
func trimPath(f string) string {
	if i := strings.LastIndexByte(f, '/'); i > 0 {
		if j := strings.LastIndexByte(f[:i], '/'); j >= 0 {
			return f[j+1:]
		}
	}
	return f
}
