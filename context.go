package johnlogs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"
)

// Standard field names. Filter on these in the dashboard: session_id is one
// run of an app, trace_id one unit of work across it, span_id one step.
const (
	KeySession = "session_id"
	KeyTrace   = "trace_id"
	KeySpan    = "span_id"
	KeyParent  = "parent_span_id"
)

type fieldsKey struct{}

// With returns ctx carrying extra fields ("key", value pairs or slog.Attr).
// Every record logged with that ctx (slog.InfoContext and friends) carries
// them. A later With of the same key wins.
func With(ctx context.Context, args ...any) context.Context {
	add := argsToAttrs(args)
	if len(add) == 0 {
		return ctx
	}
	prev := Fields(ctx)
	merged := make([]slog.Attr, 0, len(prev)+len(add))
	for _, p := range prev {
		if !hasKey(add, p.Key) {
			merged = append(merged, p)
		}
	}
	return context.WithValue(ctx, fieldsKey{}, append(merged, add...))
}

// Fields are the fields ctx carries, for handing to another logger.
func Fields(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	f, _ := ctx.Value(fieldsKey{}).([]slog.Attr)
	return f
}

// Get returns one field ctx carries, or nil.
func Get(ctx context.Context, key string) any {
	for _, a := range Fields(ctx) {
		if a.Key == key {
			return a.Value.Any()
		}
	}
	return nil
}

// Session starts a session: ctx gets a fresh session_id, which it returns.
// Call it once per app run, sign-in, or connection — whatever "one session"
// means to the app.
func Session(ctx context.Context, args ...any) (context.Context, string) {
	id := NewID()
	return With(ctx, append([]any{KeySession, id}, args...)...), id
}

// Start opens a span named name. ctx gets a span_id, the trace_id of the
// span it is inside (or a new one), and parent_span_id. Call end with the
// outcome: it logs "<name>" with duration_ms through slog.Default(), at Info,
// or Error with the error.
//
//	ctx, end := johnlogs.Start(ctx, "checkout", "event_id", ev)
//	defer func() { end(err) }()
func Start(ctx context.Context, name string, args ...any) (context.Context, func(error)) {
	trace, _ := Get(ctx, KeyTrace).(string)
	if trace == "" {
		trace = NewID()
	}
	parent, _ := Get(ctx, KeySpan).(string)
	fields := []any{KeyTrace, trace, KeySpan, NewID(), "span", name}
	if parent != "" {
		fields = append(fields, KeyParent, parent)
	}
	ctx = With(ctx, append(fields, args...)...)
	slog.Default().Log(ctx, slog.LevelDebug, name+" started")
	began := time.Now()
	return ctx, func(err error) {
		ms := time.Since(began).Milliseconds()
		if err != nil {
			slog.Default().Log(ctx, slog.LevelError, name+" failed", "duration_ms", ms, "error", err.Error())
			return
		}
		slog.Default().Log(ctx, slog.LevelInfo, name+" done", "duration_ms", ms)
	}
}

// NewID is 16 random hex characters.
func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func argsToAttrs(args []any) []slog.Attr {
	var out []slog.Attr
	for len(args) > 0 {
		switch a := args[0].(type) {
		case slog.Attr:
			out = append(out, a)
			args = args[1:]
		case string:
			if len(args) == 1 {
				out = append(out, slog.String("!BADKEY", a))
				args = nil
				continue
			}
			out = append(out, slog.Any(a, args[1]))
			args = args[2:]
		default:
			out = append(out, slog.Any("!BADKEY", a))
			args = args[1:]
		}
	}
	return out
}

func hasKey(as []slog.Attr, k string) bool {
	for _, a := range as {
		if a.Key == k {
			return true
		}
	}
	return false
}
