# john-logs-sdk

Structured logging for Go that ships to a john-logs gateway. It is a
`log/slog` handler; its one dependency is klauspost/compress (zstd).

```bash
go get github.com/john-avenue/john-logs-sdk
```

```go
logs := johnlogs.New(johnlogs.Config{
	URL:     os.Getenv("JOHN_LOGS_URL"),
	Token:   os.Getenv("JOHN_LOGS_TOKEN"),
	Service: "my-app",
	Version: version,
	Spool:   filepath.Join(dataDir, "logspool"), // recommended: nothing lost to an outage or a restart
	Console: slog.NewTextHandler(os.Stderr, nil), // optional
})
defer logs.Close(context.Background())
slog.SetDefault(logs.Logger())
```

`johnlogs.FromEnv("my-app")` builds the same config from `JOHN_LOGS_URL`,
`JOHN_LOGS_TOKEN`, `JOHN_LOGS_ENV`, `JOHN_LOGS_LEVEL` and `JOHN_LOGS_SPOOL`.

v0.2 speaks `POST /v2/ingest` only: the gateway must be upgraded first.
[PROTOCOL.md](PROTOCOL.md) is the wire format.

## Sessions and traces

Fields put on a `context.Context` ride on every record logged with it, so one
run, one task or one request can be pulled out with a single filter.

```go
ctx, sessionID := johnlogs.Session(ctx, "user", email) // once per run / sign-in
ctx = johnlogs.With(ctx, "task_id", task.ID, "account", acct)

ctx, end := johnlogs.Start(ctx, "checkout")            // trace_id, span_id, parent_span_id
defer func() { end(err) }()                            // logs "checkout done|failed" with duration_ms

slog.InfoContext(ctx, "queue passed", "position", 12)
```

| Field | Meaning |
|---|---|
| `session_id` | one run of an app (or a sign-in) |
| `trace_id` | one unit of work; nested spans share it |
| `span_id`, `parent_span_id`, `span` | one step, its parent, its name |
| `level` | `trace`, `debug`, `info`, `warn`, `error` |
| `service`, `env`, `version`, `host` | from `Config` |

## Bodies

Put request and response bodies in a record as `johnlogs.Body`, not as text:

```go
logs.Send(map[string]any{
	"message":   "GET https://example.com/event/{id}",
	"resp_body": johnlogs.Body{Data: body, Type: resp.Header.Get("Content-Type")},
})
```

The body is stored whole in the batch's pack (S3, behind the gateway),
compressed against the last body in its group (the record's message by
default), so the hundredth copy of a page costs a few hundred bytes. The
record gets search keys instead of the bytes: `resp_body` (the first 4 KB of
text), `resp_body_partial`, `resp_body_size`, `resp_body_sha256`,
`resp_body_ref`, `resp_body_shape` (the same page apart from nonces, ids and
timestamps has the same shape), `resp_body_kind`, `resp_body_title`,
`resp_body_markers` (datadome, cloudflare_challenge, …) and
`resp_body_json_keys`. The gateway serves the whole body back by ref or by
sha256, and can grep inside bodies.

## Batching and the spool

Records are sealed into a batch every 500 ms, or as soon as it holds 2,000
records or 8 MiB (`FlushEvery`, `BatchSize`, `BatchBytes`); what does not fit
waits for the next batch. Batches wait in the spool until the gateway accepts
them, retried for as long as it takes: on 429/5xx the client honours
`Retry-After` (or backs off 0.5 s → 30 s with jitter) and halves how many
batches it sends at once (`Uploads`, default 4).

With `Spool` set, the spool is on disk, and a crash or restart loses nothing:
the next run sends what the last one could not. Without it, batches wait in
memory.

`SpoolMax` caps it (10 GiB on disk, 256 MiB in memory). At the cap,
`WhenFull` decides what goes: `DropOldest` (default) or `DropNewest`.

## Being loud

- `Client.Stats()`: state (`ok`, `behind`, `failing`, `full`), what is waiting,
  what was lost, the last error. Cheap to poll.
- `Config.OnState`: called whenever the state changes.
- Every `StatusEvery` (1 min) the client logs a `johnlogs status` record with
  its backlog and losses.
- Every request carries `X-Johnlogs-State`, `-Pending-Bytes`, `-Dropped`, …,
  which the gateway turns into CloudWatch metrics and alarms.

## Safety

- Field names that look like credentials (`token`, `password`, `secret`,
  `cookie`, `authorization`, `api_key`, card fields, …) are replaced with
  `[redacted]` at any depth, in shipped records and on the console. Override
  with `Config.Secret`.
- Strings longer than `Config.MaxField` (256 KiB) are clipped. Bodies are
  never clipped.
- Logging never blocks and never panics the caller.
- The ingest token is write-only. It cannot read logs.

## Raw records

Code that already builds its own maps can skip slog:

```go
logs.Send(map[string]any{"message": "GET /x -> 200", "status": 200})
```
