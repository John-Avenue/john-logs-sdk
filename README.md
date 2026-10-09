# john-logs-sdk

Structured logging for Go that ships to a john-logs gateway. It is a
`log/slog` handler with no dependencies outside the standard library.

```bash
go get github.com/john-avenue/john-logs-sdk
```

```go
logs := johnlogs.New(johnlogs.Config{
	URL:     os.Getenv("JOHN_LOGS_URL"),
	Token:   os.Getenv("JOHN_LOGS_TOKEN"),
	Service: "my-app",
	Version: version,
	Console: slog.NewTextHandler(os.Stderr, nil), // optional
})
defer logs.Close(context.Background())
slog.SetDefault(logs.Logger())
```

`johnlogs.FromEnv("my-app")` builds the same config from `JOHN_LOGS_URL`,
`JOHN_LOGS_TOKEN`, `JOHN_LOGS_ENV` and `JOHN_LOGS_LEVEL`.

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

## Verbosity

`johnlogs.LevelTrace` sits below Debug for whole request/response bodies.
Guard expensive work with `logger.Enabled(ctx, johnlogs.LevelTrace)`. Pass a
`*slog.LevelVar` as `Config.Level` to change the level while running.

## Safety

- Field names that look like credentials (`token`, `password`, `secret`,
  `cookie`, `authorization`, `api_key`, card fields, …) are replaced with
  `[redacted]` at any depth, in shipped records and on the console. Override
  with `Config.Secret`.
- Strings longer than `Config.MaxField` (256 KiB) are clipped.
- Logging never blocks and never panics the caller. A full buffer or an
  unreachable gateway drops records; `Client.Dropped()` counts them, and the
  next shipped record carries `dropped_since_last`.
- The ingest token is write-only. It cannot read logs.

## Raw records

Code that already builds its own maps can skip slog:

```go
logs.Send(map[string]any{"message": "GET /x -> 200", "status": 200})
```
