# john-logs batch protocol (v2)

What an SDK sends to a john-logs gateway, what the gateway stores, and how a
body is read back. Package `wire` is the code; this is the prose. The SDK and
the gateway both import `wire`, so they cannot disagree.

## Why it looks like this

v1 shipped every record, bodies included, as one JSON array per request. On
2026-10-23 that lost 87% of the `tickets` stream: one uploader goroutine, three
tries, then the batch was dropped, while an 8,192-record queue holding whole
bodies filled up and dropped the rest. Bodies were 10.6 GB/day, and most of it
was the same pages again: same-size copies of a page differed only by nonces.

v2:

- batches are sealed every 500 ms (or at 2,000 records / 8 MiB) and wait on
  the client's disk until the gateway accepts them, however long that takes;
- bodies leave the log rows. Each is stored once in the batch's **pack**,
  compressed against an earlier body from the same endpoint (a 153 KB page
  becomes ~2 KB), and the row keeps search keys and a `*_ref` to it;
- the gateway answers 429 + `Retry-After` when it or OpenObserve is full, and
  clients back off instead of dropping.

## Request

```
POST /v2/ingest
Authorization: Bearer <ingest token>
Content-Type: application/x-johnlogs-batch
X-Johnlogs-Batch: <batch id>           same as the header's id; the idempotency key
X-Johnlogs-Client: <client id>
X-Johnlogs-Sdk: 0.2.0
X-Johnlogs-Host / -Service
X-Johnlogs-State: ok | behind | failing | full
X-Johnlogs-Pending-Bytes / -Pending-Records    what is still waiting on that client
X-Johnlogs-Spool-Used / -Spool-Max
X-Johnlogs-Dropped: <records lost since the client started>
X-Johnlogs-Oldest-Ms: <age of the oldest waiting batch>
```

The `X-Johnlogs-*` status headers are how the gateway sees every client's
backlog (for metrics and alarms) without the client sending anything extra.

Body (all integers big-endian):

```
"JLB2" | u32 header length | header JSON | records | pack
```

Header:

| field | |
|---|---|
| `id` | batch id: `<unix ms, hex>-<client id>-<seq, hex>`, lowercase hex and dashes |
| `n` | records in the batch |
| `rec_len`, `rec_raw` | records length compressed / uncompressed |
| `pack_len`, `bodies`, `body_raw` | pack length, blobs in it, their decoded bytes |
| `producer` | client id |
| `created` | unix µs when sealed |
| `dropped` | records the client lost since its previous batch (0 almost always) |

`records` is zstd-compressed NDJSON, one record (a flat JSON object) per line.

`pack` is blobs back to back:

```
u32 blob length | "JB" | kind | sha256 (32) | u32 size | [base] | zstd frame
```

- kind 0, **whole**: the frame is the body.
- kind 1, **delta**: the frame was compressed with a base body as its raw zstd
  dictionary (dictionary id = first 4 bytes of the base's sha256, or 1 if zero).
  `[base]` = `u16 length | base ref | base sha256`. A base is always a whole
  body, so any body is at most two reads.

sha256 and size are of the decoded body; readers check them.

A **ref** is `<batch id>:<offset>:<length>`: the pack and the blob's bytes in
it. Rows carry refs, so the log is the index of where every body is.

## Response

| status | the client |
|---|---|
| 2xx | deletes the batch from its spool |
| 408, 425, 429, 5xx, network error | retries after `Retry-After` or 0.5 s doubling to 30 s, with jitter; halves its concurrency |
| 401, 403, 404, 405 | retries every minute (bad token, or a gateway without v2) |
| other 4xx | the batch can never be accepted: moved to the spool's `dead/` and counted |

A batch may arrive twice (the client timed out after the gateway accepted it).
The gateway drops a repeat of a recent batch id.

## Body fields in a row

For a body under field `F` (`resp_body`, `req_body`):

| field | |
|---|---|
| `F` | the first `InlineBytes` (default 4096) as text; the whole body when it fits. Absent for non-UTF-8 bodies |
| `F_partial` | true when `F` is only the start |
| `F_size` | bytes |
| `F_sha256` | hash of the exact bytes |
| `F_ref` | where the whole body is |
| `F_shape` | 64-bit hash of the body with every word run that holds a digit or is 16+ long blanked: same page apart from nonces/ids/timestamps = same shape |
| `F_kind` | html, json, js, css, xml, text, image, font, protobuf, binary |
| `F_title` | HTML `<title>` |
| `F_markers` | signatures found in the first 512 KiB, comma-separated (`datadome`, `cloudflare_challenge`, `turnstile`, `kasada`, `akamai`, `perimeterx`, `incapsula`, `queueit`, `hcaptcha`, `recaptcha`, `access_denied`, `rate_limited`) |
| `F_json_keys` | a JSON object's top-level keys |

## Client spool

`Config.Spool` set: batches are frames in segment files (`seg-<seq>.jls`, see
spool.go) under a locked slot directory, acknowledged offsets in
`seg-<seq>.ack`. A new run resends whatever is left. Bodies are only
compressed against bases in the same segment, so deleting the oldest segment
to stay under `SpoolMax` never breaks a newer delta.

At `SpoolMax`, `WhenFull` decides: `DropOldest` (default) or `DropNewest`.
Losses are counted (`Stats().Dropped`), make `Stats().State` "full" for a
minute, go to `OnState`, ride the next batch's `dropped`, and show in the
`X-Johnlogs-Dropped` header.
