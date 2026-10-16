# Migrating from 0.3 to 0.4

0.4 makes the framer panic-free and allocation-free. Most changes are renames; the bigger
ones are fallible results everywhere and borrowed HTTP headers.

## Receiving

### `mut_buf` / `revolve_write_offset` / `process_data` → `read_buf` / `advance` / `next_frame`

`next_frame` returns `Option<Result<WsFrame, WsRxError>>`. An `Err` only drops that frame; keep
calling.

```rust
// 0.3
let n = socket.read(rx.mut_buf()).await?;
rx.revolve_write_offset(n);
while let Some(frame) = rx.process_data() {
    match frame { WsFrame::Text(t) => {}, _ => {} }
}

// 0.4
let n = socket.read(rx.read_buf()).await?;
rx.advance(n);
while let Some(frame) = rx.next_frame() {
    match frame {
        Ok(WsFrame::Text(t)) => {}
        Ok(_) => {}
        Err(e) => log::warn!("dropped frame: {e}"),
    }
}
```

What `Err` replaces: oversized frames used to wedge the connection (the buffer filled up and
reads returned 0), invalid UTF-8 was undefined behaviour (`from_utf8_unchecked`), a Close
frame without a status code panicked, and continuation frames were silently dropped (fragmented
messages are now reassembled).

### `WsFrame::Unknown` removed

Unknown opcodes are now `Err(WsRxError::Protocol)`; the variant is gone from `WsFrame` and
`WsFrameOwned`.

```rust
// 0.3
WsFrame::Unknown => {}
// 0.4 (nothing to match; use the Err arm)
```

### `process_http_response(n)` → `advance(n)` + `http_response()`

The byte count is no longer passed to the response parser, headers are borrowed (no `alloc`
needed) and the `Sec-WebSocket-Accept` can be verified.

```rust
// 0.3
let n = socket.read(rx.mut_buf()).await?;
if let Some(res) = rx.process_http_response(n) {
    let ok = res.status_code == 101;
    let signed = res.headers.iter().find(|h| h.name == "randomsigned"); // alloc feature
}

// 0.4
let n = socket.read(rx.read_buf()).await?;
rx.advance(n);
if let Some(res) = rx.http_response() {
    let res = res?; // WsRxError::Protocol / Oversized for malformed responses
    let ok = res.is_websocket_accepted(&tx.accept_key()); // status 101 + accept key
    let signed: Option<&[u8]> = res.header("randomsigned"); // case-insensitive
}
```

`HttpHeaderOwned` and `HttpResponse::headers: Vec<_>` are removed; use `HttpResponse::headers()`
/ `header()`. A response body (`Content-Length`) is skipped; frames sent right after the
response are parsed by `next_frame`.

## Sending

### All tx methods return `Option<&[u8]>`

`frame`, `text`, `binary`, `close`, `ping`, `pong`, `http_upgrade_request`, `http_response`
return `None` instead of panicking when the tx buffer is too small or the frame is invalid
(control payload over 125 bytes, close reason over 123 bytes).

```rust
// 0.3
socket.write_all(tx.text("hi")).await?;
// 0.4
socket.write_all(tx.text("hi").ok_or(Error::TxBuf)?).await?;
```

### `generate_http_upgrade` → `http_upgrade_request`

Extra headers are a plain slice; the expected accept key is available afterwards.

```rust
// 0.3
tx.generate_http_upgrade(host, path, None)
tx.generate_http_upgrade(host, path, Some(&headers))
// 0.4
tx.http_upgrade_request(host, path, &[])
tx.http_upgrade_request(host, path, &headers)
let accept = tx.accept_key();
```

### `generate_http_response` → `http_response`

```rust
// 0.3
tx.generate_http_response(101, "Switching Protocols", &headers)
// 0.4
tx.http_response(101, "Switching Protocols", &headers).unwrap_or_default()
```

### `partial_frame` → `frame_chunk`

Same `offset` contract, now `Option<(&[u8], bool)>` (bool = more chunks follow). Control frames
are never split. The first chunk carries the opcode, following ones are continuation frames.

```rust
// 0.3
let (data, more) = tx.partial_frame(&frame, &mut offset);
// 0.4
let (data, more) = tx.frame_chunk(&frame, &mut offset).ok_or(Error::TxBuf)?;
```

### New: `text_with` / `binary_with`

Serialize directly into the tx buffer instead of building a `String`:

```rust
// 0.3
let json = serde_json::to_string(&packet)?;
socket.write_all(tx.text(&json)).await?;
// 0.4
let bytes = tx.text_with(|buf| serde_json_core::to_slice(&packet, buf).ok()).ok_or(Error::TooBig)?;
socket.write_all(bytes).await?;
```

### `frame_owned` takes a reference; `WsFrameOwned::into_ref` → `as_frame`

```rust
// 0.3
tx.frame_owned(frame)          // consumed the frame
let f = owned.into_ref();
// 0.4
tx.frame_owned(&frame)
let f = owned.as_frame();
```

## Other

| 0.3 | 0.4 |
|---|---|
| `WsUrl::from_str(s)` | `WsUrl::parse(s)` (also rejects empty hosts and `?`/`#` in the host) |
| `WsUrl::ip` / `WsUrlOwned::ip` | `hostname` (it was never necessarily an IP) |
| `WsUrlOwned::as_ref()` | `WsUrlOwned::as_url()` |
| `process_sec_websocket_key(key) -> [u8; 28]` (panicked on long keys) | `-> Option<[u8; 28]>` (`None` unless the key is 24 chars) |
| `WsFrameHeader`, `WsTxFramer::generate_packet` | removed (use `frame` / `text_with`) |
| `httparse::Header` from your own `httparse` dependency | re-exported as `ws_framer::Header` |
| `ws-framer-macros` dependency | removed |
| edition 2021 | edition 2024 |
