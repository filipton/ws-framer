# Changelog

## 0.4.0

Breaking release, see [MIGRATING.md](MIGRATING.md).

### Fixed
- Close frame without a status code panicked (now `Close(1005, "")`).
- Received text and close reasons used `from_utf8_unchecked` (undefined behaviour on invalid
  UTF-8); now validated (`WsRxError::InvalidUtf8`).
- HTTP upgrade response with a `Content-Length` larger than the received data corrupted memory
  (unchecked `ptr::copy`); the body is now skipped safely.
- A frame larger than the rx buffer could never complete and wedged the connection (reads into
  an empty buffer returned 0); it is now reported as `WsRxError::Oversized` and skipped.
- 64-bit frame lengths are handled with checked math (no truncation / overflow).
- Fragmented messages were dropped; they are now reassembled in place (or reported + skipped
  if they don't fit).
- Unknown opcodes, reserved bits, fragmented or too long control frames are reported as
  `WsRxError::Protocol` and skipped instead of producing `Unknown` frames.
- SHA-1 read the input through an unaligned `*const u32` cast (undefined behaviour); rewritten
  without `unsafe`.
- `process_sec_websocket_key` panicked on keys longer than 24 chars.
- Tx: every builder indexed the buffer unchecked (panic on small buffers / long paths);
  `WsFrame::Unknown` hit `todo!()`; a 65535 byte payload used a 64-bit length.
- `WsUrl::parse` accepted empty hosts and `?`/`#` in the host.

### Added
- `WsRxFramer::http_response` with status code, borrowed headers (`header()`, `headers()`) and
  `is_websocket_accepted`; `WsTxFramer::accept_key`.
- `WsTxFramer::text_with` / `binary_with`: serialize payloads directly into the tx buffer.
- `WsRxError` (`Display` + `core::error::Error`), `CLOSE_NO_STATUS`, `Header` re-export.
- Host tests incl. every-split-point and fuzz tests.

### Changed
- Renamed: `mut_buf` → `read_buf`, `revolve_write_offset` → `advance`, `process_data` →
  `next_frame`, `process_http_response` → `http_response`, `generate_http_upgrade` →
  `http_upgrade_request`, `generate_http_response` → `http_response`, `partial_frame` →
  `frame_chunk`, `WsUrl::from_str` → `WsUrl::parse`, `ip` → `hostname`,
  `WsUrlOwned::as_ref` → `as_url`, `WsFrameOwned::into_ref` → `as_frame`.
- Tx methods return `Option<&[u8]>`.
- No `alloc` needed for HTTP headers; `ws-framer-macros` dependency dropped; edition 2024.

### Removed
- `WsFrame::Unknown`, `WsFrameOwned::Unknown`, `WsFrameHeader`, `WsTxFramer::generate_packet`,
  `HttpHeaderOwned`.
