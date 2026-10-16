# ws-framer

Allocation-free, panic-free `no_std` websocket (RFC 6455) framer.

- **Receive** into a caller-provided buffer, frames are parsed (and unmasked, fragmented messages
  reassembled) in place. Reads can stop at any byte, so a read can be cancelled in a `select`
  without losing data.
- **Send** frames built into another buffer, or serialize a payload (e.g. JSON with
  `serde-json-core`) straight into it.
- **HTTP upgrade** request/response helpers with status code, borrowed headers and
  `Sec-WebSocket-Accept` verification (`http` feature, default).
- **Never panics** on any input: oversized frames, invalid UTF-8, malformed frames or HTTP are
  reported as `WsRxError` and skipped, so the connection survives. Tx methods return `None`
  when the buffer is too small.

## Features

| Feature | |
|---|---|
| `http` (default) | HTTP upgrade helpers (`httparse`) |
| `getrandom04` (default), `getrandom03`, `getrandom02` | randomness for client masking keys and `Sec-WebSocket-Key`; on bare metal register a getrandom custom backend. Without any of them the keys are all zero. |
| `alloc` | `WsFrameOwned`, `WsUrlOwned` |

## Client example (async, cancel-safe select loop)

```rust,ignore
use ws_framer::{WsFrame, WsRxFramer, WsTxFramer, WsUrl};

let url = WsUrl::parse("ws://192.168.1.10:8080/ws?id=1").unwrap();
let mut rx = WsRxFramer::new(&mut rx_buf);
let mut tx = WsTxFramer::new(true, &mut tx_buf); // clients mask their frames

// handshake
socket.write_all(tx.http_upgrade_request(url.host, url.path, &[]).ok_or(Error::TxBuf)?).await?;
let accept = tx.accept_key();
let accepted = loop {
    let n = socket.read(rx.read_buf()).await?;
    if n == 0 { return Err(Error::Closed) }
    rx.advance(n);
    if let Some(resp) = rx.http_response() {
        let resp = resp?;
        let signed = resp.header("x-custom"); // borrowed header access
        break resp.is_websocket_accepted(&accept);
    }
};

loop {
    match select(socket.read(rx.read_buf()), outgoing.receive()).await {
        Either::First(n) => {
            let n = n?;
            if n == 0 { break }
            rx.advance(n);
            while let Some(frame) = rx.next_frame() {
                match frame {
                    Ok(WsFrame::Text(json)) => handle(json),
                    Ok(WsFrame::Ping(p)) => pending_pong = true, // answer from the write side
                    Ok(WsFrame::Close(code, _)) => return Ok(code),
                    Ok(_) => {}
                    Err(e) => log::warn!("dropped frame: {e}"), // connection keeps working
                }
            }
        }
        Either::Second(packet) => {
            // serialize straight into the tx buffer, no String / Vec
            let bytes = tx
                .text_with(|buf| serde_json_core::to_slice(&packet, buf).ok())
                .ok_or(Error::TooBig)?;
            socket.write_all(bytes).await?;
        }
    }
}
```

Big payloads can be split into several frames with `WsTxFramer::frame_chunk`.

See `examples/ws-framer-test.rs` for a std echo server/client.

## Upgrading from 0.3

See [MIGRATING.md](MIGRATING.md).
