use crate::{CLOSE_NO_STATUS, WsFrame, WsRxError, WsRxFramer, WsTxFramer};
use std::vec;
use std::vec::Vec;

#[derive(Debug, PartialEq, Eq, Clone)]
enum Ev {
    Text(Vec<u8>),
    Binary(Vec<u8>),
    Close(u16, Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Err(WsRxError),
}

fn ev(r: Result<WsFrame<'_>, WsRxError>) -> Ev {
    match r {
        Ok(WsFrame::Text(t)) => Ev::Text(t.as_bytes().to_vec()),
        Ok(WsFrame::Binary(b)) => Ev::Binary(b.to_vec()),
        Ok(WsFrame::Close(c, r)) => Ev::Close(c, r.as_bytes().to_vec()),
        Ok(WsFrame::Ping(b)) => Ev::Ping(b.to_vec()),
        Ok(WsFrame::Pong(b)) => Ev::Pong(b.to_vec()),
        Err(e) => Ev::Err(e),
    }
}

/// Independent frame encoder.
fn enc(fin: bool, op: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut v = vec![(fin as u8) << 7 | op];
    let m = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n @ 0..=125 => v.push(m | n as u8),
        n @ 126..=0xFFFF => {
            v.push(m | 126);
            v.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            v.push(m | 127);
            v.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(k) => {
            v.extend_from_slice(&k);
            v.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        }
        None => v.extend_from_slice(payload),
    }
    v
}

/// Feeds `data` in `chunk` sized reads, draining frames after each read. Also checks that the
/// framer always has room to read (it never wedges).
fn feed(rx: &mut WsRxFramer<'_>, data: &[u8], chunk: usize) -> Vec<Ev> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let buf = rx.read_buf();
        assert!(!buf.is_empty(), "rx framer wedged");
        let n = chunk.min(buf.len()).min(rest.len());
        buf[..n].copy_from_slice(&rest[..n]);
        rx.advance(n);
        rest = &rest[n..];
        while let Some(r) = rx.next_frame() {
            out.push(ev(r));
        }
    }
    out
}

fn feed_all(buf_len: usize, data: &[u8], chunk: usize) -> Vec<Ev> {
    let mut buf = vec![0; buf_len];
    let mut rx = WsRxFramer::new(&mut buf);
    feed(&mut rx, data, chunk)
}

#[test]
fn close_without_code() {
    let mut data = enc(true, 8, &[], None);
    data.extend(enc(true, 8, &[3], None)); // 1 byte payload is invalid
    data.extend(enc(true, 8, b"\x03\xe8bye", None));
    assert_eq!(
        feed_all(64, &data, 64),
        [
            Ev::Close(CLOSE_NO_STATUS, vec![]),
            Ev::Err(WsRxError::Protocol),
            Ev::Close(1000, b"bye".to_vec()),
        ]
    );
}

#[test]
fn invalid_utf8() {
    let mut data = enc(true, 1, &[0xff, 0xfe], None);
    data.extend(enc(true, 8, b"\x03\xe8\xff", None));
    data.extend(enc(true, 1, "żółw".as_bytes(), Some([1, 2, 3, 4])));
    assert_eq!(
        feed_all(64, &data, 64),
        [
            Ev::Err(WsRxError::InvalidUtf8),
            Ev::Err(WsRxError::InvalidUtf8),
            Ev::Text("żółw".as_bytes().to_vec()),
        ]
    );
}

#[test]
fn oversized_frame_is_skipped() {
    let big = vec![7u8; 300];
    let mut data = enc(true, 2, &big, Some([9, 8, 7, 6]));
    data.extend(enc(true, 1, b"ok", None));
    for chunk in [1, 5, 64, 1000] {
        assert_eq!(
            feed_all(64, &data, chunk),
            [
                Ev::Err(WsRxError::Oversized { len: 300 }),
                Ev::Text(b"ok".to_vec())
            ],
            "chunk {chunk}"
        );
    }

    // absurd 64-bit lengths must not overflow anything
    let mut huge = vec![0x82, 127];
    huge.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        feed_all(64, &huge, 64),
        [Ev::Err(WsRxError::Oversized { len: u64::MAX })]
    );
}

#[test]
fn protocol_errors_are_skipped() {
    let mut data = enc(true, 3, b"x", None); // reserved opcode
    data.extend([0xC1, 0x01, b'x']); // rsv1 set
    data.extend(enc(false, 9, b"p", None)); // fragmented ping
    data.extend(enc(true, 0, b"c", None)); // continuation without start
    data.extend(enc(true, 9, &[1; 126], None)); // control frame too long
    data.extend(enc(true, 10, b"pong", None));
    assert_eq!(
        feed_all(256, &data, 7),
        [
            Ev::Err(WsRxError::Protocol),
            Ev::Err(WsRxError::Protocol),
            Ev::Err(WsRxError::Protocol),
            Ev::Err(WsRxError::Protocol),
            Ev::Err(WsRxError::Protocol),
            Ev::Pong(b"pong".to_vec()),
        ]
    );
}

#[test]
fn fragmented_messages() {
    let mut data = enc(false, 1, b"Hel", Some([1, 2, 3, 4]));
    data.extend(enc(true, 9, b"ping", None)); // control frames may interleave
    data.extend(enc(false, 0, b"lo ", None));
    data.extend(enc(true, 0, "wörld".as_bytes(), Some([5, 6, 7, 8])));
    data.extend(enc(true, 2, b"after", None));
    for chunk in 1..data.len() {
        assert_eq!(
            feed_all(64, &data, chunk),
            [
                Ev::Ping(b"ping".to_vec()),
                Ev::Text("Hello wörld".as_bytes().to_vec()),
                Ev::Binary(b"after".to_vec()),
            ]
        );
    }

    // a message that outgrows the buffer is dropped as a whole
    let mut data = enc(false, 2, &[1; 30], None);
    data.extend(enc(false, 0, &[2; 30], None));
    data.extend(enc(true, 0, &[3; 30], None));
    data.extend(enc(true, 1, b"next", None));
    let evs = feed_all(64, &data, 64);
    assert!(matches!(evs[0], Ev::Err(WsRxError::Oversized { .. })));
    assert_eq!(evs[1..], [Ev::Text(b"next".to_vec())]);

    // new data frame while a message is open
    let mut data = enc(false, 1, b"a", None);
    data.extend(enc(true, 1, b"b", None));
    data.extend(enc(true, 1, b"c", None));
    assert_eq!(
        feed_all(64, &data, 64),
        [Ev::Err(WsRxError::Protocol), Ev::Text(b"c".to_vec())]
    );
}

#[test]
fn every_split_point() {
    let mut data = enc(true, 1, b"first", None);
    data.extend(enc(true, 2, &[0xAB; 200], Some([1, 2, 3, 4]))); // 16-bit length
    data.extend(enc(false, 1, b"frag", None));
    data.extend(enc(true, 0, b"ment", None));
    data.extend(enc(true, 8, b"\x03\xe8", None));
    let expected = [
        Ev::Text(b"first".to_vec()),
        Ev::Binary(vec![0xAB; 200]),
        Ev::Text(b"fragment".to_vec()),
        Ev::Close(1000, vec![]),
    ];

    for split in 0..=data.len() {
        let mut buf = vec![0; 256];
        let mut rx = WsRxFramer::new(&mut buf);
        let mut evs = feed(&mut rx, &data[..split], usize::MAX);
        evs.extend(feed(&mut rx, &data[split..], usize::MAX));
        assert_eq!(evs, expected, "split {split}");
    }
}

#[test]
fn tx_rx_round_trip_masked() {
    let mut tx_buf = vec![0; 512];
    let mut rx_buf = vec![0; 512];
    let mut tx = WsTxFramer::new(true, &mut tx_buf);
    let mut rx = WsRxFramer::new(&mut rx_buf);

    let big = vec![0x5A; 300];
    let frames = [
        WsFrame::Text("hello"),
        WsFrame::Binary(&big),
        WsFrame::Ping(b"p"),
        WsFrame::Pong(&[]),
        WsFrame::Close(4000, "sleep"),
    ];
    for f in frames {
        let bytes = tx.frame(f.clone()).unwrap().to_vec();
        assert_ne!(bytes[1] & 0x80, 0, "client frames are masked");
        let evs = feed(&mut rx, &bytes, 3);
        assert_eq!(evs, [ev(Ok(f))]);
    }

    // payload serialized straight into the tx buffer
    let bytes = tx
        .text_with(|buf| {
            buf[..4].copy_from_slice(b"{\"a\"");
            buf[4..7].copy_from_slice(b":1}");
            Some(7)
        })
        .unwrap()
        .to_vec();
    assert_eq!(feed(&mut rx, &bytes, 2), [Ev::Text(b"{\"a\":1}".to_vec())]);
    assert!(
        tx.text_with(|buf| {
            buf[0] = 0xff;
            Some(1)
        })
        .is_none()
    );
    assert!(tx.text_with(|_| None).is_none());
    assert!(tx.binary_with(|buf| Some(buf.len() + 1)).is_none());

    // invalid control frames are refused instead of sent
    assert!(tx.ping(&[0; 126]).is_none());
    assert!(tx.close(1000, &"x".repeat(124)).is_none());
}

#[test]
fn chunked_tx_reassembles() {
    let msg: Vec<u8> = (0..=255).cycle().take(1000).collect();
    let mut tx_buf = vec![0; 100];
    let mut rx_buf = vec![0; 2048];
    let mut tx = WsTxFramer::new(true, &mut tx_buf);
    let mut rx = WsRxFramer::new(&mut rx_buf);

    let frame = WsFrame::Binary(&msg);
    let (mut offset, mut evs, mut parts) = (0, Vec::new(), 0);
    loop {
        let (bytes, more) = tx.frame_chunk(&frame, &mut offset).unwrap();
        evs.extend(feed(&mut rx, bytes, 64));
        parts += 1;
        if !more {
            break;
        }
    }
    assert!(parts > 1);
    assert_eq!(evs, [Ev::Binary(msg)]);

    let mut offset = 0;
    assert!(tx.frame_chunk(&WsFrame::Text(""), &mut offset).is_some());
    let mut offset = 5;
    assert!(tx.frame_chunk(&WsFrame::Ping(b"x"), &mut offset).is_none());
    let mut tiny = [0; 4];
    let mut tx = WsTxFramer::new(true, &mut tiny);
    assert!(tx.text("x").is_none());
    assert!(tx.frame_chunk(&WsFrame::Text("x"), &mut 0).is_none());
}

#[cfg(feature = "http")]
mod http {
    use super::*;
    use httparse::Header;

    fn request_key(req: &[u8]) -> std::string::String {
        let req = core::str::from_utf8(req).unwrap();
        let line = req
            .lines()
            .find(|l| l.starts_with("Sec-WebSocket-Key: "))
            .unwrap();
        line["Sec-WebSocket-Key: ".len()..].into()
    }

    #[test]
    fn upgrade_handshake() {
        let mut tx_buf = vec![0; 512];
        let mut tx = WsTxFramer::new(true, &mut tx_buf);
        let extra = [Header {
            name: "X-Test",
            value: b"1",
        }];
        let req = tx
            .http_upgrade_request("example.com:80", "/ws?id=1", &extra)
            .unwrap()
            .to_vec();
        assert!(req.starts_with(b"GET /ws?id=1 HTTP/1.1\r\n"));
        assert!(req.ends_with(b"X-Test: 1\r\n\r\n"));
        let accept = crate::process_sec_websocket_key(&request_key(&req)).unwrap();
        assert_eq!(accept, tx.accept_key());

        let mut resp = std::format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nsec-websocket-accept: {}\r\nrandomsigned: 42\r\n\r\n",
            core::str::from_utf8(&accept).unwrap()
        )
        .into_bytes();
        resp.extend(enc(true, 1, b"hi", None)); // first frame in the same read

        let mut rx_buf = vec![0; 256];
        let mut rx = WsRxFramer::new(&mut rx_buf);
        for (i, b) in resp.iter().enumerate() {
            rx.read_buf()[0] = *b;
            rx.advance(1);
            if let Some(r) = rx.http_response() {
                let r = r.unwrap();
                assert!(r.is_websocket_accepted(&accept));
                assert!(!r.is_websocket_accepted(b"wrong"));
                assert_eq!(r.header("RandomSigned"), Some(&b"42"[..]));
                assert!(i < resp.len() - 1);
                let rest = resp[i + 1..].to_vec();
                assert_eq!(feed(&mut rx, &rest, 1), [Ev::Text(b"hi".to_vec())]);
                return;
            }
        }
        panic!("no response parsed");
    }

    #[test]
    fn bad_responses() {
        let parse = |data: &[u8], buf_len: usize| {
            let mut buf = vec![0; buf_len];
            let mut rx = WsRxFramer::new(&mut buf);
            let n = data.len().min(buf_len);
            rx.read_buf()[..n].copy_from_slice(&data[..n]);
            rx.advance(n);
            let res = rx.http_response().map(|r| r.map(|r| r.status_code));
            let after = feed(&mut rx, &enc(true, 1, b"x", None), 64);
            (res, after)
        };

        // huge Content-Length: body skipped, no memory corruption, framer still usable
        let (res, after) = parse(
            b"HTTP/1.1 400 Bad\r\nContent-Length: 99999999999999\r\n\r\nbody",
            64,
        );
        assert_eq!(res, Some(Ok(400)));
        assert!(after.is_empty());

        let (res, after) = parse(b"HTTP/1.1 101 OK\r\nContent-Length: 4\r\n\r\nbody", 64);
        assert_eq!(res, Some(Ok(101)));
        assert_eq!(after, [Ev::Text(b"x".to_vec())]);

        let (res, _) = parse(b"HTTP/1.1 101 OK\r\nContent-Length: nope\r\n\r\n", 64);
        assert_eq!(res, Some(Err(WsRxError::Protocol)));
        let (res, _) = parse(b"garbage\r\n\r\n", 64);
        assert_eq!(res, Some(Err(WsRxError::Protocol)));
        let (res, _) = parse(
            b"HTTP/1.1 101 OK\r\nA: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            32,
        );
        assert!(matches!(res, Some(Err(WsRxError::Oversized { .. }))));
        let (res, _) = parse(b"HTTP/1.1 10", 64);
        assert_eq!(res, None);
    }

    #[test]
    fn tx_too_small_is_none() {
        let mut buf = [0; 16];
        let mut tx = WsTxFramer::new(true, &mut buf);
        assert!(tx.http_upgrade_request("host", "/long/path", &[]).is_none());
        assert!(tx.http_response(101, "Switching Protocols", &[]).is_none());
    }
}

#[test]
fn fuzz_never_panics_or_wedges() {
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut rand = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    for i in 0..3000 {
        let len = (rand() % 400) as usize;
        let mut data: Vec<u8> = (0..len).map(|_| rand() as u8).collect();
        // bias towards valid-looking headers so the parser goes deep
        if let Some(b) = data.get_mut(1)
            && i % 2 == 0
        {
            *b = (*b & 0x80) | (*b % 60);
        }
        let buf_len = [16, 64, 300][i % 3];
        let chunk = 1 + (rand() % 50) as usize;
        let _ = feed_all(buf_len, &data, chunk);

        #[cfg(feature = "http")]
        {
            let mut buf = vec![0; buf_len];
            let mut rx = WsRxFramer::new(&mut buf);
            let n = data.len().min(buf_len);
            rx.read_buf()[..n].copy_from_slice(&data[..n]);
            rx.advance(n);
            let _ = rx.http_response().map(|r| r.map(|r| r.headers().len()));
            let _ = feed(&mut rx, &data, chunk);
        }
    }
}
