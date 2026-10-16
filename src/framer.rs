use crate::consts::MAX_HEADER_LEN;
#[cfg(feature = "http")]
use crate::consts::{PROCESSED_WS_KEY_B64_LEN, WS_KEY_B64_LEN};
use crate::{OP_BINARY, OP_CLOSE, OP_CONTINUATION, OP_PING, OP_PONG, OP_TEXT, WsFrame, WsRxError};
#[cfg(feature = "http")]
use httparse::Header;

/// Parsed frame header.
struct FrameHeader {
    fin: bool,
    rsv: u8,
    opcode: u8,
    mask: Option<[u8; 4]>,
    payload_len: u64,
    header_len: usize,
}

impl FrameHeader {
    /// Parses a header from the start of `raw`; `None` until enough bytes are there.
    fn parse(raw: &[u8]) -> Option<Self> {
        let (b0, b1) = (*raw.first()?, *raw.get(1)?);
        let (mut payload_len, mut header_len) = (u64::from(b1 & 0x7F), 2);
        if payload_len == 126 {
            payload_len = u64::from(u16::from_be_bytes(raw.get(2..4)?.try_into().ok()?));
            header_len = 4;
        } else if payload_len == 127 {
            payload_len = u64::from_be_bytes(raw.get(2..10)?.try_into().ok()?);
            header_len = 10;
        }

        let mask = if b1 & 0x80 != 0 {
            let key = raw.get(header_len..header_len + 4)?.try_into().ok()?;
            header_len += 4;
            Some(key)
        } else {
            None
        };

        Some(Self {
            fin: b0 & 0x80 != 0,
            rsv: b0 & 0x70,
            opcode: b0 & 0x0F,
            mask,
            payload_len,
            header_len,
        })
    }

    fn is_control(&self) -> bool {
        self.opcode & 0x08 != 0
    }

    /// Whole frame size (saturating, a huge frame is oversized anyway).
    fn total_len(&self) -> u64 {
        (self.header_len as u64).saturating_add(self.payload_len)
    }
}

fn apply_mask(data: &mut [u8], key: [u8; 4]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % 4];
    }
}

/// Framer used to receive websocket frames (and the HTTP upgrade response).
///
/// Usage: read from the socket into [`WsRxFramer::read_buf`], report the count with
/// [`WsRxFramer::advance`], then call [`WsRxFramer::next_frame`] until it
/// returns `None`. Fragmented messages are reassembled in place. Any read split is fine, so the
/// read can be cancelled (e.g. inside a `select`) without losing data.
pub struct WsRxFramer<'a> {
    buf: &'a mut [u8],
    /// Bytes stored in `buf`: `buf[..frag_len]` is reassembled fragment payload, the rest raw data.
    len: usize,
    frag_len: usize,
    /// Opcode of the fragmented message being reassembled.
    frag_opcode: Option<u8>,
    /// The message in `buf[..frag_len]` was handed out; drop it on the next call.
    release_frag: bool,
    /// Raw bytes still to discard (handed out frame, oversized frame, HTTP body).
    skip: u64,
    /// Rest of the current fragmented message is dropped (it overflowed or was invalid).
    discard_msg: bool,
}

/// HTTP response head; borrows the rx framer's buffer.
#[cfg(feature = "http")]
#[derive(Debug, Clone, Copy)]
pub struct HttpResponse<'a> {
    pub status_code: u16,
    headers: [Header<'a>; 16],
    headers_len: usize,
}

#[cfg(feature = "http")]
impl<'a> HttpResponse<'a> {
    /// All response headers.
    pub fn headers(&self) -> &[Header<'a>] {
        self.headers.get(..self.headers_len).unwrap_or_default()
    }

    /// Value of the first header called `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.headers()
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value)
    }

    /// `true` if this is a `101` response with the expected `Sec-WebSocket-Accept` (see
    /// [`WsTxFramer::accept_key`]).
    pub fn is_websocket_accepted(&self, accept_key: &[u8]) -> bool {
        self.status_code == 101 && self.header("Sec-WebSocket-Accept") == Some(accept_key)
    }
}

impl<'a> WsRxFramer<'a> {
    /// Creates a framer receiving into `buf`; frames (or fragmented messages) larger than it are
    /// reported as [`WsRxError::Oversized`] and skipped.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            len: 0,
            frag_len: 0,
            frag_opcode: None,
            release_frag: false,
            skip: 0,
            discard_msg: false,
        }
    }

    /// Free part of the buffer to read socket data into (never empty while data is awaited,
    /// unless the buffer is smaller than a frame header).
    pub fn read_buf(&mut self) -> &mut [u8] {
        self.compact();
        self.buf.get_mut(self.len..).unwrap_or_default()
    }

    /// Records `n` bytes read into [`WsRxFramer::read_buf`].
    pub fn advance(&mut self, n: usize) {
        self.len = self.len.saturating_add(n).min(self.buf.len());
    }

    /// Drops handed-out data and skipped bytes.
    fn compact(&mut self) {
        if self.release_frag {
            self.buf.copy_within(self.frag_len..self.len, 0);
            self.len -= self.frag_len;
            self.frag_len = 0;
            self.release_frag = false;
        }

        let raw = self.len - self.frag_len;
        let n = usize::try_from(self.skip).map_or(raw, |s| s.min(raw));
        if n > 0 {
            self.buf
                .copy_within(self.frag_len + n..self.len, self.frag_len);
            self.len -= n;
            self.skip -= n as u64;
        }
    }

    /// Drops the fragmented message being reassembled.
    fn abort_message(&mut self) {
        self.frag_opcode = None;
        self.release_frag = self.frag_len > 0;
        self.discard_msg = false;
    }

    /// Parses the HTTP response head of the upgrade request.
    ///
    /// Returns `None` until the whole head arrived. A body (`Content-Length`) is skipped; data
    /// after it is parsed as frames by [`WsRxFramer::next_frame`].
    #[cfg(feature = "http")]
    pub fn http_response(&mut self) -> Option<Result<HttpResponse<'_>, WsRxError>> {
        self.compact();
        if self.skip > 0 {
            return None;
        }

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);
        let raw = self.buf.get(self.frag_len..self.len)?;
        let head_len = match resp.parse(raw) {
            Ok(httparse::Status::Complete(n)) => n,
            Ok(httparse::Status::Partial) if self.len < self.buf.len() => return None,
            Ok(httparse::Status::Partial) => {
                self.skip = u64::MAX; // head doesn't fit: nothing usable follows
                return Some(Err(WsRxError::Oversized {
                    len: self.len as u64,
                }));
            }
            Err(_) => {
                self.skip = u64::MAX;
                return Some(Err(WsRxError::Protocol));
            }
        };

        let content_length = resp
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
            .map(|h| {
                core::str::from_utf8(h.value)
                    .ok()?
                    .trim()
                    .parse::<u64>()
                    .ok()
            });
        let Some(body_len) = content_length.unwrap_or(Some(0)) else {
            self.skip = u64::MAX;
            return Some(Err(WsRxError::Protocol));
        };
        self.skip = (head_len as u64).saturating_add(body_len);

        let Some(status_code) = resp.code else {
            return Some(Err(WsRxError::Protocol));
        };
        let mut out = HttpResponse {
            status_code,
            headers: [httparse::EMPTY_HEADER; 16],
            headers_len: resp.headers.len(),
        };
        for (o, h) in out.headers.iter_mut().zip(resp.headers.iter()) {
            *o = *h;
        }
        Some(Ok(out))
    }

    /// Returns the next complete frame (or reassembled message), `None` if more data is needed.
    ///
    /// Errors are per frame: the offending frame/message is dropped, keep calling.
    pub fn next_frame(&mut self) -> Option<Result<WsFrame<'_>, WsRxError>> {
        loop {
            self.compact();
            if self.skip > 0 {
                return None;
            }

            let s = self.frag_len;
            let Some(h) = FrameHeader::parse(self.buf.get(s..self.len)?) else {
                if self.len == self.buf.len() && s > 0 {
                    // reassembled fragments leave no room for the next header
                    let len = s as u64;
                    self.abort_message();
                    self.discard_msg = true;
                    return Some(Err(WsRxError::Oversized { len }));
                }
                return None;
            };
            let total = h.total_len();

            if self.discard_msg && h.opcode == OP_CONTINUATION {
                self.skip = total;
                self.discard_msg = !h.fin;
                continue;
            }

            if !h.is_control() {
                // a new message (or a misplaced continuation) ends any discarding
                self.discard_msg = false;
            }
            let fragmenting = self.frag_opcode.is_some();
            let protocol_error = h.rsv != 0
                || !matches!(
                    h.opcode,
                    OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
                )
                || (h.is_control() && (!h.fin || h.payload_len > 125))
                || (h.opcode == OP_CONTINUATION && !fragmenting)
                || (h.opcode != OP_CONTINUATION && !h.is_control() && fragmenting);
            if protocol_error || (s as u64).saturating_add(total) > self.buf.len() as u64 {
                self.skip = total;
                let message_len = if h.opcode == OP_CONTINUATION {
                    s as u64
                } else {
                    0
                };
                if !h.is_control() {
                    self.abort_message();
                    self.discard_msg = !h.fin;
                }
                return Some(Err(if protocol_error {
                    WsRxError::Protocol
                } else {
                    WsRxError::Oversized {
                        len: message_len.saturating_add(h.payload_len),
                    }
                }));
            }

            // fits the buffer, so it fits usize
            let (hl, pl) = (h.header_len, h.payload_len as usize);
            if self.len - s < hl + pl {
                return None;
            }

            let payload = s + hl..s + hl + pl;
            if let Some(key) = h.mask {
                apply_mask(&mut self.buf[payload.clone()], key);
            }

            if h.is_control() || (h.fin && !fragmenting) {
                self.skip = total;
                return Some(WsFrame::decode(h.opcode, &self.buf[payload]));
            }

            // fragment: append payload to buf[..frag_len] and drop its header
            self.buf.copy_within(payload, s);
            self.buf.copy_within(s + hl + pl..self.len, s + pl);
            self.len -= hl;
            self.frag_len += pl;
            if h.opcode != OP_CONTINUATION {
                self.frag_opcode = Some(h.opcode);
            }

            if h.fin {
                let opcode = self.frag_opcode.take().unwrap_or(OP_BINARY);
                self.release_frag = true;
                return Some(WsFrame::decode(opcode, &self.buf[..self.frag_len]));
            }
        }
    }
}

/// Bounds-checked writer over a byte buffer.
struct Writer<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(bytes.len())?;
        self.buf.get_mut(self.pos..end)?.copy_from_slice(bytes);
        self.pos = end;
        Some(())
    }
}

/// Length of a frame header for `payload_len` bytes.
fn header_len(payload_len: usize, mask: bool) -> usize {
    let ext = match payload_len {
        0..=125 => 0,
        126..=0xFFFF => 2,
        _ => 8,
    };
    2 + ext + if mask { 4 } else { 0 }
}

/// Writes a frame header into `out` (exactly `header_len(payload_len, key.is_some())` bytes).
fn write_header(out: &mut [u8], opcode: u8, fin: bool, payload_len: usize, key: Option<[u8; 4]>) {
    let mut w = Writer { buf: out, pos: 0 };
    let mask_bit = if key.is_some() { 0x80 } else { 0 };
    let b0 = if fin { 0x80 } else { 0 } | (opcode & 0x0F);
    _ = match payload_len {
        0..=125 => w.put(&[b0, mask_bit | payload_len as u8]),
        126..=0xFFFF => w
            .put(&[b0, mask_bit | 126])
            .and_then(|_| w.put(&(payload_len as u16).to_be_bytes())),
        _ => w
            .put(&[b0, mask_bit | 127])
            .and_then(|_| w.put(&(payload_len as u64).to_be_bytes())),
    };
    if let Some(key) = key {
        _ = w.put(&key);
    }
}

/// Framer used to send websocket frames (and HTTP upgrade requests/responses).
///
/// Every method returns `None` instead of panicking when the buffer is too small or the frame
/// is invalid (e.g. a control frame over 125 bytes).
pub struct WsTxFramer<'a> {
    buf: &'a mut [u8],
    /// Frames are masked (required for clients)
    mask: bool,
    /// Sec-WebSocket-Key of the last generated upgrade request
    #[cfg(feature = "http")]
    key: [u8; WS_KEY_B64_LEN],
}

impl<'a> WsTxFramer<'a> {
    /// Creates a framer writing into `buf`; clients must use `mask = true`.
    pub fn new(mask: bool, buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            mask,
            #[cfg(feature = "http")]
            key: [0; WS_KEY_B64_LEN],
        }
    }

    /// HTTP upgrade request for `path` (incl. query) on `host`, with a new random key.
    #[cfg(feature = "http")]
    pub fn http_upgrade_request(
        &mut self,
        host: &str,
        path: &str,
        extra_headers: &[Header],
    ) -> Option<&[u8]> {
        self.key = crate::crypto::random_key();
        let key_header = [
            Header {
                name: "Host",
                value: host.as_bytes(),
            },
            Header {
                name: "Sec-WebSocket-Key",
                value: &self.key,
            },
        ];

        let mut w = Writer {
            buf: &mut *self.buf,
            pos: 0,
        };
        w.put(b"GET ")?;
        w.put(path.as_bytes())?;
        w.put(b" HTTP/1.1\r\n")?;
        for headers in [
            &crate::consts::WS_DEFAULT_CONNECT_HEADERS[..],
            &key_header,
            extra_headers,
        ] {
            put_headers(&mut w, headers)?;
        }
        w.put(b"\r\n")?;
        let end = w.pos;
        self.buf.get(..end)
    }

    /// Expected `Sec-WebSocket-Accept` for the last [`WsTxFramer::http_upgrade_request`]; check
    /// it with [`HttpResponse::is_websocket_accepted`].
    #[cfg(feature = "http")]
    pub fn accept_key(&self) -> [u8; PROCESSED_WS_KEY_B64_LEN] {
        crate::crypto::accept_key(&self.key)
    }

    /// HTTP response (server side, e.g. `101 Switching Protocols`).
    #[cfg(feature = "http")]
    pub fn http_response(
        &mut self,
        status_code: u16,
        status_text: &str,
        headers: &[Header],
    ) -> Option<&[u8]> {
        let mut itoa = itoa::Buffer::new();
        let mut w = Writer {
            buf: &mut *self.buf,
            pos: 0,
        };
        w.put(b"HTTP/1.1 ")?;
        w.put(itoa.format(status_code).as_bytes())?;
        w.put(b" ")?;
        w.put(status_text.as_bytes())?;
        w.put(b"\r\n")?;
        put_headers(&mut w, headers)?;
        w.put(b"\r\n")?;
        let end = w.pos;
        self.buf.get(..end)
    }

    fn masking_key(&self) -> Option<[u8; 4]> {
        self.mask.then(|| {
            let mut key = [0; 4];
            crate::rng_fill(&mut key);
            key
        })
    }

    /// Builds one frame whose payload is the concatenation of `parts`.
    fn build(&mut self, opcode: u8, fin: bool, parts: &[&[u8]]) -> Option<&[u8]> {
        let len = parts
            .iter()
            .try_fold(0usize, |l, p| l.checked_add(p.len()))?;
        let hl = header_len(len, self.mask);
        let key = self.masking_key();
        let out = self.buf.get_mut(..hl.checked_add(len)?)?;

        let (header, payload) = out.split_at_mut(hl);
        write_header(header, opcode, fin, len, key);
        let mut w = Writer {
            buf: payload,
            pos: 0,
        };
        for part in parts {
            w.put(part)?;
        }
        if let Some(key) = key {
            apply_mask(payload, key);
        }
        Some(out)
    }

    /// Encodes a whole frame.
    pub fn frame(&mut self, frame: WsFrame<'_>) -> Option<&[u8]> {
        let opcode = frame.opcode();
        match frame {
            WsFrame::Close(code, reason) if reason.len() <= 123 => {
                self.build(opcode, true, &[&code.to_be_bytes(), reason.as_bytes()])
            }
            WsFrame::Close(..) => None,
            WsFrame::Ping(d) | WsFrame::Pong(d) if d.len() > 125 => None,
            _ => self.build(opcode, true, &[frame.data()]),
        }
    }

    /// Encodes the part of `frame` starting at payload `offset`, as big as the buffer allows.
    ///
    /// Advances `offset`; the returned bool is `true` while more parts follow (call again).
    /// Control frames are never split (`None` if they don't fit).
    pub fn frame_chunk(
        &mut self,
        frame: &WsFrame<'_>,
        offset: &mut usize,
    ) -> Option<(&[u8], bool)> {
        if frame.opcode() & 0x08 != 0 {
            if *offset != 0 {
                return None;
            }
            return self.frame(frame.clone()).map(|f| (f, false));
        }

        let rest = frame.data().get(*offset..)?;
        let room = self.buf.len().saturating_sub(MAX_HEADER_LEN);
        let chunk = rest.len().min(room);
        if chunk == 0 && !rest.is_empty() {
            return None;
        }

        let more = chunk < rest.len();
        let opcode = if *offset == 0 {
            frame.opcode()
        } else {
            OP_CONTINUATION
        };
        *offset += chunk;
        self.build(opcode, !more, &[rest.get(..chunk)?])
            .map(|f| (f, more))
    }

    /// Text frame whose payload `write` serializes straight into the tx buffer (no copy, no
    /// allocation), e.g. `|buf| serde_json_core::to_slice(&value, buf).ok()`.
    ///
    /// `write` returns the number of bytes written; `None` there (or invalid UTF-8) aborts.
    pub fn text_with(&mut self, write: impl FnOnce(&mut [u8]) -> Option<usize>) -> Option<&[u8]> {
        self.payload_with(OP_TEXT, write)
    }

    /// Binary frame whose payload `write` puts straight into the tx buffer.
    pub fn binary_with(&mut self, write: impl FnOnce(&mut [u8]) -> Option<usize>) -> Option<&[u8]> {
        self.payload_with(OP_BINARY, write)
    }

    fn payload_with(
        &mut self,
        opcode: u8,
        write: impl FnOnce(&mut [u8]) -> Option<usize>,
    ) -> Option<&[u8]> {
        let key = self.masking_key();
        let area = self.buf.get_mut(MAX_HEADER_LEN..)?;
        let n = write(area)?;
        let payload = area.get_mut(..n)?;
        if opcode == OP_TEXT && core::str::from_utf8(payload).is_err() {
            return None;
        }
        if let Some(key) = key {
            apply_mask(payload, key);
        }

        // header goes right before the payload
        let start = MAX_HEADER_LEN - header_len(n, self.mask);
        write_header(
            self.buf.get_mut(start..MAX_HEADER_LEN)?,
            opcode,
            true,
            n,
            key,
        );
        self.buf.get(start..MAX_HEADER_LEN + n)
    }

    /// Encodes an owned frame.
    #[cfg(feature = "alloc")]
    pub fn frame_owned(&mut self, frame: &crate::WsFrameOwned) -> Option<&[u8]> {
        self.frame(frame.as_frame())
    }

    /// Text frame.
    pub fn text(&mut self, data: &str) -> Option<&[u8]> {
        self.frame(WsFrame::Text(data))
    }

    /// Binary frame.
    pub fn binary(&mut self, data: &[u8]) -> Option<&[u8]> {
        self.frame(WsFrame::Binary(data))
    }

    /// Close frame; `reason` must be at most 123 bytes.
    pub fn close(&mut self, code: u16, reason: &str) -> Option<&[u8]> {
        self.frame(WsFrame::Close(code, reason))
    }

    /// Ping frame (payload at most 125 bytes).
    pub fn ping(&mut self, data: &[u8]) -> Option<&[u8]> {
        self.frame(WsFrame::Ping(data))
    }

    /// Pong frame (payload at most 125 bytes).
    pub fn pong(&mut self, data: &[u8]) -> Option<&[u8]> {
        self.frame(WsFrame::Pong(data))
    }
}

#[cfg(feature = "http")]
fn put_headers(w: &mut Writer<'_>, headers: &[Header]) -> Option<()> {
    for header in headers {
        w.put(header.name.as_bytes())?;
        w.put(b": ")?;
        w.put(header.value)?;
        w.put(b"\r\n")?;
    }
    Some(())
}
