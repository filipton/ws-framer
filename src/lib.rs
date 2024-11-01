#![no_std]

use core::marker::PhantomData;
use crypto::Base64Pad;

#[cfg(feature = "http")]
use httparse::Header;

mod crypto;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WsFrameHeader {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: u8,
    pub mask: bool,
    pub masking_key: [u8; 4],
    pub payload_len: usize,
    offset: usize,
}

#[cfg(feature = "http")]
const WS_DEFAULT_HEADERS: [Header; 3] = [
    Header {
        name: "Connection",
        value: b"Upgrade",
    },
    Header {
        name: "Upgrade",
        value: b"websocket",
    },
    Header {
        name: "Sec-WebSocket-Version",
        value: b"13",
    },
];

const WS_KEY_GUID: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const WS_KEY_B64_LEN: usize = Base64Pad::encode_len(16);
const WS_HASH_LEN: usize = WS_KEY_GUID.len() + WS_KEY_B64_LEN;
const SHA1_BLOCKS_LEN: usize = crypto::sha1_blocks_len(WS_HASH_LEN);
const PROCESSED_WS_KEY_B64_LEN: usize = Base64Pad::encode_len(20);
const U16_MAX: usize = u16::MAX as usize;

pub struct WsFramer<'a, RG: RngProvider> {
    buf: &'a mut [u8],
    mask: bool,

    current_header: Option<WsFrameHeader>,
    read_offset: usize,
    write_offset: usize,
    packet_size: usize,

    rng_provider: core::marker::PhantomData<RG>,
}

impl<'a, RG: RngProvider> WsFramer<'a, RG> {
    pub fn new(mask: bool, buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            mask,

            current_header: None,
            read_offset: 0,
            write_offset: 0,
            packet_size: 0,

            rng_provider: PhantomData,
        }
    }

    #[cfg(feature = "http")]
    pub fn gen_connect_packet<'b>(
        &'b mut self,
        host: &str,
        path: &str,
        additional_headers: Option<&[Header]>,
    ) -> &'b [u8] {
        let mut ws_key = [0u8; 16];
        RG::random_buf(&mut ws_key);
        let mut ws_key_b64 = [0u8; WS_KEY_B64_LEN];
        Base64Pad::encode_slice(&ws_key, &mut ws_key_b64);

        self.buf[0..4].copy_from_slice(b"GET ");
        let mut offset = 4 + path.as_bytes().len();
        self.buf[4..offset].copy_from_slice(path.as_bytes());
        self.buf[offset..offset + 11].copy_from_slice(b" HTTP/1.1\r\n");
        offset += 11;

        let headers = [
            Header {
                name: "Host",
                value: host.as_bytes(),
            },
            Header {
                name: "Sec-WebSocket-Key",
                value: &ws_key_b64,
            },
        ];

        self.append_headers(&WS_DEFAULT_HEADERS, &mut offset);
        self.append_headers(&headers, &mut offset);
        if let Some(additional) = additional_headers {
            self.append_headers(&additional, &mut offset);
        }

        for header in headers {
            self.buf[offset..offset + header.name.len()].copy_from_slice(header.name.as_bytes());
            offset += header.name.len();

            self.buf[offset..offset + 2].copy_from_slice(b": ");
            offset += 2;

            self.buf[offset..offset + header.value.len()].copy_from_slice(header.value);
            offset += header.value.len();

            self.buf[offset..offset + 2].copy_from_slice(b"\r\n");
            offset += 2;
        }

        self.buf[offset..offset + 2].copy_from_slice(b"\r\n");
        &self.buf[0..offset + 2]
    }

    #[cfg(feature = "http")]
    pub fn construct_http_resp<'b>(
        &'b mut self,
        status_code: u16,
        status_text: &str,
        headers: &[Header],
    ) -> &'b [u8] {
        self.buf[..9].copy_from_slice(b"HTTP/1.1 ");
        let mut itoa = itoa::Buffer::new();
        let status_code = itoa.format(status_code);

        self.buf[9..9 + status_code.len()].copy_from_slice(status_code.as_bytes());
        let mut offset = 9 + status_code.len();
        self.buf[offset] = b' ';
        self.buf[offset + 1..offset + 1 + status_text.len()]
            .copy_from_slice(status_text.as_bytes());
        offset += 1 + status_text.len();
        self.buf[offset..offset + 2].copy_from_slice(b"\r\n");
        offset += 2;

        for header in headers {
            self.buf[offset..offset + header.name.len()].copy_from_slice(header.name.as_bytes());
            offset += header.name.len();

            self.buf[offset..offset + 2].copy_from_slice(b": ");
            offset += 2;

            self.buf[offset..offset + header.value.len()].copy_from_slice(header.value);
            offset += header.value.len();

            self.buf[offset..offset + 2].copy_from_slice(b"\r\n");
            offset += 2;
        }

        self.buf[offset..offset + 2].copy_from_slice(b"\r\n");
        &self.buf[0..offset + 2]
    }

    fn append_headers<'b>(&'b mut self, headers: &[Header], offset: &mut usize) {
        for header in headers {
            self.buf[*offset..*offset + header.name.len()].copy_from_slice(header.name.as_bytes());
            *offset += header.name.len();

            self.buf[*offset..*offset + 2].copy_from_slice(b": ");
            *offset += 2;

            self.buf[*offset..*offset + header.value.len()].copy_from_slice(header.value);
            *offset += header.value.len();

            self.buf[*offset..*offset + 2].copy_from_slice(b"\r\n");
            *offset += 2;
        }
    }

    pub fn gen_packet<'b>(&'b mut self, header: WsFrameHeader, data: &[u8]) -> &'b [u8] {
        let first_byte = (header.fin as u8) << 7
            | (header.rsv1 as u8) << 6
            | (header.rsv2 as u8) << 5
            | (header.rsv3 as u8) << 4
            | header.opcode & 0x0F;
        self.buf[0] = first_byte;

        let mut offset = 1;
        match header.payload_len {
            0..=125 => {
                self.buf[offset] = (header.mask as u8) << 7 | header.payload_len as u8;
                offset += 1;
            }
            126..U16_MAX => {
                self.buf[offset] = (header.mask as u8) << 7 | 126;
                self.buf[offset + 1..offset + 1 + 2]
                    .copy_from_slice(&(header.payload_len as u16).to_be_bytes());

                offset += 3;
            }
            U16_MAX.. => {
                self.buf[offset] = (header.mask as u8) << 7 | 127;
                self.buf[offset + 1..offset + 1 + 8]
                    .copy_from_slice(&(header.payload_len as u64).to_be_bytes());

                offset += 9;
            }
        }

        if header.mask {
            self.buf[offset..offset + 4].copy_from_slice(&header.masking_key);
            offset += 4;

            for d in data
                .iter()
                .enumerate()
                .map(|(i, &x)| x ^ header.masking_key[i % 4])
            {
                self.buf[offset] = d;
                offset += 1;
            }
        } else {
            self.buf[offset..offset + data.len()].copy_from_slice(data);
            offset += data.len();
        }

        &self.buf[..offset]
    }

    pub fn frame<'b>(&'b mut self, frame: WsFrame<'_>) -> &'b [u8] {
        let mut masking_key = [0; 4];
        if self.mask {
            RG::random_buf(&mut masking_key);
        }

        let payload = match frame {
            WsFrame::Text(data) => data.as_bytes(),
            WsFrame::Binary(data) => data,
            WsFrame::Close(code) => &code.to_be_bytes(),
            WsFrame::Ping(data) => data,
            WsFrame::Pong(data) => data,
            WsFrame::Unknown => todo!(),
        };

        let header = WsFrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: frame.opcode(),
            mask: self.mask,
            masking_key,
            payload_len: payload.len(),
            offset: 0,
        };

        self.gen_packet(header, payload)
    }

    pub fn text<'b>(&'b mut self, data: &str) -> &'b [u8] {
        self.frame(WsFrame::Text(data))
    }

    pub fn binary<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Binary(data))
    }

    pub fn close<'b>(&'b mut self, code: u16) -> &'b [u8] {
        self.frame(WsFrame::Close(code))
    }

    pub fn ping<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Ping(data))
    }

    pub fn pong<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Pong(data))
    }

    pub fn process_data<'b>(&'b mut self, n: usize) -> Option<WsFrame<'b>> {
        self.write_offset += n;
        if self.read_offset > 0 {
            self.write_offset -= self.packet_size;

            unsafe {
                core::ptr::copy(
                    self.buf.as_ptr().offset(self.read_offset as isize),
                    self.buf.as_mut_ptr(),
                    self.write_offset,
                );
            }

            self.read_offset = 0;
            self.packet_size = 0;
        }

        if self.current_header.is_none() {
            let tmp_buf = self.buf[0..self.write_offset].as_mut();
            let fin = (tmp_buf.get(0)? & 0b10000000) >> 7;
            let rsv1 = (tmp_buf.get(0)? & 0b01000000) >> 6;
            let rsv2 = (tmp_buf.get(0)? & 0b00100000) >> 5;
            let rsv3 = (tmp_buf.get(0)? & 0b00010000) >> 4;
            let opcode = tmp_buf.get(0)? & 0b00001111;
            let mask = (tmp_buf.get(1)? & 0b10000000) >> 7;
            let mut payload_len = (tmp_buf.get(1)? & 0b01111111) as usize;

            let mut offset = 2;
            if payload_len == 126 {
                payload_len = u16::from_be_bytes(tmp_buf.get(2..4)?.try_into().unwrap()) as usize;
                offset += 2;
            } else if payload_len == 127 {
                payload_len = u64::from_be_bytes(tmp_buf.get(2..10)?.try_into().unwrap()) as usize;
                offset += 8;
            }

            let mut masking_key = [0; 4];
            if mask == 1 {
                masking_key.copy_from_slice(&tmp_buf.get(offset..offset + 4)?);
                offset += 4;
            }

            self.current_header = Some(WsFrameHeader {
                fin: fin == 1,
                rsv1: rsv1 == 1,
                rsv2: rsv2 == 1,
                rsv3: rsv3 == 1,
                opcode,
                mask: mask == 1,
                masking_key,
                payload_len,
                offset,
            });

            self.packet_size = offset + payload_len;
        }

        if self.write_offset >= self.packet_size && self.current_header.is_some() {
            let header = self.current_header.take().unwrap();
            self.read_offset = header.offset + header.payload_len;

            return Some(WsFrame::from_data(
                &header,
                &mut self.buf[header.offset..header.offset + header.payload_len],
            ));
        }

        None
    }

    pub fn mut_buf<'b>(&'b mut self) -> &'b mut [u8] {
        self.buf[self.write_offset..].as_mut()
    }

    pub fn reset(&mut self) {
        self.current_header = None;
        self.read_offset = 0;
        self.write_offset = 0;
        self.packet_size = 0;
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum WsFrame<'a> {
    Text(&'a str),
    Binary(&'a [u8]),
    Close(u16), // REASON IS REMOVED DUE TO no_std RESTRICTIONS
    Ping(&'a [u8]),
    Pong(&'a [u8]),
    Unknown,
}

impl<'a> WsFrame<'a> {
    pub fn opcode(&self) -> u8 {
        match self {
            WsFrame::Text(_) => 1,
            WsFrame::Binary(_) => 2,
            WsFrame::Close(_) => 8,
            WsFrame::Ping(_) => 9,
            WsFrame::Pong(_) => 10,
            WsFrame::Unknown => 0,
        }
    }

    pub(crate) fn from_data(header: &WsFrameHeader, buf: &'a mut [u8]) -> Self {
        if header.mask {
            for (i, x) in buf.iter_mut().enumerate() {
                let key = header.masking_key[i % 4];
                *x ^= key;
            }
        }

        match header.opcode {
            1 => Self::Text(unsafe { core::str::from_utf8_unchecked(buf) }),
            2 => Self::Binary(buf),
            8 => Self::Close(u16::from_be_bytes([buf[0], buf[1]])),
            9 => Self::Ping(buf),
            10 => Self::Pong(buf),
            _ => Self::Unknown,
        }
    }
}

pub trait RngProvider {
    fn random_u32() -> u32;
    fn random_buf(buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let len = chunk.len();
            chunk[..].copy_from_slice(&Self::random_u32().to_be_bytes()[..len]);
        }
    }
}

pub fn process_sec_websocket_key(key: &str) -> [u8; PROCESSED_WS_KEY_B64_LEN] {
    let mut blocks = [0; SHA1_BLOCKS_LEN];
    blocks[..key.len()].copy_from_slice(key.as_bytes());
    blocks[key.len()..key.len() + WS_KEY_GUID.len()].copy_from_slice(WS_KEY_GUID.as_bytes());

    let mut tmp = [0; PROCESSED_WS_KEY_B64_LEN];
    let hash = crate::crypto::sha1(&mut blocks, WS_HASH_LEN);
    crate::crypto::Base64Pad::encode_slice(&hash, &mut tmp);

    tmp
}

#[derive(Debug, PartialEq)]
pub struct WsUrl<'a> {
    pub host: &'a str,
    pub ip: &'a str,
    pub port: u16,

    pub path: &'a str,
    pub secure: bool,
}

impl WsUrl<'_> {
    pub fn from_str<'a>(ws_url: &'a str) -> Option<WsUrl<'a>> {
        let (secure, host_start_offset) = if ws_url.starts_with("ws://") {
            (false, 5)
        } else if ws_url.starts_with("wss://") {
            (true, 6)
        } else {
            return None;
        };

        let mut host_end = None;
        if let Some(ws_url) = ws_url.get(host_start_offset..) {
            let chars = ws_url.char_indices();
            for c in chars {
                if c.1 == '/' {
                    host_end = Some(c.0 + host_start_offset);
                    break;
                }
            }
        }

        let host = ws_url.get(host_start_offset..host_end.unwrap_or(ws_url.len()))?;
        let path = ws_url.get(host_end.unwrap_or(ws_url.len())..ws_url.len())?;
        let path = if path.len() == 0 { "/" } else { path };

        let mut host_split = host.split(':');
        let ip = host_split.next()?;
        let port = host_split
            .next()
            .and_then(|p_str| u16::from_str_radix(p_str, 10).ok())
            .unwrap_or(if secure { 443 } else { 80 });

        if host_split.count() > 0 {
            return None;
        }

        Some(WsUrl {
            host,
            ip,
            port,
            path,
            secure,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ws_url_parse() {
        assert_eq!(
            WsUrl::from_str("ws://127.0.0.1"),
            Some(WsUrl {
                host: "127.0.0.1",
                ip: "127.0.0.1",
                port: 80,
                path: "/",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::from_str("wss://127.0.0.1"),
            Some(WsUrl {
                host: "127.0.0.1",
                ip: "127.0.0.1",
                port: 443,
                path: "/",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::from_str("ws://127.0.0.1:4321"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                ip: "127.0.0.1",
                port: 4321,
                path: "/",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::from_str("wss://127.0.0.1:4321"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                ip: "127.0.0.1",
                port: 4321,
                path: "/",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::from_str("ws://127.0.0.1:4321/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                ip: "127.0.0.1",
                port: 4321,
                path: "/cxz/ewq",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::from_str("wss://127.0.0.1:4321/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                ip: "127.0.0.1",
                port: 4321,
                path: "/cxz/ewq",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::from_str("ws://127.0.0.1/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1",
                ip: "127.0.0.1",
                port: 80,
                path: "/cxz/ewq",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::from_str("wss://127.0.0.1/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1",
                ip: "127.0.0.1",
                port: 443,
                path: "/cxz/ewq",
                secure: true
            })
        );

        assert_eq!(WsUrl::from_str("wsc://127.0.0.1/cxz/ewq"), None);
        assert_eq!(WsUrl::from_str("ws://127.0.0.1:4321:123/cxz/ewq"), None);
    }

    #[test]
    fn validate_sec_ws_key() {
        assert_eq!(
            process_sec_websocket_key("dGhlIHNhbXBsZSBub25jZQ=="),
            b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".as_ref()
        );
    }
}
