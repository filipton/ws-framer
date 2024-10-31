use std::marker::PhantomData;

use crypto::Base64Pad;
use httparse::Header;
use structs::WsFrameHeader;

pub mod client;
mod crypto;
pub mod server;
pub mod structs;

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

const WS_KEY_B64_LEN: usize = Base64Pad::encode_len(16);
const U16_MAX: usize = u16::MAX as usize;

pub struct WsFramer<'a, RG: RngProvider> {
    buf: &'a mut [u8],
    mask: bool,
    rng_provider: core::marker::PhantomData<RG>,
}

impl<'a, RG: RngProvider> WsFramer<'a, RG> {
    pub fn new(mask: bool, buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            mask,
            rng_provider: PhantomData,
        }
    }

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

        let headers: &[Header] = match additional_headers {
            Some(additional_headers) => {
                &[&WS_DEFAULT_HEADERS[..], &headers, additional_headers].concat()
            }
            None => &[&WS_DEFAULT_HEADERS[..], &headers].concat(),
        };

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
            WsFrame::Close(code, reason) => &[&code.to_be_bytes(), reason.as_bytes()].concat(),
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
        };

        self.gen_packet(header, payload)
    }

    pub fn text<'b>(&'b mut self, data: &str) -> &'b [u8] {
        self.frame(WsFrame::Text(data))
    }

    pub fn binary<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Binary(data))
    }

    pub fn close<'b>(&'b mut self, code: u16, reason: &str) -> &'b [u8] {
        self.frame(WsFrame::Close(code, reason))
    }

    pub fn ping<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Ping(data))
    }

    pub fn pong<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Pong(data))
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum WsFrame<'a> {
    Text(&'a str),
    Binary(&'a [u8]),
    Close(u16, &'a str),
    Ping(&'a [u8]),
    Pong(&'a [u8]),
    Unknown,
}

impl WsFrame<'_> {
    pub fn opcode(&self) -> u8 {
        match self {
            WsFrame::Text(_) => 1,
            WsFrame::Binary(_) => 2,
            WsFrame::Close(..) => 8,
            WsFrame::Ping(_) => 9,
            WsFrame::Pong(_) => 10,
            WsFrame::Unknown => 0,
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
