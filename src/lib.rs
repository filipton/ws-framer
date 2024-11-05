#![no_std]

pub use crypto::process_sec_websocket_key;
pub use framer::{WsRxFramer, WsTxFramer};
pub use url::WsUrl;

mod consts;
mod crypto;
mod framer;
mod url;

#[derive(Debug, Clone)]
/// Websocket frame header
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

#[allow(dead_code)]
#[derive(Debug, Clone)]
/// Websocket frame (packet)
/// Stores reference to inner framer buffer
pub enum WsFrame<'a> {
    Text(&'a str),
    Binary(&'a [u8]),
    Close(u16, &'a str),
    Ping(&'a [u8]),
    Pong(&'a [u8]),
    Unknown,
}

impl<'a> WsFrame<'a> {
    /// Return opcode for frame
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

    /// Internal function to parse frame from header and buffer data
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
            8 => Self::Close(u16::from_be_bytes([buf[0], buf[1]]), unsafe {
                core::str::from_utf8_unchecked(&buf[2..])
            }),
            9 => Self::Ping(buf),
            10 => Self::Pong(buf),
            _ => Self::Unknown,
        }
    }
}

/// Trait used for random generation
/// Used to implement on different no-std platforms
pub trait RngProvider {
    fn random_u32() -> u32;
    fn random_buf(buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let len = chunk.len();
            chunk[..].copy_from_slice(&Self::random_u32().to_be_bytes()[..len]);
        }
    }
}
