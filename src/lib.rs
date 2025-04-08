#![no_std]

pub use crypto::process_sec_websocket_key;
pub use framer::{WsRxFramer, WsTxFramer};
pub use url::WsUrl;

#[cfg(feature = "alloc")]
pub use url::WsUrlOwned;

#[cfg(feature = "alloc")]
extern crate alloc;

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

#[cfg(feature = "alloc")]
#[allow(dead_code)]
#[derive(Debug, Clone)]
/// Websocket frame (packet)
/// Owned version of WsFrame
pub enum WsFrameOwned {
    Text(alloc::string::String),
    Binary(alloc::vec::Vec<u8>),
    Close(u16, alloc::string::String),
    Ping(alloc::vec::Vec<u8>),
    Pong(alloc::vec::Vec<u8>),
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

    /// Helper to return data bytes from frame (if you dont care about frame type)
    pub fn data(&self) -> &'a [u8] {
        match self {
            WsFrame::Text(str) => str.as_bytes(),
            WsFrame::Binary(byt) => byt,
            WsFrame::Close(_, reason) => reason.as_bytes(),
            WsFrame::Ping(byt) => byt,
            WsFrame::Pong(byt) => byt,
            WsFrame::Unknown => &[],
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a> WsFrameOwned {
    pub fn into_ref(&'a self) -> WsFrame<'a> {
        match self {
            WsFrameOwned::Text(string) => WsFrame::Text(&string),
            WsFrameOwned::Binary(vec) => WsFrame::Binary(&vec),
            WsFrameOwned::Close(code, reason) => WsFrame::Close(*code, &reason),
            WsFrameOwned::Ping(vec) => WsFrame::Ping(&vec),
            WsFrameOwned::Pong(vec) => WsFrame::Pong(&vec),
            WsFrameOwned::Unknown => WsFrame::Unknown,
        }
    }
}

pub(crate) fn rng_fill(buf: &mut [u8]) {
    #[cfg(feature = "getrandom02")]
    {
        _ = getrandom02::getrandom(buf);
    }

    #[cfg(feature = "getrandom03")]
    {
        _ = getrandom03::fill(buf);
    }
}
