#![no_std]
//! Allocation-free websocket (RFC 6455) framer for `no_std`.
//!
//! [`WsRxFramer`] parses incoming frames (and the HTTP upgrade response) in place inside a
//! caller-provided buffer, [`WsTxFramer`] builds outgoing frames into another one. Neither
//! panics on any input: malformed, oversized or invalid data is reported as [`WsRxError`] and
//! skipped, so the connection survives.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub use crypto::process_sec_websocket_key;
#[cfg(feature = "http")]
pub use framer::HttpResponse;
pub use framer::{WsRxFramer, WsTxFramer};
/// HTTP header type used by the upgrade request/response helpers.
#[cfg(feature = "http")]
pub use httparse::Header;
pub use url::WsUrl;
#[cfg(feature = "alloc")]
pub use url::WsUrlOwned;

mod consts;
mod crypto;
mod framer;
mod url;

#[cfg(test)]
mod tests;

/// Close code reported for a Close frame without a status code (RFC 6455, 7.1.5).
pub const CLOSE_NO_STATUS: u16 = 1005;

/// Websocket frame (message); borrows the framer's buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrame<'a> {
    Text(&'a str),
    Binary(&'a [u8]),
    /// Status code ([`CLOSE_NO_STATUS`] if the peer sent none) and reason.
    Close(u16, &'a str),
    Ping(&'a [u8]),
    Pong(&'a [u8]),
}

/// Owned version of [`WsFrame`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrameOwned {
    Text(alloc::string::String),
    Binary(alloc::vec::Vec<u8>),
    Close(u16, alloc::string::String),
    Ping(alloc::vec::Vec<u8>),
    Pong(alloc::vec::Vec<u8>),
}

/// Problem with received data. The offending frame (or message) is dropped and parsing
/// continues with the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsRxError {
    /// A frame, fragmented message or HTTP response head that doesn't fit the rx buffer.
    /// `len` is its payload size so far; the rest of it is skipped as it arrives.
    Oversized { len: u64 },
    /// Text frame or close reason that isn't valid UTF-8.
    InvalidUtf8,
    /// Data violating RFC 6455 / HTTP (reserved bits or opcodes, fragmented or too long control
    /// frame, unexpected continuation, malformed HTTP response).
    Protocol,
}

impl core::fmt::Display for WsRxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WsRxError::Oversized { len } => write!(f, "frame of {len} bytes exceeds the rx buffer"),
            WsRxError::InvalidUtf8 => f.write_str("text is not valid UTF-8"),
            WsRxError::Protocol => f.write_str("websocket/HTTP protocol violation"),
        }
    }
}

impl core::error::Error for WsRxError {}

pub(crate) const OP_CONTINUATION: u8 = 0;
pub(crate) const OP_TEXT: u8 = 1;
pub(crate) const OP_BINARY: u8 = 2;
pub(crate) const OP_CLOSE: u8 = 8;
pub(crate) const OP_PING: u8 = 9;
pub(crate) const OP_PONG: u8 = 10;

impl<'a> WsFrame<'a> {
    /// Opcode of the frame.
    pub fn opcode(&self) -> u8 {
        match self {
            WsFrame::Text(_) => OP_TEXT,
            WsFrame::Binary(_) => OP_BINARY,
            WsFrame::Close(..) => OP_CLOSE,
            WsFrame::Ping(_) => OP_PING,
            WsFrame::Pong(_) => OP_PONG,
        }
    }

    /// Payload bytes (for Close: only the reason).
    pub fn data(&self) -> &'a [u8] {
        match self {
            WsFrame::Text(str) => str.as_bytes(),
            WsFrame::Close(_, reason) => reason.as_bytes(),
            WsFrame::Binary(byt) | WsFrame::Ping(byt) | WsFrame::Pong(byt) => byt,
        }
    }

    /// Decodes a complete, unmasked payload.
    pub(crate) fn decode(opcode: u8, payload: &'a [u8]) -> Result<Self, WsRxError> {
        let utf8 = |b| core::str::from_utf8(b).map_err(|_| WsRxError::InvalidUtf8);
        match opcode {
            OP_TEXT => utf8(payload).map(Self::Text),
            OP_BINARY => Ok(Self::Binary(payload)),
            OP_CLOSE => match payload {
                [] => Ok(Self::Close(CLOSE_NO_STATUS, "")),
                [_] => Err(WsRxError::Protocol),
                [hi, lo, reason @ ..] => {
                    utf8(reason).map(|r| Self::Close(u16::from_be_bytes([*hi, *lo]), r))
                }
            },
            OP_PING => Ok(Self::Ping(payload)),
            OP_PONG => Ok(Self::Pong(payload)),
            _ => Err(WsRxError::Protocol),
        }
    }
}

#[cfg(feature = "alloc")]
impl WsFrameOwned {
    /// Borrows this frame as a [`WsFrame`].
    pub fn as_frame(&self) -> WsFrame<'_> {
        match self {
            WsFrameOwned::Text(string) => WsFrame::Text(string),
            WsFrameOwned::Binary(vec) => WsFrame::Binary(vec),
            WsFrameOwned::Close(code, reason) => WsFrame::Close(*code, reason),
            WsFrameOwned::Ping(vec) => WsFrame::Ping(vec),
            WsFrameOwned::Pong(vec) => WsFrame::Pong(vec),
        }
    }
}

/// Fills `buf` with random bytes from the enabled `getrandom*` feature (zeros without one).
pub(crate) fn rng_fill(buf: &mut [u8]) {
    #[cfg(feature = "getrandom02")]
    {
        _ = getrandom02::getrandom(buf);
    }

    #[cfg(feature = "getrandom03")]
    {
        _ = getrandom03::fill(buf);
    }

    #[cfg(feature = "getrandom04")]
    {
        _ = getrandom04::fill(buf);
    }

    #[cfg(not(any(
        feature = "getrandom02",
        feature = "getrandom03",
        feature = "getrandom04"
    )))]
    {
        _ = buf;
    }
}
