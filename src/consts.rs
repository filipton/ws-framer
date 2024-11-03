#[cfg(feature = "http")]
use httparse::Header;

use crate::crypto::Base64Pad;

#[cfg(feature = "http")]
/// Default upgrade request headers
pub const WS_DEFAULT_CONNECT_HEADERS: [Header; 3] = [
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

/// Guid that is concatinated with Sec-WebSocket-Key header (by server)
pub const WS_KEY_GUID: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Random websocket key length (in base64 chars)
pub const WS_KEY_B64_LEN: usize = Base64Pad::encode_len(16);

/// Output size of Sec-WebSocket-Accept header input (not output base64)
pub const WS_HASH_LEN: usize = WS_KEY_GUID.len() + WS_KEY_B64_LEN;

/// Padded blocks size for sha1 input
pub const SHA1_BLOCKS_LEN: usize = crate::crypto::sha1_blocks_len(WS_HASH_LEN);

/// Output size of Sec-WebSocket-Accept (in base64 form)
pub const PROCESSED_WS_KEY_B64_LEN: usize = Base64Pad::encode_len(20);

pub const U16_MAX: usize = u16::MAX as usize;
