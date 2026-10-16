#[cfg(feature = "http")]
use httparse::Header;

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

/// Guid that is concatenated with Sec-WebSocket-Key header (by server)
pub const WS_KEY_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Random websocket key length (in base64 chars)
pub const WS_KEY_B64_LEN: usize = crate::crypto::base64_len(16);

/// Output size of Sec-WebSocket-Accept (in base64 form)
pub const PROCESSED_WS_KEY_B64_LEN: usize = crate::crypto::base64_len(20);

/// Longest frame header: 2 bytes + 64-bit length + masking key.
pub const MAX_HEADER_LEN: usize = 14;
