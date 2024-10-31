use crate::WsFrameHeader;

#[allow(dead_code)]
#[derive(Debug)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Close(u16, String),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Unknown,
}

impl WsMessage {
    pub fn opcode(&self) -> u8 {
        match self {
            WsMessage::Text(_) => 1,
            WsMessage::Binary(_) => 2,
            WsMessage::Close(..) => 8,
            WsMessage::Ping(_) => 9,
            WsMessage::Pong(_) => 10,
            WsMessage::Unknown => 0,
        }
    }

    /// Parse ws frame
    ///
    /// NOTE: this requires you to read WsFramerHeader first!
    /// TODO: make this better
    pub fn from_data(frame_header: &WsFrameHeader, buf: &mut [u8]) -> Self {
        crate::server::parse_payload(buf, frame_header);
        match frame_header.opcode {
            1 => Self::Text(String::from_utf8_lossy(&buf).to_string()),
            2 | 9 | 10 => Self::Binary(buf.to_vec()),
            8 => Self::Close(
                u16::from_be_bytes([buf[0], buf[1]]),
                String::from_utf8_lossy(&buf[2..]).to_string(),
            ),
            _ => Self::Unknown,
        }
    }
}
