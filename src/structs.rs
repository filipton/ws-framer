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
}

pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Close(), // TODO: reason i guess
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

impl WsMessage {
    pub fn opcode(&self) -> u8 {
        match self {
            WsMessage::Text(_) => 1,
            WsMessage::Binary(_) => 2,
            WsMessage::Close() => 8,
            WsMessage::Ping(_) => 9,
            WsMessage::Pong(_) => 10,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        let frame_header = WsFrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: self.opcode(),
            mask: true,
            masking_key: crate::client::generate_masking_key(),
            payload_len: 5,
        };

        let ws_data = match self {
            WsMessage::Text(str) => str.as_bytes(),
            WsMessage::Binary(vec) => &vec,
            WsMessage::Close() => &[],
            WsMessage::Ping(vec) => &vec,
            WsMessage::Pong(vec) => &vec,
        };

        crate::client::generate_ws_frame(frame_header, ws_data)
    }
}
