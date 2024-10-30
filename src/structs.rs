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

#[allow(dead_code)]
#[derive(Debug)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Close(u16, String), // TODO: reason i guess
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

    pub fn to_data(self, mask: bool) -> Vec<u8> {
        let opcode = self.opcode();
        let ws_data = match self {
            WsMessage::Text(str) => str.as_bytes().to_vec(),
            WsMessage::Binary(vec) => vec,
            WsMessage::Close(code, reason) => {
                let mut tmp = Vec::new();
                tmp.extend_from_slice(&code.to_be_bytes());
                tmp.extend_from_slice(reason.as_bytes());
                tmp
            }
            WsMessage::Ping(vec) => vec,
            WsMessage::Pong(vec) => vec,
            WsMessage::Unknown => vec![],
        };

        let masking_key = match mask {
            true => crate::client::generate_masking_key(),
            false => [0; 4],
        };

        let frame_header = WsFrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            mask,
            masking_key,
            payload_len: ws_data.len(),
        };

        crate::client::generate_ws_frame(frame_header, &ws_data)
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

pub trait RandomProvider {
    fn fill_buffer(&self, buff: &mut [u8]);
}

pub struct StdProvider;
impl RandomProvider for StdProvider {
    fn fill_buffer(&self, buff: &mut [u8]) {
        rand::Rng::fill(&mut rand::thread_rng(), buff);
    }
}
