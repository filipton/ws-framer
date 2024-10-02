#[derive(Debug)]
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
