use crate::WsFrameHeader;

pub fn parse_ws_frame_header<'a>(buf: &'a [u8]) -> (WsFrameHeader, &'a [u8]) {
    let fin = (buf[0] & 0b10000000) >> 7;
    let rsv1 = (buf[0] & 0b01000000) >> 6;
    let rsv2 = (buf[0] & 0b00100000) >> 5;
    let rsv3 = (buf[0] & 0b00010000) >> 4;
    let opcode = buf[0] & 0b00001111;
    let mask = (buf[1] & 0b10000000) >> 7;
    let mut payload_len = (buf[1] & 0b01111111) as usize;

    let mut offset = 2;
    if payload_len == 126 {
        payload_len = u16::from_be_bytes(buf[2..4].try_into().unwrap()) as usize;
        offset += 2;
    } else if payload_len == 127 {
        payload_len = u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize;
        offset += 8;
    }

    let mut masking_key = [0; 4];
    if mask == 1 {
        masking_key.copy_from_slice(&buf[offset..offset + 4]);
        offset += 4;
    }

    (
        WsFrameHeader {
            fin: fin == 1,
            rsv1: rsv1 == 1,
            rsv2: rsv2 == 1,
            rsv3: rsv3 == 1,
            opcode,
            mask: mask == 1,
            masking_key,
            payload_len,
            offset: 0
        },
        &buf[offset..],
    )
}

pub fn parse_payload(payload: &mut [u8], header: &WsFrameHeader) {
    if header.mask {
        for (i, x) in payload.iter_mut().enumerate() {
            let key = header.masking_key[i % 4];
            *x ^= key;
        }
    }
}
