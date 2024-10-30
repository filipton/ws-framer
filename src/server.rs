use crate::structs::WsFrameHeader;

const WS_KEY_GUID: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub fn parse_sec_websocket_key(key: &str) -> String {
    let tmp = format!("{key}{WS_KEY_GUID}");
    let hash = crate::crypto::sha1(tmp.as_bytes());
    crate::crypto::Base64Pad::encode(&hash)
}

pub fn construct_http_resp(
    http_ver: &str,
    status_code: u16,
    status_text: &str,
    headers: std::collections::HashMap<String, String>,
) -> String {
    let headers_str = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\r\n");

    format!("HTTP/{http_ver} {status_code} {status_text}\r\n{headers_str}\r\n\r\n")
}

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
