use crate::{crypto::Base64Pad, structs::WsFrameHeader};
use httparse::Header;

const WS_DEFAULT_HEADERS: [Header; 3] = [
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

const WS_KEY_B64_LEN: usize = Base64Pad::encode_len(16);
pub fn generate_start_packet(
    host: &str,
    path: &str,
    additional_headers: Option<&[Header]>,
    gen: &mut impl FnMut(&mut [u8]),
    buf: &mut [u8],
) -> usize {
    let mut ws_key = [0u8; 16];
    gen(&mut ws_key);
    let mut ws_key_b64 = [0u8; WS_KEY_B64_LEN];
    Base64Pad::encode_slice(&ws_key, &mut ws_key_b64);

    buf[0..4].copy_from_slice(b"GET ");

    let mut offset = 4 + path.as_bytes().len();
    buf[4..offset].copy_from_slice(path.as_bytes());
    buf[offset..offset + 11].copy_from_slice(b" HTTP/1.1\r\n");
    offset += 11;

    let headers = [
        Header {
            name: "Host",
            value: host.as_bytes(),
        },
        Header {
            name: "Sec-WebSocket-Key",
            value: &ws_key_b64,
        },
    ];

    let headers: &[Header] = match additional_headers {
        Some(additional_headers) => {
            &[&WS_DEFAULT_HEADERS[..], &headers, additional_headers].concat()
        }
        None => &[&WS_DEFAULT_HEADERS[..], &headers].concat(),
    };

    for header in headers {
        buf[offset..offset + header.name.len()].copy_from_slice(header.name.as_bytes());
        offset += header.name.len();

        buf[offset..offset + 2].copy_from_slice(b": ");
        offset += 2;

        buf[offset..offset + header.value.len()].copy_from_slice(header.value);
        offset += header.value.len();

        buf[offset..offset + 2].copy_from_slice(b"\r\n");
        offset += 2;
    }

    buf[offset..offset + 2].copy_from_slice(b"\r\n");
    offset + 2
}

const U16_MAX: usize = u16::MAX as usize;
pub fn generate_ws_frame(header: WsFrameHeader, data: &[u8], buf: &mut [u8]) -> usize {
    let first_byte = (header.fin as u8) << 7
        | (header.rsv1 as u8) << 6
        | (header.rsv2 as u8) << 5
        | (header.rsv3 as u8) << 4
        | header.opcode & 0x0F;
    buf[0] = first_byte;

    let mut offset = 1;
    match header.payload_len {
        0..=125 => {
            buf[offset] = (header.mask as u8) << 7 | header.payload_len as u8;
            offset += 1;
        }
        126..U16_MAX => {
            buf[offset] = (header.mask as u8) << 7 | 126;
            buf[offset + 1..offset + 1 + 2]
                .copy_from_slice(&(header.payload_len as u16).to_be_bytes());
            offset += 3;
        }
        U16_MAX.. => {
            buf[offset] = (header.mask as u8) << 7 | 127;
            buf[offset + 1..offset + 1 + 8]
                .copy_from_slice(&(header.payload_len as u64).to_be_bytes());
            offset += 9;
        }
    }

    if header.mask {
        buf[offset..offset + 4].copy_from_slice(&header.masking_key);
        offset += 4;

        for d in data
            .iter()
            .enumerate()
            .map(|(i, &x)| x ^ header.masking_key[i % 4])
        {
            buf[offset] = d;
            offset += 1;
        }
    } else {
        buf[offset..offset + data.len()].copy_from_slice(data);
        offset += data.len();
    }

    offset
}
