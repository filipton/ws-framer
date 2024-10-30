use crate::{
    crypto::Base64Pad,
    structs::{WsFrameHeader, WsMessage},
};
use anyhow::Result;
use rand::{Rng, RngCore};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    u16,
};

pub fn start_client(ip: &str) -> Result<()> {
    let bytes = generate_start_packet(ip, "/", None, &mut |buff: &mut [u8]| {
        rand::thread_rng().fill_bytes(buff);
    });

    let mut client = TcpStream::connect(ip)?;
    client.write_all(&bytes)?;

    let mut buf = [0; 1024];
    let n = client.read(&mut buf)?;
    println!("resp_n: {n}");
    println!("buf: {:?}", core::str::from_utf8(&buf[..n]));

    client.write_all(&WsMessage::Text("Lorem".to_string()).to_data(true))?;

    std::thread::sleep(std::time::Duration::from_secs(1));
    client.write_all(&WsMessage::Close(1000, "".to_string()).to_data(true))?;
    Ok(())
}

const WS_KEY_B64_LEN: usize = Base64Pad::encode_len(16);
pub fn generate_start_packet(
    host: &str,
    path: &str,
    additional_headers: Option<HashMap<&str, &str>>,
    gen: &mut impl FnMut(&mut [u8]),
) -> Vec<u8> {
    let mut ws_key = [0u8; 16];
    gen(&mut ws_key);

    let mut tmp = Vec::new();
    tmp.extend_from_slice(b"GET ");
    tmp.extend_from_slice(path.as_bytes());
    tmp.extend_from_slice(b" HTTP/1.1\r\n");
    tmp.extend_from_slice(b"Host: ");
    tmp.extend_from_slice(host.as_bytes());
    tmp.extend_from_slice(b"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");

    let tmp_len = tmp.len();
    tmp.resize(tmp_len + WS_KEY_B64_LEN, 0);
    Base64Pad::encode_slice(&ws_key, &mut tmp[tmp_len..]);
    tmp.extend_from_slice(b"\r\n");

    if let Some(headers) = additional_headers {
        for (k, v) in headers {
            tmp.extend_from_slice(k.as_bytes());
            tmp.extend_from_slice(b": ");
            tmp.extend_from_slice(v.as_bytes());
            tmp.extend_from_slice(b"\r\n");
        }
    }
    tmp.extend_from_slice(b"\r\n");

    tmp
}

const U16_MAX: usize = u16::MAX as usize;
pub fn generate_ws_frame(header: WsFrameHeader, data: &[u8]) -> Vec<u8> {
    let mut tmp = Vec::new();
    let first_byte = (header.fin as u8) << 7
        | (header.rsv1 as u8) << 6
        | (header.rsv2 as u8) << 5
        | (header.rsv3 as u8) << 4
        | header.opcode & 0x0F;
    tmp.push(first_byte);

    match header.payload_len {
        0..=125 => {
            tmp.push((header.mask as u8) << 7 | header.payload_len as u8);
        }
        126..U16_MAX => {
            tmp.push((header.mask as u8) << 7 | 126);
            tmp.extend_from_slice(&(header.payload_len as u16).to_be_bytes());
        }
        U16_MAX.. => {
            tmp.push((header.mask as u8) << 7 | 127);
            tmp.extend_from_slice(&(header.payload_len as u64).to_be_bytes());
        }
    }

    if header.mask {
        tmp.extend_from_slice(&header.masking_key);
        tmp.extend(
            data.iter()
                .enumerate()
                .map(|(i, &x)| x ^ header.masking_key[i % 4]),
        );
    } else {
        tmp.extend_from_slice(data);
    }

    tmp
}

pub fn generate_masking_key() -> [u8; 4] {
    rand::thread_rng().next_u32().to_be_bytes()
}
