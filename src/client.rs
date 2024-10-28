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
    let mut headers = HashMap::new();
    headers.insert("Host".to_string(), ip.to_string());
    headers.insert("Connection".to_string(), "Upgrade".to_string());
    headers.insert("Upgrade".to_string(), "websocket".to_string());
    headers.insert("Sec-WebSocket-Version".to_string(), "13".to_string());
    headers.insert("Sec-WebSocket-Key".to_string(), generate_sec_ws_key());
    let http_req = generate_http_req("GET", "/", "1.1", headers);

    let mut client = TcpStream::connect(ip)?;
    client.write_all(http_req.as_bytes())?;

    let mut buf = [0; 1024];
    let n = client.read(&mut buf)?;
    println!("resp_n: {n}");
    println!("buf: {:?}", core::str::from_utf8(&buf[..n]));

    client.write_all(&WsMessage::Text("Lorem".to_string()).to_data())?;

    std::thread::sleep(std::time::Duration::from_secs(1));
    client.write_all(&WsMessage::Close(1000, "".to_string()).to_data())?;
    Ok(())
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

pub fn generate_sec_ws_key() -> String {
    let mut ws_key = [0u8; 16];
    rand::thread_rng().fill(&mut ws_key);
    Base64Pad::encode(&ws_key)
}

pub fn generate_masking_key() -> [u8; 4] {
    rand::thread_rng().next_u32().to_be_bytes()
}

pub fn generate_http_req(
    method: &str,
    path: &str,
    http_ver: &str,
    headers: HashMap<String, String>,
) -> String {
    let headers_str = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\r\n");

    format!("{method} {path} HTTP/{http_ver}\r\n{headers_str}\r\n\r\n")
}
