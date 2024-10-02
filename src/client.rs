use crate::structs::WsFrameHeader;
use anyhow::Result;
use base64::prelude::*;
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

    let ws_frame = generate_ws_frame(
        WsFrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: 0b0001,
            mask: true,
            masking_key: generate_masking_key(),
            payload_len: 5,
        },
        b"Lorem",
    );
    client.write_all(&ws_frame)?;
    println!("{ws_frame:02X?}");

    std::thread::sleep(std::time::Duration::from_secs(1));
    let ws_frame = generate_ws_frame(
        WsFrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: 0b1000,
            mask: true,
            masking_key: generate_masking_key(),
            payload_len: 0,
        },
        &[],
    );
    client.write_all(&ws_frame)?;
    println!("{ws_frame:02X?}");

    /*
    println!("Trying to connect to: {ip}...");
    let (mut socket, resp) = tungstenite::connect(ip)?;

    println!("Http response: {resp:?}");

    socket.send(tungstenite::Message::Text("Lorem".into()))?;
    //socket.send(tungstenite::Message::Text("Very long text,dsadsahjdsahjdhsadhsa dsahdasd asd asd sad sadsadasdsad saewq ewqewqeqw ewqeqweqweqweqw cf43 f534 fg543g465g543g grewsgfdsvfdsgvfds wqfwqafweqfewq fewqrweqrweqfewq cewqfdewqfewqfewrq rteqreqwfergerwtgre grewtyrewytreytre gbfdgbfdghfdhgfdsgrfqe wc4wqcewqcewqcwe END".into()))?;

    /*
    let mut to_send = [0u8; 40960];
    for i in 0..to_send.len() {
        to_send[i] = (i % 250) as u8;
    }
    socket.send(tungstenite::Message::Binary(to_send.to_vec()))?;
    */

    std::thread::sleep(std::time::Duration::from_secs(5));
    socket.close(None)?;
    */
    Ok(())
}

const U16_MAX: usize = u16::MAX as usize;
fn generate_ws_frame(header: WsFrameHeader, data: &[u8]) -> Vec<u8> {
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

fn generate_sec_ws_key() -> String {
    let mut ws_key = [0u8; 16];
    rand::thread_rng().fill(&mut ws_key);
    BASE64_STANDARD.encode(ws_key)
}

fn generate_masking_key() -> [u8; 4] {
    rand::thread_rng().next_u32().to_be_bytes()
}

fn generate_http_req(
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
