use anyhow::Result;
use base64::prelude::*;
use sha1::{Digest, Sha1};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
};

pub fn start_server(ip: &str) -> Result<()> {
    println!(
        "dsa: {:?}",
        parse_sec_websocket_key("dGhlIHNhbXBsZSBub25jZQ==")
    );

    let listener = TcpListener::bind(ip)?;
    println!("Server started on: {ip:?}!");

    while let Ok((mut stream, addr)) = listener.accept() {
        println!("Client connected: {addr}");

        let mut buf = [0; 4096];
        let n = stream.read(&mut buf)?;

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        let res = req.parse(&buf[..n])?;

        if res.is_partial() {
            println!("[ERROR] HTTP request not complete (partial)");
            continue;
        }

        let sec_ws_key = core::str::from_utf8(
            req.headers
                .iter()
                .find(|x| x.name == "Sec-WebSocket-Key")
                .unwrap()
                .value,
        )?;
        println!("sec_ws_key: {sec_ws_key}");

        let mut headers = HashMap::new();
        headers.insert("Upgrade".to_string(), "websocket".to_string());
        headers.insert("Connection".to_string(), "Upgrade".to_string());
        headers.insert(
            "Sec-WebSocket-Accept".to_string(),
            parse_sec_websocket_key(sec_ws_key),
        );
        let resp = construct_http_resp("1.1", 101, "Switching Protocols", headers);
        println!("resp: {resp:?}");
        stream.write_all(resp.as_bytes())?;

        let mut buf = [0; 4096];
        loop {
            let read_n = stream.read(&mut buf)?;
            if read_n == 0 {
                break;
            }

            println!("read_n: {read_n}");
            parse_ws_frame(&mut buf[..read_n])?;
        }
    }

    Ok(())
}

const WS_KEY_GUID: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
fn parse_sec_websocket_key(key: &str) -> String {
    let tmp = format!("{key}{WS_KEY_GUID}");
    let mut hasher = Sha1::new();
    hasher.update(tmp.as_bytes());
    BASE64_STANDARD.encode(hasher.finalize())
}

fn construct_http_resp(
    http_ver: &str,
    status_code: u16,
    status_text: &str,
    headers: HashMap<String, String>,
) -> String {
    let headers_str = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\r\n");

    format!("HTTP/{http_ver} {status_code} {status_text}\r\n{headers_str}\r\n\r\n")
}

fn parse_ws_frame(buf: &mut [u8]) -> Result<()> {
    let fin = (buf[0] & 0b10000000) >> 7;
    let rsv1 = (buf[0] & 0b01000000) >> 6;
    let rsv2 = (buf[0] & 0b00100000) >> 5;
    let rsv3 = (buf[0] & 0b00010000) >> 4;
    let opcode = buf[0] & 0b00001111;
    let mask = (buf[1] & 0b10000000) >> 7;
    let mut payload_len = (buf[1] & 0b01111111) as u64;

    let mut offset = 2;
    if payload_len == 126 {
        payload_len = u16::from_be_bytes(buf[2..4].try_into().unwrap()) as u64;
        offset += 2;
    } else if payload_len == 127 {
        payload_len = u64::from_be_bytes(buf[2..10].try_into().unwrap());
        offset += 8;
    }

    let masking_key = match mask {
        1 => {
            let mut key = [0; 4];
            key.copy_from_slice(&buf[offset..offset + 4]);
            offset += 4;
            Some(key)
        }
        _ => None,
    };

    println!("fin: {fin}");
    println!("rsv1: {rsv1}");
    println!("rsv2: {rsv2}");
    println!("rsv3: {rsv3}");
    println!("opcode: 0b{opcode:04b}");
    println!("mask: {mask}");
    println!("payload_len: {payload_len}");
    println!("masking key: {masking_key:02X?}");

    let payload = &mut buf[offset..offset + payload_len as usize];
    if let Some(masking_key) = masking_key {
        for (i, x) in payload.iter_mut().enumerate() {
            let key = masking_key[i % 4];
            *x ^= key;
        }
    }

    println!("payload: {:02X?}", &payload);
    println!("payload str: {:?}", core::str::from_utf8(&payload));
    Ok(())
}
