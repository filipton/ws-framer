use anyhow::Result;
use base64::prelude::*;
use sha1::{Digest, Sha1};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
};

use crate::structs::WsFrameHeader;

pub fn start_server(ip: &str) -> Result<()> {
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

        let mut header_buf = [0; 14];
        loop {
            let read_n = stream.read(&mut header_buf)?;
            println!("read_header_n: {read_n}");
            if read_n == 0 {
                break;
            }

            let (header, rest) = parse_ws_frame_header(&header_buf[..read_n])?;
            println!("header: {header:?}, rest: {rest:?}");
            let mut buf = vec![0; header.payload_len];
            buf[..rest.len()].copy_from_slice(rest);
            stream.read_exact(&mut buf[rest.len()..header.payload_len])?;
            parse_payload(&mut buf, &header);

            //println!("{} {:02?}", buf.len(), buf);
            println!("{:?}", core::str::from_utf8(&buf));

            let mut echoed_header = header.clone();
            echoed_header.mask = false;
            let ws_frame = crate::client::generate_ws_frame(echoed_header, &buf);
            _ = stream.write_all(&ws_frame);
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

fn parse_ws_frame_header<'a>(buf: &'a [u8]) -> Result<(WsFrameHeader, &'a [u8])> {
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

    Ok((
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
    ))
}

fn parse_payload(payload: &mut [u8], header: &WsFrameHeader) {
    if header.mask {
        for (i, x) in payload.iter_mut().enumerate() {
            let key = header.masking_key[i % 4];
            *x ^= key;
        }
    }
}
