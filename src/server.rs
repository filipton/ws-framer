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

        loop {
            let read_n = stream.read(&mut buf)?;
            if read_n == 0 {
                break;
            }

            println!("read_n: {read_n}");
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
