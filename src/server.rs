use anyhow::Result;
use base64::prelude::*;
use sha1::{Digest, Sha1};
use std::net::TcpListener;

pub fn start_server(ip: &str) -> Result<()> {
    println!(
        "dsa: {:?}",
        parse_sec_websocket_key("dGhlIHNhbXBsZSBub25jZQ==")
    );

    let listener = TcpListener::bind(ip)?;
    println!("Server started on: {ip:?}!");

    while let Ok((stream, addr)) = listener.accept() {
        println!("Client connected: {addr}");
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
