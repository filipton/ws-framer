use std::net::TcpListener;

use anyhow::Result;

pub fn start_server(ip: &str) -> Result<()> {
    let listener = TcpListener::bind(ip)?;
    println!("Server started on: {ip:?}!");

    while let Ok((stream, addr)) = listener.accept() {
        println!("Client connected: {addr}");
    }

    Ok(())
}
