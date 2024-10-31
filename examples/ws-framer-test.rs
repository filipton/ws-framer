use core::str;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use anyhow::Result;
use clap::Parser;
use rand::RngCore;
use ws_framer::{structs::WsMessage, WsFramer};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long)]
    mode: Mode,

    #[arg(short, long)]
    ip: String,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum Mode {
    Server,
    Client,
}

fn main() -> Result<()> {
    let args = Args::parse();
    println!("{args:?}");

    match args.mode {
        Mode::Server => start_server(&args.ip)?,
        Mode::Client => start_client(&args.ip)?,
    }

    Ok(())
}

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
            ws_framer::server::parse_sec_websocket_key(sec_ws_key),
        );
        let resp =
            ws_framer::server::construct_http_resp("1.1", 101, "Switching Protocols", headers);
        println!("resp: {resp:?}");
        stream.write_all(resp.as_bytes())?;

        let mut header_buf = [0; 14];
        loop {
            let read_n = stream.read(&mut header_buf)?;
            println!("read_header_n: {read_n}");
            if read_n == 0 {
                break;
            }

            let (header, rest) = ws_framer::server::parse_ws_frame_header(&header_buf[..read_n]);
            println!("header: {header:?}, rest: {rest:?}");
            let mut buf = vec![0; header.payload_len];
            buf[..rest.len()].copy_from_slice(rest);
            stream.read_exact(&mut buf[rest.len()..header.payload_len])?;

            let ws_frame = ws_framer::structs::WsMessage::from_data(&header, &mut buf);
            println!("recv_ws_frame: {ws_frame:?}");

            let mut echoed_header = header.clone();
            echoed_header.mask = false;

            let mut out_buf = vec![0; header.payload_len + 14 - rest.len()];
            let ws_frame_n =
                ws_framer::client::generate_ws_frame(echoed_header, &buf, &mut out_buf);
            _ = stream.write_all(&out_buf[..ws_frame_n]);
        }
    }

    Ok(())
}

pub fn start_client(ip: &str) -> Result<()> {
    let mut buf = vec![0; 10240];
    let mut rng_gen = |buff: &mut [u8]| {
        rand::thread_rng().fill_bytes(buff);
    };

    let mut framer = WsFramer::new(true, &mut buf, &mut rng_gen);

    let mut client = TcpStream::connect(ip)?;
    client.write_all(framer.gen_connect_packet(ip, "/", None))?;
    client.write_all(framer.gen_connect_packet(ip, "/", None))?;

    let mut buf = [0; 1024];
    let n = client.read(&mut buf)?;
    println!("resp_n: {n}");
    println!("buf: {:?}", core::str::from_utf8(&buf[..n]));

    //client.write_all(&framer.text("Lorem"));
    /*
    let frame = WsMessage::Text("Lorem".to_string())
        .to_data(true, Some(&mut || rand::thread_rng().next_u32()));
    client.write_all(&frame.0[..frame.1])?;
    */

    std::thread::sleep(std::time::Duration::from_secs(1));
    let frame = &WsMessage::Close(1000, "".to_string())
        .to_data(true, Some(&mut || rand::thread_rng().next_u32()));
    client.write_all(&frame.0[..frame.1])?;

    Ok(())
}
