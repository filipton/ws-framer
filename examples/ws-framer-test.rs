use core::str;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use anyhow::Result;
use clap::Parser;
use httparse::Header;
use ws_framer::{WsRxFramer, WsTxFramer};

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

        let mut rx_buf = vec![0; 10240];
        let mut tx_buf = vec![0; 10240];
        let mut rx_framer = WsRxFramer::new(&mut rx_buf);
        let mut tx_framer = WsTxFramer::new(false, &mut tx_buf);

        let mut buf = [0; 4096];
        let n = stream.read(&mut buf)?;

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        let res = req
            .parse(&buf[..n])
            .map_err(|e| anyhow::anyhow!("parse err: {e:?}"))?;

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

        let headers = [
            Header {
                name: "Upgrade",
                value: b"websocket",
            },
            Header {
                name: "Connection",
                value: b"upgrade",
            },
            Header {
                name: "Sec-WebSocket-Accept",
                value: &ws_framer::process_sec_websocket_key(sec_ws_key),
            },
        ];

        stream.write_all(tx_framer.generate_http_response(101, "Switching Protocols", &headers))?;
        stream.write_all(&tx_framer.text("Hello"))?;
        loop {
            let read_n = stream.read(rx_framer.mut_buf())?;
            if read_n == 0 {
                break;
            }

            rx_framer.revolve_write_offset(read_n);
            while let Some(frame) = rx_framer.process_data() {
                println!("{frame:?}");
                stream.write_all(&tx_framer.frame(frame))?;
            }
        }
    }

    Ok(())
}

pub fn start_client(ip: &str) -> Result<()> {
    let mut rx_buf = vec![0; 10240];
    let mut tx_buf = vec![0; 10240];
    let mut rx_framer = WsRxFramer::new(&mut rx_buf);
    let mut tx_framer = WsTxFramer::new(true, &mut tx_buf);

    let mut client = TcpStream::connect(ip)?;
    client.write_all(&tx_framer.generate_http_upgrade(ip, "/", None))?;
    loop {
        let n = client.read(rx_framer.mut_buf())?;
        let res = rx_framer.process_http_response(n);

        if let Some(code) = res {
            println!("http_resp_code: {code}");
            break;
        }
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(&tx_framer.text("Hello"));
    buf.extend_from_slice(&tx_framer.text("Friend"));
    buf.extend_from_slice(&tx_framer.ping(&[]));
    client.write_all(&buf)?;

    std::thread::sleep(std::time::Duration::from_secs(1));
    client.write_all(&tx_framer.close(1000, "Connection closed!"))?;
    Ok(())

    /*
    loop {
        /*
        loop {
            let read_n = client.read(rx_framer.mut_buf())?;
            if read_n == 0 {
                break;
            }

            let res = rx_framer.process_data(read_n);
            if res.is_some() {
                println!("{res:?}");
                client.write_all(&tx_framer.frame(res.unwrap()))?;
            }
        }
        */
        client.write_all(&tx_framer.text("Lorem"))?;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    */

    //std::thread::sleep(std::time::Duration::from_secs(1));
    //client.write_all(&tx_framer.close(1000))?;
    //Ok(())
}
