//! Echo server / client over std TCP:
//! `cargo run --example ws-framer-test -- -m server -i 127.0.0.1:4321`
//! `cargo run --example ws-framer-test -- -m client -i 127.0.0.1:4321`

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use httparse::Header;
use ws_framer::{WsFrame, WsRxFramer, WsTxFramer};

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
    match args.mode {
        Mode::Server => start_server(&args.ip),
        Mode::Client => start_client(&args.ip),
    }
}

/// Reads until the framer yields frames, calling `on_frame` for each; `Ok(false)` on EOF.
fn pump(
    stream: &mut TcpStream,
    rx: &mut WsRxFramer<'_>,
    mut on_frame: impl FnMut(WsFrame<'_>) -> Result<()>,
) -> Result<bool> {
    let n = stream.read(rx.read_buf())?;
    if n == 0 {
        return Ok(false);
    }
    rx.advance(n);
    while let Some(frame) = rx.next_frame() {
        match frame {
            Ok(frame) => on_frame(frame)?,
            Err(e) => println!("[rx error] {e:?}"),
        }
    }
    Ok(true)
}

fn start_server(ip: &str) -> Result<()> {
    let listener = TcpListener::bind(ip)?;
    println!("Server started on: {ip}");

    while let Ok((mut stream, addr)) = listener.accept() {
        println!("Client connected: {addr}");
        let mut rx_buf = vec![0; 10240];
        let mut tx_buf = vec![0; 10240];
        let mut rx = WsRxFramer::new(&mut rx_buf);
        let mut tx = WsTxFramer::new(false, &mut tx_buf);

        let mut req_buf = [0; 4096];
        let n = stream.read(&mut req_buf)?;
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        if !req
            .parse(&req_buf[..n])
            .map_err(|e| anyhow!("{e:?}"))?
            .is_complete()
        {
            println!("[ERROR] HTTP request not complete");
            continue;
        }

        let key = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Sec-WebSocket-Key"))
            .context("no Sec-WebSocket-Key")?
            .value;
        let accept = ws_framer::process_sec_websocket_key(core::str::from_utf8(key)?)
            .context("invalid Sec-WebSocket-Key")?;
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
                value: &accept,
            },
        ];

        stream.write_all(
            tx.http_response(101, "Switching Protocols", &headers)
                .context("tx buffer too small")?,
        )?;
        stream.write_all(tx.text("Hello").context("tx buffer too small")?)?;

        // echo everything back
        let mut out_stream = stream.try_clone()?;
        while pump(&mut stream, &mut rx, |frame| {
            println!("{frame:?}");
            let out = tx.frame(frame).context("cannot encode frame")?;
            Ok(out_stream.write_all(out)?)
        })? {}
    }

    Ok(())
}

fn start_client(ip: &str) -> Result<()> {
    let mut rx_buf = vec![0; 10240];
    let mut tx_buf = vec![0; 10240];
    let mut rx = WsRxFramer::new(&mut rx_buf);
    let mut tx = WsTxFramer::new(true, &mut tx_buf);

    let mut client = TcpStream::connect(ip)?;
    client.write_all(
        tx.http_upgrade_request(ip, "/", &[])
            .context("tx buffer too small")?,
    )?;

    loop {
        let n = client.read(rx.read_buf())?;
        if n == 0 {
            return Err(anyhow!("connection closed during handshake"));
        }
        rx.advance(n);
        if let Some(resp) = rx.http_response() {
            let resp = resp.map_err(|e| anyhow!("bad response: {e:?}"))?;
            println!("http status: {}", resp.status_code);
            if !resp.is_websocket_accepted(&tx.accept_key()) {
                return Err(anyhow!("server did not accept the websocket upgrade"));
            }
            break;
        }
    }

    client.write_all(tx.text("Hello").context("tx buffer too small")?)?;
    while pump(&mut client, &mut rx, |frame| {
        println!("{frame:?}");
        Ok(())
    })? {}

    Ok(())
}
