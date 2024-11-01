use core::str;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use anyhow::Result;
use clap::Parser;
use httparse::Header;
use rand::RngCore;
use ws_framer::WsFramer;

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

        let mut buf = vec![0; 10240];
        let mut framer = WsFramer::<StdRandom>::new(false, &mut buf);

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

        stream.write_all(framer.construct_http_resp(101, "Switching Protocols", &headers))?;

        let mut count = 0;
        'outer: loop {
            loop {
                let read_n = stream.read(framer.mut_buf())?;
                if read_n == 0 {
                    break 'outer;
                }

                let res = framer.process_data(read_n);
                if res.is_some() {
                    println!("{res:?}");
                    stream.write_all(&framer.text(&format!("{count}Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum pulvinar porta arcu, at accumsan risus. Interdum et malesuada fames ac ante ipsum primis in faucibus. Cras feugiat, nibh nec vestibulum scelerisque, sem neque vestibulum sem, et lobortis justo tellus et ligula. Phasellus sed eleifend tortor. Morbi lacinia lacus nec ipsum imperdiet eleifend bibendum in ipsum. Suspendisse in lacus et sem ultrices rhoncus quis sit amet enim. Praesent maximus enim non pretium fringilla.{count}")))?;
                    count += 1;
                    stream.write_all(&framer.text(&format!("{count}Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum pulvinar porta arcu, at accumsan risus. Interdum et malesuada fames ac ante ipsum primis in faucibus. Cras feugiat, nibh nec vestibulum scelerisque, sem neque vestibulum sem, et lobortis justo tellus et ligula. Phasellus sed eleifend tortor. Morbi lacinia lacus nec ipsum imperdiet eleifend bibendum in ipsum. Suspendisse in lacus et sem ultrices rhoncus quis sit amet enim. Praesent maximus enim non pretium fringilla.{count}")))?;
                    count += 1;
                    stream.write_all(&framer.text(&format!("{count}Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum pulvinar porta arcu, at accumsan risus. Interdum et malesuada fames ac ante ipsum primis in faucibus. Cras feugiat, nibh nec vestibulum scelerisque, sem neque vestibulum sem, et lobortis justo tellus et ligula. Phasellus sed eleifend tortor. Morbi lacinia lacus nec ipsum imperdiet eleifend bibendum in ipsum. Suspendisse in lacus et sem ultrices rhoncus quis sit amet enim. Praesent maximus enim non pretium fringilla.{count}")))?;
                    count += 1;
                    break;
                }
            }

            /*
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
            /*
            let ws_frame_n =
                ws_framer::client::generate_ws_frame(echoed_header, &buf, &mut out_buf);
            _ = stream.write_all(&out_buf[..ws_frame_n]);
            */
            */
        }
    }

    Ok(())
}

pub fn start_client(ip: &str) -> Result<()> {
    let mut buf = vec![0; 10240];
    let mut framer = WsFramer::<StdRandom>::new(true, &mut buf);

    let mut client = TcpStream::connect(ip)?;
    client.write_all(&framer.gen_connect_packet(ip, "/", None))?;

    let mut buf = [0; 1024];
    let n = client.read(&mut buf)?;
    println!("resp_n: {n}");
    println!("buf: {:?}", core::str::from_utf8(&buf[..n]));

    let mut peek_buf = [0; 1];
    let mut count = 0;
    'outer: loop {
        client.write_all(&framer.text("Lorem"))?;
        let pn = client.peek(&mut peek_buf)?;

        if pn > 0 {
            loop {
                let read_n = client.read(framer.mut_buf())?;
                if read_n == 0 {
                    break 'outer;
                }

                let res = framer.process_data(read_n);
                if res.is_some() {
                    println!("recv: {res:?}");
                    client.write_all(&framer.text(&format!("{count}Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum pulvinar porta arcu, at accumsan risus. Interdum et malesuada fames ac ante ipsum primis in faucibus. Cras feugiat, nibh nec vestibulum scelerisque, sem neque vestibulum sem, et lobortis justo tellus et ligula. Phasellus sed eleifend tortor. Morbi lacinia lacus nec ipsum imperdiet eleifend bibendum in ipsum. Suspendisse in lacus et sem ultrices rhoncus quis sit amet enim. Praesent maximus enim non pretium fringilla.{count}")))?;
                    count += 1;
                    client.write_all(&framer.text(&format!("{count}Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum pulvinar porta arcu, at accumsan risus. Interdum et malesuada fames ac ante ipsum primis in faucibus. Cras feugiat, nibh nec vestibulum scelerisque, sem neque vestibulum sem, et lobortis justo tellus et ligula. Phasellus sed eleifend tortor. Morbi lacinia lacus nec ipsum imperdiet eleifend bibendum in ipsum. Suspendisse in lacus et sem ultrices rhoncus quis sit amet enim. Praesent maximus enim non pretium fringilla.{count}")))?;
                    count += 1;
                    client.write_all(&framer.text(&format!("{count}Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum pulvinar porta arcu, at accumsan risus. Interdum et malesuada fames ac ante ipsum primis in faucibus. Cras feugiat, nibh nec vestibulum scelerisque, sem neque vestibulum sem, et lobortis justo tellus et ligula. Phasellus sed eleifend tortor. Morbi lacinia lacus nec ipsum imperdiet eleifend bibendum in ipsum. Suspendisse in lacus et sem ultrices rhoncus quis sit amet enim. Praesent maximus enim non pretium fringilla.{count}")))?;
                    count += 1;
                    break;
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    /*
    let frame = WsMessage::Text("Lorem".to_string())
        .to_data(true, Some(&mut || rand::thread_rng().next_u32()));
    client.write_all(&frame.0[..frame.1])?;
    */

    std::thread::sleep(std::time::Duration::from_secs(1));
    client.write_all(&framer.close(1000))?;

    Ok(())
}

pub struct StdRandom;
impl ws_framer::RngProvider for StdRandom {
    fn random_u32() -> u32 {
        rand::thread_rng().next_u32()
    }
}
