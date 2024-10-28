use anyhow::Result;
use clap::Parser;

mod client;
mod crypto;
mod server;
mod structs;

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
        Mode::Server => server::start_server(&args.ip)?,
        Mode::Client => client::start_client(&args.ip)?,
    }

    Ok(())
}
