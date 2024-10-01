use anyhow::Result;

pub fn start_client(ip: &str) -> Result<()> {
    println!("Trying to connect to: {ip}...");
    let (mut socket, resp) = tungstenite::connect(ip)?;

    println!("Http response: {resp:?}");
    socket.send(tungstenite::Message::Text("Lorem".into()))?;
    std::thread::sleep(std::time::Duration::from_secs(5));
    socket.close(None)?;

    Ok(())
}
