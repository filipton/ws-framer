use anyhow::Result;

pub fn start_client(ip: &str) -> Result<()> {
    println!("Trying to connect to: {ip}...");
    let (mut socket, resp) = tungstenite::connect(ip)?;

    println!("Http response: {resp:?}");

    //socket.send(tungstenite::Message::Text("Lorem".into()))?;
    socket.send(tungstenite::Message::Text("Very long text,dsadsahjdsahjdhsadhsa dsahdasd asd asd sad sadsadasdsad saewq ewqewqeqw ewqeqweqweqweqw cf43 f534 fg543g465g543g grewsgfdsvfdsgvfds wqfwqafweqfewq fewqrweqrweqfewq cewqfdewqfewqfewrq rteqreqwfergerwtgre grewtyrewytreytre gbfdgbfdghfdhgfdsgrfqe wc4wqcewqcewqcwe".into()))?;

    std::thread::sleep(std::time::Duration::from_secs(5));
    socket.close(None)?;

    Ok(())
}
