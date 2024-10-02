use anyhow::Result;

pub fn start_client(ip: &str) -> Result<()> {
    println!("Trying to connect to: {ip}...");
    let (mut socket, resp) = tungstenite::connect(ip)?;

    println!("Http response: {resp:?}");

    socket.send(tungstenite::Message::Text("Lorem".into()))?;
    //socket.send(tungstenite::Message::Text("Very long text,dsadsahjdsahjdhsadhsa dsahdasd asd asd sad sadsadasdsad saewq ewqewqeqw ewqeqweqweqweqw cf43 f534 fg543g465g543g grewsgfdsvfdsgvfds wqfwqafweqfewq fewqrweqrweqfewq cewqfdewqfewqfewrq rteqreqwfergerwtgre grewtyrewytreytre gbfdgbfdghfdhgfdsgrfqe wc4wqcewqcewqcwe END".into()))?;

    /*
    let mut to_send = [0u8; 40960];
    for i in 0..to_send.len() {
        to_send[i] = (i % 250) as u8;
    }
    socket.send(tungstenite::Message::Binary(to_send.to_vec()))?;
    */

    std::thread::sleep(std::time::Duration::from_secs(5));
    socket.close(None)?;

    Ok(())
}
