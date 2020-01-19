use std::io;

use failure::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[test]
#[cfg(mio)]
fn stop() -> Result<(), Error> {
    let key = septid::load_key(io::Cursor::new([0u8; 32]))?;
    let (mut server, sender) = septid::start_server(&septid::StartServer {
        key,
        bind_address: vec!["127.0.68.1:6254".to_string()],
        target_address: vec!["127.0.68.1:6255".to_string()],
        encrypt: true,
    })?;

    // mostly checking this is `move + Send`, it will probably execute before the loop starts
    let handle = thread::spawn(move || {
        sender.send(septid::Command::Terminate).unwrap();
    });

    septid::tick(&mut server)?;

    handle.join().unwrap();

    Ok(())
}

#[tokio::test]
async fn against_us() -> Result<(), Error> {
    pretty_env_logger::init();

    let key = septid::load_key(io::Cursor::new([0u8; 32]))?;

    let mut enc = septid::start_server(&septid::StartServer {
        key: key.clone(),
        bind_address: vec!["127.0.68.1:6222".to_string()],
        target_address: vec!["127.0.68.1:6555".to_string()],
        encrypt: true,
    })
    .await?;

    let mut dec = septid::start_server(&septid::StartServer {
        key: key.clone(),
        bind_address: vec!["127.0.68.1:6555".to_string()],
        target_address: vec!["127.0.68.1:6888".to_string()],
        encrypt: false,
    })
    .await?;

    let buf = tokio::task::spawn_blocking(|| -> Result<[u8; 5], Error> {
        let target = TcpListener::bind("127.0.68.1:6888")?;
        let mut feed = TcpStream::connect("127.0.68.1:6222")?;
        feed.write_all(b"hello")?;
        let (mut socket, _us) = target.accept()?;
        let mut buf = [0u8; 5];
        socket.read_exact(&mut buf)?;
        Ok(buf)
    })
    .await??;

    assert_eq!(b"hello", &buf[..]);

    enc.send(septid::Command::Terminate).await?;
    dec.send(septid::Command::Terminate).await?;

    Ok(())
}
