use anyhow::Result;
use async_std::net::TcpListener;
use async_std::net::TcpStream;
use async_std::task;
use futures::AsyncReadExt as _;
use futures::AsyncWriteExt as _;
use std::net::Shutdown;

#[test]
fn stop() -> Result<()> {
    task::block_on(test_stop())
}

async fn test_stop() -> Result<()> {
    let key = septid::MasterKey::from_slice(&[0u8; 32]);

    let mut server = septid::server::start_server(&septid::server::StartServer {
        key,
        bind_address: vec!["127.0.68.1:6254".to_string()],
        target_address: vec!["127.0.68.1:6255".to_string()],
        encrypt: true,
    })
    .await?;

    let handle = task::spawn(async move { server.request_shutdown().await });

    handle.await?;

    Ok(())
}

#[test]
fn against_us() -> Result<()> {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Debug)
        .init();
    task::block_on(test_against_us())
}

async fn test_against_us() -> Result<()> {
    let key = septid::MasterKey::from_slice(&[0u8; 32]);

    let mut enc = septid::server::start_server(&septid::server::StartServer {
        key: key.clone(),
        bind_address: vec!["127.0.68.1:6222".to_string()],
        target_address: vec!["127.0.68.1:6555".to_string()],
        encrypt: true,
    })
    .await?;

    let mut dec = septid::server::start_server(&septid::server::StartServer {
        key: key.clone(),
        bind_address: vec!["127.0.68.1:6555".to_string()],
        target_address: vec!["127.0.68.1:6888".to_string()],
        encrypt: false,
    })
    .await?;

    {
        let target = TcpListener::bind("127.0.68.1:6888").await?;
        let mut feed = TcpStream::connect("127.0.68.1:6222").await?;
        feed.write_all(b"hello").await?;
        let (mut socket, _us) = target.accept().await?;
        let mut buf = [0u8; 5];
        socket.read_exact(&mut buf).await?;
        assert_eq!(b"hello", &buf[..]);
        feed.shutdown(Shutdown::Both)?;
    }

    enc.request_shutdown().await?;
    dec.request_shutdown().await?;

    // enc.run_to_completion().await?;
    // dec.run_to_completion().await?;

    Ok(())
}
