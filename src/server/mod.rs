use std::net;
use std::net::ToSocketAddrs;

use async_std::net::TcpListener;
use async_std::net::TcpStream;
use async_std::task;
use failure::Error;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::future::Either;
use futures::stream::StreamExt as _;
use futures::AsyncReadExt;
use futures::AsyncWriteExt;

mod stream;

use super::MasterKey;
use crate::proto::flip_if;
use crate::proto::kex;
use stream::decrypt_packets;
use stream::encrypt_packets;

#[derive(Copy, Clone, Debug)]
pub enum Command {
    NoNewConnections,
    Terminate,
}

pub struct StartServer {
    pub key: MasterKey,
    pub bind_address: Vec<String>,
    pub target_address: Vec<String>,
    pub encrypt: bool,
}

pub async fn start_server(config: &StartServer) -> Result<mpsc::Sender<Command>, Error> {
    let (command_send, mut command_recv) = mpsc::channel::<Command>(1);

    let mut sources = Vec::with_capacity(config.bind_address.len() * 2);

    let mut target_addrs = Vec::with_capacity(config.target_address.len() * 2);
    for target in &config.target_address {
        target_addrs.extend(target.to_socket_addrs()?);
    }

    for source in &config.bind_address {
        for source in source.to_socket_addrs()? {
            let listener = TcpListener::bind(&source).await?;
            log::info!("{:?}: listening", source);
            sources.push(listener);
        }
    }

    let mut shutdowns: Vec<oneshot::Sender<()>> = Vec::new();

    for listener in sources {
        let key = config.key.clone();
        let target_addrs = target_addrs.clone();
        let encrypt = config.encrypt;
        let (send, recv) = oneshot::channel();
        shutdowns.push(send);
        let local_addr = listener.local_addr()?;
        task::spawn(async move {
            let mut recv = recv;
            loop {
                let accepter = listener.accept();
                pin_utils::pin_mut!(accepter);
                let stream = match futures::future::select(accepter, recv).await {
                    Either::Left((Ok((stream, client_addr)), remaining)) => {
                        recv = remaining;
                        log::info!("{:?} {:?}: accepted client", local_addr, client_addr);
                        stream
                    }
                    _ => break,
                };

                handle_client(stream, &key, &target_addrs[0], encrypt)
                    .await
                    .unwrap();
            }
        });
    }

    task::spawn(async move {
        command_recv.next().await;
        for shutdown in shutdowns {
            let _ = shutdown.send(());
        }
    });

    Ok(command_send)
}

async fn handle_client(
    accepted: TcpStream,
    key: &MasterKey,
    target_addr: &net::SocketAddr,
    encrypt: bool,
) -> Result<(), Error> {
    let decrypt = !encrypt;

    let initiated = TcpStream::connect(&target_addr).await?;

    let (plain, mut encrypted) = flip_if(encrypt, initiated, accepted);

    let (to_write, mut state) = kex::Kex::new(key.clone(), decrypt);
    encrypted.write_all(&to_write).await?;
    encrypted.read_exact(&mut state.buf).await?;

    let (to_write, mut state) = state.step();
    encrypted.write_all(&to_write).await?;
    encrypted.read_exact(&mut state.buf).await?;

    let kex::Done { decrypt, encrypt } = state.step()?;

    log::info!(
        "{:?} -> {:?}: keys agreed",
        plain.local_addr()?,
        encrypted.local_addr()?
    );

    let (plain_read, plain_write) = plain.split();
    let (encrypted_read, encrypted_write) = encrypted.split();

    task::spawn(encrypt_packets(encrypt, plain_read, encrypted_write));
    task::spawn(decrypt_packets(decrypt, encrypted_read, plain_write));

    Ok(())
}
