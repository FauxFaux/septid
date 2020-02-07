use std::net;
use std::net::ToSocketAddrs;

use async_std::net::TcpListener;
use async_std::net::TcpStream;
use async_std::task;
use async_std::task::JoinHandle;
use failure::Error;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::AsyncReadExt;
use futures::AsyncWriteExt;
use futures::FutureExt as _;

mod stream;

use super::MasterKey;
use crate::proto::flip_if;
use crate::proto::kex;
use stream::decrypt_packets;
use stream::encrypt_packets;

#[derive(Copy, Clone, Debug)]
pub enum Command {
    NoNewConnections,
}

pub struct StartServer {
    pub key: MasterKey,
    pub bind_address: Vec<String>,
    pub target_address: Vec<String>,
    pub encrypt: bool,
}

pub struct Running {
    commands: mpsc::Sender<Command>,
    listeners: FuturesUnordered<JoinHandle<Result<(), Error>>>,
}

pub async fn start_server(config: &StartServer) -> Result<Running, Error> {
    let (command_send, mut command_recv) = mpsc::channel::<Command>(1);

    let mut sources = Vec::with_capacity(config.bind_address.len() * 2);

    let mut target_addrs = Vec::with_capacity(config.target_address.len() * 2);
    for target in &config.target_address {
        target_addrs.extend(target.to_socket_addrs()?);
    }

    for source in &config.bind_address {
        let listener = TcpListener::bind(&source).await?;
        log::info!("{:?}: listening", source);
        sources.push(listener);
    }

    let mut shutdowns: Vec<oneshot::Sender<()>> = Vec::new();
    let listeners = FuturesUnordered::new();

    for listener in sources {
        let key = config.key.clone();
        let target_addrs = target_addrs.clone();
        let encrypt = config.encrypt;
        let (send, recv) = oneshot::channel();
        let mut recv = recv.fuse();
        shutdowns.push(send);
        let local_addr = listener.local_addr()?;
        listeners.push(task::spawn(async move {
            let mut accepter = listener.incoming().fuse();
            loop {
                let stream = futures::select! {
                    stream = accepter.next() => stream,
                    _command = recv => {
                        log::debug!("asked to shutdown, cancelling listen");
                        break;
                    },
                    complete => {
                        log::warn!("listener exiting as everyone has left us alone");
                        break;
                    },
                };

                let stream = stream.expect("TcpListener stream is infinite")?;

                handle_client(stream, &key, &target_addrs[0], encrypt).await?;
            }
            Ok::<(), Error>(())
        }));
    }

    task::spawn(async move {
        command_recv.next().await;
        for shutdown in shutdowns {
            let _ = shutdown.send(());
        }
    });

    Ok(Running {
        commands: command_send,
        listeners,
    })
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

impl Running {
    pub async fn request_shutdown(&mut self) -> Result<(), Error> {
        use futures::sink::SinkExt as _;
        self.commands.send(Command::NoNewConnections).await?;
        Ok(())
    }

    pub async fn run_to_completion(mut self) -> Result<(), Error> {
        while let Some(listener) = self.listeners.next().await {
            listener?;
        }
        Ok(())
    }
}
