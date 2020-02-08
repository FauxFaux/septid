use std::net;
use std::net::ToSocketAddrs;

use async_std::net::TcpListener;
use async_std::net::TcpStream;
use async_std::task;
use failure::Error;
use futures::channel::oneshot;
use futures::future::join;
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt as _;
use futures::AsyncReadExt as _;
use futures::AsyncWriteExt as _;
use futures::FutureExt as _;

mod stream;

use super::MasterKey;
use crate::proto::flip_if;
use crate::proto::kex;
use stream::decrypt_packets;
use stream::encrypt_packets;

pub struct StartServer {
    pub key: MasterKey,
    pub bind_address: Vec<String>,
    pub target_address: Vec<String>,
    pub encrypt: bool,
}

pub struct Running {
    shutdown_send: Option<oneshot::Sender<()>>,
    listeners: FuturesUnordered<task::JoinHandle<Result<(), Error>>>,
}

pub async fn start_server(config: &StartServer) -> Result<Running, Error> {
    let mut target_addrs = Vec::with_capacity(config.target_address.len() * 2);
    for target in &config.target_address {
        target_addrs.extend(target.to_socket_addrs()?);
    }

    let (shutdown_send, shutdown_recv) = oneshot::channel();
    let shutdown_recv = shutdown_recv.shared();
    let listeners = FuturesUnordered::new();

    for source in &config.bind_address {
        let listener = TcpListener::bind(source).await?;
        let key = config.key.clone();
        let target_addrs = target_addrs.clone();
        let encrypt = config.encrypt;
        let mut shutdown_recv = shutdown_recv.clone();
        listeners.push(task::spawn(async move {
            let mut accepter = listener.incoming().fuse();
            let mut workers = FuturesUnordered::new();
            loop {
                let stream = futures::select! {
                    stream = accepter.next() => stream,
                    _ = shutdown_recv => {
                        log::debug!("asked to shutdown, cancelling listen");
                        break;
                    },
                    _worker = workers.next() => continue,
                    complete => {
                        log::warn!("listener exiting as everyone has left us alone");
                        break;
                    },
                };

                let stream = stream.expect("TcpListener stream is infinite")?;

                workers.push(task::spawn(handle_client(
                    stream,
                    key.clone(),
                    target_addrs[0].clone(),
                    encrypt,
                )));
            }

            while let Some(worker) = workers.next().await {
                worker?;
            }

            Ok::<(), Error>(())
        }));
    }

    Ok(Running {
        shutdown_send: Some(shutdown_send),
        listeners,
    })
}

async fn handle_client(
    accepted: TcpStream,
    key: MasterKey,
    target_addr: net::SocketAddr,
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

    let (enc, dec) = join(
        encrypt_packets(encrypt, plain_read, encrypted_write),
        decrypt_packets(decrypt, encrypted_read, plain_write),
    )
    .await;

    enc?;
    dec?;

    Ok(())
}

impl Running {
    pub async fn request_shutdown(&mut self) -> Result<(), Error> {
        let _result_void_void = self
            .shutdown_send
            .take()
            .ok_or(failure::err_msg("already requested"))?
            .send(());
        Ok(())
    }

    pub async fn run_to_completion(mut self) -> Result<(), Error> {
        while let Some(listener) = self.listeners.next().await {
            listener?;
        }
        Ok(())
    }
}
