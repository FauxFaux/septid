use std::collections::HashMap;
use std::net;
use std::net::ToSocketAddrs;

use failure::err_msg;
use failure::Error;
use futures::future::Either;
use log::debug;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

mod crypto;
mod kex;
mod named_array;
mod packet;
mod stream;

use crate::stream::decrypt_packets;
use crate::stream::encrypt_packets;
pub use crypto::load_key;

named_array!(MasterKey, 256);

named_array!(Nonce, 256);
named_array!(BothNonces, 2 * Nonce::BITS);
named_array!(XParam, 256);
named_array!(YParam, 2048);

named_array!(EncKey, 256);
named_array!(MacKey, 256);

pub const Y_H_LEN: usize = YParam::BYTES + packet::PACKET_MAC_LEN;

pub struct StartServer {
    pub key: MasterKey,
    pub bind_address: Vec<String>,
    pub target_address: Vec<String>,
    pub encrypt: bool,
}

#[derive(Copy, Clone, Debug)]
pub enum Command {
    NoNewConnections,
    Terminate,
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

    let mut shutdowns: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();

    for mut listener in sources {
        let key = config.key.clone();
        let target_addrs = target_addrs.clone();
        let encrypt = config.encrypt;
        let (send, recv) = tokio::sync::oneshot::channel();
        shutdowns.push(send);
        let local_addr = listener.local_addr()?;
        tokio::spawn(async move {
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

    tokio::spawn(async move {
        command_recv.recv().await;
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

    let (mut plain, mut encrypted) = flip_if(encrypt, initiated, accepted);

    let (to_write, mut state) = kex::Kex::new(key.clone(), decrypt);
    encrypted.write_all(&to_write).await?;
    encrypted.read_exact(&mut state.buf).await?;

    let (to_write, mut state) = state.step()?;
    encrypted.write_all(&to_write).await?;
    encrypted.read_exact(&mut state.buf).await?;

    let kex::Done { decrypt, encrypt } = state.step()?;

    log::info!(
        "{:?} -> {:?}: keys agreed",
        plain.local_addr()?,
        encrypted.local_addr()?
    );

    let (plain_read, plain_write) = tokio::io::split(plain);
    let (encrypted_read, encrypted_write) = tokio::io::split(encrypted);

    tokio::spawn(encrypt_packets(encrypt, plain_read, encrypted_write));
    tokio::spawn(decrypt_packets(decrypt, encrypted_read, plain_write));

    Ok(())
}

fn flip_if<T>(flip: bool, left: T, right: T) -> (T, T) {
    if flip {
        (right, left)
    } else {
        (left, right)
    }
}

pub struct Server {
    key: MasterKey,
    encrypt: bool,
    target_addrs: Vec<std::net::SocketAddr>,
    command_recv: mpsc::Receiver<Command>,
}

pub struct SessionCrypto {
    enc: EncKey,
    mac: MacKey,
    packet_number: u64,
}

impl MacKey {
    fn begin(&self) -> hmac::Hmac<sha2::Sha256> {
        use crypto_mac::Mac;
        hmac::Hmac::<sha2::Sha256>::new_varkey(&self.0).expect("all keys are valid for hmac")
    }
}
