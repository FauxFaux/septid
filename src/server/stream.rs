use failure::err_msg;
use failure::Error;
use failure::ResultExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

use crate::packet;
use crate::SessionCrypto;

pub async fn encrypt_packets<F, T>(
    mut crypto: SessionCrypto,
    mut from: F,
    mut to: T,
) -> Result<(), Error>
where
    F: Unpin + AsyncRead,
    T: Unpin + AsyncWrite,
{
    let mut buf = [0u8; packet::PACKET_MAX_MESSAGE_LEN];
    loop {
        let len = from.read(&mut buf).await?;
        let buf = &buf[..len];
        if buf.is_empty() {
            return Ok(());
        }
        log::debug!("sending {}", buf.len());
        to.write_all(&packet::enpacket(&mut crypto, buf)).await?;
    }
}

pub async fn decrypt_packets<F, T>(
    mut crypto: SessionCrypto,
    mut from: F,
    mut to: T,
) -> Result<(), Error>
where
    F: Unpin + AsyncRead,
    T: Unpin + AsyncWrite,
{
    let mut buf = [0u8; packet::PACKET_LEN];
    loop {
        from.read_exact(&mut buf)
            .await
            .with_context(|_| err_msg("taking a packet from the wire"))?;
        let output = packet::unpacket(&mut crypto, buf.as_mut()).map_err(failure::err_msg)?;
        to.write_all(output).await?;
    }
}
