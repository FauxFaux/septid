use anyhow::anyhow;
use anyhow::Context as _;
use anyhow::Result;
use futures::AsyncRead;
use futures::AsyncReadExt;
use futures::AsyncWrite;
use futures::AsyncWriteExt;

use crate::proto::packet;
use crate::proto::SessionCrypto;

pub(crate) async fn encrypt_packets<F, T>(
    mut crypto: SessionCrypto,
    mut from: F,
    mut to: T,
) -> Result<()>
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

pub(crate) async fn decrypt_packets<F, T>(
    mut crypto: SessionCrypto,
    mut from: F,
    mut to: T,
) -> Result<()>
where
    F: Unpin + AsyncRead,
    T: Unpin + AsyncWrite,
{
    let mut buf = [0u8; packet::PACKET_LEN];
    loop {
        from.read_exact(&mut buf)
            .await
            .with_context(|| anyhow!("taking a packet from the wire"))?;
        let output = packet::unpacket(&mut crypto, buf.as_mut()).map_err(|e| anyhow!(e))?;
        to.write_all(output).await?;
    }
}
