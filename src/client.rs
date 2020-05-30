use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use anyhow::anyhow;
use anyhow::Error;
use anyhow::Context as _;
use futures::io::BufWriter;
use futures::AsyncRead;
use futures::AsyncReadExt as _;
use futures::AsyncWrite;
use futures::AsyncWriteExt as _;

use crate::proto::kex;
use crate::proto::packet;
use crate::proto::SessionCrypto;
use crate::MasterKey;

/// A secure pipe over an `AsyncWrite`.
#[pin_project::pin_project]
pub struct SPipe<S> {
    #[pin]
    inner: BufWriter<S>,
    crypto: SessionCrypto,
}

impl<S: AsyncWrite + AsyncRead + Unpin> SPipe<S> {
    /// Negotiate a session (which requires reading and writing), then switch to write-only mode.
    ///
    /// This method will not complete until the session is fully established.
    pub async fn negotiate(key: MasterKey, mut inner: S) -> Result<SPipe<S>, Error> {
        let crypto = drive_exchange(key, &mut inner)
            .await
            .with_context(|| anyhow!("negotiating with server"))?;
        Ok(SPipe {
            inner: BufWriter::with_capacity(packet::PACKET_LEN, inner),
            crypto,
        })
    }
}

async fn drive_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    key: MasterKey,
    mut inner: S,
) -> Result<SessionCrypto, Error> {
    let (to_write, mut kex) = kex::Kex::new(key, false);
    inner
        .write_all(&to_write)
        .await
        .with_context(|| anyhow!("sending opening message to server"))?;
    inner
        .read_exact(&mut kex.buf)
        .await
        .with_context(|| anyhow!("reading server's opening message"))?;

    let (to_write, mut kex) = kex.step();
    inner
        .write_all(&to_write)
        .await
        .with_context(|| anyhow!("responding to server's challenge"))?;
    inner.read_exact(&mut kex.buf).await.with_context(|| {
        anyhow!(concat!(
            "reading server's challenge response,",
            " failure can mean our key is wrong,",
            " or there are no backends available"
        ))
    })?;

    let kex::Done { encrypt, .. } = kex
        .step()
        .with_context(|| anyhow!("validating handshake from server"))?;

    Ok(encrypt)
}

impl<S: AsyncWrite> AsyncWrite for SPipe<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut us = self.project();

        // ensure the BufWriter is empty
        futures::ready!(us.inner.as_mut().poll_flush(cx))?;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let buf = &buf[..buf.len().min(packet::PACKET_MAX_MESSAGE_LEN)];

        // as we successfully flushed above, the BufWriter will always accept our packet
        match us
            .inner
            .poll_write(cx, &packet::enpacket(&mut us.crypto, buf))
        {
            Poll::Ready(Ok(packet::PACKET_LEN)) => Poll::Ready(Ok(buf.len())),
            other => panic!("buffering failed: {:?}", other),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}
