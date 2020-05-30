use std::io;
use std::io::Read;
use std::io::Write;

use anyhow::anyhow;
use anyhow::Context as _;
use anyhow::Result;

use crate::proto::kex;
use crate::proto::packet;
use crate::proto::SessionCrypto;
use crate::MasterKey;

/// A secure pipe over a `Write`.
///
/// The `write` implementation forms a packet from its input immediately, then blocks trying
/// to write it to the network. It will consume up to 1kB at a time. This will hence be much
/// more efficient if you buffer the input before writing it.
pub struct SPipe<S> {
    inner: S,
    crypto: SessionCrypto,
}

impl<S: Write + Read> SPipe<S> {
    /// Negotiate a session (which requires reading and writing), then switch to write-only mode.
    ///
    /// This method will block until the session is established.
    pub fn negotiate(key: MasterKey, mut inner: S) -> Result<SPipe<S>> {
        let crypto =
            drive_exchange(key, &mut inner).with_context(|| anyhow!("negotiating with server"))?;
        Ok(SPipe { inner, crypto })
    }
}

fn drive_exchange<S: Read + Write>(key: MasterKey, mut inner: S) -> Result<SessionCrypto> {
    let (to_write, mut kex) = kex::Kex::new(key, false);
    inner
        .write_all(&to_write)
        .with_context(|| anyhow!("sending opening message to server"))?;
    inner
        .read_exact(&mut kex.buf)
        .with_context(|| anyhow!("reading server's opening message"))?;

    let (to_write, mut kex) = kex.step();
    inner
        .write_all(&to_write)
        .with_context(|| anyhow!("responding to server's challenge"))?;
    inner.read_exact(&mut kex.buf).with_context(|| {
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

impl<S> SPipe<S> {
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Write> Write for SPipe<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let buf = &buf[..buf.len().min(packet::PACKET_MAX_MESSAGE_LEN)];
        self.inner
            .write_all(&packet::enpacket(&mut self.crypto, buf))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
