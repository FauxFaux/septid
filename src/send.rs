use std::io;
use std::io::Read;
use std::io::Write;

use failure::Error;

use crate::kex;
use crate::MasterKey;
use crate::SessionCrypto;

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
    pub fn negotiate(key: MasterKey, mut inner: S) -> Result<SPipe<S>, Error> {
        let (to_write, mut kex) = kex::Kex::new(key, false);
        inner.write_all(&to_write)?;
        inner.read_exact(&mut kex.buf)?;

        let (to_write, mut kex) = kex.step()?;
        inner.write_all(&to_write)?;
        inner.read_exact(&mut kex.buf)?;

        let kex::Done {
            encrypt: crypto, ..
        } = kex.step()?;

        Ok(SPipe { inner, crypto })
    }
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
        let buf = &buf[..buf.len().min(super::packet::PACKET_MAX_MESSAGE_LEN)];
        self.inner
            .write_all(&super::packet::enpacket(&mut self.crypto, buf))?;
        println!("write {} bytes", buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
