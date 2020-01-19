use std::io::Write;
use std::io;
use std::io::Read;

use failure::Error;

use crate::MasterKey;
use crate::kex;
use crate::SessionCrypto;

struct SPipe<S> {
    inner: S,
    crypto: SessionCrypto,
}

impl<S: Write + Read> SPipe<S> {
    pub fn negotiate(key: MasterKey, mut inner: S) -> Result<SPipe<S>, Error> {
        let (to_write, mut kex) = kex::Kex::new(key, false);
        inner.write_all(&to_write)?;
        inner.read_exact(&mut kex.buf)?;

        let (to_write, mut kex) = kex.step()?;
        inner.write_all(&to_write)?;
        inner.read_exact(&mut kex.buf)?;

        let kex::Done { encrypt: crypto, .. } = kex.step()?;

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
        self.inner.write_all(&super::packet::enpacket(&mut self.crypto, buf))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
