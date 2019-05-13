use std::io;

use failure::Error;
use log::debug;
use mio::net::TcpStream;

use crate::packet;
use crate::SessionCrypto;

pub fn encrypt_packet(
    crypto: &mut SessionCrypto,
    from: &mut Stream,
    to: &mut Stream,
) -> Result<bool, Error> {
    fill_buffer_target(from, packet::PACKET_MAX_MESSAGE_LEN)?;
    if from.read_buffer.is_empty() {
        return Ok(false);
    }

    debug!("encrypt from:{}", from.token.0);

    let data_len = packet::PACKET_MAX_MESSAGE_LEN.min(from.read_buffer.len());
    let input = &from.read_buffer[..data_len];

    let packet = packet::enpacket(crypto, input);

    to.write_all(&packet)?;
    from.read_buffer.drain(..data_len);

    debug!("encrypt-done from:{} len:{}", from.token.0, data_len);

    Ok(true)
}

pub fn decrypt_packet(
    crypto: &mut SessionCrypto,
    from: &mut Stream,
    to: &mut Stream,
) -> Result<bool, Error> {
    let token = from.token;

    let mut packet = match from.read_exact(packet::PACKET_LEN)? {
        Some(packet) => packet,
        None => return Ok(false),
    };

    debug!("decrypt from:{}", token.0);

    let output = packet::unpacket(crypto, packet.as_mut()).map_err(failure::err_msg)?;

    to.write_all(output)?;

    Ok(true)
}

fn fill_buffer_target(stream: &mut Stream, target: usize) -> Result<(), io::Error> {
    let Stream {
        read_buffer,
        inner: sock,
        ..
    } = stream;

    while read_buffer.len() < target {
        use std::io::Read;
        let mut buf = [0u8; 8 * 1024];
        let len = match sock.read(&mut buf) {
            Ok(len) => len,
            Err(ref e) if io::ErrorKind::WouldBlock == e.kind() => break,
            Err(e) => return Err(e),
        };

        let buf = &buf[..len];
        if buf.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        read_buffer.extend_from_slice(buf);
    }

    Ok(())
}

fn flush_buffer(stream: &mut Stream) -> Result<(), io::Error> {
    let Stream {
        write_buffer: buf,
        inner: sock,
        ..
    } = stream;

    if buf.is_empty() {
        return Ok(());
    }

    use std::io::Write;

    loop {
        let len = match sock.write(buf) {
            Ok(len) => len,
            Err(ref e) if io::ErrorKind::WouldBlock == e.kind() => break,
            Err(e) => return Err(e),
        };
        if len == buf.len() {
            buf.truncate(0);
            break;
        }

        if 0 == len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        buf.drain(..len);
    }

    Ok(())
}

pub struct Stream {
    inner: TcpStream,
    token: mio::Token,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
}

impl Stream {
    pub fn new(inner: TcpStream, token: mio::Token) -> Stream {
        Stream {
            inner,
            token,
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
        }
    }

    pub fn initial_registration(&mut self, poll: &mio::Poll) -> Result<(), io::Error> {
        poll.register(
            &self.inner,
            self.token,
            mio::Ready::empty(),
            mio::PollOpt::edge(),
        )
    }

    pub fn reregister(&self, poll: &mio::Poll) -> Result<(), io::Error> {
        let read = self.read_buffer.len() < packet::PACKET_LEN;
        let write = !self.write_buffer.is_empty();

        let mut interest = mio::Ready::empty();

        if read {
            interest |= mio::Ready::readable();
        }

        if write {
            interest |= mio::Ready::writable();
        }

        poll.reregister(&self.inner, self.token, interest, mio::PollOpt::edge())
    }

    pub fn read_exact(&mut self, len: usize) -> Result<Option<ReadResult>, io::Error> {
        fill_buffer_target(self, len)?;
        if self.read_buffer.len() < len {
            return Ok(None);
        }

        Ok(Some(ReadResult {
            inner: &mut self.read_buffer,
            len,
        }))
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        self.write_buffer.extend_from_slice(buf);
        flush_buffer(self)
    }
}

struct ReadResult<'v> {
    inner: &'v mut Vec<u8>,
    len: usize,
}

impl<'v> AsRef<[u8]> for ReadResult<'v> {
    fn as_ref(&self) -> &[u8] {
        &self.inner[..self.len]
    }
}

impl<'v> AsMut<[u8]> for ReadResult<'v> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner[..self.len]
    }
}

impl<'v> Drop for ReadResult<'v> {
    fn drop(&mut self) {
        self.inner.drain(..self.len);
    }
}
