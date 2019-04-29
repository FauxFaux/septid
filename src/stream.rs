use std::io;

use aes_ctr::stream_cipher::NewStreamCipher;
use aes_ctr::stream_cipher::SyncStreamCipher;
use aes_ctr::Aes256Ctr;
use byteorder::ByteOrder;
use byteorder::BE;
use cast::u32;
use cast::usize;
use failure::ensure;
use failure::Error;
use log::debug;
use mio::net::TcpStream;
use subtle::ConstantTimeEq;

use crate::SessionCrypto;

const PACKET_MAX_MESSAGE_LEN: usize = 1024;
const PACKET_MESSAGE_LEN_LEN: usize = 4; // u32
const PACKET_MESSAGE_ENCRYPTED_LEN: usize = PACKET_MAX_MESSAGE_LEN + PACKET_MESSAGE_LEN_LEN;
pub const PACKET_MAC_LEN: usize = 256 / 8; // 32
const PACKET_LEN: usize = PACKET_MESSAGE_ENCRYPTED_LEN + PACKET_MAC_LEN;

pub fn encrypt_packet(
    crypto: &mut SessionCrypto,
    from: &mut Stream,
    to: &mut Stream,
) -> Result<bool, Error> {
    fill_buffer_target(from, PACKET_MAX_MESSAGE_LEN)?;
    if from.read_buffer.is_empty() {
        return Ok(false);
    }

    debug!("encrypt from:{}", from.token.0);

    let data_len = PACKET_MAX_MESSAGE_LEN.min(from.read_buffer.len());
    let input = &from.read_buffer[..data_len];

    let packet = enpacket(crypto, input);

    to.write_all(&packet)?;
    from.read_buffer.drain(..data_len);

    debug!("encrypt-done from:{} len:{}", from.token.0, data_len);

    Ok(true)
}

fn enpacket(crypto: &mut SessionCrypto, input: &[u8]) -> [u8; PACKET_LEN] {
    let mut packet = [0u8; PACKET_LEN];

    (&mut packet[..input.len()]).copy_from_slice(input);
    BE::write_u32(
        &mut packet[PACKET_MAX_MESSAGE_LEN..],
        u32(input.len()).expect("<1024"),
    );

    let packet_number = aes_ctr(crypto, &mut packet[..PACKET_MESSAGE_ENCRYPTED_LEN]);

    let mac = {
        use crypto_mac::Mac;
        let mut computer = crypto.mac.begin();
        computer.input(&packet[..PACKET_MESSAGE_ENCRYPTED_LEN]);
        computer.input(&packet_number.to_be_bytes());
        computer.result().code()
    };

    (&mut packet[PACKET_MESSAGE_ENCRYPTED_LEN..]).copy_from_slice(&mac);

    packet
}

pub fn decrypt_packet(
    crypto: &mut SessionCrypto,
    from: &mut Stream,
    to: &mut Stream,
) -> Result<bool, Error> {
    let token = from.token;

    let mut packet = match from.read_exact(PACKET_LEN)? {
        Some(packet) => packet,
        None => return Ok(false),
    };

    debug!("decrypt from:{}", token.0);

    let output = unpacket(crypto, packet.as_mut())?;

    to.write_all(output)?;

    Ok(true)
}

fn unpacket<'s, 'p>(
    crypto: &'s mut SessionCrypto,
    packet: &'p mut [u8],
) -> Result<&'p [u8], Error> {
    //    msg_padded: [ message ] [ padded up to 1024 bytes ] [ length: 4 bytes ]
    // msg_encrypted: encrypt(msg_padded)
    //       payload: [ msg_encrypted ] [ mac([ msg_encrypted ] [ packet number: 8 bytes ]):
    // copy the mac out of the read buffer
    let (msg_encrypted, mac_actual) = packet.as_mut().split_at_mut(PACKET_MESSAGE_ENCRYPTED_LEN);

    let mac_expected = {
        use crypto_mac::Mac;
        let mut computer = crypto.mac.begin();
        computer.input(msg_encrypted);
        computer.input(&crypto.packet_number.to_be_bytes());
        computer.result().code()
    };

    ensure!(
        1 == mac_expected.ct_eq(&mac_actual).unwrap_u8(),
        "packet mac bad"
    );

    aes_ctr(crypto, msg_encrypted);

    let actual_len = usize(BE::read_u32(&msg_encrypted[PACKET_MAX_MESSAGE_LEN..]));

    ensure!(
        actual_len != 0 && actual_len <= PACKET_MAX_MESSAGE_LEN,
        "invalid len"
    );

    ensure!(
        msg_encrypted[actual_len..PACKET_MAX_MESSAGE_LEN]
            .iter()
            .all(|&x| 0 == x),
        "invalid padding"
    );

    Ok(&msg_encrypted[..actual_len])
}

fn aes_ctr(crypto: &mut SessionCrypto, data: &mut [u8]) -> u64 {
    let number_to_use = crypto.packet_number;
    crypto.packet_number += 1;

    let mut nonce = [0u8; 16];
    BE::write_u64(&mut nonce[..8], number_to_use);

    let mut cipher = Aes256Ctr::new_var(&crypto.enc.0[..], &nonce).expect("length from arrays");
    cipher.apply_keystream(data);

    number_to_use
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

pub fn flush_buffer(stream: &mut Stream) -> Result<(), io::Error> {
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
        let read = self.read_buffer.len() < PACKET_LEN;
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

pub struct ReadResult<'v> {
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
