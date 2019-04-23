use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::mem;

use aes_ctr::stream_cipher::NewStreamCipher;
use aes_ctr::stream_cipher::SyncStreamCipher;
use aes_ctr::Aes256Ctr;
use byteorder::ByteOrder;
use byteorder::BE;
use cast::u32;
use cast::usize;
use failure::ensure;
use failure::err_msg;
use failure::Error;
use getrandom::getrandom;
use log::debug;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Token;
use num_bigint::BigUint;

const PACKET_MAX_MESSAGE_LEN: usize = 1024;
const PACKET_MESSAGE_LEN_LEN: usize = 4; // u32
const PACKET_PACKET_NUMBER_LEN: usize = 8; // u64
const PACKET_MESSAGE_ENCRYPTED_LEN: usize = PACKET_MAX_MESSAGE_LEN + PACKET_MESSAGE_LEN_LEN;
const PACKET_LEN: usize = PACKET_MESSAGE_ENCRYPTED_LEN + MacResult::BYTES;

#[macro_export]
macro_rules! named_array {
    ($name:ident, $len:expr) => {
        #[derive(Clone)]
        pub struct $name([u8; $len / 8]);

        #[allow(dead_code)]
        impl $name {
            pub const BYTES: usize = $len / 8;
            pub const BITS: usize = $len;

            pub fn random() -> Result<Self, getrandom::Error> {
                let mut ret = [0u8; Self::BYTES];
                getrandom::getrandom(&mut ret)?;
                Ok(Self(ret))
            }

            pub fn from_slice(data: &[u8]) -> Self {
                let mut ret = [0u8; Self::BYTES];
                ret.copy_from_slice(data);
                Self(ret)
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                (&mut self.0[..]).zeroize()
            }
        }
    };
}

mod crypto;

use crypto::MacResult;

named_array!(MasterKey, 256);

named_array!(Nonce, 256);
named_array!(BothNonces, 2 * Nonce::BITS);
named_array!(XParam, 256);
named_array!(YParam, 2048);

named_array!(EncKey, 256);
named_array!(MacKey, 256);

fn main() -> Result<(), Error> {
    pretty_env_logger::init();
    let mut args = env::args();
    let _us = args.next().unwrap_or_else(String::new);
    let mut opts = getopts::Options::new();
    opts.optflag("e", "encrypt", "forward data over an encrypted connection");
    opts.optflag(
        "d",
        "decrypt",
        "decrypt data from a encrypt, and forward it",
    );

    opts.reqopt(
        "k",
        "key-file",
        "key for encryption and authentication",
        "FILE",
    );

    opts.reqopt("s", "source", "listen for connections", "IP:PORT");
    opts.reqopt("t", "target", "make connections to", "HOST:PORT");

    opts.optopt("u", "uid", "drop privileges after binding", "USER:GROUP");

    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(args) {
        Ok(matches) => matches,
        Err(f) => {
            use std::error::Error as _;
            eprintln!("error: {}", f.description());
            return Ok(());
        }
    };

    // TODO: error feedback
    assert_eq!(
        0,
        matches.free.len(),
        "all arguments must start with a hyphen"
    );

    let decrypt = matches.opt_present("d");
    let encrypt = matches.opt_present("e");

    assert_ne!(decrypt, encrypt, "-d or -e is required");

    let addr = matches
        .opt_get::<String>("s")?
        .expect("opt required")
        .parse()?;

    let source = mio::net::TcpListener::bind(&addr)?;
    let target = matches.opt_get("t")?.expect("opt required");

    let key_path: String = matches.opt_get("k")?.expect("opt required");
    let key = load_key(&key_path)?;

    assert!(!matches.opt_present("u"), "-u unsupported");

    getrandom(&mut [0u8; 1])?;

    let mut server = Server {
        encrypt,
        clients: HashMap::new(),
        source: Some(source),
        target,
    };

    let signals =
        signal_hook::iterator::Signals::new(&[signal_hook::SIGTERM, signal_hook::SIGINT])?;

    const SERVER: Token = Token(1);
    const SIGNALS: Token = Token(2);

    let poll = mio::Poll::new()?;
    poll.register(
        server.source.as_ref().unwrap(),
        SERVER,
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )?;

    poll.register(
        &signals,
        SIGNALS,
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )?;

    let mut next_token = 10usize;

    let mut events = mio::Events::with_capacity(32);
    'app: loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            match event.token() {
                SERVER => {
                    if !event.readiness().is_readable() {
                        continue;
                    }

                    let source = match server.source.as_ref() {
                        Some(listener) => listener,
                        None => continue,
                    };

                    let (input, from) = source.accept()?;
                    let addr = {
                        use std::net::ToSocketAddrs;
                        server
                            .target
                            .to_socket_addrs()?
                            .next()
                            .ok_or_else(|| err_msg("no resolution"))?
                    };

                    let output = TcpStream::connect(&addr)?;

                    let in_token = Token(next_token);
                    next_token = next_token.checked_add(1).unwrap();
                    let out_token = Token(next_token);
                    next_token = next_token.checked_add(1).unwrap();

                    let our_nonce = Nonce::random()?;

                    let mut input = Stream::new(input, in_token);
                    input.initial_registration(&poll)?;

                    let mut output = Stream::new(output, out_token);
                    output.initial_registration(&poll)?;

                    debug!(
                        "connection in:{} out:{} addr:{}",
                        in_token.0, out_token.0, from
                    );

                    if encrypt {
                        output.write_buffer.extend_from_slice(&our_nonce.0);
                        flush_buffer(&mut output)?;
                    } else {
                        input.write_buffer.extend_from_slice(&our_nonce.0);
                        flush_buffer(&mut input)?;
                    }

                    input.reregister(&poll)?;
                    output.reregister(&poll)?;

                    server.clients.insert(
                        in_token,
                        Conn {
                            input,
                            output,
                            packet_number_encrypt: 0,
                            packet_number_decrypt: 0,
                            crypto: Crypto::NonceSent {
                                our_nonce,
                                our_x: XParam::random()?,
                            },
                        },
                    );
                }
                SIGNALS => {
                    // spurious wakeup, do nothing
                    // do we need to consume the iterator (with .count), vs. just .next?
                    if 0 == signals.pending().count() {
                        continue;
                    }

                    match server.source.take() {
                        // first time, drop the incoming connection
                        Some(listen) => mem::drop(listen),
                        // been here before, just cancel the whole app
                        None => break 'app,
                    };

                    println!("no longer accepting new connections");
                    println!("waiting for existing connections to terminate...");

                    if server.clients.is_empty() {
                        break 'app;
                    }
                }
                client => {
                    debug!("event client:{}", client.0);
                    if let Some(conn) = server.clients.get_mut(&round_down(client)) {
                        duplify(&key, decrypt, conn)?;
                        conn.input.reregister(&poll)?;
                        conn.output.reregister(&poll)?;
                    }
                }
            }
        }
    }

    println!("done");

    Ok(())
}

/// 2 -> 2, 3 -> 2, 4 -> 4, 5 -> 4
fn round_down(value: Token) -> Token {
    Token(value.0 & !1)
}

fn duplify(key: &MasterKey, decrypt: bool, conn: &mut Conn) -> Result<(), Error> {
    flush_buffer(&mut conn.input)?;
    flush_buffer(&mut conn.output)?;

    loop {
        match &conn.crypto {
            Crypto::NonceSent { our_nonce, our_x } => {
                let negotiate = if decrypt {
                    &mut conn.input
                } else {
                    &mut conn.output
                };

                let server = decrypt;

                let nonce_len = Nonce::BYTES;
                fill_buffer_target(negotiate, nonce_len)?;
                if negotiate.read_buffer.len() < nonce_len {
                    break;
                }

                let other_nonce = Nonce::from_slice(&negotiate.read_buffer[..nonce_len]);
                drop(negotiate.read_buffer.drain(..nonce_len));

                let (client_nonce, server_nonce) = if decrypt {
                    (&other_nonce, our_nonce)
                } else {
                    (our_nonce, &other_nonce)
                };

                let mut nonces = [0u8; 32 * 2];
                nonces[..32].copy_from_slice(&client_nonce.0);
                nonces[32..].copy_from_slice(&server_nonce.0);

                let mut double_dk = [0u8; 32 * 2];
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&key.0, &nonces, 1, &mut double_dk);

                let dh_mac_client = MacKey::from_slice(&double_dk[..32]);
                let dh_mac_server = MacKey::from_slice(&double_dk[32..]);

                let two = BigUint::from(2u8);

                // TODO: constant time
                let our_y = two.modpow(
                    &BigUint::from_bytes_be(&our_x.0),
                    &BigUint::from_bytes_be(&crypto::GROUP_14_PRIME.0),
                );

                // TODO: pad to length
                let our_y = our_y.to_bytes_be();
                assert_eq!(256, our_y.len(), "short y");

                negotiate.write_buffer.extend_from_slice(&our_y);

                let y_mac = crypto::mac(
                    if server {
                        &dh_mac_server
                    } else {
                        &dh_mac_client
                    },
                    &our_y,
                );
                negotiate.write_buffer.extend_from_slice(&y_mac.code());

                debug!("nonce-sent client:{}", negotiate.token.0);

                conn.crypto = Crypto::NonceReceived {
                    nonces,
                    our_x: our_x.clone(),
                    their_dh_mac_key: if server { dh_mac_client } else { dh_mac_server },
                };
            }
            Crypto::NonceReceived {
                nonces,
                our_x,
                their_dh_mac_key,
            } => {
                let negotiate = if decrypt {
                    &mut conn.input
                } else {
                    &mut conn.output
                };

                let y_h_len = YParam::BYTES + MacResult::BYTES;
                fill_buffer_target(negotiate, y_h_len)?;
                if negotiate.read_buffer.len() < y_h_len {
                    break;
                }

                let their_mac = MacResult::from_slice(&negotiate.read_buffer[256..][..32]);

                let expected_mac = crypto::mac(&their_dh_mac_key, &negotiate.read_buffer[..256]);
                use subtle::ConstantTimeEq;
                ensure!(expected_mac.ct_eq(&their_mac).unwrap_u8() == 1, "bad mac");

                let their_y = BigUint::from_bytes_be(&negotiate.read_buffer[..256]);
                let prime = BigUint::from_bytes_be(&crypto::GROUP_14_PRIME.0);
                ensure!(their_y < prime, "bad y");

                drop(negotiate.read_buffer.drain(..256 + 32));

                let shared = their_y
                    .modpow(&BigUint::from_bytes_be(&our_x.0), &prime)
                    .to_bytes_be();
                assert_eq!(256, shared.len(), "short shared");

                let mut buf = Vec::with_capacity(32 + 32 + 256);
                buf.extend_from_slice(nonces);
                buf.extend_from_slice(&shared);

                let mut quad_dk = [0u8; EncKey::BYTES * 2 + MacKey::BYTES * 2];
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&key.0, &buf, 1, &mut quad_dk);

                let server = two_keys(&quad_dk[..64]);
                let client = two_keys(&quad_dk[64..]);

                debug!("keys-agreed client:{}", negotiate.token.0);

                conn.crypto = if decrypt {
                    Crypto::Done {
                        ours: server,
                        theirs: client,
                    }
                } else {
                    Crypto::Done {
                        ours: client,
                        theirs: server,
                    }
                }
            }
            Crypto::Done { ours, theirs } => {
                if decrypt {
                    decrypt_stream(
                        theirs,
                        &mut conn.input,
                        &mut conn.output,
                        &mut conn.packet_number_decrypt,
                    )?;
                    encrypt_stream(
                        ours,
                        &mut conn.output,
                        &mut conn.input,
                        &mut conn.packet_number_encrypt,
                    )?;
                } else {
                    encrypt_stream(
                        theirs,
                        &mut conn.input,
                        &mut conn.output,
                        &mut conn.packet_number_encrypt,
                    )?;
                    decrypt_stream(
                        ours,
                        &mut conn.output,
                        &mut conn.input,
                        &mut conn.packet_number_decrypt,
                    )?;
                }
                break;
            }
        }
    }

    flush_buffer(&mut conn.input)?;
    flush_buffer(&mut conn.output)?;

    Ok(())
}

fn encrypt_stream(
    (enc, mac): &(EncKey, MacKey),
    from: &mut Stream,
    to: &mut Stream,
    packet_number: &mut u64,
) -> Result<(), Error> {
    fill_buffer_target(from, PACKET_MAX_MESSAGE_LEN)?;
    if from.read_buffer.is_empty() {
        return Ok(());
    }

    debug!("encrypt from:{}", from.token.0);

    let data_len = PACKET_MAX_MESSAGE_LEN.min(from.read_buffer.len());
    let input = &from.read_buffer[..data_len];
    let mut packet = [0u8; PACKET_LEN];

    (&mut packet[..data_len]).copy_from_slice(input);
    BE::write_u32(
        &mut packet[PACKET_MAX_MESSAGE_LEN..],
        u32(data_len).expect("<1024"),
    );

    BE::write_u64(&mut packet[PACKET_MESSAGE_ENCRYPTED_LEN..], *packet_number);
    aes_ctr(
        enc,
        &mut packet[..PACKET_MESSAGE_ENCRYPTED_LEN],
        packet_number,
    );

    let data_to_mac = &packet[..PACKET_MESSAGE_ENCRYPTED_LEN + PACKET_PACKET_NUMBER_LEN];
    let hash = crypto::mac(mac, data_to_mac);
    (&mut packet[PACKET_MESSAGE_ENCRYPTED_LEN..]).copy_from_slice(&hash.code());

    to.write_buffer.extend_from_slice(&packet);
    from.read_buffer.drain(..data_len);

    debug!("encrypt-done from:{} len:{}", from.token.0, data_len);

    Ok(())
}

fn decrypt_stream(
    (enc, mac): &(EncKey, MacKey),
    from: &mut Stream,
    to: &mut Stream,
    packet_number: &mut u64,
) -> Result<(), Error> {
    fill_buffer_target(from, PACKET_LEN)?;
    if from.read_buffer.len() < PACKET_LEN {
        return Ok(());
    }

    debug!("decrypt from:{}", from.token.0);

    let packet = &mut from.read_buffer[..PACKET_LEN];

    //    msg_padded: [ message ] [ padded up to 1024 bytes ] [ length: 4 bytes ]
    // msg_encrypted: encrypt(msg_padded)
    //       payload: [ msg_encrypted ] [ mac([ msg_encrypted ] [ packet number: 8 bytes ]):

    // copy the mac out of the read buffer
    let mut mac_actual = crypto::MacResult::from_slice(&packet[PACKET_MESSAGE_ENCRYPTED_LEN..]);

    // write the packet number into the read_buffer, overwriting part of the mac
    BE::write_u64(&mut packet[PACKET_MESSAGE_ENCRYPTED_LEN..], *packet_number);

    let data_to_mac = &packet[..PACKET_MESSAGE_ENCRYPTED_LEN + PACKET_PACKET_NUMBER_LEN];
    use subtle::ConstantTimeEq;
    ensure!(
        1 == crypto::mac(mac, &data_to_mac)
            .ct_eq(&mac_actual)
            .unwrap_u8(),
        "packet mac bad"
    );

    aes_ctr(
        enc,
        &mut packet[..PACKET_MESSAGE_ENCRYPTED_LEN],
        packet_number,
    );

    let actual_len = usize(BE::read_u32(&packet[PACKET_MAX_MESSAGE_LEN..]));
    ensure!(
        actual_len != 0 && actual_len <= PACKET_MAX_MESSAGE_LEN,
        "invalid len"
    );
    ensure!(
        packet[actual_len..PACKET_MAX_MESSAGE_LEN]
            .iter()
            .all(|&x| 0 == x),
        "invalid padding"
    );

    let msg = &packet[..actual_len];
    to.write_buffer.extend_from_slice(msg);

    from.read_buffer.drain(..PACKET_LEN);

    Ok(())
}

fn aes_ctr(enc: &EncKey, data: &mut [u8], packet_number: &mut u64) {
    let mut nonce = [0u8; 16];
    BE::write_u64(&mut nonce[..8], *packet_number);
    *packet_number += 1;

    let mut cipher = Aes256Ctr::new_var(&enc.0[..], &nonce).expect("length from arrays");
    cipher.apply_keystream(data);
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

fn load_key(from: &str) -> Result<MasterKey, Error> {
    use digest::Digest as _;
    use digest::FixedOutput as _;

    let mut ctx = sha2::Sha256::new();
    let mut file = fs::File::open(from)?;
    io::copy(&mut file, &mut ctx)?;

    Ok(MasterKey::from_slice(&ctx.fixed_result()))
}

fn two_keys(buf: &[u8]) -> (EncKey, MacKey) {
    (
        EncKey::from_slice(&buf[..EncKey::BYTES]),
        MacKey::from_slice(&buf[EncKey::BYTES..]),
    )
}

struct Server {
    encrypt: bool,
    source: Option<TcpListener>,
    target: String,
    clients: HashMap<Token, Conn>,
}

struct Conn {
    input: Stream,
    output: Stream,
    packet_number_encrypt: u64,
    packet_number_decrypt: u64,
    crypto: Crypto,
}

struct Stream {
    inner: TcpStream,
    token: mio::Token,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
}

#[derive(Clone)]
enum Crypto {
    NonceSent {
        our_nonce: Nonce,
        our_x: XParam,
    },
    NonceReceived {
        nonces: [u8; 32 * 2],
        our_x: XParam,
        their_dh_mac_key: MacKey,
    },
    Done {
        ours: (EncKey, MacKey),
        theirs: (EncKey, MacKey),
    },
}

impl Stream {
    fn new(inner: TcpStream, token: mio::Token) -> Stream {
        Stream {
            inner,
            token,
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
        }
    }

    fn initial_registration(&mut self, poll: &mio::Poll) -> Result<(), io::Error> {
        poll.register(
            &self.inner,
            self.token,
            mio::Ready::empty(),
            mio::PollOpt::edge(),
        )
    }

    fn reregister(&self, poll: &mio::Poll) -> Result<(), io::Error> {
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
}
