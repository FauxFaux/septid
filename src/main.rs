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
use failure::ResultExt;
use getrandom::getrandom;
use log::debug;
use log::info;
use log::warn;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Token;
use num_bigint::BigUint;

type Bits256 = [u8; 32];
type Bits2048 = [u8; 256];

mod crypto;

fn main() -> Result<(), Error> {
    pretty_env_logger::init();
    let mut args = env::args();
    let us = args.next().unwrap_or_else(String::new);
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
        key,
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

                    let our_nonce = rand256()?;

                    let mut input = Stream::new(input, in_token);
                    input.initial_registration(&poll)?;

                    let mut output = Stream::new(output, out_token);
                    output.initial_registration(&poll)?;

                    debug!(
                        "connection in:{} out:{} addr:{}",
                        in_token.0, out_token.0, from
                    );

                    if encrypt {
                        output.write_buffer.extend_from_slice(&our_nonce);
                        flush_buffer(&mut output)?;
                    } else {
                        input.write_buffer.extend_from_slice(&our_nonce);
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
                                our_x: rand256()?,
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
                        duplify(key, decrypt, conn)?;
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

fn duplify(key: Bits256, decrypt: bool, conn: &mut Conn) -> Result<(), Error> {
    flush_buffer(&mut conn.input)?;
    flush_buffer(&mut conn.output)?;

    loop {
        match conn.crypto {
            Crypto::NonceSent { our_nonce, our_x } => {
                let negotiate = if decrypt {
                    &mut conn.input
                } else {
                    &mut conn.output
                };

                let server = decrypt;

                let nonce_len = Bits256::default().len();
                fill_buffer_target(negotiate, nonce_len)?;
                if negotiate.read_buffer.len() < nonce_len {
                    break;
                }

                let mut other_nonce = Bits256::default();
                other_nonce.copy_from_slice(&negotiate.read_buffer[..nonce_len]);
                drop(negotiate.read_buffer.drain(..nonce_len));

                let (client_nonce, server_nonce) = if decrypt {
                    (other_nonce, our_nonce)
                } else {
                    (our_nonce, other_nonce)
                };

                let mut nonces = [0u8; 32 * 2];
                nonces[..32].copy_from_slice(&client_nonce);
                nonces[32..].copy_from_slice(&server_nonce);

                let mut double_dk = [0u8; 32 * 2];
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&key, &nonces, 1, &mut double_dk);

                let mut dh_mac_client = Bits256::default();
                let mut dh_mac_server = Bits256::default();

                dh_mac_client.copy_from_slice(&double_dk[..32]);
                dh_mac_server.copy_from_slice(&double_dk[32..]);

                let two = BigUint::from(2u8);

                // TODO: constant time
                let our_y = two.modpow(
                    &BigUint::from_bytes_be(&our_x),
                    &BigUint::from_bytes_be(&crypto::GROUP_14_PRIME),
                );

                // TODO: pad to length
                let our_y = our_y.to_bytes_be();
                assert_eq!(256, our_y.len(), "short y");

                negotiate.write_buffer.extend_from_slice(&our_y);

                let y_mac =
                    crypto::mac(&if server { dh_mac_server } else { dh_mac_client }, &our_y);
                negotiate.write_buffer.extend_from_slice(&y_mac);

                debug!("nonce-sent client:{}", negotiate.token.0);

                conn.crypto = Crypto::NonceReceived {
                    nonces,
                    our_x,
                    their_mac_key: if server { dh_mac_client } else { dh_mac_server },
                };
            }
            Crypto::NonceReceived {
                nonces,
                our_x,
                their_mac_key,
            } => {
                let negotiate = if decrypt {
                    &mut conn.input
                } else {
                    &mut conn.output
                };

                let y_h_len = 256 + Bits256::default().len();
                fill_buffer_target(negotiate, y_h_len)?;
                if negotiate.read_buffer.len() < y_h_len {
                    break;
                }

                let their_mac = &negotiate.read_buffer[256..][..32];
                let expected_mac = crypto::mac(&their_mac_key, &negotiate.read_buffer[..256]);
                use subtle::ConstantTimeEq;
                ensure!(expected_mac.ct_eq(their_mac).unwrap_u8() == 1, "bad mac");

                let their_y = BigUint::from_bytes_be(&negotiate.read_buffer[..256]);
                let prime = BigUint::from_bytes_be(&crypto::GROUP_14_PRIME);
                ensure!(their_y < prime, "bad y");

                drop(negotiate.read_buffer.drain(..256 + 32));

                let shared = their_y
                    .modpow(&BigUint::from_bytes_be(&our_x), &prime)
                    .to_bytes_be();
                assert_eq!(256, shared.len(), "short shared");

                let mut buf = Vec::with_capacity(32 + 32 + 256);
                buf.extend_from_slice(&nonces);
                buf.extend_from_slice(&shared);

                let mut quad_dk = [0u8; 32 * 4];
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&key, &buf, 1, &mut quad_dk);

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
            Crypto::Done {
                ref ours,
                ref theirs,
            } => {
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
    (enc, mac): &(Bits256, Bits256),
    from: &mut Stream,
    to: &mut Stream,
    packet_number: &mut u64,
) -> Result<(), Error> {
    let message_len = 1024;
    let len_len = 4;
    let mac_len = 32;
    let msg_encrypted_len = message_len + len_len;
    let packet_len = msg_encrypted_len + mac_len;

    fill_buffer_target(from, message_len)?;
    if from.read_buffer.is_empty() {
        return Ok(());
    }

    debug!("encrypt from:{}", from.token.0);

    let data_len = message_len.min(from.read_buffer.len());
    let input = &from.read_buffer[..data_len];
    let mut packet = [0u8; 1060];

    (&mut packet[..data_len]).copy_from_slice(input);
    BE::write_u32(&mut packet[message_len..], u32(data_len).expect("<1024"));

    BE::write_u64(&mut packet[msg_encrypted_len..], *packet_number);
    aes_ctr(enc, &mut packet[..msg_encrypted_len], packet_number);

    let data_to_mac = &packet[..msg_encrypted_len + 8];
    let hash = crypto::mac(mac, data_to_mac);
    (&mut packet[msg_encrypted_len..]).copy_from_slice(&hash);

    to.write_buffer.extend_from_slice(&packet);
    from.read_buffer.drain(..data_len);

    debug!("encrypt-done from:{} len:{}", from.token.0, data_len);

    Ok(())
}

fn decrypt_stream(
    (enc, mac): &(Bits256, Bits256),
    from: &mut Stream,
    to: &mut Stream,
    packet_number: &mut u64,
) -> Result<(), Error> {
    let message_len = 1024;
    let len_len = 4;
    let mac_len = 32;
    let msg_encrypted_len = message_len + len_len;
    let packet_len = msg_encrypted_len + mac_len;

    fill_buffer_target(from, packet_len)?;
    if from.read_buffer.len() < packet_len {
        return Ok(());
    }

    debug!("decrypt from:{}", from.token.0);

    let packet = &mut from.read_buffer[..packet_len];

    //    msg_padded: [ message ] [ padded up to 1024 bytes ] [ length: 4 bytes ]
    // msg_encrypted: encrypt(msg_padded)
    //       payload: [ msg_encrypted ] [ mac([ msg_encrypted ] [ packet number: 8 bytes ]):

    // copy the mac out of the read buffer
    let mut mac_actual = Bits256::default();
    assert_eq!(mac_actual.len(), mac_len);
    mac_actual.copy_from_slice(&packet[msg_encrypted_len..]);

    // write the packet number into the read_buffer, overwriting part of the mac
    BE::write_u64(&mut packet[msg_encrypted_len..], *packet_number);

    let data_to_mac = &packet[..msg_encrypted_len + 8];
    use subtle::ConstantTimeEq;
    ensure!(
        1 == crypto::mac(mac, &data_to_mac)
            .ct_eq(&mac_actual)
            .unwrap_u8(),
        "packet mac bad"
    );

    aes_ctr(enc, &mut packet[..msg_encrypted_len], packet_number);

    let actual_len = usize(BE::read_u32(&packet[message_len..]));
    ensure!(actual_len != 0 && actual_len <= 1024, "invalid len");
    ensure!(
        packet[actual_len..message_len].iter().all(|&x| 0 == x),
        "invalid padding"
    );

    let msg = &packet[..actual_len];
    to.write_buffer.extend_from_slice(msg);

    from.read_buffer.drain(..packet_len);

    Ok(())
}

fn aes_ctr(enc: &Bits256, data: &mut [u8], packet_number: &mut u64) {
    let mut nonce = [0u8; 16];
    BE::write_u64(&mut nonce[..8], *packet_number);
    *packet_number += 1;

    let mut cipher = Aes256Ctr::new_var(&enc[..], &nonce).expect("length from arrays");
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
        let mut buf = [0u8; 4096];
        let len = match sock.read(&mut buf).map_non_block()? {
            Some(len) => len,
            None => break,
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

    while let Some(len) = sock.write(buf).map_non_block()? {
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

fn load_key(from: &str) -> Result<Bits256, Error> {
    use digest::Digest as _;
    use digest::FixedOutput as _;

    let mut ctx = sha2::Sha256::new();
    let mut file = fs::File::open(from)?;
    io::copy(&mut file, &mut ctx)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&ctx.fixed_result());

    Ok(key)
}

fn two_keys(buf: &[u8]) -> (Bits256, Bits256) {
    assert_eq!(2 * 32, buf.len());

    let mut k1 = Bits256::default();
    let mut k2 = Bits256::default();
    k1.copy_from_slice(&buf[..32]);
    k2.copy_from_slice(&buf[32..]);
    (k1, k2)
}

struct Server {
    encrypt: bool,
    key: Bits256,
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

#[derive(Copy, Clone)]
enum Crypto {
    NonceSent {
        our_nonce: Bits256,
        our_x: Bits256,
    },
    NonceReceived {
        nonces: [u8; 32 * 2],
        our_x: Bits256,
        their_mac_key: Bits256,
    },
    Done {
        ours: (Bits256, Bits256),
        theirs: (Bits256, Bits256),
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
        let read = self.read_buffer.len() < 1060;
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

fn rand256() -> Result<Bits256, Error> {
    let mut ret = Bits256::default();
    getrandom(&mut ret)?;
    Ok(ret)
}

/// A helper trait to provide the map_non_block function on Results.
pub trait MapNonBlock<T> {
    /// Maps a `Result<T>` to a `Result<Option<T>>` by converting
    /// operation-would-block errors into `Ok(None)`.
    fn map_non_block(self) -> io::Result<Option<T>>;
}

impl<T> MapNonBlock<T> for io::Result<T> {
    fn map_non_block(self) -> io::Result<Option<T>> {
        use std::io::ErrorKind::WouldBlock;

        match self {
            Ok(value) => Ok(Some(value)),
            Err(err) => {
                if let WouldBlock = err.kind() {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }
}
