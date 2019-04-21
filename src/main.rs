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
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Token;
use num_bigint::BigUint;
use ring::rand::SecureRandom;

type Bits256 = [u8; 32];
type Bits2048 = [u8; 256];

mod crypto;

fn main() -> Result<(), Error> {
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

    let mut rng = ring::rand::SystemRandom::new();
    rng.fill(&mut [0u8; 1])
        .with_context(|_| err_msg("paranoid random number warm-up"))?;

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

                    let (input, _) = source.accept()?;
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

                    let crypto = Crypto {
                        client_nonce: rand256(&mut rng)?,
                        server_nonce: rand256(&mut rng)?,
                        our_x: BigUint::from_bytes_le(&rand256(&mut rng)?),
                        setup: ConnSetup::NonceSent,
                    };

                    let mut input = Stream::new(input, in_token);
                    input.initial_registration(&poll)?;

                    let mut output = Stream::new(output, out_token);
                    output.initial_registration(&poll)?;

                    if encrypt {
                        output.write_buffer.extend_from_slice(&crypto.client_nonce);
                        flush_buffer(&mut output)?;
                    } else {
                        input.write_buffer.extend_from_slice(&crypto.server_nonce);
                        flush_buffer(&mut input)?;
                    }

                    server.clients.insert(
                        in_token,
                        Conn {
                            input,
                            output,
                            packet_number_recv: 0,
                            packet_number_send: 0,
                            crypto,
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
                    if let Some(conn) = server.clients.get_mut(&round_down(client)) {
                        duplify(key, decrypt, conn)?;
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
        match conn.crypto.setup {
            ConnSetup::NonceSent => {
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

                {
                    // TODO: wat
                    let mut other_nonce = Bits256::default();
                    other_nonce.copy_from_slice(
                        &negotiate.read_buffer.drain(..nonce_len).collect::<Vec<_>>(),
                    );

                    if server {
                        conn.crypto.client_nonce.copy_from_slice(&other_nonce);
                    } else {
                        conn.crypto.server_nonce.copy_from_slice(&other_nonce);
                    }
                }

                let mut nonces = [0u8; 32 * 2];
                nonces[..32].copy_from_slice(&conn.crypto.client_nonce);
                nonces[32..].copy_from_slice(&conn.crypto.server_nonce);

                let mut double_dk = [0u8; 32 * 2];
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&key, &nonces, 1, &mut double_dk);

                let mut dh_mac_client = Bits256::default();
                let mut dh_mac_server = Bits256::default();

                dh_mac_client.copy_from_slice(&double_dk[..32]);
                dh_mac_server.copy_from_slice(&double_dk[32..]);

                let nonce = ConnNonce {
                    dh_mac_client,
                    dh_mac_server,
                };

                let two = BigUint::from(2u8);

                // TODO: constant time
                let our_y = two.modpow(
                    &conn.crypto.our_x,
                    &BigUint::from_bytes_be(&crypto::GROUP_14_PRIME),
                );

                // TODO: pad to length
                let our_y = our_y.to_bytes_be();
                assert_eq!(256, our_y.len(), "short y");

                negotiate.write_buffer.extend_from_slice(&our_y);

                let y_mac =
                    crypto::mac(&if server { dh_mac_server } else { dh_mac_client }, &our_y);
                negotiate.write_buffer.extend_from_slice(&y_mac);

                conn.crypto.setup = ConnSetup::NonceReceived { nonce };
            }
            ConnSetup::NonceReceived { nonce } => {
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
                let expected_mac = crypto::mac(
                    &if decrypt {
                        nonce.dh_mac_client
                    } else {
                        nonce.dh_mac_server
                    },
                    &negotiate.read_buffer[..256],
                );
                use subtle::ConstantTimeEq;
                ensure!(expected_mac.ct_eq(their_mac).unwrap_u8() == 1, "bad mac");

                let their_y = BigUint::from_bytes_be(&negotiate.read_buffer[..256]);
                let prime = BigUint::from_bytes_be(&crypto::GROUP_14_PRIME);
                ensure!(their_y < prime, "bad y");

                drop(negotiate.read_buffer.drain(..256 + 32));

                let shared = their_y.modpow(&conn.crypto.our_x, &prime).to_bytes_be();
                assert_eq!(256, shared.len(), "short shared");

                let mut buf = Vec::with_capacity(32 + 32 + 256);
                buf.extend_from_slice(&conn.crypto.client_nonce);
                buf.extend_from_slice(&conn.crypto.server_nonce);
                buf.extend_from_slice(&shared);

                let mut quad_dk = [0u8; 32 * 4];
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&key, &buf, 1, &mut quad_dk);

                let server = two_keys(&quad_dk[..64]);
                let client = two_keys(&quad_dk[64..]);

                conn.crypto.setup = if decrypt {
                    ConnSetup::Done {
                        ours: server,
                        theirs: client,
                    }
                } else {
                    ConnSetup::Done {
                        ours: client,
                        theirs: server,
                    }
                }
            }
            ConnSetup::Done {
                ref ours,
                ref theirs,
            } => {
                if decrypt {
                    decrypt_stream(theirs, &mut conn.input, &mut conn.output)?;
                    encrypt_stream(ours, &mut conn.output, &mut conn.input)?;
                } else {
                    encrypt_stream(theirs, &mut conn.input, &mut conn.output)?;
                    decrypt_stream(ours, &mut conn.output, &mut conn.input)?;
                }
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
    let data_len = message_len.min(from.read_buffer.len());
    let input = &from.read_buffer[..data_len];
    let mut packet = [0u8; 1060];

    (&mut packet[..data_len]).copy_from_slice(input);
    BE::write_u32(&mut packet[message_len..], u32(data_len).expect("<1024"));

    // TODO: packet number
    let mut cipher = Aes256Ctr::new_var(&enc[..], &[0u8; 16]).expect("length from arrays");
    cipher.apply_keystream(&mut packet[..msg_encrypted_len]);
    drop(cipher);

    // TODO: packet number
    BE::write_u64(&mut packet[msg_encrypted_len..], 0);

    let data_to_mac = &packet[..msg_encrypted_len + 8];
    let hash = crypto::mac(mac, data_to_mac);
    (&mut packet[msg_encrypted_len..]).copy_from_slice(&hash);

    to.write_buffer.extend_from_slice(&packet);
    from.read_buffer.drain(..data_len);

    Ok(())
}

fn decrypt_stream(
    (enc, mac): &(Bits256, Bits256),
    from: &mut Stream,
    to: &mut Stream,
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

    let packet = &mut from.read_buffer[..packet_len];

    //    msg_padded: [ message ] [ padded up to 1024 bytes ] [ length: 4 bytes ]
    // msg_encrypted: encrypt(msg_padded)
    //       payload: [ msg_encrypted ] [ mac([ msg_encrypted ] [ packet number: 8 bytes ]):

    // copy the mac out of the read buffer
    let mut mac_actual = Bits256::default();
    assert_eq!(mac_actual.len(), mac_len);
    mac_actual.copy_from_slice(&packet[msg_encrypted_len..]);

    // write the packet number into the read_buffer, overwriting part of the mac
    // TODO: packet number
    BE::write_u64(&mut packet[msg_encrypted_len..], 0);

    let data_to_mac = &packet[..msg_encrypted_len + 8];
    use subtle::ConstantTimeEq;
    ensure!(
        1 == crypto::mac(mac, &data_to_mac)
            .ct_eq(&mac_actual)
            .unwrap_u8(),
        "packet mac bad"
    );

    // TODO: packet number
    let mut cipher = Aes256Ctr::new_var(&enc[..], &[0u8; 16]).expect("length from arrays");
    cipher.apply_keystream(&mut packet[..msg_encrypted_len]);
    drop(cipher);

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

fn fill_buffer_target(stream: &mut Stream, target: usize) -> Result<(), Error> {
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
            // TODO: do we need to handle EOF here?
            break;
        }
        read_buffer.extend_from_slice(buf);
    }

    Ok(())
}

fn flush_buffer(stream: &mut Stream) -> Result<(), Error> {
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
    packet_number_recv: u64,
    packet_number_send: u64,
    crypto: Crypto,
}

struct Stream {
    inner: TcpStream,
    token: mio::Token,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
}

#[derive(Copy, Clone)]
struct ConnNonce {
    dh_mac_client: Bits256,
    dh_mac_server: Bits256,
}

#[derive(Copy, Clone)]
enum ConnSetup {
    NonceSent,
    NonceReceived {
        nonce: ConnNonce,
    },
    Done {
        ours: (Bits256, Bits256),
        theirs: (Bits256, Bits256),
    },
}

#[derive(Clone)]
struct Crypto {
    client_nonce: Bits256,
    server_nonce: Bits256,
    our_x: BigUint,
    setup: ConnSetup,
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

    fn initial_registration(&self, poll: &mio::Poll) -> Result<(), io::Error> {
        poll.register(
            &self.inner,
            self.token,
            mio::Ready::readable(),
            mio::PollOpt::edge(),
        )
    }
}

fn rand256(rng: &mut ring::rand::SystemRandom) -> Result<Bits256, Error> {
    let mut ret = Bits256::default();
    rng.fill(&mut ret)?;
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
