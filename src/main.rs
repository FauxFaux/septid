// efficiency, could copy instead
#![feature(vec_drain_as_slice)]

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::mem;

use failure::ensure;
use failure::err_msg;
use failure::Error;
use getrandom::getrandom;
use log::debug;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Token;
use num_bigint::BigUint;

mod crypto;
mod named_array;
mod stream;

use crypto::MacResult;

named_array!(MasterKey, 256);

named_array!(Nonce, 256);
named_array!(BothNonces, 2 * Nonce::BITS);
named_array!(XParam, 256);
named_array!(YParam, 2048);

named_array!(EncKey, 256);
named_array!(MacKey, 256);

pub const Y_H_LEN: usize = YParam::BYTES + MacResult::BYTES;

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
    let key = crypto::load_key(&key_path)?;

    assert!(!matches.opt_present("u"), "-u unsupported");

    getrandom(&mut [0u8; 1])?;

    let mut server = Server {
        encrypt,
        clients: HashMap::new(),
        source: Some(source),
        target,
        next_token: 10,
    };

    let mut addrs = {
        use std::net::ToSocketAddrs;
        server.target.to_socket_addrs()?.cycle()
    };

    addrs.next().ok_or_else(|| err_msg("no resolution"))?;

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

                    let (accepted, from) = source.accept()?;

                    let initiated = TcpStream::connect(&addrs.next().expect("non-empty cycle"))?;

                    let our_nonce = Nonce::random()?;

                    let (plain, encrypted) = if encrypt {
                        (accepted, initiated)
                    } else {
                        (initiated, accepted)
                    };

                    let (encrypted_token, plain_token) = server.token_pair();

                    let mut encrypted = stream::Stream::new(encrypted, encrypted_token);
                    encrypted.initial_registration(&poll)?;

                    let mut plain = stream::Stream::new(plain, plain_token);
                    plain.initial_registration(&poll)?;

                    debug!(
                        "connection enc:{} plain:{} addr:{}",
                        encrypted_token.0, plain_token.0, from
                    );

                    encrypted.write_all(&our_nonce.0)?;

                    encrypted.reregister(&poll)?;
                    plain.reregister(&poll)?;

                    server.clients.insert(
                        encrypted_token,
                        Conn {
                            encrypted,
                            plain,
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
                        conn.encrypted.reregister(&poll)?;
                        conn.plain.reregister(&poll)?;
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
    loop {
        match &conn.crypto {
            Crypto::NonceSent { our_nonce, our_x } => {
                let other_nonce = match conn.encrypted.read_exact(Nonce::BYTES)? {
                    Some(nonce) => Nonce::from_slice(&nonce),
                    None => break,
                };

                let (response, nonces, their_dh_mac_key) =
                    crypto::generate_y_reply(key, &other_nonce, decrypt, our_nonce, our_x)?;

                conn.encrypted.write_all(&response)?;

                conn.crypto = Crypto::NonceReceived {
                    nonces,
                    our_x: our_x.clone(),
                    their_dh_mac_key,
                };
            }
            Crypto::NonceReceived {
                nonces,
                our_x,
                their_dh_mac_key,
            } => {
                let y_h = match conn.encrypted.read_exact(Y_H_LEN)? {
                    Some(y_h) => y_h,
                    None => break,
                };

                let (client, server) =
                    crypto::y_h_to_keys(key, their_dh_mac_key, our_x, nonces, &y_h)?;

                conn.crypto = if decrypt {
                    Crypto::Done {
                        decrypt: server,
                        encrypt: client,
                    }
                } else {
                    Crypto::Done {
                        decrypt: client,
                        encrypt: server,
                    }
                }
            }
            Crypto::Done { decrypt, encrypt } => {
                stream::decrypt_stream(
                    decrypt,
                    &mut conn.encrypted,
                    &mut conn.plain,
                    &mut conn.packet_number_decrypt,
                )?;
                stream::encrypt_stream(
                    encrypt,
                    &mut conn.plain,
                    &mut conn.encrypted,
                    &mut conn.packet_number_encrypt,
                )?;
                break;
            }
        }
    }

    stream::flush_buffer(&mut conn.encrypted)?;
    stream::flush_buffer(&mut conn.plain)?;

    Ok(())
}

struct Server {
    encrypt: bool,
    source: Option<TcpListener>,
    target: String,
    clients: HashMap<Token, Conn>,
    next_token: usize,
}

impl Server {
    fn token_pair(&mut self) -> (Token, Token) {
        let left = Token(self.next_token);
        self.next_token = self.next_token.checked_add(1).unwrap();
        let right = Token(self.next_token);
        self.next_token = self.next_token.checked_add(1).unwrap();
        (left, right)
    }
}

struct Conn {
    plain: stream::Stream,
    encrypted: stream::Stream,
    packet_number_encrypt: u64,
    packet_number_decrypt: u64,
    crypto: Crypto,
}

#[derive(Clone)]
enum Crypto {
    NonceSent {
        our_nonce: Nonce,
        our_x: XParam,
    },
    NonceReceived {
        nonces: BothNonces,
        our_x: XParam,
        their_dh_mac_key: MacKey,
    },
    Done {
        decrypt: (EncKey, MacKey),
        encrypt: (EncKey, MacKey),
    },
}
