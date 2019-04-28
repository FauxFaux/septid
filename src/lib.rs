// efficiency, could copy instead
#![feature(vec_drain_as_slice)]

use std::collections::HashMap;

use failure::err_msg;
use failure::Error;
use log::debug;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Token;
use mio_extras::channel as mio_channel;

mod crypto;
mod named_array;
mod stream;

pub use crypto::load_key;

named_array!(MasterKey, 256);

named_array!(Nonce, 256);
named_array!(BothNonces, 2 * Nonce::BITS);
named_array!(XParam, 256);
named_array!(YParam, 2048);

named_array!(EncKey, 256);
named_array!(MacKey, 256);

pub const Y_H_LEN: usize = YParam::BYTES + stream::PACKET_MAC_LEN;

pub struct StartServer {
    pub key: MasterKey,
    pub bind_address: Vec<String>,
    pub target_address: Vec<String>,
    pub encrypt: bool,
}

pub enum Command {
    NoNewConnections,
    Terminate,
}

pub fn start_server(config: &StartServer) -> Result<(), Error> {
    // TODO: [0]
    let source = mio::net::TcpListener::bind(&config.bind_address[0].parse()?)?;

    let mut target_addrs = {
        use std::net::ToSocketAddrs;
        // TODO: [0]
        config.target_address[0].to_socket_addrs()?.cycle()
    };

    target_addrs
        .next()
        .ok_or_else(|| err_msg("no resolution"))?;

    let (command_send, command_recv) = mio_extras::channel::sync_channel::<Command>(1);

    let mut server = Server {
        key: config.key.clone(),
        encrypt: config.encrypt,
        clients: HashMap::with_capacity(100),
        source: Some(source),
        next_token: 10,
        target_addrs,
        command_recv,
    };

    const COMMANDS: Token = Token(1);
    const SERVER: Token = Token(2);

    let poll = mio::Poll::new()?;
    poll.register(
        &server.command_recv,
        COMMANDS,
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )?;

    poll.register(
        server.source.as_ref().unwrap(),
        SERVER,
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )?;

    let mut events = mio::Events::with_capacity(32);
    'app: loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            match event.token() {
                COMMANDS => {
                    while let Ok(command) = server.command_recv.try_recv() {
                        match command {
                            Command::NoNewConnections => drop(server.source.take()),
                            Command::Terminate => break 'app,
                        }
                    }
                }
                SERVER => {
                    if !event.readiness().is_readable() {
                        continue;
                    }

                    let source = match server.source.as_ref() {
                        Some(listener) => listener,
                        None => continue,
                    };

                    let (accepted, from) = source.accept()?;

                    let initiated =
                        TcpStream::connect(&server.target_addrs.next().expect("non-empty cycle"))?;

                    let (plain, encrypted) = if server.encrypt {
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

                    let our_nonce = Nonce::random()?;
                    let our_x = XParam::random()?;
                    encrypted.write_all(&our_nonce.0)?;

                    encrypted.reregister(&poll)?;
                    plain.reregister(&poll)?;

                    server.clients.insert(
                        encrypted_token,
                        Conn {
                            encrypted,
                            plain,
                            crypto: Crypto::NonceSent { our_nonce, our_x },
                        },
                    );
                }
                client => {
                    debug!("event client:{}", client.0);
                    if let Some(conn) = server.clients.get_mut(&round_down(client)) {
                        duplify(&server.key, !server.encrypt, conn, &poll)?;
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

fn duplify(key: &MasterKey, decrypt: bool, conn: &mut Conn, poll: &mio::Poll) -> Result<(), Error> {
    match &mut conn.crypto {
        Crypto::NonceSent { our_nonce, our_x } => {
            let other_nonce = match conn.encrypted.read_exact(Nonce::BYTES)? {
                Some(nonce) => Nonce::from_slice(&nonce),
                None => return Ok(()),
            };

            let (response, nonces, their_dh_mac_key) =
                crypto::generate_y_reply(key, &other_nonce, decrypt, our_nonce, our_x)?;

            conn.encrypted.write_all(&response)?;
            conn.encrypted.reregister(&poll)?;

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
                None => return Ok(()),
            };

            let (client, server) = crypto::y_h_to_keys(key, their_dh_mac_key, our_x, nonces, &y_h)?;

            // BORROW CHECKER
            drop(y_h);

            conn.encrypted.reregister(&poll)?;
            conn.plain.reregister(&poll)?;

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
            while stream::decrypt_packet(decrypt, &mut conn.encrypted, &mut conn.plain)? {}
            while stream::encrypt_packet(encrypt, &mut conn.plain, &mut conn.encrypted)? {}
            conn.encrypted.reregister(&poll)?;
            conn.plain.reregister(&poll)?;
        }
    };

    Ok(())
}

struct Server {
    key: MasterKey,
    encrypt: bool,
    source: Option<TcpListener>,
    clients: HashMap<Token, Conn>,
    next_token: usize,
    target_addrs: std::iter::Cycle<std::vec::IntoIter<std::net::SocketAddr>>,
    command_recv: mio_channel::Receiver<Command>,
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
    crypto: Crypto,
}

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
        decrypt: SessionCrypto,
        encrypt: SessionCrypto,
    },
}

pub struct SessionCrypto {
    enc: EncKey,
    mac: MacKey,
    packet_number: u64,
}

impl MacKey {
    fn begin(&self) -> hmac::Hmac<sha2::Sha256> {
        use crypto_mac::Mac;
        hmac::Hmac::<sha2::Sha256>::new_varkey(&self.0).expect("all keys are valid for hmac")
    }
}
