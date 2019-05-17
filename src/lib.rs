use std::collections::HashMap;
use std::net;
use std::net::ToSocketAddrs;

use failure::err_msg;
use failure::Error;
use log::debug;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Token;
use mio_extras::channel as mio_channel;

mod crypto;
mod named_array;
mod packet;
mod stream;

pub use crypto::load_key;

named_array!(MasterKey, 256);

named_array!(Nonce, 256);
named_array!(BothNonces, 2 * Nonce::BITS);
named_array!(XParam, 256);
named_array!(YParam, 2048);

named_array!(EncKey, 256);
named_array!(MacKey, 256);

pub const Y_H_LEN: usize = YParam::BYTES + packet::PACKET_MAC_LEN;

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

const COMMANDS: Token = Token(1);

pub fn start_server(
    config: &StartServer,
) -> Result<(Server, mio_channel::SyncSender<Command>), Error> {
    let mut start_token = 2;

    let mut sources = HashMap::with_capacity(8);

    for source in &config.bind_address {
        for source in source.to_socket_addrs()? {
            sources.insert(Token(start_token), TcpListener::bind(&source)?);
            start_token += 1;
        }
    }

    if start_token % 2 == 1 {
        start_token += 1;
    }

    let mut target_addrs = Vec::with_capacity(config.target_address.len() * 2);
    for target in &config.target_address {
        target_addrs.extend(target.to_socket_addrs()?);
    }

    let mut target_addrs = target_addrs.into_iter().cycle();

    target_addrs
        .next()
        .ok_or_else(|| err_msg("no resolution"))?;

    let (command_send, command_recv) = mio_extras::channel::sync_channel::<Command>(1);

    let server = Server {
        key: config.key.clone(),
        encrypt: config.encrypt,
        clients: HashMap::with_capacity(100),
        sources,
        next_token: start_token,
        target_addrs,
        command_recv,
        poll: mio::Poll::new()?,
        events: mio::Events::with_capacity(32),
    };

    server.poll.register(
        &server.command_recv,
        COMMANDS,
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )?;

    for (token, socket) in &server.sources {
        server
            .poll
            .register(socket, *token, mio::Ready::readable(), mio::PollOpt::edge())?;
    }

    Ok((server, command_send))
}

pub fn tick(server: &mut Server) -> Result<bool, Error> {
    server.poll.poll(&mut server.events, None)?;
    for event in server.events.iter().collect::<Vec<_>>() {
        let token = event.token();

        if let Some(conn) = server.clients.get_mut(&round_down(token)) {
            handle_client(&server.key, !server.encrypt, conn, &server.poll)?;
        } else if COMMANDS == token {
            while let Ok(command) = server.command_recv.try_recv() {
                match command {
                    Command::NoNewConnections => server.sources.clear(),
                    Command::Terminate => return Ok(false),
                }
            }
        } else if let Some(source) = server.sources.get_mut(&token) {
            if !event.readiness().is_readable() {
                continue;
            }

            let (accepted, from) = source.accept()?;

            let (token, conn) = handle_accept(
                accepted,
                &server.target_addrs.next().expect("non-empty cycle"),
                server.token_pair(),
                &server.poll,
                server.encrypt,
            )?;

            debug!("connection enc:{} addr:{}", token.0, from);

            server.clients.insert(token, conn);
        } else {
            debug!("unexpected-event token:{}", token.0);
        }
    }

    Ok(true)
}

fn handle_accept(
    accepted: TcpStream,
    target_addr: &net::SocketAddr,
    (encrypted_token, plain_token): (Token, Token),
    poll: &mio::Poll,
    encrypt: bool,
) -> Result<(Token, Conn), Error> {
    let initiated = TcpStream::connect(&target_addr)?;

    let (plain, encrypted) = flip_if(encrypt, initiated, accepted);

    let mut encrypted = stream::Stream::new(encrypted, encrypted_token);
    encrypted.initial_registration(poll)?;

    let mut plain = stream::Stream::new(plain, plain_token);
    plain.initial_registration(poll)?;

    let our_nonce = Nonce::random()?;
    let our_x = XParam::random()?;
    encrypted.write_all(&our_nonce.0)?;

    encrypted.reregister(poll)?;

    Ok((
        encrypted_token,
        Conn {
            encrypted,
            plain,
            crypto: Crypto::NonceSent { our_nonce, our_x },
        },
    ))
}

fn flip_if<T>(flip: bool, left: T, right: T) -> (T, T) {
    if flip {
        (right, left)
    } else {
        (left, right)
    }
}

/// 2 -> 2, 3 -> 2, 4 -> 4, 5 -> 4
fn round_down(value: Token) -> Token {
    Token(value.0 & !1)
}

fn handle_client(
    key: &MasterKey,
    decrypt: bool,
    conn: &mut Conn,
    poll: &mio::Poll,
) -> Result<(), Error> {
    match &mut conn.crypto {
        Crypto::NonceSent { our_nonce, our_x } => {
            let other_nonce = match conn.encrypted.read_exact(Nonce::BYTES)? {
                Some(nonce) => Nonce::from_slice(nonce.as_ref()),
                None => return Ok(()),
            };

            let (response, nonces, their_dh_mac_key) =
                crypto::generate_y_reply(key, our_nonce, &other_nonce, decrypt, our_x)?;

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

            let (client, server) =
                crypto::y_h_to_keys(key, their_dh_mac_key, our_x, nonces, y_h.as_ref())?;

            // BORROW CHECKER
            drop(y_h);

            conn.encrypted.reregister(&poll)?;
            conn.plain.reregister(&poll)?;

            let (decrypt, encrypt) = flip_if(decrypt, server, client);

            conn.crypto = Crypto::Done { decrypt, encrypt };
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

pub struct Server {
    key: MasterKey,
    encrypt: bool,
    sources: HashMap<Token, TcpListener>,
    clients: HashMap<Token, Conn>,
    next_token: usize,
    target_addrs: std::iter::Cycle<std::vec::IntoIter<std::net::SocketAddr>>,
    command_recv: mio_channel::Receiver<Command>,
    poll: mio::Poll,
    events: mio::Events,
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
