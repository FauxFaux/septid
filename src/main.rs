use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::mem;

use failure::err_msg;
use failure::Error;
use failure::ResultExt;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Token;
use ring::rand::SecureRandom;

type Bits256 = [u8; 32];
type Bits2048 = [u8; 256];

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
                    next_token.checked_add(1).unwrap();
                    let out_token = Token(next_token);
                    next_token.checked_add(1).unwrap();

                    let crypto = Crypto {
                        our_nonce: rand256(&mut rng)?,
                        our_x: rand256(&mut rng)?,
                        setup: ConnSetup::NonceSent,
                    };

                    let mut input = Stream::new(input, in_token);
                    input.initial_registration(&poll)?;

                    let mut output = Stream::new(output, out_token);
                    output.initial_registration(&poll)?;

                    if encrypt {
                        output.write_buffer.extend_from_slice(&crypto.our_nonce);
                        flush_buffer(&mut output)?;
                    } else {
                        input.write_buffer.extend_from_slice(&crypto.our_nonce);
                        flush_buffer(&mut input)?;
                    }

                    server.clients.insert(
                        in_token,
                        Conn {
                            input,
                            output,
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
                        duplify(conn)?;
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

fn duplify(conn: &mut Conn) -> Result<(), Error> {
    use std::io::Read;

    flush_buffer(&mut conn.input)?;
    flush_buffer(&mut conn.output)?;

    let mut buf = [0u8; 4096];

    fill_buffer_target(&mut conn.input, 5)?;

    conn.output
        .write_buffer
        .extend_from_slice(&conn.input.read_buffer);
    conn.input.read_buffer.truncate(0);

    flush_buffer(&mut conn.output)?;

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
    other_nonce: Bits256,
    dh_mac_client: Bits256,
    dh_mac_server: Bits256,
}

#[derive(Copy, Clone)]
enum ConnSetup {
    NonceSent,
    NonceReceived {
        their_nonce: ConnNonce,
    },
    YReceived {
        nonce: ConnNonce,
        their_y: Bits2048,
        their_h: Bits256,
    },
}

#[derive(Copy, Clone)]
struct Crypto {
    our_nonce: Bits256,
    our_x: Bits256,
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
