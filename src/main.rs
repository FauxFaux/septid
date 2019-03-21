use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::mem;

use failure::err_msg;
use failure::Error;
use mio::tcp::{TcpListener, TcpStream};
use mio::Token;
use std::io::Write;

type Key = [u8; 32];

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

                    let output = mio::net::TcpStream::connect(&addr)?;

                    let in_token = Token(next_token);
                    next_token.checked_add(1).unwrap();
                    let out_token = Token(next_token);
                    next_token.checked_add(1).unwrap();

                    poll.register(
                        &input,
                        in_token,
                        mio::Ready::readable(),
                        mio::PollOpt::edge(),
                    )?;

                    poll.register(
                        &output,
                        out_token,
                        mio::Ready::writable(),
                        mio::PollOpt::edge(),
                    )?;

                    server.clients.insert(
                        in_token,
                        Conn {
                            input,
                            output,
                            to_input: Vec::new(),
                            to_output: Vec::new(),
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

    flush_buffer(&mut conn.input, &mut conn.to_input)?;
    flush_buffer(&mut conn.output, &mut conn.to_output)?;

    let mut buf = [0u8; 4096];

    while let Some(input) = conn.input.read(&mut buf).map_non_block()? {
        if 0 == input {
            unimplemented!("eof");
        }

        let buf = &buf[..input];

        // TODO: mutate the buf slice again?
        let mut idx = 0;

        while let Some(written) = conn.output.write(&buf[idx..]).map_non_block()? {
            if 0 == written {
                unimplemented!("eof");
            }

            idx += written;

            if buf.len() == idx {
                break;
            }
        }

        if buf.len() == idx {
            continue;
        }

        let buf = &buf[idx..];

        conn.to_output.extend_from_slice(buf);
        break;
    }

    Ok(())
}

fn flush_buffer(sock: &mut TcpStream, buf: &mut Vec<u8>) -> Result<(), Error> {
    if buf.is_empty() {
        return Ok(());
    }

    use std::io::Write;

    while let Some(len) = sock.write(buf).map_non_block()? {
        buf.drain(..len);
    }

    Ok(())
}

fn load_key(from: &str) -> Result<Key, Error> {
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
    key: Key,
    source: Option<TcpListener>,
    target: String,
    clients: HashMap<Token, Conn>,
}

struct Conn {
    input: TcpStream,
    output: TcpStream,
    to_output: Vec<u8>,
    to_input: Vec<u8>,
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
