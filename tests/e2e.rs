use std::io;
use std::thread;

use failure::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[test]
fn stop() -> Result<(), Error> {
    let key = septid::load_key(io::Cursor::new([0u8; 32]))?;
    let (mut server, sender) = septid::start_server(&septid::StartServer {
        key,
        bind_address: vec!["127.0.68.1:6254".to_string()],
        target_address: vec!["127.0.68.1:6255".to_string()],
        encrypt: true,
    })?;

    // mostly checking this is `move + Send`, it will probably execute before the loop starts
    let handle = thread::spawn(move || {
        sender.send(septid::Command::Terminate).unwrap();
    });

    septid::tick(&mut server)?;

    handle.join().unwrap();

    Ok(())
}

#[test]
fn against_us() -> Result<(), Error> {
    let key = septid::load_key(io::Cursor::new([0u8; 32]))?;

    let (mut enc, enc_sender) = septid::start_server(&septid::StartServer {
        key: key.clone(),
        bind_address: vec!["127.0.68.1:6222".to_string()],
        target_address: vec!["127.0.68.1:6555".to_string()],
        encrypt: true,
    })?;

    let (mut dec, dec_sender) = septid::start_server(&septid::StartServer {
        key: key.clone(),
        bind_address: vec!["127.0.68.1:6555".to_string()],
        target_address: vec!["127.0.68.1:6888".to_string()],
        encrypt: false,
    })?;

    let enc = thread::spawn(move || while septid::tick(&mut enc).unwrap() {});
    let dec = thread::spawn(move || while septid::tick(&mut dec).unwrap() {});

    let target = TcpListener::bind("127.0.68.1:6888")?;
    let mut feed = TcpStream::connect("127.0.68.1:6222")?;
    feed.write_all(b"hello")?;
    let (mut socket, _us) = target.accept()?;
    let mut buf = [0u8; 5];
    socket.read_exact(&mut buf)?;

    assert_eq!(b"hello", &buf[..]);

    enc_sender.send(septid::Command::Terminate)?;
    dec_sender.send(septid::Command::Terminate)?;

    enc.join().unwrap();
    dec.join().unwrap();

    Ok(())
}
