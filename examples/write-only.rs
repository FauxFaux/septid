use std::env;
use std::fs;
use std::io;
use std::net::TcpStream;

use anyhow::format_err;
use anyhow::Error;
use anyhow::Context as _;

fn main() -> Result<(), Error> {
    let usage = "path-to-keyfile destination-address:port";

    let key = env::args_os().nth(1).expect(usage);
    let key =
        fs::File::open(&key).with_context(|| format_err!("opening input key file: {:?}", key))?;
    let key = septid::MasterKey::from_reader(key)?;

    let dest = env::args().nth(2).expect(usage);
    let dest = TcpStream::connect(&dest)
        .with_context(|| format_err!("connecting to destinaton: {:?}", dest))?;

    let mut pipe = septid::SPipe::negotiate(key, dest)?;

    io::copy(&mut io::stdin().lock(), &mut pipe)?;

    Ok(())
}
