use std::env;
use std::fs;
use std::io;
use std::net::TcpStream;

use failure::format_err;
use failure::Error;
use failure::ResultExt;

fn main() -> Result<(), Error> {
    let usage = "path-to-keyfile destination-address:port";
    let key_path = env::args_os().nth(1).expect(usage);
    let key = septid::load_key(
        fs::File::open(&key_path).with_context(|_| format_err!("opening {:?}", key_path))?,
    )?;
    let dest = env::args().nth(2).expect(usage);
    let dest =
        TcpStream::connect(&dest).with_context(|_| format_err!("connecting to {:?}", dest))?;
    let mut pipe = septid::SPipe::negotiate(key, dest)?;

    io::copy(&mut io::stdin().lock(), &mut pipe)?;

    Ok(())
}
