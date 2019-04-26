use std::env;
use std::fs;

use failure::err_msg;
use failure::format_err;
use failure::ResultExt;
use getrandom::getrandom;

fn main() -> Result<(), failure::Error> {
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

    let addr = matches.opt_get::<String>("s")?.expect("opt required");

    let target = matches.opt_get("t")?.expect("opt required");

    let key_path: String = matches.opt_get("k")?.expect("opt required");

    assert!(!matches.opt_present("u"), "-u unsupported");

    let key = {
        let file = fs::File::open(&key_path)
            .with_context(|_| format_err!("opening key {:?}", key_path))?;
        septid::load_key(file)?
    };

    getrandom(&mut [0u8; 1]).with_context(|_| err_msg("warming up random numbers"))?;

    septid::start_server(&septid::StartServer {
        bind_address: vec![addr],
        encrypt,
        key,
        target_address: vec![target],
    })
}
