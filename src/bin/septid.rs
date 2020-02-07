use std::env;
use std::fs;

use failure::format_err;
use failure::ResultExt;
use septid::server::Command;

fn main() -> Result<(), failure::Error> {
    async_std::task::block_on(run())
}

async fn run() -> Result<(), failure::Error> {
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
            eprintln!("error: {}", f);
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
        septid::MasterKey::from_reader(file)?
    };

    let command = septid::server::start_server(&septid::server::StartServer {
        bind_address: vec![addr],
        encrypt,
        key,
        target_address: vec![target],
    })
    .await?;

    //    let command = Cell::new(Some(command));
    //
    //    ctrlc::set_handler(move || {
    //        if let Some(mut command) = command.take() {
    //            unimplemented!();
    ////            command.request_shutdown()
    ////                .expect("we're the only sender; maybe the server is already gone?");
    //        }
    //    })?;

    command.run_to_completion().await?;

    Ok(())
}
