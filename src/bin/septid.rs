use std::fs;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context as _;
use anyhow::Result;
use async_std::task;
use clap::Parser;

fn main() -> Result<()> {
    pretty_env_logger::init();
    task::block_on(run())
}

// #[derive(clap::Parser)]
// enum EncDec {
//     Encrypt,
//     Decryp,
// }

#[derive(Parser)]
#[clap(author, about, version, group = clap::ArgGroup::new("mode").required(true))]
struct Opts {
    /// forward data over an encrypted connection
    #[clap(short, long, group = "mode", conflicts_with = "decrypt")]
    encrypt: bool,
    /// decrypt data from a encrypt, and forward it
    #[clap(short, long, group = "mode")]
    #[allow(dead_code)]
    decrypt: bool,
    /// key for encryption and authentication
    #[clap(short, long, value_name = "FILE")]
    key_file: PathBuf,
    /// listen for connections
    #[clap(short, long, value_name = "IP:PORT")]
    source: String,
    /// make connections to
    #[clap(short, long, value_name = "HOST:PORT")]
    target: String,
    /// drop privileges after binding
    #[clap(short, long, value_name = "USER:GROUP")]
    uid: Option<String>,
}

async fn run() -> Result<()> {
    let matches: Opts = Opts::parse();
    assert!(matches.uid.is_none(), "-u unsupported");

    let key = {
        let file = fs::File::open(&matches.key_file)
            .with_context(|| anyhow!("opening key {:?}", matches.key_file))?;
        septid::MasterKey::from_reader(file)?
    };

    let command = septid::server::start_server(&septid::server::StartServer {
        bind_address: vec![matches.source],
        encrypt: matches.encrypt,
        key,
        target_address: vec![matches.target],
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
