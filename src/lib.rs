mod crypto;
mod kex;
mod named_array;
mod packet;
mod send;
#[cfg(feature = "server")]
pub mod server;

pub use crypto::MasterKey;
pub use send::SPipe;

fn flip_if<T>(flip: bool, left: T, right: T) -> (T, T) {
    if flip {
        (right, left)
    } else {
        (left, right)
    }
}

struct SessionCrypto {
    enc: crypto::EncKey,
    mac: crypto::MacKey,
    packet_number: u64,
}
