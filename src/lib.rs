mod crypto;
mod kex;
mod named_array;
mod packet;
mod send;
#[cfg(feature = "server")]
pub mod server;

pub use crypto::load_key;
pub use send::SPipe;

named_array!(MasterKey, 256);

named_array!(Nonce, 256);
named_array!(BothNonces, 2 * Nonce::BITS);
named_array!(XParam, 256);
named_array!(YParam, 2048);

named_array!(EncKey, 256);
named_array!(MacKey, 256);

pub const Y_H_LEN: usize = YParam::BYTES + packet::PACKET_MAC_LEN;

fn flip_if<T>(flip: bool, left: T, right: T) -> (T, T) {
    if flip {
        (right, left)
    } else {
        (left, right)
    }
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
