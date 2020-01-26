pub(crate) mod crypto;
pub(crate) mod kex;
pub(crate) mod named_array;
pub(crate) mod packet;

pub(crate) fn flip_if<T>(flip: bool, left: T, right: T) -> (T, T) {
    if flip {
        (right, left)
    } else {
        (left, right)
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct SessionCrypto {
    enc: crypto::EncKey,
    mac: crypto::MacKey,
    packet_number: u64,
}
