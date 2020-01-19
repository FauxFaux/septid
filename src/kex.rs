use failure::Error;

use super::crypto::BothNonces;
use super::crypto::MacKey;
use super::crypto::MasterKey;
use super::crypto::Nonce;
use super::crypto::XParam;
use super::crypto::Y_H_LEN;
use super::SessionCrypto;

pub struct Kex {
    key: MasterKey,
    decrypt: bool,
    our_x: XParam,

    our_nonce: Nonce,

    pub buf: [u8; Nonce::BYTES],
}

pub struct NonceReceived {
    kex: Kex,

    nonces: BothNonces,
    their_dh_mac_key: MacKey,

    pub buf: [u8; Y_H_LEN],
}

#[allow(dead_code)]
pub(crate) struct Done {
    pub(crate) decrypt: SessionCrypto,
    pub(crate) encrypt: SessionCrypto,
}

impl Kex {
    pub fn new(key: MasterKey, decrypt: bool) -> ([u8; Nonce::BYTES], Kex) {
        let our_nonce = Nonce::random();
        let our_x = XParam::random();
        (
            our_nonce.0,
            Kex {
                key,
                decrypt,
                our_nonce,
                our_x,
                buf: [0u8; Nonce::BYTES],
            },
        )
    }

    pub fn step(self) -> Result<([u8; Y_H_LEN], NonceReceived), Error> {
        let (response, nonces, their_dh_mac_key) = super::crypto::generate_y_reply(
            &self.key,
            &self.our_nonce,
            &Nonce(self.buf),
            self.decrypt,
            &self.our_x,
        )?;
        Ok((
            response,
            NonceReceived {
                kex: self,
                nonces,
                their_dh_mac_key,
                buf: [0u8; Y_H_LEN],
            },
        ))
    }
}

impl NonceReceived {
    pub(crate) fn step(self) -> Result<Done, Error> {
        let (client, server) = super::crypto::y_h_to_keys(
            &self.kex.key,
            &self.their_dh_mac_key,
            &self.kex.our_x,
            &self.nonces,
            &self.buf[..],
        )?;

        let (decrypt, encrypt) = super::flip_if(self.kex.decrypt, server, client);

        Ok(Done { decrypt, encrypt })
    }
}
