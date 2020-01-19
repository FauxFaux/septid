use failure::Error;

use super::BothNonces;
use super::EncKey;
use super::MacKey;
use super::MasterKey;
use super::Nonce;
use super::SessionCrypto;
use super::XParam;
use super::YParam;
use super::Y_H_LEN;

pub struct NonceSent {
    key: MasterKey,
    decrypt: bool,
    our_x: XParam,

    our_nonce: Nonce,
}

pub struct NonceReceived {
    key: MasterKey,
    decrypt: bool,
    our_x: XParam,

    nonces: BothNonces,

    their_dh_mac_key: MacKey,
}

pub struct Done {
    pub decrypt: SessionCrypto,
    pub encrypt: SessionCrypto,
}

impl NonceSent {
    pub fn new(key: MasterKey, decrypt: bool) -> ([u8; Nonce::BYTES], NonceSent) {
        let our_nonce = Nonce::random();
        let our_x = XParam::random();
        (
            our_nonce.0,
            NonceSent {
                key,
                decrypt,
                our_nonce,
                our_x,
            },
        )
    }

    pub fn step(
        self,
        other_nonce: [u8; Nonce::BYTES],
    ) -> Result<([u8; Y_H_LEN], NonceReceived), Error> {
        let (response, nonces, their_dh_mac_key) = super::crypto::generate_y_reply(
            &self.key,
            &self.our_nonce,
            &Nonce(other_nonce),
            self.decrypt,
            &self.our_x,
        )?;
        Ok((
            response,
            NonceReceived {
                key: self.key,
                our_x: self.our_x,
                decrypt: self.decrypt,
                nonces,
                their_dh_mac_key,
            },
        ))
    }
}

impl NonceReceived {
    pub fn step(self, y_h: [u8; Y_H_LEN]) -> Result<Done, Error> {
        let (client, server) = super::crypto::y_h_to_keys(
            &self.key,
            &self.their_dh_mac_key,
            &self.our_x,
            &self.nonces,
            y_h.as_ref(),
        )?;

        let (decrypt, encrypt) = super::flip_if(self.decrypt, server, client);

        Ok(Done { decrypt, encrypt })
    }
}
