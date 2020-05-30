use anyhow::Result;

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
#[derive(Debug, PartialEq)]
pub(crate) struct Done {
    pub(crate) decrypt: SessionCrypto,
    pub(crate) encrypt: SessionCrypto,
}

impl Kex {
    pub fn new(key: MasterKey, decrypt: bool) -> ([u8; Nonce::BYTES], Kex) {
        let our_nonce = Nonce::random();
        let our_x = XParam::random();
        Self::new_from(key, decrypt, our_nonce, our_x)
    }

    fn new_from(
        key: MasterKey,
        decrypt: bool,
        our_nonce: Nonce,
        our_x: XParam,
    ) -> ([u8; Nonce::BYTES], Kex) {
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

    pub fn step(self) -> ([u8; Y_H_LEN], NonceReceived) {
        let (response, nonces, their_dh_mac_key) = super::crypto::generate_y_reply(
            &self.key,
            &self.our_nonce,
            &Nonce(self.buf),
            self.decrypt,
            &self.our_x,
        );
        (
            response,
            NonceReceived {
                kex: self,
                nonces,
                their_dh_mac_key,
                buf: [0u8; Y_H_LEN],
            },
        )
    }
}

impl NonceReceived {
    pub(crate) fn step(self) -> Result<Done> {
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

#[test]
fn key_exchange_pair() {
    let (client_write, mut client) = Kex::new(MasterKey([1u8; 32]), false);
    let (server_write, mut server) = Kex::new(MasterKey([1u8; 32]), true);

    client.buf.copy_from_slice(&server_write);
    server.buf.copy_from_slice(&client_write);

    let (client_write, mut client) = client.step();
    let (server_write, mut server) = server.step();

    client.buf.copy_from_slice(&server_write);
    server.buf.copy_from_slice(&client_write);

    let client = client.step().unwrap();
    let server = server.step().unwrap();

    assert_eq!(client.encrypt, server.decrypt);
    assert_eq!(client.decrypt, server.encrypt);
}

#[test]
fn key_exchange_static() {
    let our_nonce = [1u8; 32];
    let (to_write, mut kex) = Kex::new_from(
        MasterKey([2u8; 32]),
        true,
        Nonce(our_nonce),
        XParam([3u8; 32]),
    );
    assert_eq!(to_write, our_nonce);
    kex.buf.copy_from_slice(&[4u8; 32]);
    let (to_write, _) = kex.step();
    assert_eq!(
        &to_write[..],
        &[
            157, 241, 246, 144, 96, 229, 71, 49, 123, 104, 240, 101, 116, 253, 6, 194, 110, 71,
            204, 145, 148, 118, 63, 60, 152, 137, 110, 232, 36, 18, 197, 69, 47, 250, 234, 87, 219,
            76, 172, 124, 63, 250, 32, 11, 163, 146, 166, 58, 255, 114, 169, 72, 153, 179, 138,
            203, 29, 157, 154, 221, 43, 57, 104, 153, 71, 6, 218, 142, 104, 173, 117, 161, 196, 3,
            0, 181, 104, 27, 1, 233, 62, 153, 42, 97, 134, 19, 68, 79, 150, 185, 42, 235, 152, 73,
            93, 20, 93, 97, 246, 254, 230, 236, 106, 253, 229, 188, 128, 106, 157, 110, 243, 0,
            192, 83, 71, 118, 73, 207, 123, 65, 23, 96, 29, 9, 193, 189, 13, 96, 190, 3, 10, 110,
            119, 175, 51, 205, 68, 148, 112, 162, 141, 250, 255, 247, 254, 193, 74, 222, 110, 176,
            79, 150, 199, 224, 220, 142, 195, 4, 205, 57, 40, 122, 247, 132, 182, 180, 48, 55, 187,
            77, 215, 49, 114, 168, 36, 16, 92, 165, 112, 70, 209, 95, 73, 235, 164, 152, 144, 183,
            175, 146, 169, 167, 139, 237, 39, 95, 123, 34, 129, 236, 81, 161, 169, 149, 138, 187,
            253, 35, 42, 175, 81, 210, 63, 58, 168, 199, 130, 238, 157, 27, 185, 196, 14, 25, 238,
            5, 34, 200, 78, 255, 200, 71, 178, 111, 79, 169, 24, 102, 226, 206, 194, 175, 146, 250,
            214, 201, 144, 151, 217, 228, 106, 182, 122, 189, 194, 91, 157, 202, 54, 242, 25, 217,
            183, 148, 85, 211, 48, 13, 17, 2, 8, 146, 12, 219, 159, 174, 59, 74, 72, 30, 200, 39,
            187, 123, 217, 236, 10, 108
        ][..]
    );
}
