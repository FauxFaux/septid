use std::io;

use crypto_mac::Mac;
use failure::ensure;
use failure::Error;
use hmac::Hmac;
use num_bigint::BigUint;
use sha2::Sha256;
use subtle::Choice;
use subtle::ConstantTimeEq;

use super::named_array;
use super::BothNonces;
use super::EncKey;
use super::MacKey;
use super::MasterKey;
use super::Nonce;
use super::XParam;
use super::YParam;
use super::Y_H_LEN;
use crate::SessionCrypto;

// TODO: maybe don't use the macro, so we don't pay the drop cost
named_array!(MacResult, 256);

impl ConstantTimeEq for MacResult {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl MacResult {
    /// Prefer `ct_eq`
    pub fn code(&self) -> &[u8] {
        &self.0
    }
}

pub fn mac(key: &super::MacKey, data: &[u8]) -> MacResult {
    let mut hmac = Hmac::<Sha256>::new_varkey(&key.0).expect("all keys are valid for hmac");
    hmac.input(data);
    MacResult::from_slice(&hmac.result().code())
}

pub fn generate_y_reply(
    key: &MasterKey,
    other_nonce: &Nonce,
    decrypt: bool,
    our_nonce: &Nonce,
    our_x: &XParam,
) -> Result<([u8; Y_H_LEN], BothNonces, MacKey), Error> {
    let (client_nonce, server_nonce) = if decrypt {
        (other_nonce, our_nonce)
    } else {
        (our_nonce, other_nonce)
    };

    let mut nonces = [0u8; BothNonces::BYTES];
    nonces[..32].copy_from_slice(&client_nonce.0);
    nonces[32..].copy_from_slice(&server_nonce.0);
    let nonces = BothNonces(nonces);

    let mut double_dk = [0u8; 32 * 2];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&key.0, &nonces.0, 1, &mut double_dk);

    let dh_mac_client = MacKey::from_slice(&double_dk[..32]);
    let dh_mac_server = MacKey::from_slice(&double_dk[32..]);

    let two = BigUint::from(2u8);

    // TODO: constant time
    let our_y = two.modpow(
        &BigUint::from_bytes_be(&our_x.0),
        &BigUint::from_bytes_be(&GROUP_14_PRIME.0),
    );

    // TODO: pad to length
    let our_y = our_y.to_bytes_be();
    assert_eq!(YParam::BYTES, our_y.len(), "short y");

    let y_mac = mac(
        if decrypt {
            &dh_mac_server
        } else {
            &dh_mac_client
        },
        &our_y,
    );

    let mut response = [0u8; Y_H_LEN];

    response[..YParam::BYTES].copy_from_slice(&our_y);
    response[YParam::BYTES..].copy_from_slice(&y_mac.code());

    let their_dh_mac_key = if decrypt {
        dh_mac_client
    } else {
        dh_mac_server
    };

    Ok((response, nonces, their_dh_mac_key))
}

pub fn y_h_to_keys(
    key: &MasterKey,
    their_dh_mac_key: &MacKey,
    our_x: &XParam,
    nonces: &BothNonces,
    y_h: &[u8],
) -> Result<(SessionCrypto, SessionCrypto), Error> {
    let (their_y, their_mac) = y_h.split_at(YParam::BYTES);

    let their_mac = MacResult::from_slice(their_mac);

    let expected_mac = mac(&their_dh_mac_key, their_y);
    ensure!(expected_mac.ct_eq(&their_mac).unwrap_u8() == 1, "bad mac");

    let their_y = BigUint::from_bytes_be(their_y);
    let prime = BigUint::from_bytes_be(&GROUP_14_PRIME.0);
    ensure!(their_y < prime, "bad y");

    let shared = their_y
        .modpow(&BigUint::from_bytes_be(&our_x.0), &prime)
        .to_bytes_be();
    assert_eq!(256, shared.len(), "short shared");

    let mut buf = Vec::with_capacity(32 + 32 + 256);
    buf.extend_from_slice(&nonces.0);
    buf.extend_from_slice(&shared);

    let mut quad_dk = [0u8; EncKey::BYTES * 2 + MacKey::BYTES * 2];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&key.0, &buf, 1, &mut quad_dk);

    let client = two_keys(&quad_dk[64..]);
    let server = two_keys(&quad_dk[..64]);

    Ok((client, server))
}

pub fn load_key<R: io::Read>(mut from: R) -> Result<MasterKey, Error> {
    use digest::Digest as _;
    use digest::FixedOutput as _;

    let mut ctx = sha2::Sha256::new();
    io::copy(&mut from, &mut ctx)?;

    Ok(MasterKey::from_slice(&ctx.fixed_result()))
}

fn two_keys(buf: &[u8]) -> SessionCrypto {
    SessionCrypto {
        enc: EncKey::from_slice(&buf[..EncKey::BYTES]),
        mac: MacKey::from_slice(&buf[EncKey::BYTES..]),
        packet_number: 0,
    }
}

/// rfc3526 2048
const GROUP_14_PRIME: super::YParam = super::YParam([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
]);
