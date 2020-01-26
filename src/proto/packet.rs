use std::convert::TryFrom;

use super::crypto;
use super::SessionCrypto;

pub const PACKET_MAX_MESSAGE_LEN: usize = 1024;
const PACKET_MESSAGE_LEN_LEN: usize = 4; // u32
const PACKET_MESSAGE_ENCRYPTED_LEN: usize = PACKET_MAX_MESSAGE_LEN + PACKET_MESSAGE_LEN_LEN;
pub const PACKET_MAC_LEN: usize = 256 / 8; // 32
pub const PACKET_LEN: usize = PACKET_MESSAGE_ENCRYPTED_LEN + PACKET_MAC_LEN;

pub(crate) fn enpacket(crypto: &mut SessionCrypto, input: &[u8]) -> [u8; PACKET_LEN] {
    assert!(input.len() <= PACKET_MAX_MESSAGE_LEN);

    let mut packet = [0u8; PACKET_LEN];

    (&mut packet[..input.len()]).copy_from_slice(input);
    let input_len = u32::try_from(input.len()).expect("<=1024");
    packet[PACKET_MAX_MESSAGE_LEN..PACKET_MESSAGE_ENCRYPTED_LEN]
        .copy_from_slice(&input_len.to_be_bytes());

    let packet_number = crypto::aes_ctr(crypto, &mut packet[..PACKET_MESSAGE_ENCRYPTED_LEN]);

    let mac = {
        use crypto_mac::Mac;
        let mut computer = crypto.mac.begin();
        computer.input(&packet[..PACKET_MESSAGE_ENCRYPTED_LEN]);
        computer.input(&packet_number.to_be_bytes());
        computer.result().code()
    };

    (&mut packet[PACKET_MESSAGE_ENCRYPTED_LEN..]).copy_from_slice(&mac);

    packet
}

pub(crate) fn unpacket<'s, 'p>(
    crypto: &'s mut SessionCrypto,
    packet: &'p mut [u8],
) -> Result<&'p [u8], &'static str> {
    use std::convert::TryInto as _;

    assert_eq!(packet.len(), PACKET_LEN);

    //    msg_padded: [ message ] [ padded up to 1024 bytes ] [ length: 4 bytes ]
    // msg_encrypted: encrypt(msg_padded)
    //       payload: [ msg_encrypted ] [ mac([ msg_encrypted ] [ packet number: 8 bytes ]):
    // copy the mac out of the read buffer
    let (msg_encrypted, mac_actual) = packet.as_mut().split_at_mut(PACKET_MESSAGE_ENCRYPTED_LEN);

    let mac_expected = {
        use crypto_mac::Mac;
        let mut computer = crypto.mac.begin();
        computer.input(msg_encrypted);
        computer.input(&crypto.packet_number.to_be_bytes());
        computer.result().code()
    };

    use subtle::ConstantTimeEq as _;
    if 1 != mac_expected.ct_eq(&mac_actual).unwrap_u8() {
        return Err("packet mac bad");
    }

    crypto::aes_ctr(crypto, msg_encrypted);

    let actual_len = u32::from_be_bytes(
        msg_encrypted[PACKET_MAX_MESSAGE_LEN..]
            .try_into()
            .expect("fixed size slice"),
    );

    if actual_len == 0 || actual_len > (PACKET_MAX_MESSAGE_LEN as u32) {
        return Err("invalid len");
    }

    let actual_len = usize::try_from(actual_len).expect("<=1024");

    if !msg_encrypted[actual_len..PACKET_MAX_MESSAGE_LEN]
        .iter()
        .all(|&x| 0 == x)
    {
        return Err("invalid padding");
    }

    Ok(&msg_encrypted[..actual_len])
}
