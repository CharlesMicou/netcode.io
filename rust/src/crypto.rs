use crate::common::*;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use std::io;

pub const NETCODE_ENCRYPT_EXTA_BYTES: usize = 16;

#[derive(Debug)]
pub enum EncryptError {
    InvalidPublicKeySize,
    BufferSizeMismatch,
    IO(io::Error),
    Failed,
}

impl From<io::Error> for EncryptError {
    fn from(err: io::Error) -> Self {
        EncryptError::IO(err)
    }
}

/// Generates a new random private key.
pub fn generate_key() -> [u8; NETCODE_KEY_BYTES] {
    let mut key: [u8; NETCODE_KEY_BYTES] = [0; NETCODE_KEY_BYTES];

    random_bytes(&mut key);

    key
}

pub fn random_bytes(out: &mut [u8]) {
    getrandom::getrandom(out).expect("Failed to read from the operating system's entropy source");
}

fn nonce_from_sequence(sequence: u64) -> Nonce {
    let mut bytes = [0; 12];
    bytes[4..].copy_from_slice(&sequence.to_le_bytes());

    Nonce::from(bytes)
}

pub fn encode(
    out: &mut [u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    nonce: u64,
    key: &[u8; NETCODE_KEY_BYTES],
) -> Result<usize, EncryptError> {
    if out.len() < data.len() + NETCODE_ENCRYPT_EXTA_BYTES {
        return Err(EncryptError::BufferSizeMismatch);
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    out[..data.len()].copy_from_slice(data);

    let tag = cipher
        .encrypt_in_place_detached(
            &nonce_from_sequence(nonce),
            additional_data.unwrap_or(&[]),
            &mut out[..data.len()],
        )
        .map_err(|_| EncryptError::Failed)?;

    out[data.len()..data.len() + NETCODE_ENCRYPT_EXTA_BYTES].copy_from_slice(&tag);

    Ok(data.len() + NETCODE_ENCRYPT_EXTA_BYTES)
}

pub fn decode(
    out: &mut [u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    nonce: u64,
    key: &[u8; NETCODE_KEY_BYTES],
) -> Result<usize, EncryptError> {
    let message_len = data
        .len()
        .checked_sub(NETCODE_ENCRYPT_EXTA_BYTES)
        .ok_or(EncryptError::BufferSizeMismatch)?;

    if out.len() < message_len {
        return Err(EncryptError::BufferSizeMismatch);
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    out[..message_len].copy_from_slice(&data[..message_len]);

    cipher
        .decrypt_in_place_detached(
            &nonce_from_sequence(nonce),
            additional_data.unwrap_or(&[]),
            &mut out[..message_len],
            Tag::from_slice(&data[message_len..]),
        )
        .map_err(|_| EncryptError::Failed)?;

    Ok(message_len)
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY: [u8; NETCODE_KEY_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const SEQUENCE: u64 = 0x0102_0304_0506_0708;
    const PLAINTEXT: &[u8] = b"netcode wire format vector";
    const ADDITIONAL_DATA: &[u8] = b"NETCODE 1.01\0additional-dat";

    // Captured from libsodium, so that swapping the implementation underneath
    // cannot silently change what goes on the wire.
    const CIPHERTEXT: [u8; PLAINTEXT.len() + NETCODE_ENCRYPT_EXTA_BYTES] = [
        0x9e, 0x2c, 0xd9, 0x87, 0xc4, 0x5d, 0x8f, 0x38, 0x13, 0xc2, 0x58, 0xa9, 0x53, 0x1e, 0x0e,
        0xca, 0x8d, 0x67, 0x86, 0xe4, 0xfe, 0x21, 0x26, 0xea, 0x38, 0x47, 0x6d, 0x91, 0x4d, 0xaa,
        0xce, 0x44, 0x81, 0x82, 0xfb, 0x7a, 0x50, 0x99, 0xc7, 0x1e, 0x06, 0xc0,
    ];

    #[test]
    fn encodes_a_known_vector() {
        let mut out = [0; CIPHERTEXT.len()];
        let written = encode(
            &mut out,
            PLAINTEXT,
            Some(ADDITIONAL_DATA),
            SEQUENCE,
            &KEY,
        )
        .unwrap();

        assert_eq!(written, CIPHERTEXT.len());
        assert_eq!(out, CIPHERTEXT);
    }

    #[test]
    fn decodes_a_known_vector() {
        let mut decoded = [0; PLAINTEXT.len()];
        let read = decode(
            &mut decoded,
            &CIPHERTEXT,
            Some(ADDITIONAL_DATA),
            SEQUENCE,
            &KEY,
        )
        .unwrap();

        assert_eq!(read, PLAINTEXT.len());
        assert_eq!(&decoded[..], PLAINTEXT);
    }

    #[test]
    fn round_trips_with_additional_data() {
        let mut encoded = [0; PLAINTEXT.len() + NETCODE_ENCRYPT_EXTA_BYTES];
        encode(
            &mut encoded,
            PLAINTEXT,
            Some(ADDITIONAL_DATA),
            SEQUENCE,
            &KEY,
        )
        .unwrap();

        let mut decoded = [0; PLAINTEXT.len()];
        let read = decode(
            &mut decoded,
            &encoded,
            Some(ADDITIONAL_DATA),
            SEQUENCE,
            &KEY,
        )
        .unwrap();

        assert_eq!(read, PLAINTEXT.len());
        assert_eq!(&decoded[..], PLAINTEXT);
    }

    #[test]
    fn rejects_a_tampered_tag() {
        let mut encoded = [0; PLAINTEXT.len() + NETCODE_ENCRYPT_EXTA_BYTES];
        encode(
            &mut encoded,
            PLAINTEXT,
            Some(ADDITIONAL_DATA),
            SEQUENCE,
            &KEY,
        )
        .unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;

        let mut decoded = [0; PLAINTEXT.len()];
        assert!(decode(
            &mut decoded,
            &encoded,
            Some(ADDITIONAL_DATA),
            SEQUENCE,
            &KEY,
        )
        .is_err());
    }

    #[test]
    fn rejects_a_ciphertext_shorter_than_the_tag() {
        let mut decoded = [0; PLAINTEXT.len()];

        for len in 0..NETCODE_ENCRYPT_EXTA_BYTES {
            assert!(decode(
                &mut decoded,
                &CIPHERTEXT[..len],
                Some(ADDITIONAL_DATA),
                SEQUENCE,
                &KEY,
            )
            .is_err());
        }
    }

    #[test]
    fn rejects_a_mismatched_sequence() {
        let mut encoded = [0; PLAINTEXT.len() + NETCODE_ENCRYPT_EXTA_BYTES];
        encode(
            &mut encoded,
            PLAINTEXT,
            Some(ADDITIONAL_DATA),
            SEQUENCE,
            &KEY,
        )
        .unwrap();

        let mut decoded = [0; PLAINTEXT.len()];
        assert!(decode(
            &mut decoded,
            &encoded,
            Some(ADDITIONAL_DATA),
            SEQUENCE + 1,
            &KEY,
        )
        .is_err());
    }
}
