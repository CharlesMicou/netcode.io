use libsodium_sys;

use crate::common::*;
use byteorder::{LittleEndian, WriteBytesExt};
use std::io;
use std::sync::atomic;

// TODO: fix me
#[cfg_attr(feature = "cargo-clippy", allow(replace_consts))]
static mut SODIUM_INIT: atomic::AtomicUsize = atomic::AtomicUsize::new(0);

pub const NETCODE_ENCRYPT_EXTA_BYTES: usize =
    libsodium_sys::crypto_aead_chacha20poly1305_ABYTES as usize;

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

fn init_sodium() {
    unsafe {
        if SODIUM_INIT.load(atomic::Ordering::Relaxed) == 0 {
            libsodium_sys::sodium_init();
            SODIUM_INIT.store(1, atomic::Ordering::Relaxed);
        }
    }
}

/// Generates a new random private key.
pub fn generate_key() -> [u8; NETCODE_KEY_BYTES] {
    let mut key: [u8; NETCODE_KEY_BYTES] = [0; NETCODE_KEY_BYTES];

    random_bytes(&mut key);

    key
}

pub fn random_bytes(out: &mut [u8]) {
    unsafe {
        init_sodium();
        libsodium_sys::randombytes_buf(out.as_mut_ptr() as _, out.len());
    }
}

// TODO: fix me
#[cfg_attr(feature = "cargo-clippy", allow(cast_possible_truncation))]
pub fn encode(
    out: &mut [u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    nonce: u64,
    key: &[u8; NETCODE_KEY_BYTES],
) -> Result<usize, EncryptError> {
    if key.len() != NETCODE_KEY_BYTES {
        return Err(EncryptError::InvalidPublicKeySize);
    }

    if out.len() < data.len() + NETCODE_ENCRYPT_EXTA_BYTES {
        return Err(EncryptError::BufferSizeMismatch);
    }

    let (result, written) = unsafe {
        init_sodium();
        let mut written: u64 = out.len() as u64;

        let mut final_nonce = [0; 12];
        io::Cursor::new(&mut final_nonce[4..]).write_u64::<LittleEndian>(nonce)?;

        let result = libsodium_sys::crypto_aead_chacha20poly1305_ietf_encrypt(
            out.as_mut_ptr(),
            &mut written,
            data.as_ptr(),
            data.len() as u64,
            additional_data.map_or(::std::ptr::null_mut(), |v| v.as_ptr()),
            additional_data.map_or(0, |v| v.len()) as u64,
            ::std::ptr::null(),
            final_nonce.as_ptr(),
            key.as_ptr(),
        );

        (result, written)
    };

    match result {
        -1 => Err(EncryptError::Failed),
        _ => Ok(written as usize),
    }
}

// TODO: fix me
#[cfg_attr(feature = "cargo-clippy", allow(cast_possible_truncation))]
pub fn decode(
    out: &mut [u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    nonce: u64,
    key: &[u8; NETCODE_KEY_BYTES],
) -> Result<usize, EncryptError> {
    if key.len() != NETCODE_KEY_BYTES {
        return Err(EncryptError::InvalidPublicKeySize);
    }

    if out.len() < data.len() - NETCODE_ENCRYPT_EXTA_BYTES {
        return Err(EncryptError::BufferSizeMismatch);
    }

    let (result, read) = unsafe {
        init_sodium();
        let mut read: u64 = out.len() as u64;

        let mut final_nonce = [0; 12];
        io::Cursor::new(&mut final_nonce[4..]).write_u64::<LittleEndian>(nonce)?;

        let result = libsodium_sys::crypto_aead_chacha20poly1305_ietf_decrypt(
            out.as_mut_ptr(),
            &mut read,
            ::std::ptr::null_mut(),
            data.as_ptr(),
            data.len() as u64,
            additional_data.map_or(::std::ptr::null_mut(), |v| v.as_ptr()),
            additional_data.map_or(0, |v| v.len()) as u64,
            final_nonce.as_ptr(),
            key.as_ptr(),
        );

        (result, read)
    };

    match result {
        -1 => Err(EncryptError::Failed),
        _ => Ok(read as usize),
    }
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
