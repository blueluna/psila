use psila_crypto::CryptoBackend;
use crate::RustCryptoBackend;

#[test]
fn test_key_hash_default_link_key() {
    use psila_data::security::{CryptoProvider, DEFAULT_LINK_KEY};

    let mut provider = CryptoProvider::new(RustCryptoBackend::default());

    let mut hashed_key = [0; 16];
    provider
        .hash_key(&DEFAULT_LINK_KEY, 0x00, &mut hashed_key)
        .unwrap();

    let correct_key = [
        0x4b, 0xab, 0x0f, 0x17, 0x3e, 0x14, 0x34, 0xa2, 0xd5, 0x72, 0xe1, 0xc1, 0xef, 0x47,
        0x87, 0x82,
    ];

    assert_eq!(hashed_key, correct_key);
}

#[test]
fn test_key_hash_2() {
    use psila_data::security::CryptoProvider;
    let mut provider = CryptoProvider::new(RustCryptoBackend::default());

    // Specification test vectors, C.6.1 Test Vector Set 1
    let key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
        0x4E, 0x4F,
    ];
    let mut hashed_key = [0u8; 16];
    provider.hash_key(&key, 0xc0, &mut hashed_key).unwrap();
    let correct_key = [
        0x45, 0x12, 0x80, 0x7B, 0xF9, 0x4C, 0xB3, 0x40, 0x0F, 0x0E, 0x2C, 0x25, 0xFB, 0x76,
        0xE9, 0x99,
    ];

    assert_eq!(hashed_key, correct_key);
}



#[test]
fn test_decryption_and_authentication_check_1() {
    let mut crypt = RustCryptoBackend::default();

    let key = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
        0xCE, 0xCF,
    ];
    let nonce = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x03, 0x02, 0x01, 0x00, 0x06,
    ];
    const ENCRYPTED: [u8; 31] = [
        0x1A, 0x55, 0xA3, 0x6A, 0xBB, 0x6C, 0x61, 0x0D, 0x06, 0x6B, 0x33, 0x75, 0x64, 0x9C,
        0xEF, 0x10, 0xD4, 0x66, 0x4E, 0xCA, 0xD8, 0x54, 0xA8, 0x0A, 0x89, 0x5C, 0xC1, 0xD8,
        0xFF, 0x94, 0x69,
    ];
    let a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    // M, length of the authentication field in octets 0, 4, 6, 8, 10, 12, 14, 16
    const M: usize = 8;
    let mut message = [0u8; ENCRYPTED.len() - M];

    let encrypted = &ENCRYPTED[..ENCRYPTED.len() - M];
    let mic = &ENCRYPTED[ENCRYPTED.len() - M..];

    let used = crypt
        .ccmstar_decrypt(&key, &nonce, encrypted, mic, &a, &mut message)
        .unwrap();

    assert_eq!(used, 23);

    const CLEAR_TEXT: [u8; 23] = [
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
    ];

    assert_eq!(message, CLEAR_TEXT);
}

#[test]
fn test_encryption_and_authentication_check_1() {
    let mut crypt = RustCryptoBackend::default();

    let key = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
        0xCE, 0xCF,
    ];
    let nonce = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x03, 0x02, 0x01, 0x00, 0x06,
    ];
    const CLEAR_TEXT: [u8; 23] = [
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    ];
    const ENCRYPTED: [u8; 23] = [
        0x1A, 0x55, 0xA3, 0x6A, 0xBB, 0x6C, 0x61, 0x0D, 0x06, 0x6B, 0x33, 0x75, 0x64, 0x9C,
        0xEF, 0x10, 0xD4, 0x66, 0x4E, 0xCA, 0xD8, 0x54, 0xA8,
    ];
    let mic = [0x0A, 0x89, 0x5C, 0xC1, 0xD8, 0xFF, 0x94, 0x69];
    let a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    // M, length of the authentication code in octets 0, 4, 6, 8, 10, 12, 14, 16
    const M: usize = 8;
    let mut output = [0u8; CLEAR_TEXT.len()];

    let mut mic_out = [0u8; M];

    let used = crypt
        .ccmstar_encrypt(&key, &nonce, &CLEAR_TEXT, &mut mic_out, &a, &mut output)
        .unwrap();

    assert_eq!(used, 23);

    assert_eq!(output, ENCRYPTED);
    assert_eq!(mic, mic_out);
}
