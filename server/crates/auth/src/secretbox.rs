//! Envelope encryption under the boot KEK: AES-256-GCM with a fresh CSPRNG nonce.
//!
//! One implementation, two callers with the same requirement — the TOTP seed at rest (S-05)
//! and the runtime SMTP password in the settings table (S-26). Both are secrets we must be
//! able to *store* under a key that never leaves boot configuration (S-25), and a second copy
//! of an AEAD construction is how the two drift into different nonce or framing rules.
//!
//! Wire format is `nonce ‖ ciphertext‖tag` — the nonce is 12 bytes and is generated per seal,
//! never derived and never reused. There is no associated data: the ciphertexts are stored in
//! typed columns whose meaning is fixed by the schema, so there is no context to bind that the
//! row itself does not already carry.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use pub_core::{Error, Result};

use crate::random::RandomSource;

/// AES-GCM nonce length in bytes.
const NONCE_BYTES: usize = 12;

/// Seals `plaintext` with the 32-byte KEK; output is `nonce ‖ ciphertext‖tag`.
pub fn seal(kek: &[u8], rng: &dyn RandomSource, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|_| Error::Config { message: "auth.kek must be exactly 32 bytes".to_owned() })?;
    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill(&mut nonce);
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad: b"" })
        // The message never names the plaintext or the key (S-25).
        .map_err(|_| Error::Internal { message: "sealing failed".to_owned() })?;
    let mut out = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a [`seal`]ed blob. Tampered or foreign-KEK material fails authentication.
pub fn open(kek: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|_| Error::Config { message: "auth.kek must be exactly 32 bytes".to_owned() })?;
    if sealed.len() < NONCE_BYTES {
        return Err(Error::Internal { message: "sealed value is truncated".to_owned() });
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().expect("split_at(NONCE_BYTES) yields exactly that many bytes");
    cipher
        .decrypt(&Nonce::from(nonce), Payload { msg: ciphertext, aad: b"" })
        .map_err(|_| Error::Internal { message: "unsealing failed (wrong KEK or corrupt data)".to_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::OsRandom;

    #[test]
    fn a_sealed_value_round_trips_and_never_repeats_a_ciphertext() {
        let kek = [3u8; 32];
        let secret = b"hunter2-but-longer".to_vec();
        let sealed = seal(&kek, &OsRandom, &secret).unwrap();
        assert_ne!(sealed, secret, "the plaintext must not survive in the blob");
        // A fresh nonce per seal: identical plaintexts must not produce identical ciphertexts.
        assert_ne!(sealed, seal(&kek, &OsRandom, &secret).unwrap());
        assert_eq!(open(&kek, &sealed).unwrap(), secret);
    }

    #[test]
    fn tampering_a_foreign_kek_and_truncation_all_fail_authentication() {
        let kek = [3u8; 32];
        let sealed = seal(&kek, &OsRandom, b"secret").unwrap();
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(open(&kek, &tampered).is_err());
        assert!(open(&[9u8; 32], &sealed).is_err());
        assert!(open(&kek, &sealed[..8]).is_err());
    }

    #[test]
    fn a_wrong_sized_kek_is_a_configuration_error_not_an_internal_one() {
        assert_eq!(seal(&[1u8; 16], &OsRandom, b"x").unwrap_err().code(), "config_invalid");
        assert_eq!(open(&[1u8; 16], &[0u8; 32]).unwrap_err().code(), "config_invalid");
    }
}
