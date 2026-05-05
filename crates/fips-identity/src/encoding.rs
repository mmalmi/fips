//! NIP-19 bech32 encoding for Nostr keys.

use bech32::{Bech32, Hrp};
use secp256k1::{SecretKey, XOnlyPublicKey};

use super::IdentityError;

/// Human-readable part for npub (NIP-19).
const NPUB_HRP: Hrp = Hrp::parse_unchecked("npub");

/// Human-readable part for nsec (NIP-19).
const NSEC_HRP: Hrp = Hrp::parse_unchecked("nsec");

/// Encode an x-only public key as a bech32 npub string (NIP-19).
pub fn encode_npub(pubkey: &XOnlyPublicKey) -> String {
    bech32::encode::<Bech32>(NPUB_HRP, &pubkey.serialize()).expect("npub encoding cannot fail")
}

/// Decode an npub string to an x-only public key.
pub fn decode_npub(npub: &str) -> Result<XOnlyPublicKey, IdentityError> {
    let (hrp, data) = bech32::decode(npub)?;

    if hrp != NPUB_HRP {
        return Err(IdentityError::InvalidNpubPrefix(hrp.to_string()));
    }

    if data.len() != 32 {
        return Err(IdentityError::InvalidNpubLength(data.len()));
    }

    let pubkey = XOnlyPublicKey::from_slice(&data)?;
    Ok(pubkey)
}

/// Encode a secret key as a bech32 nsec string (NIP-19).
pub fn encode_nsec(secret_key: &SecretKey) -> String {
    bech32::encode::<Bech32>(NSEC_HRP, &secret_key.secret_bytes())
        .expect("nsec encoding cannot fail")
}

/// Decode an nsec string to a secret key.
pub fn decode_nsec(nsec: &str) -> Result<SecretKey, IdentityError> {
    let (hrp, data) = bech32::decode(nsec)?;

    if hrp != NSEC_HRP {
        return Err(IdentityError::InvalidNsecPrefix(hrp.to_string()));
    }

    if data.len() != 32 {
        return Err(IdentityError::InvalidNsecLength(data.len()));
    }

    let secret_key = SecretKey::from_slice(&data)?;
    Ok(secret_key)
}

/// Decode a secret key from either nsec (bech32) or hex format.
pub fn decode_secret(s: &str) -> Result<SecretKey, IdentityError> {
    if s.starts_with("nsec1") {
        decode_nsec(s)
    } else {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidNsecLength(bytes.len()));
        }
        let secret_key = SecretKey::from_slice(&bytes)?;
        Ok(secret_key)
    }
}
