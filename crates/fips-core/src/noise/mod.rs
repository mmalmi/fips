//! Noise Protocol Implementations for FIPS
//!
//! Implements Noise Protocol Framework patterns using secp256k1:
//!
//! - **IK pattern**: Used by FMP (link layer) for hop-by-hop peer authentication.
//!   The initiator knows the responder's static key and sends its encrypted
//!   static in msg1. Two-message handshake.
//!
//! - **XK pattern**: Used by FSP (session layer) for end-to-end sessions.
//!   The initiator knows the responder's static key but defers revealing its
//!   own identity until msg3, providing stronger identity hiding. Three-message
//!   handshake.
//!
//! ## IK Handshake Pattern (Link Layer)
//!
//! ```text
//!   <- s                    (pre-message: responder's static known)
//!   -> e, es, s, ss         (msg1: ephemeral + encrypted static)
//!   <- e, ee, se            (msg2: ephemeral)
//! ```
//!
//! ## XK Handshake Pattern (Session Layer)
//!
//! ```text
//!   <- s                    (pre-message: responder's static known)
//!   -> e, es                (msg1: ephemeral + DH with responder's static)
//!   <- e, ee                (msg2: ephemeral + DH)
//!   -> s, se                (msg3: encrypted static + DH)
//! ```
//!
//! ## Separation of Concerns
//!
//! The IK pattern handles **link-layer peer authentication** — securing the
//! direct link between neighboring nodes. The XK pattern handles **session-layer
//! end-to-end encryption** between arbitrary network addresses, with stronger
//! initiator identity protection.

mod handshake;
mod replay;
mod session;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use std::fmt;
use thiserror::Error;

pub use handshake::HandshakeState;
pub use replay::ReplayWindow;
pub use session::NoiseSession;

/// Protocol name for Noise IK with secp256k1 (link layer).
/// Format: Noise_IK_secp256k1_ChaChaPoly_SHA256
pub(crate) const PROTOCOL_NAME_IK: &[u8] = b"Noise_IK_secp256k1_ChaChaPoly_SHA256";

/// Protocol name for Noise XK with secp256k1 (session layer).
/// Format: Noise_XK_secp256k1_ChaChaPoly_SHA256
pub(crate) const PROTOCOL_NAME_XK: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";

/// Maximum message size for noise transport messages.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of the AEAD tag.
pub const TAG_SIZE: usize = 16;

/// Size of a public key (compressed secp256k1).
pub const PUBKEY_SIZE: usize = 33;

/// Size of the startup epoch (random bytes for restart detection).
pub const EPOCH_SIZE: usize = 8;

/// Size of encrypted epoch (epoch + AEAD tag).
pub const EPOCH_ENCRYPTED_SIZE: usize = EPOCH_SIZE + TAG_SIZE;

/// Size of IK handshake message 1: ephemeral (33) + encrypted static (33 + 16 tag) + encrypted epoch (8 + 16 tag).
pub const HANDSHAKE_MSG1_SIZE: usize = PUBKEY_SIZE + PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE;

/// Size of IK handshake message 2: ephemeral (33) + encrypted epoch (8 + 16 tag).
pub const HANDSHAKE_MSG2_SIZE: usize = PUBKEY_SIZE + EPOCH_ENCRYPTED_SIZE;

/// XK msg1: ephemeral only (33 bytes).
pub const XK_HANDSHAKE_MSG1_SIZE: usize = PUBKEY_SIZE;

/// XK msg2: ephemeral (33) + encrypted epoch (8 + 16 tag) = 57 bytes.
pub const XK_HANDSHAKE_MSG2_SIZE: usize = PUBKEY_SIZE + EPOCH_ENCRYPTED_SIZE;

/// XK msg3: encrypted static (33 + 16 tag) + encrypted epoch (8 + 16 tag) = 73 bytes.
pub const XK_HANDSHAKE_MSG3_SIZE: usize = PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE;

/// Replay window size in packets (matching WireGuard).
pub const REPLAY_WINDOW_SIZE: usize = 2048;

/// Errors from Noise protocol operations.
#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("handshake not complete")]
    HandshakeNotComplete,

    #[error("handshake already complete")]
    HandshakeAlreadyComplete,

    #[error("wrong handshake state: expected {expected}, got {got}")]
    WrongState { expected: String, got: String },

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("message too large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("message too short: expected at least {expected}, got {got}")]
    MessageTooShort { expected: usize, got: usize },

    #[error("nonce overflow")]
    NonceOverflow,

    #[error("replay detected: counter {0} already seen or too old")]
    ReplayDetected(u64),

    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// Role in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// We initiated the connection.
    Initiator,
    /// They initiated the connection.
    Responder,
}

impl fmt::Display for HandshakeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeRole::Initiator => write!(f, "initiator"),
            HandshakeRole::Responder => write!(f, "responder"),
        }
    }
}

/// Which Noise pattern is being used for this handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoisePattern {
    /// Noise IK: two-message handshake (link layer).
    Ik,
    /// Noise XK: three-message handshake (session layer).
    Xk,
}

/// Handshake state machine states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeProgress {
    /// Initial state, ready to send/receive message 1.
    Initial,
    /// Message 1 sent/received, ready for message 2.
    Message1Done,
    /// Message 2 sent/received, ready for message 3 (XK only).
    Message2Done,
    /// Handshake complete, ready for transport.
    Complete,
}

impl fmt::Display for HandshakeProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeProgress::Initial => write!(f, "initial"),
            HandshakeProgress::Message1Done => write!(f, "message1_done"),
            HandshakeProgress::Message2Done => write!(f, "message2_done"),
            HandshakeProgress::Complete => write!(f, "complete"),
        }
    }
}

/// Symmetric cipher state for post-handshake encryption.
///
/// The `cipher` field caches the AEAD instance so we don't re-derive it
/// per packet. `ChaCha20Poly1305::new_from_slice` is cheap on its own but
/// it's still allocator + key-clone work that we'd otherwise pay on every
/// transport datagram; caching it costs ~80 bytes of struct width and
/// eliminates that overhead from the bulk-data hot path.
#[derive(Clone)]
pub struct CipherState {
    /// Encryption key (32 bytes). Retained alongside the cached cipher so
    /// `Clone` can rebuild the cipher independently and rekey paths can
    /// re-derive without re-reading from the cipher.
    key: [u8; 32],
    /// Cached AEAD instance, valid iff `has_key`.
    cipher: Option<ChaCha20Poly1305>,
    /// Nonce counter (8 bytes used, 4 bytes zero prefix).
    pub(super) nonce: u64,
    /// Whether this cipher has a valid key.
    has_key: bool,
}

impl CipherState {
    /// Create a new cipher state with the given key.
    pub(crate) fn new(key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(&key).ok();
        Self {
            key,
            cipher,
            nonce: 0,
            has_key: true,
        }
    }

    /// Create an empty cipher state (no key yet).
    pub(super) fn empty() -> Self {
        Self {
            key: [0u8; 32],
            cipher: None,
            nonce: 0,
            has_key: false,
        }
    }

    /// Initialize with a key.
    pub(super) fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = key;
        self.cipher = ChaCha20Poly1305::new_from_slice(&key).ok();
        self.nonce = 0;
        self.has_key = true;
    }

    /// Encrypt plaintext, returning ciphertext with appended tag.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            // No key means no encryption (shouldn't happen in transport phase)
            return Ok(plaintext.to_vec());
        }

        if plaintext.len() > MAX_MESSAGE_SIZE - TAG_SIZE {
            return Err(NoiseError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_MESSAGE_SIZE - TAG_SIZE,
            });
        }

        let nonce = self.next_nonce()?;
        let cipher = self.cipher.as_ref().ok_or(NoiseError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| NoiseError::EncryptionFailed)?;

        Ok(ciphertext)
    }

    /// Decrypt ciphertext (with appended tag), returning plaintext.
    ///
    /// Uses the internal nonce counter. For transport phase with explicit
    /// counters from the wire format, use `decrypt_with_counter` instead.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            // No key means no encryption
            return Ok(ciphertext.to_vec());
        }

        if ciphertext.len() < TAG_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: TAG_SIZE,
                got: ciphertext.len(),
            });
        }

        let nonce = self.next_nonce()?;
        let cipher = self.cipher.as_ref().ok_or(NoiseError::DecryptionFailed)?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| NoiseError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Decrypt with an explicit counter value (for transport phase).
    ///
    /// This is used when the counter comes from the wire format rather than
    /// an internal counter. The counter must be validated by a replay window
    /// before calling this method.
    pub fn decrypt_with_counter(
        &self,
        ciphertext: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            return Ok(ciphertext.to_vec());
        }

        if ciphertext.len() < TAG_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: TAG_SIZE,
                got: ciphertext.len(),
            });
        }

        let cipher = self.cipher.as_ref().ok_or(NoiseError::DecryptionFailed)?;

        let nonce = Self::counter_to_nonce(counter);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| NoiseError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Encrypt plaintext with Additional Authenticated Data (AAD).
    ///
    /// The AAD is authenticated but not encrypted. Used for the FMP
    /// established frame format where the 16-byte outer header is
    /// bound to the AEAD tag.
    pub fn encrypt_with_aad(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            return Ok(plaintext.to_vec());
        }

        if plaintext.len() > MAX_MESSAGE_SIZE - TAG_SIZE {
            return Err(NoiseError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_MESSAGE_SIZE - TAG_SIZE,
            });
        }

        let nonce = self.next_nonce()?;
        let cipher = self.cipher.as_ref().ok_or(NoiseError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| NoiseError::EncryptionFailed)?;

        Ok(ciphertext)
    }

    /// Encrypt plaintext with an explicit counter (no AAD).
    ///
    /// Symmetric to `decrypt_with_counter`: takes `&self` and a caller-
    /// supplied counter rather than mutating the internal nonce. Intended
    /// for pipelined encrypt paths where a dispatcher pre-assigns counters
    /// and fans the AEAD work out across worker threads. Callers are
    /// responsible for ensuring counter uniqueness — typically by holding
    /// the cipher behind a lock or queue that hands out counters in order.
    pub fn encrypt_with_counter(
        &self,
        plaintext: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            return Ok(plaintext.to_vec());
        }

        if plaintext.len() > MAX_MESSAGE_SIZE - TAG_SIZE {
            return Err(NoiseError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_MESSAGE_SIZE - TAG_SIZE,
            });
        }

        let cipher = self.cipher.as_ref().ok_or(NoiseError::EncryptionFailed)?;

        let nonce = Self::counter_to_nonce(counter);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| NoiseError::EncryptionFailed)?;

        Ok(ciphertext)
    }

    /// Encrypt plaintext with an explicit counter and AAD.
    ///
    /// Symmetric to `decrypt_with_counter_and_aad`: takes `&self` and a
    /// caller-supplied counter rather than mutating the internal nonce.
    /// Same uniqueness contract as `encrypt_with_counter`.
    pub fn encrypt_with_counter_and_aad(
        &self,
        plaintext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            return Ok(plaintext.to_vec());
        }

        if plaintext.len() > MAX_MESSAGE_SIZE - TAG_SIZE {
            return Err(NoiseError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_MESSAGE_SIZE - TAG_SIZE,
            });
        }

        let cipher = self.cipher.as_ref().ok_or(NoiseError::EncryptionFailed)?;

        let nonce = Self::counter_to_nonce(counter);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| NoiseError::EncryptionFailed)?;

        Ok(ciphertext)
    }

    /// Clone the underlying AEAD instance, if a key has been installed.
    ///
    /// Returns `None` for an empty (un-keyed) state. The returned cipher
    /// is a 32-byte key copy and can be moved across threads. Combined
    /// with `decrypt_with_counter[_and_aad]` and the matching nonce, this
    /// lets a dispatcher offload the AEAD rounds to a worker pool while
    /// the main task keeps the replay window and counter assignment
    /// sequential.
    pub fn cipher_clone(&self) -> Option<ChaCha20Poly1305> {
        self.cipher.clone()
    }

    /// Decrypt with an explicit counter and AAD (for transport phase).
    ///
    /// Combines explicit counter (from wire format) with AAD verification.
    /// The AAD must match exactly what was used during encryption or the
    /// AEAD tag verification will fail.
    pub fn decrypt_with_counter_and_aad(
        &self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            return Ok(ciphertext.to_vec());
        }

        if ciphertext.len() < TAG_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: TAG_SIZE,
                got: ciphertext.len(),
            });
        }

        let cipher = self.cipher.as_ref().ok_or(NoiseError::DecryptionFailed)?;

        let nonce = Self::counter_to_nonce(counter);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| NoiseError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Convert a counter value to a nonce.
    fn counter_to_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Get the next nonce, incrementing the counter.
    fn next_nonce(&mut self) -> Result<Nonce, NoiseError> {
        if self.nonce == u64::MAX {
            return Err(NoiseError::NonceOverflow);
        }

        let n = self.nonce;
        self.nonce += 1;

        // Noise uses 8-byte counter with 4-byte zero prefix
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&n.to_le_bytes());

        Ok(*Nonce::from_slice(&nonce_bytes))
    }

    /// Get the current nonce value (for debugging/testing).
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Check if cipher has a key.
    pub fn has_key(&self) -> bool {
        self.has_key
    }
}

impl fmt::Debug for CipherState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherState")
            .field("nonce", &self.nonce)
            .field("has_key", &self.has_key)
            .field("key", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests;
