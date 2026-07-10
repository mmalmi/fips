use super::{CipherState, HandshakeRole, NoiseError, ReplayWindow};
use ring::aead::LessSafeKey;
use secp256k1::{PublicKey, XOnlyPublicKey};
#[cfg(test)]
use std::ops::Range;
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// Shared send-side counter authority for one Noise transport session.
///
/// AEAD keys can be rebuilt for worker threads, but nonce uniqueness must stay
/// single-owner. This authority is the small clonable object that lets a future
/// dataplane workers reserve counters without borrowing the whole `NoiseSession`.
#[derive(Clone, Debug)]
pub(crate) struct SendCounterAuthority {
    next: Arc<AtomicU64>,
}

impl SendCounterAuthority {
    fn new(next: u64) -> Self {
        Self {
            next: Arc::new(AtomicU64::new(next)),
        }
    }

    pub(crate) fn current(&self) -> u64 {
        self.next.load(Ordering::Relaxed)
    }

    pub(crate) fn reserve(&self) -> Result<u64, NoiseError> {
        self.next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next == u64::MAX {
                    None
                } else {
                    Some(next + 1)
                }
            })
            .map_err(|_| NoiseError::NonceOverflow)
    }

    #[cfg(test)]
    pub(crate) fn reserve_range(&self, count: usize) -> Result<Range<u64>, NoiseError> {
        let count = u64::try_from(count).map_err(|_| NoiseError::NonceOverflow)?;
        if count == 0 {
            let current = self.current();
            return Ok(current..current);
        }

        let first = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next <= u64::MAX - count {
                    Some(next + count)
                } else {
                    None
                }
            })
            .map_err(|_| NoiseError::NonceOverflow)?;
        Ok(first..first + count)
    }
}

/// Completed Noise session for transport encryption.
///
/// Provides bidirectional authenticated encryption with replay protection.
/// The send counter is monotonically incremented; received counters are
/// validated against a sliding window to prevent replay attacks.
pub struct NoiseSession {
    /// Our role in the original handshake.
    role: HandshakeRole,
    /// Cipher for sending.
    send_cipher: CipherState,
    /// Monotonic send counter authority for transport nonces.
    send_counter: SendCounterAuthority,
    /// Cipher for receiving.
    recv_cipher: CipherState,
    /// Handshake hash for channel binding.
    handshake_hash: [u8; 32],
    /// Remote peer's static public key.
    remote_static: PublicKey,
    /// Remote process epoch authenticated by the handshake.
    remote_epoch: [u8; 8],
    /// Replay window for received packets.
    replay_window: ReplayWindow,
}

impl NoiseSession {
    /// Create a new session from completed handshake data.
    pub(super) fn from_handshake(
        role: HandshakeRole,
        send_cipher: CipherState,
        recv_cipher: CipherState,
        handshake_hash: [u8; 32],
        remote_static: PublicKey,
        remote_epoch: [u8; 8],
    ) -> Self {
        let send_counter = SendCounterAuthority::new(send_cipher.nonce());
        Self {
            role,
            send_cipher,
            send_counter,
            recv_cipher,
            handshake_hash,
            remote_static,
            remote_epoch,
            replay_window: ReplayWindow::new(),
        }
    }

    /// Encrypt a message for sending (using internal counter).
    ///
    /// Returns the ciphertext. The current send counter should be included
    /// in the wire format before calling this method.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let counter = self.take_send_counter()?;
        self.send_cipher.encrypt_with_counter(plaintext, counter)
    }

    /// Get the current send counter (before incrementing).
    ///
    /// Use this to get the counter to include in the wire format.
    /// The counter will be incremented when `encrypt` is called.
    pub fn current_send_counter(&self) -> u64 {
        self.send_counter.current()
    }

    /// Decrypt a received message (using internal counter).
    ///
    /// This is for handshake-phase decryption. For transport phase with
    /// explicit counters, use `decrypt_with_replay_check` instead.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.recv_cipher.decrypt(ciphertext)
    }

    /// Check if a counter passes the replay window.
    ///
    /// Returns Ok(()) if the counter is acceptable, Err if it should be rejected.
    /// Call this before attempting decryption to avoid wasting CPU on replay attacks.
    pub fn check_replay(&self, counter: u64) -> Result<(), NoiseError> {
        if self.replay_window.check(counter) {
            Ok(())
        } else {
            Err(NoiseError::ReplayDetected(counter))
        }
    }

    /// Decrypt with explicit counter and replay protection.
    ///
    /// This is the primary decryption method for transport phase.
    /// The counter comes from the wire format and is validated against
    /// the replay window before and after decryption.
    ///
    /// On success, the counter is accepted into the replay window.
    pub fn decrypt_with_replay_check(
        &mut self,
        ciphertext: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        // Check replay window first (cheap)
        if !self.replay_window.check(counter) {
            return Err(NoiseError::ReplayDetected(counter));
        }

        // Attempt decryption (expensive)
        let plaintext = self.recv_cipher.decrypt_with_counter(ciphertext, counter)?;

        // Only accept into window after successful decryption
        // This prevents DoS attacks that exhaust the window
        self.replay_window.accept(counter);

        Ok(plaintext)
    }

    /// Encrypt a message with Additional Authenticated Data (AAD).
    ///
    /// Returns the ciphertext. The current send counter should be included
    /// in the wire format before calling this method.
    pub fn encrypt_with_aad(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let counter = self.take_send_counter()?;
        self.send_cipher
            .encrypt_with_counter_and_aad(plaintext, counter, aad)
    }

    /// Decrypt with explicit counter, replay protection, and AAD.
    ///
    /// This is the primary decryption method for the FMP transport phase
    /// with AAD binding. The AAD (typically the 16-byte outer header) must
    /// match what was used during encryption.
    pub fn decrypt_with_replay_check_and_aad(
        &mut self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        // Check replay window first (cheap)
        if !self.replay_window.check(counter) {
            return Err(NoiseError::ReplayDetected(counter));
        }

        // Attempt decryption with AAD (expensive)
        let plaintext = self
            .recv_cipher
            .decrypt_with_counter_and_aad(ciphertext, counter, aad)?;

        // Only accept into window after successful decryption
        self.replay_window.accept(counter);

        Ok(plaintext)
    }

    /// In-place variant of [`Self::decrypt_with_replay_check_and_aad`].
    ///
    /// On entry, `buf` holds `ciphertext + 16-byte AEAD tag`. On
    /// successful return, `buf[..returned_len]` holds the plaintext.
    /// The caller can then slice into `buf` without paying for an
    /// extra heap allocation + memcpy per packet — at multi-Gbps
    /// single-stream the by-value variant's `ciphertext.to_vec()`
    /// alone is a measurable fraction of the rx_loop's per-packet
    /// cost.
    pub fn decrypt_with_replay_check_and_aad_in_place(
        &mut self,
        buf: &mut [u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<usize, NoiseError> {
        if !self.replay_window.check(counter) {
            return Err(NoiseError::ReplayDetected(counter));
        }
        let plaintext_len = self
            .recv_cipher
            .decrypt_with_counter_and_aad_in_place(buf, counter, aad)?;
        self.replay_window.accept(counter);
        Ok(plaintext_len)
    }

    /// Get the highest received counter.
    pub fn highest_received_counter(&self) -> u64 {
        self.replay_window.highest()
    }

    /// Clone the recv-side AEAD instance, for off-task decrypt.
    ///
    /// Returns `None` if the recv cipher has no key (transport phase has
    /// not begun). The cloned cipher pairs with `decrypt_with_counter[_and_aad]`
    /// on `CipherState`: a dispatcher can `check_replay` here, fan the
    /// AEAD work out to a worker holding the clone + counter + aad, then
    /// call `accept_replay` here once the worker reports success.
    pub fn recv_cipher_clone(&self) -> Option<LessSafeKey> {
        self.recv_cipher.cipher_clone()
    }

    /// Snapshot the current replay-window state as an **owned**
    /// `ReplayWindow` value, for hand-off to a shard-owning decrypt
    /// worker.
    ///
    /// **The worker becomes the sole authority for replay protection
    /// on this session after this snapshot.** The local
    /// `self.replay_window` is no longer the source of truth — it
    /// only matters for rare-slow-path uses (rekey, drain-window
    /// fallback). The worker keeps its copy in its own
    /// thread-local `HashMap`, so there's no Mutex / no Arc / no
    /// sharing — direct `&mut` access on every packet.
    ///
    /// (Previously this returned an `Arc<Mutex<ReplayWindow>>` for
    /// concurrent access; the data-plane shard restructure now hands
    /// the worker exclusive ownership instead.)
    pub fn recv_replay_snapshot_owned(&self) -> crate::noise::ReplayWindow {
        self.replay_window.clone()
    }

    /// Clone the send-side AEAD instance, for off-task encrypt.
    ///
    /// Returns `None` if the send cipher has no key. Pairs with
    /// `encrypt_with_counter[_and_aad]` on `CipherState`. The caller must
    /// reserve counters through this session's shared counter authority before
    /// worker-side encryption.
    pub fn send_cipher_clone(&self) -> Option<LessSafeKey> {
        self.send_cipher.cipher_clone()
    }

    /// Clone the send-side counter authority for an owned dataplane worker.
    pub(crate) fn send_counter_authority(&self) -> SendCounterAuthority {
        self.send_counter.clone()
    }

    /// Whether the send-side cipher is keyed for worker-side encryption.
    pub fn has_send_cipher(&self) -> bool {
        self.send_cipher.has_key()
    }

    /// Reserve and return the next send counter, advancing the internal
    /// nonce. For pipelined encrypt paths that call `encrypt_with_counter`
    /// on a cloned cipher: the dispatcher pre-assigns the counter here
    /// through the session's shared authority and the worker performs the
    /// AEAD with no further mutation of session state.
    pub fn take_send_counter(&self) -> Result<u64, NoiseError> {
        self.send_counter.reserve()
    }

    /// Accept a counter into the replay window after a successful out-of-task
    /// decrypt. Caller is responsible for verifying decrypt success first.
    pub fn accept_replay(&mut self, counter: u64) {
        self.replay_window.accept(counter);
    }

    /// Reset the replay window (use when rekeying).
    pub fn reset_replay_window(&mut self) {
        self.replay_window.reset();
    }

    /// Get the handshake hash for channel binding.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Get the remote peer's static public key.
    pub fn remote_static(&self) -> &PublicKey {
        &self.remote_static
    }

    pub(crate) fn remote_epoch(&self) -> [u8; 8] {
        self.remote_epoch
    }

    /// Get the remote peer's x-only public key.
    pub fn remote_static_xonly(&self) -> XOnlyPublicKey {
        self.remote_static.x_only_public_key().0
    }

    /// Get our role in the handshake.
    pub fn role(&self) -> HandshakeRole {
        self.role
    }

    /// Get the send nonce (for debugging).
    pub fn send_nonce(&self) -> u64 {
        self.send_counter.current()
    }

    /// Get the receive nonce (for debugging).
    pub fn recv_nonce(&self) -> u64 {
        self.recv_cipher.nonce()
    }
}

impl fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseSession")
            .field("role", &self.role)
            .field("send_nonce", &self.send_counter.current())
            .field("recv_nonce", &self.recv_cipher.nonce())
            .field("handshake_hash", &hex::encode(&self.handshake_hash[..8]))
            .finish()
    }
}
