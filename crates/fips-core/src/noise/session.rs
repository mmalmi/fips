use super::{CipherState, HandshakeRole, NoiseError, ReplayWindow};
use ring::aead::LessSafeKey;
use secp256k1::{PublicKey, XOnlyPublicKey};
use std::fmt;
use std::sync::Mutex;

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
    /// Cipher for receiving.
    recv_cipher: CipherState,
    /// Handshake hash for channel binding.
    handshake_hash: [u8; 32],
    /// Remote peer's static public key.
    remote_static: PublicKey,
    /// Replay window for received packets, behind a Mutex so the
    /// receive path can run with `&self` instead of `&mut self`.
    /// The lock is held only for the cheap `check`/`accept` steps —
    /// the AEAD `open` round happens outside the lock and uses the
    /// `LessSafeKey` (which is `Sync`) directly. Concurrent receive
    /// for the same session is rare (it usually serializes through
    /// the rx_loop or a per-peer task), but lock-on-check keeps the
    /// API correct under the parallel-decrypt pool's possible races.
    replay_window: Mutex<ReplayWindow>,
}

impl Clone for NoiseSession {
    /// Clone a session for ownership transfer (peer-actor refactor step 7c-2).
    /// Both copies hold independent replay windows starting at the same state;
    /// the consumer is responsible for ensuring only ONE copy processes
    /// incoming packets for any given session, otherwise replay protection
    /// silently weakens (the same counter could be accepted by both copies).
    ///
    /// `CipherState::Clone` rebuilds its keyed AEAD from the retained 32-byte
    /// key, so the two copies have independent `LessSafeKey` instances —
    /// fine for AEAD ops since `ring` keys are functional under their public
    /// API (no per-call mutation).
    fn clone(&self) -> Self {
        let replay_window = self
            .replay_window
            .lock()
            .expect("replay_window poisoned during clone")
            .clone();
        Self {
            role: self.role,
            send_cipher: self.send_cipher.clone(),
            recv_cipher: self.recv_cipher.clone(),
            handshake_hash: self.handshake_hash,
            remote_static: self.remote_static,
            replay_window: Mutex::new(replay_window),
        }
    }
}

impl NoiseSession {
    /// Create a new session from completed handshake data.
    pub(super) fn from_handshake(
        role: HandshakeRole,
        send_cipher: CipherState,
        recv_cipher: CipherState,
        handshake_hash: [u8; 32],
        remote_static: PublicKey,
    ) -> Self {
        Self {
            role,
            send_cipher,
            recv_cipher,
            handshake_hash,
            remote_static,
            replay_window: Mutex::new(ReplayWindow::new()),
        }
    }

    /// Encrypt a message for sending (using internal counter).
    ///
    /// Returns the ciphertext. The current send counter should be included
    /// in the wire format before calling this method.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.send_cipher.encrypt(plaintext)
    }

    /// Get the current send counter (before incrementing).
    ///
    /// Use this to get the counter to include in the wire format.
    /// The counter will be incremented when `encrypt` is called.
    pub fn current_send_counter(&self) -> u64 {
        self.send_cipher.nonce
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
        if self.replay_window.lock().expect("replay_window poisoned").check(counter) {
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
        &self,
        ciphertext: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        // Check replay window first (cheap). Lock briefly, drop, then run
        // the AEAD outside the lock so concurrent receivers on the same
        // session don't serialize on the AEAD round.
        if !self
            .replay_window
            .lock()
            .expect("replay_window poisoned")
            .check(counter)
        {
            return Err(NoiseError::ReplayDetected(counter));
        }

        // Attempt decryption (expensive). `recv_cipher.decrypt_with_counter`
        // already takes `&self` and uses the cached `LessSafeKey` (which is
        // `Sync`), so this is concurrency-safe.
        let plaintext = self.recv_cipher.decrypt_with_counter(ciphertext, counter)?;

        // Only accept into window after successful decryption.
        // The check+accept pair is not atomic, but `accept` is idempotent
        // on the same counter — a concurrent receive of the same counter
        // either both pass check (and both call accept, which is a no-op
        // on duplicate) or one passes and one is rejected.
        self.replay_window
            .lock()
            .expect("replay_window poisoned")
            .accept(counter);

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
        self.send_cipher.encrypt_with_aad(plaintext, aad)
    }

    /// Decrypt with explicit counter, replay protection, and AAD.
    ///
    /// This is the primary decryption method for the FMP transport phase
    /// with AAD binding. The AAD (typically the 16-byte outer header) must
    /// match what was used during encryption.
    pub fn decrypt_with_replay_check_and_aad(
        &self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        // Check replay window first (cheap). Lock briefly, drop, then run
        // the AEAD outside the lock so concurrent receivers on the same
        // session don't serialize on the AEAD round.
        if !self
            .replay_window
            .lock()
            .expect("replay_window poisoned")
            .check(counter)
        {
            return Err(NoiseError::ReplayDetected(counter));
        }

        // Attempt decryption with AAD (expensive). `recv_cipher` ops take
        // `&self` and use the cached `LessSafeKey` (`Sync`).
        let plaintext = self
            .recv_cipher
            .decrypt_with_counter_and_aad(ciphertext, counter, aad)?;

        // Accept into window. See `decrypt_with_replay_check` for the
        // non-atomicity rationale.
        self.replay_window
            .lock()
            .expect("replay_window poisoned")
            .accept(counter);

        Ok(plaintext)
    }

    /// Get the highest received counter.
    pub fn highest_received_counter(&self) -> u64 {
        self.replay_window
            .lock()
            .expect("replay_window poisoned")
            .highest()
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

    /// Clone the send-side AEAD instance, for off-task encrypt.
    ///
    /// Returns `None` if the send cipher has no key. Pairs with
    /// `encrypt_with_counter[_and_aad]` on `CipherState`. The caller must
    /// own counter sequencing — `take_send_counter` hands out monotonic
    /// counters under the session's own &mut.
    pub fn send_cipher_clone(&self) -> Option<LessSafeKey> {
        self.send_cipher.cipher_clone()
    }

    /// Reserve and return the next send counter, advancing the internal
    /// nonce. For pipelined encrypt paths that call `encrypt_with_counter`
    /// on a cloned cipher: the dispatcher pre-assigns the counter here
    /// (under the session's &mut) and the worker performs the AEAD with
    /// no further mutation of session state.
    pub fn take_send_counter(&mut self) -> Result<u64, NoiseError> {
        if self.send_cipher.nonce == u64::MAX {
            return Err(NoiseError::NonceOverflow);
        }
        let counter = self.send_cipher.nonce;
        self.send_cipher.nonce += 1;
        Ok(counter)
    }

    /// Accept a counter into the replay window after a successful out-of-task
    /// decrypt. Caller is responsible for verifying decrypt success first.
    pub fn accept_replay(&self, counter: u64) {
        self.replay_window
            .lock()
            .expect("replay_window poisoned")
            .accept(counter);
    }

    /// Reset the replay window (use when rekeying).
    pub fn reset_replay_window(&self) {
        self.replay_window
            .lock()
            .expect("replay_window poisoned")
            .reset();
    }

    /// Get the handshake hash for channel binding.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Get the remote peer's static public key.
    pub fn remote_static(&self) -> &PublicKey {
        &self.remote_static
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
        self.send_cipher.nonce()
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
            .field("send_nonce", &self.send_cipher.nonce())
            .field("recv_nonce", &self.recv_cipher.nonce())
            .field("handshake_hash", &hex::encode(&self.handshake_hash[..8]))
            .finish()
    }
}
