//! Local node identity with signing capability.

use secp256k1::{Keypair, PublicKey, SecretKey, XOnlyPublicKey};
use std::fmt;
use zeroize::Zeroizing;

use super::auth::{AuthResponse, auth_challenge_digest};
use super::encoding::{decode_secret, encode_npub};
use super::{FipsAddress, IdentityError, NodeAddr, sha256};

/// A FIPS node identity consisting of a keypair and derived identifiers.
///
/// The identity holds the secp256k1 keypair and provides methods for signing
/// and verifying protocol messages.
/// Its owned keypair is erased when the identity is dropped. Constructors also
/// erase the intermediate private-key copies they create; as with
/// `secp256k1::Keypair::non_secure_erase`, this can only clear copies the crate
/// can still name.
pub struct Identity {
    keypair: Keypair,
    node_addr: NodeAddr,
    address: FipsAddress,
}

impl Identity {
    /// Create a new random identity.
    pub fn generate() -> Self {
        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        rand::Rng::fill_bytes(&mut rand::rng(), secret_bytes.as_mut());
        let mut secret_key = SecretKey::from_slice(secret_bytes.as_ref())
            .expect("32 random bytes is a valid secret key");
        let identity = Self::from_secret_key(secret_key);
        secret_key.non_secure_erase();
        identity
    }

    /// Create an identity from an existing keypair.
    pub fn from_keypair(mut keypair: Keypair) -> Self {
        let (pubkey, _parity) = keypair.x_only_public_key();
        let node_addr = NodeAddr::from_pubkey(&pubkey);
        let address = FipsAddress::from_node_addr(&node_addr);
        let identity = Self {
            keypair,
            node_addr,
            address,
        };
        keypair.non_secure_erase();
        identity
    }

    /// Create an identity from a secret key.
    pub fn from_secret_key(mut secret_key: SecretKey) -> Self {
        let mut keypair = Keypair::from_secret_key(&super::SECP, &secret_key);
        let identity = Self::from_keypair(keypair);
        keypair.non_secure_erase();
        secret_key.non_secure_erase();
        identity
    }

    /// Create an identity from secret key bytes.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        let mut secret_key = SecretKey::from_slice(bytes)?;
        let identity = Self::from_secret_key(secret_key);
        secret_key.non_secure_erase();
        Ok(identity)
    }

    /// Create an identity from an nsec string (bech32) or hex-encoded secret.
    pub fn from_secret_str(s: &str) -> Result<Self, IdentityError> {
        let mut secret_key = decode_secret(s)?;
        let identity = Self::from_secret_key(secret_key);
        secret_key.non_secure_erase();
        Ok(identity)
    }

    /// Return the underlying keypair.
    ///
    /// This is needed for cryptographic operations like Noise handshakes.
    pub fn keypair(&self) -> Keypair {
        self.keypair
    }

    /// Return the x-only public key.
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }

    /// Return the full public key (includes parity).
    pub fn pubkey_full(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Return the public key as a bech32-encoded npub string (NIP-19).
    pub fn npub(&self) -> String {
        encode_npub(&self.pubkey())
    }

    /// Return the node ID.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node_addr
    }

    /// Return the FIPS address.
    pub fn address(&self) -> &FipsAddress {
        &self.address
    }

    /// Sign arbitrary data with this identity's secret key.
    pub fn sign(&self, data: &[u8]) -> secp256k1::schnorr::Signature {
        let digest = sha256(data);
        super::SECP.sign_schnorr(&digest, &self.keypair)
    }

    /// Create an authentication response for a challenge.
    ///
    /// The response signs: SHA256("fips-auth-v1" || challenge || timestamp)
    pub fn sign_challenge(&self, challenge: &[u8; 32], timestamp: u64) -> AuthResponse {
        let digest = auth_challenge_digest(challenge, timestamp);
        let signature = super::SECP.sign_schnorr(&digest, &self.keypair);
        AuthResponse {
            pubkey: self.pubkey(),
            timestamp,
            signature,
        }
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.keypair.non_secure_erase();
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("node_addr", &self.node_addr)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}
