use super::*;
use rand::Rng;
use secp256k1::Parity;

fn generate_keypair() -> secp256k1::Keypair {
    let secp = secp256k1::Secp256k1::new();
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes)
        .expect("32 random bytes is a valid secret key");
    secp256k1::Keypair::from_secret_key(&secp, &secret_key)
}

fn generate_epoch() -> [u8; 8] {
    let mut epoch = [0u8; 8];
    rand::rng().fill_bytes(&mut epoch);
    epoch
}

mod counter;
mod ik;
mod ik_parity;
mod replay;
mod xk_core;
mod xk_errors;
