#[cfg(test)]
fn validate_compressed_pubkey_hex(s: &str) -> Result<(), TransportError> {
    compressed_pubkey_from_hex(s).map(drop)
}

fn compressed_pubkey_from_hex(s: &str) -> Result<secp256k1::PublicKey, TransportError> {
    if s.len() != 66 {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be 33-byte compressed pubkey hex".into(),
        ));
    }
    let bytes = hex::decode(s).map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
    if bytes.len() != 33 || !matches!(bytes[0], 0x02 | 0x03) {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be compressed secp256k1 pubkey".into(),
        ));
    }
    secp256k1::PublicKey::from_slice(&bytes)
        .map_err(|e| TransportError::InvalidAddress(e.to_string()))
}

pub(crate) fn canonical_webrtc_pubkey_hex(pubkey: secp256k1::PublicKey) -> String {
    let (xonly, _) = pubkey.x_only_public_key();
    hex::encode(xonly.public_key(secp256k1::Parity::Even).serialize())
}

pub(crate) fn canonical_webrtc_addr(
    addr: &TransportAddr,
) -> Result<TransportAddr, TransportError> {
    let Some(s) = addr.as_str() else {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be UTF-8 compressed pubkey hex".into(),
        ));
    };
    let pubkey = compressed_pubkey_from_hex(s)?;
    Ok(TransportAddr::from_string(&canonical_webrtc_pubkey_hex(
        pubkey,
    )))
}

fn xonly_from_compressed_hex(s: &str) -> Result<PublicKey, TransportError> {
    let (xonly, _) = compressed_pubkey_from_hex(s)?.x_only_public_key();
    PublicKey::from_slice(&xonly.serialize())
        .map_err(|e| TransportError::InvalidAddress(e.to_string()))
}

fn random_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    hex::encode(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
