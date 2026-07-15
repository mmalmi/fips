fn validate_compressed_pubkey_addr(addr: &TransportAddr) -> Result<(), TransportError> {
    let Some(s) = addr.as_str() else {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be UTF-8 compressed pubkey hex".into(),
        ));
    };
    validate_compressed_pubkey_hex(s)
}

fn validate_compressed_pubkey_hex(s: &str) -> Result<(), TransportError> {
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
    Ok(())
}

fn xonly_from_compressed_hex(s: &str) -> Result<PublicKey, TransportError> {
    validate_compressed_pubkey_hex(s)?;
    let bytes = hex::decode(s).map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
    PublicKey::from_slice(&bytes[1..]).map_err(|e| TransportError::InvalidAddress(e.to_string()))
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
