use alloy_primitives::{eip191_hash_message, Address, Signature};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::config::CONFIG;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid password format: expected 'timestamp:signature'")]
    InvalidFormat,
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Signature expired: {0}s old (max {1}s)")]
    SignatureExpired(u64, u64),
    #[error("Invalid signature hex")]
    InvalidSignatureHex,
    #[error("Signature recovery failed: {0}")]
    RecoveryFailed(String),
    #[error("Address mismatch: claimed {claimed}, recovered {recovered}")]
    AddressMismatch { claimed: String, recovered: String },
    #[error("Address not allowed: {0}")]
    AddressNotAllowed(String),
}

/// Verify ECDSA signature where the signed message is a timestamp.
/// Password format: "<timestamp>:<signature_hex>"
/// Address format: "0x..." (Ethereum address)
pub fn verify_signature(address: &str, password: &str) -> Result<(), AuthError> {
    // Parse password
    let (timestamp_str, sig_hex) = password
        .split_once(':')
        .ok_or(AuthError::InvalidFormat)?;
    
    let sig_hex = sig_hex.trim_end_matches('\0');
    
    // Parse and validate timestamp
    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| AuthError::InvalidTimestamp)?;
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let age = now.abs_diff(timestamp);
    if age > CONFIG.signature_window_secs {
        return Err(AuthError::SignatureExpired(age, CONFIG.signature_window_secs));
    }
    
    // Parse signature
    let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
    let sig_bytes = hex::decode(sig_hex).map_err(|_| AuthError::InvalidSignatureHex)?;
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| AuthError::RecoveryFailed(e.to_string()))?;
    
    // Recover address using EIP-191 personal_sign
    let message_hash = eip191_hash_message(timestamp_str);
    let recovered = signature
        .recover_address_from_prehash(&message_hash)
        .map_err(|e| AuthError::RecoveryFailed(e.to_string()))?;
    
    // Parse claimed address
    let claimed: Address = address
        .parse()
        .map_err(|_| AuthError::InvalidFormat)?;
    
    // Check recovered matches claimed
    if recovered != claimed {
        return Err(AuthError::AddressMismatch {
            claimed: claimed.to_string(),
            recovered: recovered.to_string(),
        });
    }
    
    // Check address is allowed
    let allowed = Address::from(CONFIG.allowed_address);
    if recovered != allowed {
        return Err(AuthError::AddressNotAllowed(recovered.to_string()));
    }
    
    Ok(())
}
