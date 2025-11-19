use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum JwtError {
    DecodeError(String),
    MissingExpiry,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::DecodeError(msg) => write!(f, "JWT decode error: {}", msg),
            JwtError::MissingExpiry => write!(f, "JWT is missing 'exp' claim"),
        }
    }
}

impl std::error::Error for JwtError {}

#[derive(Deserialize)]
struct Claims {
    exp: u64, // seconds since epoch
}

/// Decode the expiry time from a JWT token without verification
/// Returns expiry time in milliseconds since epoch
///
/// This implementation uses base64 decoding only and works across all platforms
/// including WASM. We don't verify signatures since we trust the server.
pub fn decode_expiry(token: &str) -> Result<u64, JwtError> {
    // JWT tokens are base64url encoded and have 3 parts separated by dots: header.payload.signature
    // We only care about the payload which contains the 'exp' claim
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::DecodeError("Invalid JWT format - expected 3 parts".to_string()));
    }

    // Decode the payload (second part)
    let payload = parts[1];

    // JWT uses base64url encoding, we need to convert it to standard base64
    let payload_standard = payload
        .replace('-', "+")
        .replace('_', "/");

    // Add padding if needed
    let padding = match payload_standard.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    let payload_padded = format!("{}{}", payload_standard, padding);

    // Decode base64
    use base64::prelude::*;
    let decoded = BASE64_STANDARD
        .decode(payload_padded.as_bytes())
        .map_err(|e| JwtError::DecodeError(format!("Base64 decode error: {}", e)))?;

    // Parse JSON
    let claims: Claims = serde_json::from_slice(&decoded)
        .map_err(|e| JwtError::DecodeError(format!("JSON parse error: {}", e)))?;

    // Convert seconds to milliseconds
    Ok(claims.exp * 1000)
}

/// Get current time in milliseconds since epoch
pub fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before UNIX epoch")
        .as_millis() as u64
}

/// Check if a token is expired given the current time
pub fn is_expired(expires_at: u64, now_ms: u64) -> bool {
    now_ms >= expires_at
}

/// Check if a token is near expiry (within threshold) given the current time
pub fn is_near_expiry(expires_at: u64, now_ms: u64, threshold_ms: u64) -> bool {
    let time_until_expiry = expires_at.saturating_sub(now_ms);
    time_until_expiry <= threshold_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample JWT token for testing (from jwt.io)
    // Payload: {"sub":"1234567890","name":"Test User","exp":1893456000}
    const SAMPLE_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImV4cCI6MTg5MzQ1NjAwMH0.4Adcj0prsvKvD6AO2rKz8Y1iRvQtt3RLPqOJG1hLhRo";

    #[test]
    fn test_decode_expiry_success() {
        let expiry = decode_expiry(SAMPLE_JWT).unwrap();
        // Expected: 1893456000 seconds = 1893456000000 milliseconds
        assert_eq!(expiry, 1893456000000);
    }

    #[test]
    fn test_decode_expiry_invalid_format() {
        let result = decode_expiry("invalid.token");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::DecodeError(_)));
    }

    #[test]
    fn test_decode_expiry_invalid_base64() {
        let result = decode_expiry("header.!!!invalid!!!.signature");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::DecodeError(_)));
    }

    #[test]
    fn test_decode_expiry_invalid_json() {
        let result = decode_expiry("header.novalidjson.signature");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::DecodeError(_)));
    }

    #[test]
    fn test_current_time_ms() {
        let now = current_time_ms();
        // Should be a reasonable timestamp (after 2020)
        assert!(now > 1577836800000); // Jan 1, 2020
        // Should be before year 2100
        assert!(now < 4102444800000); // Jan 1, 2100
    }

    #[test]
    fn test_is_expired() {
        let now = current_time_ms();

        // Token that expired 1 second ago
        assert!(is_expired(now - 1000, now));

        // Token that expires in 1 second
        assert!(!is_expired(now + 1000, now));

        // Token that expires right now
        assert!(is_expired(now, now));
    }

    #[test]
    fn test_is_near_expiry() {
        let now = current_time_ms();

        // Token expires in 1 minute, threshold is 5 minutes
        assert!(is_near_expiry(now + 60_000, now, 300_000));

        // Token expires in 10 minutes, threshold is 5 minutes
        assert!(!is_near_expiry(now + 600_000, now, 300_000));

        // Token already expired
        assert!(is_near_expiry(now - 1000, now, 300_000));

        // Token expires exactly at threshold
        assert!(is_near_expiry(now + 300_000, now, 300_000));
    }

    #[test]
    fn test_time_calculations_no_overflow() {
        // Test with edge cases to ensure no overflow
        let now = current_time_ms();
        let very_far_future = u64::MAX - 1000;
        assert!(!is_expired(very_far_future, now));

        // Near expiry should handle saturation
        assert!(!is_near_expiry(very_far_future, now, 500));
    }

    #[test]
    fn test_decode_real_token_format() {
        // Test with the actual token format from your API
        // This token has exp: 1762329067 (seconds)
        let real_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZXMiOlsiZG9tYWluOnJ3Il0sImRvbWFpbl9pZCI6ImQ0ZGUwNWI2LTRiNDYtNDA3NS1iMzQ3LTA3OTM4YzVmMDA3NiIsIm9yZyI6IjExOTY3OGEyLTQ2NzYtNDg4ZC1iYzY3LWE2NWRmZDZkODVlNSIsInR5cGUiOiJ1c2VyLWFjY2VzcyIsImlzcyI6ImRkcyIsInN1YiI6IjU0ZDk5YzI3LTI2MTItNGZlZS05MjVhLWE2ZTNkYWNjMzY5YyIsImF1ZCI6WyJkZHMiLCJodHRwczovL2FwLWVhc3QtMS5kb21haW5zLnByb2QuYXVraXZlcnNlLmNvbSJdLCJleHAiOjE3NjIzMjkwNjcsImlhdCI6MTc2MjMyNTQ2N30.idMENNrBCT9qeBcKtTHHzdhmPYxh0oYGFlF3Z8jh9uaI6RY4Om5sFFNh_tH58bz0eNlTCepxvRsVY80v6vVjtQ";

        let expiry = decode_expiry(real_token).unwrap();
        // Expected: 1762329067 seconds = 1762329067000 milliseconds
        assert_eq!(expiry, 1762329067000);
    }
}
