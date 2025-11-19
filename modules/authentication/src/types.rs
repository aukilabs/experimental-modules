use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Credentials for authentication to the Auki network.
/// Note: Credentials are never serialized to maintain security.
#[derive(Clone, Debug)]
pub enum Credentials {
    /// Email and password authentication - requires HTTP request to obtain network token
    EmailPassword { email: String, password: String },
    /// App key and secret authentication - IS the network token, never expires
    /// The key:secret pair is used directly as the Bearer token for all requests
    AppKey { app_key: String, app_secret: String },
    /// Opaque token with manual expiry (for OAuth/OIDC use) - IS the network token
    /// Used when authentication happens via external OAuth flow
    Opaque {
        token: String,
        refresh_token: Option<String>,
        expiry_ms: u64,
        refresh_token_expiry_ms: Option<u64>,
        oidc_client_id: Option<String>,
    },
}

/// Configuration for the authentication client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// API URL for network authentication
    pub api_url: String,
    /// Complete refresh URL for token refresh (e.g., https://api.aukiverse.com/user/refresh)
    /// For opaque credentials, this may point to a different endpoint
    pub refresh_url: String,
    /// Discovery service URL
    pub dds_url: String,
    /// Client ID for Posemesh requests
    pub client_id: String,
    /// Token refresh threshold in milliseconds
    /// Tokens will be refreshed if expiry is within this time
    #[serde(default = "default_refresh_threshold")]
    pub refresh_threshold_ms: u64,
}

fn default_refresh_threshold() -> u64 {
    300_000 // 5 minutes
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_url: String::new(),
            refresh_url: String::new(),
            dds_url: String::new(),
            client_id: String::new(),
            refresh_threshold_ms: default_refresh_threshold(),
        }
    }
}

/// Network authentication token with refresh capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAuth {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: u64, // milliseconds since epoch
}

/// Discovery service authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryAuth {
    pub token: String,
    pub expires_at: u64, // milliseconds since epoch
}

/// Domain server information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainServer {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub url: String,
    pub version: String,
    pub status: String,
    pub mode: String,
    pub variants: Vec<String>,
    pub ip: String,
    pub latitude: f64,
    pub longitude: f64,
    pub cloud_region: String,
}

/// Domain access information with token and server details
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainAccess {
    pub id: String,
    pub name: String,
    pub organization_id: String,
    pub domain_server_id: String,
    pub access_token: String,
    pub expires_at: u64, // milliseconds since epoch
    pub domain_server: DomainServer,
    pub owner_wallet_address: String,
}

/// Actions to be performed by the caller
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    /// Make an HTTP request
    HttpRequest {
        url: String,
        method: String,
        headers: HashMap<String, String>,
        body: Option<String>,
    },
    /// Wait for a duration before retrying
    Wait { duration_ms: u64 },
}

/// Events emitted by the client
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Event {
    // Network authentication
    NetworkAuthSuccess {
        token: String,
        expires_at: u64,
    },
    NetworkAuthFailed {
        reason: String,
        retry_possible: bool,
    },

    // Token refresh
    NetworkTokenRefreshed {
        token: String,
        expires_at: u64,
    },
    NetworkTokenRefreshFailed {
        reason: String,
        requires_reauth: bool,
    },

    // Discovery authentication
    DiscoveryAuthSuccess {
        token: String,
        expires_at: u64,
    },
    DiscoveryAuthFailed {
        reason: String,
    },

    // Domain access
    DomainAccessGranted {
        domain: DomainAccess,
    },
    DomainAccessDenied {
        domain_id: String,
        reason: String,
    },

    // State changes
    AuthenticationRequired,
    TokensInvalidated,
}

/// Authentication state for the user to check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationState {
    /// Client is authenticated with valid tokens
    Authenticated,
    /// Network token needs refresh (proactive)
    NeedsRefresh,
    /// Has credentials but needs to call authenticate()
    NeedsAuthentication,
    /// No credentials available, user must provide them
    NeedsCredentials,
}

/// Internal operation tracking
#[derive(Debug, Clone)]
pub(crate) enum Operation {
    NetworkAuth,
    NetworkRefresh,
    DiscoveryAuth,
    DomainAccess { domain_id: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.refresh_threshold_ms, 300_000);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            api_url: "https://api.test.com".to_string(),
            refresh_url: "https://api.test.com/user/refresh".to_string(),
            dds_url: "https://dds.test.com".to_string(),
            client_id: "test-client".to_string(),
            refresh_threshold_ms: 600_000,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(config.api_url, deserialized.api_url);
        assert_eq!(config.dds_url, deserialized.dds_url);
        assert_eq!(config.refresh_threshold_ms, deserialized.refresh_threshold_ms);
    }

    #[test]
    fn test_credentials_not_serializable() {
        // Credentials should not implement Serialize
        // This test ensures we don't accidentally add it
        fn assert_not_serialize<T>() {}
        assert_not_serialize::<Credentials>();
    }

    #[test]
    fn test_network_auth_serialization() {
        let auth = NetworkAuth {
            token: "test_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: 1234567890,
        };

        let json = serde_json::to_string(&auth).unwrap();
        let deserialized: NetworkAuth = serde_json::from_str(&json).unwrap();

        assert_eq!(auth.token, deserialized.token);
        assert_eq!(auth.refresh_token, deserialized.refresh_token);
        assert_eq!(auth.expires_at, deserialized.expires_at);
    }

    #[test]
    fn test_action_equality() {
        let action1 = Action::HttpRequest {
            url: "https://test.com".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: Some("test".to_string()),
        };

        let action2 = Action::HttpRequest {
            url: "https://test.com".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: Some("test".to_string()),
        };

        assert_eq!(action1, action2);
    }
}
