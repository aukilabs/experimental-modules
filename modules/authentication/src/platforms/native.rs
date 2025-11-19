use crate::client::Client as CoreClient;
use crate::types::*;
use std::sync::{Arc, RwLock};

// Error types for UniFFI
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AuthError {
    #[error("JSON serialization error: {0}")]
    JsonError(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

// Re-export types for UniFFI
#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeConfig {
    pub api_url: String,
    pub refresh_url: String,
    pub dds_url: String,
    pub client_id: String,
    pub refresh_threshold_ms: u64,
}

impl From<NativeConfig> for Config {
    fn from(native_config: NativeConfig) -> Self {
        Config {
            api_url: native_config.api_url,
            refresh_url: native_config.refresh_url,
            dds_url: native_config.dds_url,
            client_id: native_config.client_id,
            refresh_threshold_ms: native_config.refresh_threshold_ms,
        }
    }
}

impl From<Config> for NativeConfig {
    fn from(config: Config) -> Self {
        NativeConfig {
            api_url: config.api_url,
            refresh_url: config.refresh_url,
            dds_url: config.dds_url,
            client_id: config.client_id,
            refresh_threshold_ms: config.refresh_threshold_ms,
        }
    }
}

// Credentials wrapper
#[derive(Clone, Debug, uniffi::Enum)]
pub enum NativeCredentials {
    EmailPassword { email: String, password: String },
    AppKey { app_key: String, app_secret: String },
    Opaque {
        token: String,
        refresh_token: Option<String>,
        expiry_ms: u64,
        refresh_token_expiry_ms: Option<u64>,
        oidc_client_id: Option<String>,
    },
}

impl From<NativeCredentials> for Credentials {
    fn from(native_creds: NativeCredentials) -> Self {
        match native_creds {
            NativeCredentials::EmailPassword { email, password } => {
                Credentials::EmailPassword { email, password }
            }
            NativeCredentials::AppKey {
                app_key,
                app_secret,
            } => Credentials::AppKey {
                app_key,
                app_secret,
            },
            NativeCredentials::Opaque {
                token,
                refresh_token,
                expiry_ms,
                refresh_token_expiry_ms,
                oidc_client_id,
            } => Credentials::Opaque {
                token,
                refresh_token,
                expiry_ms,
                refresh_token_expiry_ms,
                oidc_client_id,
            },
        }
    }
}

// Authentication state enum
#[derive(Clone, Debug, uniffi::Enum)]
pub enum NativeAuthenticationState {
    Authenticated,
    NeedsRefresh,
    NeedsAuthentication,
    NeedsCredentials,
}

impl From<AuthenticationState> for NativeAuthenticationState {
    fn from(state: AuthenticationState) -> Self {
        match state {
            AuthenticationState::Authenticated => NativeAuthenticationState::Authenticated,
            AuthenticationState::NeedsRefresh => NativeAuthenticationState::NeedsRefresh,
            AuthenticationState::NeedsAuthentication => {
                NativeAuthenticationState::NeedsAuthentication
            }
            AuthenticationState::NeedsCredentials => NativeAuthenticationState::NeedsCredentials,
        }
    }
}

// Domain server information
#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeDomainServer {
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

impl From<DomainServer> for NativeDomainServer {
    fn from(server: DomainServer) -> Self {
        NativeDomainServer {
            id: server.id,
            organization_id: server.organization_id,
            name: server.name,
            url: server.url,
            version: server.version,
            status: server.status,
            mode: server.mode,
            variants: server.variants,
            ip: server.ip,
            latitude: server.latitude,
            longitude: server.longitude,
            cloud_region: server.cloud_region,
        }
    }
}

// Domain access
#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeDomainAccess {
    pub id: String,
    pub name: String,
    pub organization_id: String,
    pub domain_server_id: String,
    pub access_token: String,
    pub expires_at: u64,
    pub domain_server: NativeDomainServer,
    pub owner_wallet_address: String,
}

impl From<DomainAccess> for NativeDomainAccess {
    fn from(access: DomainAccess) -> Self {
        NativeDomainAccess {
            id: access.id,
            name: access.name,
            organization_id: access.organization_id,
            domain_server_id: access.domain_server_id,
            access_token: access.access_token,
            expires_at: access.expires_at,
            domain_server: access.domain_server.into(),
            owner_wallet_address: access.owner_wallet_address,
        }
    }
}

// Network auth token
#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeNetworkAuth {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: u64,
}

impl From<NetworkAuth> for NativeNetworkAuth {
    fn from(auth: NetworkAuth) -> Self {
        NativeNetworkAuth {
            token: auth.token,
            refresh_token: auth.refresh_token,
            expires_at: auth.expires_at,
        }
    }
}

// Discovery auth token
#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeDiscoveryAuth {
    pub token: String,
    pub expires_at: u64,
}

impl From<DiscoveryAuth> for NativeDiscoveryAuth {
    fn from(auth: DiscoveryAuth) -> Self {
        NativeDiscoveryAuth {
            token: auth.token,
            expires_at: auth.expires_at,
        }
    }
}

// Client wrapper with thread-safe interior mutability
#[derive(uniffi::Object)]
pub struct NativeClient {
    inner: Arc<RwLock<CoreClient>>,
}

#[uniffi::export]
impl NativeClient {
    /// Create a new authentication client with only configuration
    /// Credentials are provided later when calling authenticate_with()
    #[uniffi::constructor]
    pub fn new(config: NativeConfig) -> Self {
        let core_client = CoreClient::new(config.into());
        NativeClient {
            inner: Arc::new(RwLock::new(core_client)),
        }
    }

    /// Create a client from saved state JSON
    #[uniffi::constructor]
    pub fn from_state(state_json: String, config: NativeConfig) -> Result<Self, AuthError> {
        let state: crate::state::ClientState = serde_json::from_str(&state_json)
            .map_err(|e| AuthError::InvalidState(format!("Invalid state JSON: {}", e)))?;

        let core_client = CoreClient::from_state(state, config.into());
        Ok(NativeClient {
            inner: Arc::new(RwLock::new(core_client)),
        })
    }

    /// Set or update credentials
    pub fn set_credentials(&self, credentials: NativeCredentials) {
        let mut client = self.inner.write().unwrap();
        client.set_credentials(credentials.into());
    }

    /// Check if client has credentials
    pub fn has_credentials(&self) -> bool {
        let client = self.inner.read().unwrap();
        client.has_credentials()
    }

    /// Check the current authentication state
    pub fn check_auth_state(&self, now_ms: u64) -> NativeAuthenticationState {
        let client = self.inner.read().unwrap();
        client.check_auth_state(now_ms).into()
    }

    /// Authenticate with specific credentials - returns actions to perform as JSON
    /// This will clear all existing tokens and authenticate as a new user
    pub fn authenticate_with(
        &self,
        credentials: NativeCredentials,
        now_ms: u64,
    ) -> Result<String, AuthError> {
        let mut client = self.inner.write().unwrap();
        let actions = client.authenticate_with(credentials.into(), now_ms);
        serde_json::to_string(&actions)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Switch to a different user by providing new credentials
    /// This is an alias for authenticate_with() that makes the intent clearer
    pub fn switch_user(
        &self,
        credentials: NativeCredentials,
        now_ms: u64,
    ) -> Result<String, AuthError> {
        let mut client = self.inner.write().unwrap();
        let actions = client.switch_user(credentials.into(), now_ms);
        serde_json::to_string(&actions)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Start network authentication using stored credentials - returns actions to perform as JSON
    pub fn authenticate(&self, now_ms: u64) -> Result<String, AuthError> {
        let mut client = self.inner.write().unwrap();
        let actions = client.authenticate(now_ms);
        serde_json::to_string(&actions)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Authenticate with discovery service - returns actions to perform as JSON
    pub fn authenticate_discovery(&self, now_ms: u64) -> Result<String, AuthError> {
        let mut client = self.inner.write().unwrap();
        let actions = client.authenticate_discovery(now_ms);
        serde_json::to_string(&actions)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Request access to a domain - returns actions to perform as JSON
    pub fn get_domain_access(&self, domain_id: String, now_ms: u64) -> Result<String, AuthError> {
        let mut client = self.inner.write().unwrap();
        let actions = client.get_domain_access(&domain_id, now_ms);
        serde_json::to_string(&actions)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Handle HTTP response - returns events as JSON
    pub fn handle_response(&self, status: u16, body: String) -> Result<String, AuthError> {
        let mut client = self.inner.write().unwrap();
        let events = client.handle_response(status, &body);
        serde_json::to_string(&events)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Get the current network token as JSON (if available)
    pub fn network_token(&self) -> Result<Option<String>, AuthError> {
        let client = self.inner.read().unwrap();
        match client.network_token() {
            Some(token) => serde_json::to_string(token)
                .map(Some)
                .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e))),
            None => Ok(None),
        }
    }

    /// Get the current discovery token as JSON (if available)
    pub fn discovery_token(&self) -> Result<Option<String>, AuthError> {
        let client = self.inner.read().unwrap();
        match client.discovery_token() {
            Some(token) => serde_json::to_string(token)
                .map(Some)
                .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e))),
            None => Ok(None),
        }
    }

    /// Get domain access information as JSON (if available)
    pub fn domain_access(&self, domain_id: String) -> Result<Option<String>, AuthError> {
        let client = self.inner.read().unwrap();
        match client.domain_access(&domain_id) {
            Some(access) => serde_json::to_string(access)
                .map(Some)
                .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e))),
            None => Ok(None),
        }
    }

    /// Get domain server information as JSON (if available)
    pub fn domain_server(&self, domain_id: String) -> Result<Option<String>, AuthError> {
        let client = self.inner.read().unwrap();
        match client.domain_server(&domain_id) {
            Some(server) => serde_json::to_string(server)
                .map(Some)
                .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e))),
            None => Ok(None),
        }
    }

    /// Get all domains as JSON array
    pub fn all_domains(&self) -> Result<String, AuthError> {
        let client = self.inner.read().unwrap();
        let domains: Vec<DomainAccess> = client.all_domains().into_iter().cloned().collect();
        serde_json::to_string(&domains)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Check if client is currently authenticated
    pub fn is_authenticated(&self, now_ms: u64) -> bool {
        let client = self.inner.read().unwrap();
        client.is_authenticated(now_ms)
    }

    /// Check if client requires credentials
    pub fn requires_credentials(&self, now_ms: u64) -> bool {
        let client = self.inner.read().unwrap();
        client.requires_credentials(now_ms)
    }

    /// Save the current state as JSON
    pub fn save_state(&self) -> Result<String, AuthError> {
        let client = self.inner.read().unwrap();
        client.save_state().map_err(|e| AuthError::InvalidState(e))
    }

    /// Validate current state and return events as JSON
    pub fn validate_state(&self, now_ms: u64) -> Result<String, AuthError> {
        let mut client = self.inner.write().unwrap();
        let events = client.validate_state(now_ms);
        serde_json::to_string(&events)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Force re-authentication and return events as JSON
    pub fn force_reauth(&self) -> Result<String, AuthError> {
        let mut client = self.inner.write().unwrap();
        let events = client.force_reauth();
        serde_json::to_string(&events)
            .map_err(|e| AuthError::JsonError(format!("Serialization error: {}", e)))
    }

    /// Clear domain access for a specific domain
    pub fn clear_domain_access(&self, domain_id: String) {
        let mut client = self.inner.write().unwrap();
        client.clear_domain_access(&domain_id);
    }

    /// Clear all domain accesses
    pub fn clear_all_domain_accesses(&self) {
        let mut client = self.inner.write().unwrap();
        client.clear_all_domain_accesses();
    }
}

// Utility functions
#[uniffi::export]
pub fn current_time_ms() -> u64 {
    crate::current_time_ms()
}

#[uniffi::export]
pub fn is_expired(expires_at: u64, now_ms: u64) -> bool {
    crate::is_expired(expires_at, now_ms)
}

#[uniffi::export]
pub fn is_near_expiry(expires_at: u64, threshold_ms: u64, now_ms: u64) -> bool {
    crate::is_near_expiry(expires_at, threshold_ms, now_ms)
}
