use crate::jwt::{decode_expiry, is_expired, is_near_expiry};
#[cfg(test)]
use crate::jwt::current_time_ms;
use crate::state::ClientState;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// User agent for all HTTP requests
const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION")
);

// Response types for deserialization
#[derive(Deserialize, Serialize)]
struct NetworkAuthResponse {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    expires_in: Option<u64>, // OAuth response: expiry duration in seconds
}

#[derive(Deserialize)]
struct DiscoveryAuthResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct DomainAccessResponse {
    id: String,
    name: String,
    organization_id: String,
    domain_server_id: String,
    access_token: String,
    domain_server: DomainServerResponse,
    owner_wallet_address: String,
}

#[derive(Deserialize)]
struct DomainServerResponse {
    id: String,
    organization_id: String,
    name: String,
    url: String,
    version: String,
    status: String,
    mode: String,
    variants: Vec<String>,
    ip: String,
    latitude: f64,
    longitude: f64,
    cloud_region: String,
}

pub struct Client {
    credentials: Option<Credentials>,
    config: Config,
    state: ClientState,
}

impl Client {
    /// Create a new client with only configuration
    /// Credentials are provided later when calling authenticate_with()
    pub fn new(config: Config) -> Self {
        Self {
            credentials: None,
            config,
            state: ClientState::new(),
        }
    }

    /// Create a client from saved state
    /// Note: Credentials are not included in saved state for security
    pub fn from_state(state: ClientState, config: Config) -> Self {
        Self {
            credentials: None,
            config,
            state,
        }
    }

    /// Set credentials (useful after restoring from state)
    pub fn set_credentials(&mut self, credentials: Credentials) {
        self.credentials = Some(credentials);
    }

    /// Check if the client has credentials
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Get the current authentication state
    ///
    /// # Arguments
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn check_auth_state(&self, now_ms: u64) -> AuthenticationState {
        if !self.is_network_token_valid(now_ms) {
            if self.credentials.is_some() {
                AuthenticationState::NeedsAuthentication
            } else {
                AuthenticationState::NeedsCredentials
            }
        } else if self.should_refresh_network_token(now_ms) {
            AuthenticationState::NeedsRefresh
        } else {
            AuthenticationState::Authenticated
        }
    }

    // ========== Token Validation ==========

    fn should_refresh_network_token(&self, now_ms: u64) -> bool {
        match &self.state.network_auth {
            None => true,
            Some(auth) => {
                if is_expired(auth.expires_at, now_ms) {
                    true
                } else {
                    is_near_expiry(auth.expires_at, now_ms, self.config.refresh_threshold_ms)
                }
            }
        }
    }

    fn is_network_token_valid(&self, now_ms: u64) -> bool {
        match &self.state.network_auth {
            None => false,
            Some(auth) => !is_expired(auth.expires_at, now_ms),
        }
    }

    fn is_discovery_token_valid(&self, now_ms: u64) -> bool {
        match &self.state.discovery_auth {
            None => false,
            Some(auth) => !is_expired(auth.expires_at, now_ms),
        }
    }

    fn is_domain_access_valid(&self, domain_id: &str, now_ms: u64) -> bool {
        match self.state.domain_accesses.get(domain_id) {
            None => false,
            Some(access) => !is_expired(access.expires_at, now_ms),
        }
    }

    fn invalidate_all_tokens(&mut self) {
        self.state.clear_all();
    }

    fn invalidate_discovery_chain(&mut self) {
        self.state.clear_discovery_chain();
    }

    // ========== Request Builders ==========

    fn build_email_password_auth(&self, email: &str, password: &str) -> Action {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("User-Agent".to_string(), USER_AGENT.to_string());

        Action::HttpRequest {
            url: format!("{}/user/login", self.config.api_url),
            method: "POST".to_string(),
            headers,
            body: Some(serde_json::json!({
                "email": email,
                "password": password,
            }).to_string()),
        }
    }


    fn build_token_refresh(&self, refresh_token: &str) -> Action {
        // Check if we're using OAuth/OIDC credentials (opaque with oidc_client_id)
        if let Some(Credentials::Opaque { oidc_client_id: Some(client_id), .. }) = &self.credentials {
            // OAuth/OIDC refresh flow - use form-urlencoded with grant_type=refresh_token
            let body = format!(
                "grant_type=refresh_token&refresh_token={}&client_id={}",
                refresh_token, client_id
            );

            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
            headers.insert("User-Agent".to_string(), USER_AGENT.to_string());

            Action::HttpRequest {
                url: self.config.refresh_url.clone(),
                method: "POST".to_string(),
                headers,
                body: Some(body),
            }
        } else {
            // Standard refresh flow - use Bearer token in Authorization header
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("User-Agent".to_string(), USER_AGENT.to_string());
            headers.insert("Authorization".to_string(), format!("Bearer {}", refresh_token));

            Action::HttpRequest {
                url: self.config.refresh_url.clone(),
                method: "POST".to_string(),
                headers,
                body: None,
            }
        }
    }

    fn build_discovery_auth(&self, network_token: &str) -> Action {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("User-Agent".to_string(), USER_AGENT.to_string());

        // If token already has an auth scheme (Basic, Bearer), use it as-is
        // Otherwise, add Bearer prefix (for JWT tokens from email/password auth)
        let auth_header = if network_token.starts_with("Basic ") || network_token.starts_with("Bearer ") {
            network_token.to_string()
        } else {
            format!("Bearer {}", network_token)
        };
        headers.insert("Authorization".to_string(), auth_header);

        Action::HttpRequest {
            url: format!("{}/service/domains-access-token", self.config.api_url),
            method: "POST".to_string(),
            headers,
            body: Some("{}".to_string()),
        }
    }

    fn build_domain_access(&self, domain_id: &str, discovery_token: &str) -> Action {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("User-Agent".to_string(), USER_AGENT.to_string());
        headers.insert("Authorization".to_string(), format!("Bearer {}", discovery_token));
        headers.insert("posemesh-client-id".to_string(), self.config.client_id.clone());

        Action::HttpRequest {
            url: format!("{}/api/v1/domains/{}/auth", self.config.dds_url, domain_id),
            method: "POST".to_string(),
            headers,
            body: Some("{}".to_string()),
        }
    }

    // ========== Public API Methods ==========

    /// Authenticate to the Auki network with specific credentials
    /// This will clear all existing tokens and authenticate as a new user
    ///
    /// # Arguments
    /// * `credentials` - The credentials to authenticate with
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn authenticate_with(&mut self, credentials: Credentials, now_ms: u64) -> Vec<Action> {
        // Clear all tokens when switching credentials
        self.invalidate_all_tokens();
        self.credentials = Some(credentials);
        self.authenticate(now_ms)
    }

    /// Switch to a different user by providing new credentials
    /// This is an alias for authenticate_with() that makes the intent clearer
    ///
    /// # Arguments
    /// * `credentials` - The credentials for the new user
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn switch_user(&mut self, credentials: Credentials, now_ms: u64) -> Vec<Action> {
        self.authenticate_with(credentials, now_ms)
    }

    /// Authenticate to the Auki network using stored credentials
    /// Returns actions to be performed by the caller
    ///
    /// # Arguments
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn authenticate(&mut self, now_ms: u64) -> Vec<Action> {
        // If we have a valid token and it's not near expiry, nothing to do
        if self.is_network_token_valid(now_ms) && !self.should_refresh_network_token(now_ms) {
            return vec![];
        }

        // Try to refresh if we have a refresh token (works for both expired and near-expiry tokens)
        // The refresh token itself may still be valid even if the access token is expired
        if let Some(network_auth) = &self.state.network_auth {
            if !network_auth.refresh_token.is_empty() {
                self.state.pending_operations.push_back(Operation::NetworkRefresh);
                return vec![self.build_token_refresh(&network_auth.refresh_token)];
            }
        }

        // Need fresh authentication with credentials (no refresh token available)
        if let Some(credentials) = &self.credentials {
            match credentials {
                Credentials::EmailPassword { email, password } => {
                    self.state.pending_operations.push_back(Operation::NetworkAuth);
                    vec![self.build_email_password_auth(email, password)]
                }
                Credentials::AppKey { app_key, app_secret } => {
                    // AppKey/AppSecret IS the network token and never expires
                    // Encode as Basic auth: base64(app_key:app_secret)
                    use base64::prelude::*;
                    let credentials = format!("{}:{}", app_key, app_secret);
                    let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
                    let far_future = now_ms + (100 * 365 * 24 * 60 * 60 * 1000); // 100 years in ms
                    self.state.network_auth = Some(NetworkAuth {
                        token: format!("Basic {}", encoded),
                        refresh_token: String::new(),
                        expires_at: far_future,
                    });
                    vec![]
                }
                Credentials::Opaque {
                    token,
                    refresh_token,
                    expiry_ms,
                    refresh_token_expiry_ms: _,
                    oidc_client_id: _,
                } => {
                    // Opaque token is already a network token (from OAuth flow)
                    // The OIDC client ID is stored in credentials for use during refresh
                    self.state.network_auth = Some(NetworkAuth {
                        token: token.clone(),
                        refresh_token: refresh_token.clone().unwrap_or_default(),
                        expires_at: *expiry_ms,
                    });
                    vec![]
                }
            }
        } else {
            // No credentials available
            vec![]
        }
    }

    /// Authenticate to the Discovery service
    /// Automatically handles network authentication if needed
    ///
    /// # Arguments
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn authenticate_discovery(&mut self, now_ms: u64) -> Vec<Action> {
        let mut actions = vec![];

        // Ensure network token is valid
        if !self.is_network_token_valid(now_ms) {
            actions.extend(self.authenticate(now_ms));
        }

        // If discovery token is still valid, nothing to do
        if self.is_discovery_token_valid(now_ms) {
            return actions;
        }

        // Need to authenticate to discovery
        if let Some(network_auth) = &self.state.network_auth {
            self.state.pending_operations.push_back(Operation::DiscoveryAuth);
            actions.push(self.build_discovery_auth(&network_auth.token));
        }

        actions
    }

    /// Get access to a specific domain
    /// Automatically handles the full authentication chain if needed
    ///
    /// # Arguments
    /// * `domain_id` - The ID of the domain to access
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn get_domain_access(&mut self, domain_id: &str, now_ms: u64) -> Vec<Action> {
        let mut actions = vec![];

        // Ensure network token is valid
        if !self.is_network_token_valid(now_ms) {
            actions.extend(self.authenticate(now_ms));
            // Return early - caller needs to execute network auth/refresh first
            // before we can use the network token for discovery auth
            return actions;
        }

        // Ensure discovery token is valid
        if !self.is_discovery_token_valid(now_ms) {
            if let Some(network_auth) = &self.state.network_auth {
                self.state.pending_operations.push_back(Operation::DiscoveryAuth);
                actions.push(self.build_discovery_auth(&network_auth.token));
            }
            // Return early - caller needs to execute discovery auth first
            // before we can use the discovery token for domain access
            return actions;
        }

        // Check if we already have valid domain access
        if self.is_domain_access_valid(domain_id, now_ms) {
            return actions;
        }

        // Need to get domain access
        if let Some(discovery_auth) = &self.state.discovery_auth {
            self.state.pending_operations.push_back(Operation::DomainAccess {
                domain_id: domain_id.to_string(),
            });
            actions.push(self.build_domain_access(domain_id, &discovery_auth.token));
        }

        actions
    }

    /// Handle HTTP response from the caller
    /// Returns events based on the response
    pub fn handle_response(&mut self, status: u16, body: &str) -> Vec<Event> {
        // Dequeue the next pending operation
        let operation = match self.state.pending_operations.pop_front() {
            Some(op) => op,
            None => return vec![],
        };

        match operation {
            Operation::NetworkAuth => self.handle_network_auth_response(status, body),
            Operation::NetworkRefresh => self.handle_token_refresh_response(status, body),
            Operation::DiscoveryAuth => self.handle_discovery_auth_response(status, body),
            Operation::DomainAccess { domain_id } => {
                self.handle_domain_access_response(&domain_id, status, body)
            }
        }
    }

    // ========== Response Handlers ==========

    fn handle_network_auth_response(&mut self, status: u16, body: &str) -> Vec<Event> {
        if status != 200 {
            return vec![Event::NetworkAuthFailed {
                reason: format!("HTTP {}: {}", status, body),
                retry_possible: status >= 500,
            }];
        }

        match serde_json::from_str::<NetworkAuthResponse>(body) {
            Ok(response) => match decode_expiry(&response.access_token) {
                Ok(expires_at) => {
                    self.state.network_auth = Some(NetworkAuth {
                        token: response.access_token.clone(),
                        refresh_token: response.refresh_token.clone(),
                        expires_at,
                    });

                    // Clear credentials after successful authentication
                    // We now have a refresh token, so credentials are no longer needed
                    // This prevents automatic re-authentication when refresh token expires
                    if !response.refresh_token.is_empty() {
                        self.credentials = None;
                    }

                    vec![Event::NetworkAuthSuccess {
                        token: response.access_token,
                        expires_at,
                    }]
                }
                Err(e) => vec![Event::NetworkAuthFailed {
                    reason: format!("Failed to decode token: {}", e),
                    retry_possible: false,
                }],
            },
            Err(e) => vec![Event::NetworkAuthFailed {
                reason: format!("Invalid response: {}", e),
                retry_possible: false,
            }],
        }
    }

    fn handle_token_refresh_response(&mut self, status: u16, body: &str) -> Vec<Event> {
        if status != 200 {
            self.invalidate_all_tokens();
            return vec![
                Event::NetworkTokenRefreshFailed {
                    reason: format!("HTTP {}: {}", status, body),
                    requires_reauth: true,
                },
                Event::AuthenticationRequired,
            ];
        }

        match serde_json::from_str::<NetworkAuthResponse>(body) {
            Ok(response) => {
                // Try to get expiry from expires_in (OAuth response) or decode JWT
                let expires_at_result = if let Some(expires_in) = response.expires_in {
                    // OAuth response with expires_in (seconds from now)
                    let now_ms = crate::current_time_ms();
                    Ok(now_ms + (expires_in * 1000))
                } else {
                    // JWT token - decode expiry from token
                    decode_expiry(&response.access_token)
                };

                match expires_at_result {
                    Ok(expires_at) => {
                        self.state.network_auth = Some(NetworkAuth {
                            token: response.access_token.clone(),
                            refresh_token: response.refresh_token,
                            expires_at,
                        });

                        vec![Event::NetworkTokenRefreshed {
                            token: response.access_token,
                            expires_at,
                        }]
                    }
                    Err(e) => {
                        self.invalidate_all_tokens();
                        vec![
                            Event::NetworkTokenRefreshFailed {
                                reason: format!("Failed to decode token: {}", e),
                                requires_reauth: true,
                            },
                            Event::AuthenticationRequired,
                        ]
                    }
                }
            }
            Err(e) => {
                self.invalidate_all_tokens();
                vec![
                    Event::NetworkTokenRefreshFailed {
                        reason: format!("Invalid response: {}", e),
                        requires_reauth: true,
                    },
                    Event::AuthenticationRequired,
                ]
            }
        }
    }

    fn handle_discovery_auth_response(&mut self, status: u16, body: &str) -> Vec<Event> {
        if status != 200 {
            return vec![Event::DiscoveryAuthFailed {
                reason: format!("HTTP {}: {}", status, body),
            }];
        }

        match serde_json::from_str::<DiscoveryAuthResponse>(body) {
            Ok(response) => match decode_expiry(&response.access_token) {
                Ok(expires_at) => {
                    self.state.discovery_auth = Some(DiscoveryAuth {
                        token: response.access_token.clone(),
                        expires_at,
                    });

                    vec![Event::DiscoveryAuthSuccess {
                        token: response.access_token,
                        expires_at,
                    }]
                }
                Err(e) => vec![Event::DiscoveryAuthFailed {
                    reason: format!("Failed to decode token: {}", e),
                }],
            },
            Err(e) => vec![Event::DiscoveryAuthFailed {
                reason: format!("Invalid response: {}", e),
            }],
        }
    }

    fn handle_domain_access_response(
        &mut self,
        domain_id: &str,
        status: u16,
        body: &str,
    ) -> Vec<Event> {
        if status != 200 {
            return vec![Event::DomainAccessDenied {
                domain_id: domain_id.to_string(),
                reason: format!("HTTP {}: {}", status, body),
            }];
        }

        match serde_json::from_str::<DomainAccessResponse>(body) {
            Ok(response) => match decode_expiry(&response.access_token) {
                Ok(expires_at) => {
                    let domain_access = DomainAccess {
                        id: response.id,
                        name: response.name,
                        organization_id: response.organization_id,
                        domain_server_id: response.domain_server_id,
                        access_token: response.access_token,
                        expires_at,
                        domain_server: DomainServer {
                            id: response.domain_server.id,
                            organization_id: response.domain_server.organization_id,
                            name: response.domain_server.name,
                            url: response.domain_server.url,
                            version: response.domain_server.version,
                            status: response.domain_server.status,
                            mode: response.domain_server.mode,
                            variants: response.domain_server.variants,
                            ip: response.domain_server.ip,
                            latitude: response.domain_server.latitude,
                            longitude: response.domain_server.longitude,
                            cloud_region: response.domain_server.cloud_region,
                        },
                        owner_wallet_address: response.owner_wallet_address,
                    };

                    self.state
                        .domain_accesses
                        .insert(domain_id.to_string(), domain_access.clone());

                    vec![Event::DomainAccessGranted {
                        domain: domain_access,
                    }]
                }
                Err(e) => vec![Event::DomainAccessDenied {
                    domain_id: domain_id.to_string(),
                    reason: format!("Failed to decode token: {}", e),
                }],
            },
            Err(e) => vec![Event::DomainAccessDenied {
                domain_id: domain_id.to_string(),
                reason: format!("Invalid response: {}", e),
            }],
        }
    }

    // ========== State Accessors ==========

    /// Get the network authentication token
    pub fn network_token(&self) -> Option<&NetworkAuth> {
        self.state.network_auth.as_ref()
    }

    /// Get the discovery authentication token
    pub fn discovery_token(&self) -> Option<&DiscoveryAuth> {
        self.state.discovery_auth.as_ref()
    }

    /// Get domain access information
    pub fn domain_access(&self, domain_id: &str) -> Option<&DomainAccess> {
        self.state.domain_accesses.get(domain_id)
    }

    /// Get domain server information
    pub fn domain_server(&self, domain_id: &str) -> Option<&DomainServer> {
        self.state
            .domain_accesses
            .get(domain_id)
            .map(|access| &access.domain_server)
    }

    /// Get all cached domain accesses
    pub fn all_domains(&self) -> Vec<&DomainAccess> {
        self.state.domain_accesses.values().collect()
    }

    /// Check if authenticated to the network
    /// Check if authenticated
    ///
    /// # Arguments
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn is_authenticated(&self, now_ms: u64) -> bool {
        self.is_network_token_valid(now_ms)
    }

    /// Check if credentials are required
    ///
    /// # Arguments
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn requires_credentials(&self, now_ms: u64) -> bool {
        self.credentials.is_none() && !self.is_network_token_valid(now_ms)
    }

    // ========== State Management ==========

    /// Save the current state to JSON
    /// Note: Credentials are not included for security
    pub fn save_state(&self) -> Result<String, String> {
        serde_json::to_string(&self.state).map_err(|e| format!("Serialization error: {}", e))
    }

    /// Validate state after loading
    /// Returns events for any expired tokens
    ///
    /// # Arguments
    /// * `now_ms` - Current time in milliseconds since epoch
    pub fn validate_state(&mut self, now_ms: u64) -> Vec<Event> {
        let mut events = vec![];

        // Check network token
        if let Some(network_auth) = &self.state.network_auth {
            if is_expired(network_auth.expires_at, now_ms) {
                events.push(Event::TokensInvalidated);
                events.push(Event::AuthenticationRequired);
                self.invalidate_all_tokens();
                return events;
            }
        }

        // Check discovery token
        if let Some(discovery_auth) = &self.state.discovery_auth {
            if is_expired(discovery_auth.expires_at, now_ms) {
                self.invalidate_discovery_chain();
            }
        }

        // Check domain tokens
        let expired_domains: Vec<String> = self
            .state
            .domain_accesses
            .iter()
            .filter(|(_, access)| is_expired(access.expires_at, now_ms))
            .map(|(id, _)| id.clone())
            .collect();

        for domain_id in expired_domains {
            self.state.domain_accesses.remove(&domain_id);
        }

        events
    }

    /// Force re-authentication (clears all tokens)
    pub fn force_reauth(&mut self) -> Vec<Event> {
        self.invalidate_all_tokens();
        vec![Event::TokensInvalidated, Event::AuthenticationRequired]
    }

    /// Clear a specific domain access
    pub fn clear_domain_access(&mut self, domain_id: &str) {
        self.state.domain_accesses.remove(domain_id);
    }

    /// Clear all domain accesses
    pub fn clear_all_domain_accesses(&mut self) {
        self.state.domain_accesses.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_config() -> Config {
        Config {
            api_url: "https://api.test.com".to_string(),
            refresh_url: "https://api.test.com/user/refresh".to_string(),
            dds_url: "https://dds.test.com".to_string(),
            client_id: "test-client-id".to_string(),
            refresh_threshold_ms: 300_000, // 5 minutes
        }
    }

    fn create_test_credentials() -> Credentials {
        Credentials::EmailPassword {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        }
    }

    // Helper to create a JWT with a specific expiry
    fn create_jwt_with_expiry(expires_at_seconds: u64) -> String {
        use base64::prelude::*;
        let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, expires_at_seconds));
        format!("{}.{}.fake_signature", header, payload)
    }

    #[test]
    fn test_client_creation() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);

        assert!(!client.has_credentials());
        assert_eq!(client.check_auth_state(now), AuthenticationState::NeedsCredentials);

        // Set credentials
        client.set_credentials(credentials);
        assert!(client.has_credentials());
        assert!(!client.is_authenticated(now));
        assert_eq!(client.check_auth_state(now), AuthenticationState::NeedsAuthentication);
    }

    #[test]
    fn test_client_from_state_without_credentials() {
        let now = current_time_ms();
        let state = ClientState::new();
        let config = create_test_config();
        let client = Client::from_state(state, config);

        assert!(!client.has_credentials());
        assert!(client.requires_credentials(now));
        assert_eq!(client.check_auth_state(now), AuthenticationState::NeedsCredentials);
    }

    #[test]
    fn test_authenticate_returns_actions() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config.clone());

        let actions = client.authenticate_with(credentials, now);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::HttpRequest { url, method, body, .. } => {
                assert_eq!(url, &format!("{}/user/login", config.api_url));
                assert_eq!(method, "POST");
                assert!(body.is_some());
                let body_json: serde_json::Value = serde_json::from_str(body.as_ref().unwrap()).unwrap();
                assert_eq!(body_json["email"], "test@example.com");
                assert_eq!(body_json["password"], "password123");
            }
            _ => panic!("Expected HttpRequest action"),
        }
    }

    #[test]
    fn test_authenticate_with_app_key() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = Credentials::AppKey {
            app_key: "test_app_key".to_string(),
            app_secret: "test_app_secret".to_string(),
        };
        let mut client = Client::new(config.clone());
        client.set_credentials(credentials);

        let actions = client.authenticate(now);

        // AppKey credentials don't require HTTP requests - they ARE the token
        assert_eq!(actions.len(), 0);
        assert!(client.is_authenticated(now));

        let network_token = client.network_token().unwrap();
        // Token should be encoded as Basic auth: "Basic base64(app_key:app_secret)"
        use base64::prelude::*;
        let expected = format!("Basic {}", BASE64_STANDARD.encode(b"test_app_key:test_app_secret"));
        assert_eq!(network_token.token, expected);
        // Should have a far future expiry
        assert!(network_token.expires_at > now + (50 * 365 * 24 * 60 * 60 * 1000));
    }

    #[test]
    fn test_authenticate_with_opaque_token() {
        let now = current_time_ms();
        let config = create_test_config();
        let expiry = current_time_ms() + 3600_000;
        let credentials = Credentials::Opaque {
            token: "opaque_token_12345".to_string(),
            refresh_token: Some("refresh_token_67890".to_string()),
            expiry_ms: expiry,
            refresh_token_expiry_ms: Some(expiry + 7200_000),
            oidc_client_id: Some("test_client_id".to_string()),
        };
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let actions = client.authenticate(now);

        assert_eq!(actions.len(), 0);
        assert!(client.is_authenticated(now));

        let network_token = client.network_token().unwrap();
        assert_eq!(network_token.token, "opaque_token_12345");
        assert_eq!(network_token.expires_at, expiry);
    }

    #[test]
    fn test_state_machine_network_auth_success() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let actions = client.authenticate(now);
        assert_eq!(actions.len(), 1);

        let future_expiry = (current_time_ms() / 1000) + 3600;
        let access_token = create_jwt_with_expiry(future_expiry);
        let refresh_token = create_jwt_with_expiry(future_expiry + 7200);

        let response_body = json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
        }).to_string();

        let events = client.handle_response(200, &response_body);

        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Event::NetworkAuthSuccess { .. }));

        assert!(client.is_authenticated(now));
        assert!(client.network_token().is_some());
    }

    #[test]
    fn test_state_machine_network_auth_failure() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        client.authenticate(now);

        let events = client.handle_response(401, "Unauthorized");

        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::NetworkAuthFailed { reason, retry_possible } => {
                assert!(reason.contains("401"));
                assert!(!retry_possible);
            }
            _ => panic!("Expected NetworkAuthFailed event"),
        }

        assert!(!client.is_authenticated(now));
    }

    #[test]
    fn test_token_refresh_when_near_expiry() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let near_expiry = current_time_ms() + 60_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "test_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: near_expiry,
        });

        let actions = client.authenticate(now);
        assert_eq!(actions.len(), 1);

        match &actions[0] {
            Action::HttpRequest { url, headers, .. } => {
                assert!(url.contains("/user/refresh"));
                assert!(headers.get("Authorization").unwrap().contains("refresh_token"));
            }
            _ => panic!("Expected HttpRequest for refresh"),
        }
    }

    #[test]
    fn test_token_refresh_success() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let near_expiry = current_time_ms() + 60_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "old_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: near_expiry,
        });

        client.authenticate(now);

        let future_expiry = (current_time_ms() / 1000) + 3600;
        let new_access_token = create_jwt_with_expiry(future_expiry);
        let new_refresh_token = create_jwt_with_expiry(future_expiry + 7200);

        let response_body = json!({
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        }).to_string();

        let events = client.handle_response(200, &response_body);

        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Event::NetworkTokenRefreshed { .. }));

        let network_token = client.network_token().unwrap();
        assert_eq!(network_token.token, new_access_token);
    }

    #[test]
    fn test_token_refresh_failure_requires_reauth() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        client.state.network_auth = Some(NetworkAuth {
            token: "old_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: current_time_ms() + 60_000,
        });

        client.authenticate(now);

        let events = client.handle_response(401, "Refresh token expired");

        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::NetworkTokenRefreshFailed { .. }));
        assert!(matches!(events[1], Event::AuthenticationRequired));

        assert!(client.network_token().is_none());
        assert!(!client.is_authenticated(now));
    }

    #[test]
    fn test_discovery_auth_chain() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config.clone());
        client.set_credentials(credentials);

        let future_expiry = current_time_ms() + 3600_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "network_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: future_expiry,
        });

        let actions = client.authenticate_discovery(now);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::HttpRequest { url, headers, .. } => {
                assert_eq!(url, &format!("{}/service/domains-access-token", config.api_url));
                assert_eq!(headers.get("Authorization").unwrap(), "Bearer network_token");
            }
            _ => panic!("Expected HttpRequest action"),
        }
    }

    #[test]
    fn test_discovery_auth_without_network_token() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        // With auto-chaining, discovery auth automatically includes network auth
        let actions = client.authenticate_discovery(now);
        assert!(actions.len() >= 1, "Should auto-chain network auth");

        // First action should be network authentication
        match &actions[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains("/user/login"));
            }
            _ => panic!("Expected network auth first"),
        }
    }

    #[test]
    fn test_domain_access_full_chain() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let actions = client.get_domain_access("test-domain", now);

        assert!(actions.len() >= 1);
    }

    #[test]
    fn test_domain_access_with_valid_tokens() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config.clone());
        client.set_credentials(credentials);

        let future_expiry = current_time_ms() + 3600_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "network_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: future_expiry,
        });
        client.state.discovery_auth = Some(DiscoveryAuth {
            token: "discovery_token".to_string(),
            expires_at: future_expiry,
        });

        let actions = client.get_domain_access("test-domain", now);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::HttpRequest { url, headers, method, .. } => {
                assert_eq!(url, &format!("{}/api/v1/domains/test-domain/auth", config.dds_url));
                assert_eq!(method, "POST");
                assert_eq!(headers.get("Authorization").unwrap(), "Bearer discovery_token");
                assert_eq!(headers.get("posemesh-client-id").unwrap(), "test-client-id");
            }
            _ => panic!("Expected domain access request"),
        }
    }

    #[test]
    fn test_cached_domain_access_not_refetched() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let future_expiry = current_time_ms() + 3600_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "network_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: future_expiry,
        });
        client.state.discovery_auth = Some(DiscoveryAuth {
            token: "discovery_token".to_string(),
            expires_at: future_expiry,
        });

        client.state.domain_accesses.insert(
            "test-domain".to_string(),
            DomainAccess {
                id: "test-domain".to_string(),
                name: "Test Domain".to_string(),
                organization_id: "org123".to_string(),
                domain_server_id: "server123".to_string(),
                access_token: "domain_token".to_string(),
                expires_at: future_expiry,
                domain_server: DomainServer {
                    id: "server123".to_string(),
                    organization_id: "org123".to_string(),
                    name: "Test Server".to_string(),
                    url: "https://server.test.com".to_string(),
                    version: "1.0".to_string(),
                    status: "online".to_string(),
                    mode: "public".to_string(),
                    variants: vec![],
                    ip: "127.0.0.1".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    cloud_region: "us-east-1".to_string(),
                },
                owner_wallet_address: "".to_string(),
            },
        );

        let actions = client.get_domain_access("test-domain", now);

        assert_eq!(actions.len(), 0);

        assert!(client.domain_access("test-domain").is_some());
    }

    #[test]
    fn test_expired_domain_access_refetched() {
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config.clone());
        client.set_credentials(credentials);

        let future_expiry = current_time_ms() + 3600_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "network_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: future_expiry,
        });
        client.state.discovery_auth = Some(DiscoveryAuth {
            token: "discovery_token".to_string(),
            expires_at: future_expiry,
        });

        client.state.domain_accesses.insert(
            "test-domain".to_string(),
            DomainAccess {
                id: "test-domain".to_string(),
                name: "Test Domain".to_string(),
                organization_id: "org123".to_string(),
                domain_server_id: "server123".to_string(),
                access_token: "expired_token".to_string(),
                expires_at: current_time_ms() - 1000,
                domain_server: DomainServer {
                    id: "server123".to_string(),
                    organization_id: "org123".to_string(),
                    name: "Test Server".to_string(),
                    url: "https://server.test.com".to_string(),
                    version: "1.0".to_string(),
                    status: "online".to_string(),
                    mode: "public".to_string(),
                    variants: vec![],
                    ip: "127.0.0.1".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    cloud_region: "us-east-1".to_string(),
                },
                owner_wallet_address: "".to_string(),
            },
        );

        let actions = client.get_domain_access("test-domain", now);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::HttpRequest { url, .. } => {
                assert_eq!(url, &format!("{}/api/v1/domains/test-domain/auth", config.dds_url));
            }
            _ => panic!("Expected domain access request"),
        }
    }

    #[test]
    fn test_cascading_token_invalidation() {
        let _now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let future_expiry = current_time_ms() + 3600_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "network_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: future_expiry,
        });
        client.state.discovery_auth = Some(DiscoveryAuth {
            token: "discovery_token".to_string(),
            expires_at: future_expiry,
        });
        client.state.domain_accesses.insert(
            "domain1".to_string(),
            DomainAccess {
                id: "domain1".to_string(),
                name: "Domain 1".to_string(),
                organization_id: "org123".to_string(),
                domain_server_id: "server123".to_string(),
                access_token: "domain_token".to_string(),
                expires_at: future_expiry,
                domain_server: DomainServer {
                    id: "server123".to_string(),
                    organization_id: "org123".to_string(),
                    name: "Test Server".to_string(),
                    url: "https://server.test.com".to_string(),
                    version: "1.0".to_string(),
                    status: "online".to_string(),
                    mode: "public".to_string(),
                    variants: vec![],
                    ip: "127.0.0.1".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    cloud_region: "us-east-1".to_string(),
                },
                owner_wallet_address: "".to_string(),
            },
        );

        let events = client.force_reauth();

        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::TokensInvalidated));
        assert!(matches!(events[1], Event::AuthenticationRequired));

        assert!(client.network_token().is_none());
        assert!(client.discovery_token().is_none());
        assert!(client.domain_access("domain1").is_none());
    }

    #[test]
    fn test_state_serialization_roundtrip() {
        let _now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config.clone());
        client.set_credentials(credentials);

        let future_expiry = current_time_ms() + 3600_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "network_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: future_expiry,
        });

        let saved_state = client.save_state().unwrap();

        let state: ClientState = serde_json::from_str(&saved_state).unwrap();
        let restored_client = Client::from_state(state, config);

        assert!(restored_client.network_token().is_some());
        assert_eq!(
            restored_client.network_token().unwrap().token,
            "network_token"
        );

        assert!(!restored_client.has_credentials());
    }

    #[test]
    fn test_validate_state_after_restore() {
        let now = current_time_ms();
        let config = create_test_config();
        let mut client_state = ClientState::new();

        client_state.network_auth = Some(NetworkAuth {
            token: "expired_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: current_time_ms() - 1000,
        });

        let mut client = Client::from_state(client_state, config);
        let events = client.validate_state(now);

        assert!(events.len() >= 2);
        assert!(events.iter().any(|e| matches!(e, Event::TokensInvalidated)));
        assert!(events.iter().any(|e| matches!(e, Event::AuthenticationRequired)));

        assert!(client.network_token().is_none());
    }

    #[test]
    fn test_expired_network_token_uses_refresh() {
        // Test that when network token is expired, we use refresh_token instead of re-authenticating
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        // Set an expired token with a refresh_token
        let expired_time = now - 1000; // 1 second ago
        client.state.network_auth = Some(NetworkAuth {
            token: "expired_token".to_string(),
            refresh_token: "valid_refresh_token".to_string(),
            expires_at: expired_time,
        });

        // Calling authenticate should use refresh, not re-authenticate
        let actions = client.authenticate(now);
        assert_eq!(actions.len(), 1, "Should generate one refresh action");

        match &actions[0] {
            Action::HttpRequest { url, headers, method, .. } => {
                assert_eq!(method, "POST");
                assert!(url.contains("/user/refresh"), "Should call refresh endpoint, got: {}", url);
                assert!(headers.get("Authorization").unwrap().contains("valid_refresh_token"),
                    "Should use refresh_token in Authorization header");
            }
            _ => panic!("Expected HttpRequest for token refresh"),
        }
    }

    #[test]
    fn test_full_expiration_chain_network_discovery_domain() {
        // Test the full chain: all tokens expired
        // get_domain_access should trigger: network refresh -> discovery re-auth -> domain re-auth
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let expired_time = now - 1000;
        let domain_id = "test-domain-123";

        // Set all tokens as expired
        client.state.network_auth = Some(NetworkAuth {
            token: "expired_network_token".to_string(),
            refresh_token: "network_refresh_token".to_string(),
            expires_at: expired_time,
        });

        client.state.discovery_auth = Some(DiscoveryAuth {
            token: "expired_discovery_token".to_string(),
            expires_at: expired_time,
        });

        client.state.domain_accesses.insert(
            domain_id.to_string(),
            DomainAccess {
                id: domain_id.to_string(),
                name: "Test Domain".to_string(),
                organization_id: "org-1".to_string(),
                domain_server_id: "server-1".to_string(),
                access_token: "expired_domain_token".to_string(),
                expires_at: expired_time,
                owner_wallet_address: "0x123".to_string(),
                domain_server: DomainServer {
                    id: "server-1".to_string(),
                    organization_id: "org-1".to_string(),
                    name: "Test Server".to_string(),
                    url: "https://test.server.com".to_string(),
                    version: "1.0.0".to_string(),
                    status: "active".to_string(),
                    mode: "production".to_string(),
                    variants: vec![],
                    ip: "1.2.3.4".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    cloud_region: "us-west-1".to_string(),
                },
            },
        );

        // Call get_domain_access - with new early-return behavior,
        // should only return network refresh action first
        let actions = client.get_domain_access(domain_id, now);

        assert_eq!(actions.len(), 1, "Should generate only network refresh action (early return)");

        // Verify first action is network refresh
        match &actions[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains("/user/refresh"), "First action should be network token refresh");
            }
            _ => panic!("Expected HttpRequest for network token refresh"),
        }

        // Simulate successful network token refresh
        let future_expiry = (now / 1000) + 3600; // 1 hour from now (in seconds)
        let new_access_token = create_jwt_with_expiry(future_expiry);
        let new_refresh_token = create_jwt_with_expiry(future_expiry + 7200);
        let refresh_response = format!(
            r#"{{"access_token":"{}","refresh_token":"{}"}}"#,
            new_access_token, new_refresh_token
        );
        let events = client.handle_response(200, &refresh_response);
        assert!(events.iter().any(|e| matches!(e, Event::NetworkTokenRefreshed { .. })));

        // Call get_domain_access again - should now return discovery auth action
        let actions2 = client.get_domain_access(domain_id, now);
        assert_eq!(actions2.len(), 1, "Should generate only discovery auth action (early return)");

        match &actions2[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains("/service/domains-access-token"),
                    "Second action should be discovery auth");
            }
            _ => panic!("Expected HttpRequest for discovery auth"),
        }

        // Simulate successful discovery auth
        let discovery_token = create_jwt_with_expiry(future_expiry);
        let discovery_response = format!(r#"{{"access_token":"{}"}}"#, discovery_token);
        let events = client.handle_response(200, &discovery_response);
        assert!(events.iter().any(|e| matches!(e, Event::DiscoveryAuthSuccess { .. })));

        // Call get_domain_access again - should now return domain access action
        let actions3 = client.get_domain_access(domain_id, now);
        assert_eq!(actions3.len(), 1, "Should generate domain access action");

        match &actions3[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains(&format!("/api/v1/domains/{}", domain_id)),
                    "Third action should be domain access request");
            }
            _ => panic!("Expected HttpRequest for domain access"),
        }
    }

    #[test]
    fn test_partial_expiration_chain_only_domain_expired() {
        // Test partial chain: only domain expired, network and discovery valid
        // get_domain_access should only trigger: domain re-auth
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let valid_time = now + 3600_000; // 1 hour from now
        let expired_time = now - 1000; // 1 second ago
        let domain_id = "test-domain-123";

        // Network and discovery tokens are valid
        client.state.network_auth = Some(NetworkAuth {
            token: "valid_network_token".to_string(),
            refresh_token: "network_refresh_token".to_string(),
            expires_at: valid_time,
        });

        client.state.discovery_auth = Some(DiscoveryAuth {
            token: "valid_discovery_token".to_string(),
            expires_at: valid_time,
        });

        // Only domain token is expired
        client.state.domain_accesses.insert(
            domain_id.to_string(),
            DomainAccess {
                id: domain_id.to_string(),
                name: "Test Domain".to_string(),
                organization_id: "org-1".to_string(),
                domain_server_id: "server-1".to_string(),
                access_token: "expired_domain_token".to_string(),
                expires_at: expired_time,
                owner_wallet_address: "0x123".to_string(),
                domain_server: DomainServer {
                    id: "server-1".to_string(),
                    organization_id: "org-1".to_string(),
                    name: "Test Server".to_string(),
                    url: "https://test.server.com".to_string(),
                    version: "1.0.0".to_string(),
                    status: "active".to_string(),
                    mode: "production".to_string(),
                    variants: vec![],
                    ip: "1.2.3.4".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    cloud_region: "us-west-1".to_string(),
                },
            },
        );

        // Call get_domain_access - should only generate domain auth action
        let actions = client.get_domain_access(domain_id, now);

        assert_eq!(actions.len(), 1, "Should only generate 1 action for domain auth");

        match &actions[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains(&format!("/api/v1/domains/{}", domain_id)),
                    "Should only request domain access");
            }
            _ => panic!("Expected HttpRequest for domain access"),
        }
    }

    #[test]
    fn test_partial_expiration_chain_domain_and_discovery_expired() {
        // Test partial chain: domain and discovery expired, network valid
        // get_domain_access should trigger: discovery re-auth -> domain re-auth
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        let valid_time = now + 3600_000; // 1 hour from now
        let expired_time = now - 1000; // 1 second ago
        let domain_id = "test-domain-123";

        // Network token is valid
        client.state.network_auth = Some(NetworkAuth {
            token: "valid_network_token".to_string(),
            refresh_token: "network_refresh_token".to_string(),
            expires_at: valid_time,
        });

        // Discovery token is expired
        client.state.discovery_auth = Some(DiscoveryAuth {
            token: "expired_discovery_token".to_string(),
            expires_at: expired_time,
        });

        // Domain token is expired
        client.state.domain_accesses.insert(
            domain_id.to_string(),
            DomainAccess {
                id: domain_id.to_string(),
                name: "Test Domain".to_string(),
                organization_id: "org-1".to_string(),
                domain_server_id: "server-1".to_string(),
                access_token: "expired_domain_token".to_string(),
                expires_at: expired_time,
                owner_wallet_address: "0x123".to_string(),
                domain_server: DomainServer {
                    id: "server-1".to_string(),
                    organization_id: "org-1".to_string(),
                    name: "Test Server".to_string(),
                    url: "https://test.server.com".to_string(),
                    version: "1.0.0".to_string(),
                    status: "active".to_string(),
                    mode: "production".to_string(),
                    variants: vec![],
                    ip: "1.2.3.4".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    cloud_region: "us-west-1".to_string(),
                },
            },
        );

        // Call get_domain_access - with new early-return behavior,
        // should only return discovery auth action first
        let actions = client.get_domain_access(domain_id, now);

        assert_eq!(actions.len(), 1, "Should generate only discovery auth action (early return)");

        match &actions[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains("/service/domains-access-token"),
                    "First action should be discovery auth");
            }
            _ => panic!("Expected HttpRequest for discovery auth"),
        }

        // Simulate successful discovery auth
        let future_expiry = (now / 1000) + 3600; // 1 hour from now (in seconds)
        let discovery_token = create_jwt_with_expiry(future_expiry);
        let discovery_response = format!(r#"{{"access_token":"{}"}}"#, discovery_token);
        let events = client.handle_response(200, &discovery_response);
        assert!(events.iter().any(|e| matches!(e, Event::DiscoveryAuthSuccess { .. })));

        // Call get_domain_access again - should now return domain access action
        let actions2 = client.get_domain_access(domain_id, now);
        assert_eq!(actions2.len(), 1, "Should generate domain access action");

        match &actions2[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains(&format!("/api/v1/domains/{}", domain_id)),
                    "Second action should be domain access request");
            }
            _ => panic!("Expected HttpRequest for domain access"),
        }
    }

    #[test]
    fn test_no_refresh_token_falls_back_to_reauth() {
        // Test that when network token is expired but has NO refresh_token,
        // we fall back to full re-authentication
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);
        client.set_credentials(credentials);

        // Set an expired token WITHOUT a refresh_token (e.g., opaque token)
        let expired_time = now - 1000;
        client.state.network_auth = Some(NetworkAuth {
            token: "expired_opaque_token".to_string(),
            refresh_token: String::new(), // No refresh token
            expires_at: expired_time,
        });

        // Calling authenticate should do full re-auth since no refresh_token
        let actions = client.authenticate(now);
        assert_eq!(actions.len(), 1);

        match &actions[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains("/user/login"),
                    "Should fall back to full authentication when no refresh_token");
            }
            _ => panic!("Expected HttpRequest for full authentication"),
        }
    }

    #[test]
    fn test_switch_user_clears_tokens() {
        // Test that switching users clears all existing tokens
        let now = current_time_ms();
        let config = create_test_config();
        let credentials1 = Credentials::EmailPassword {
            email: "user1@example.com".to_string(),
            password: "password1".to_string(),
        };
        let credentials2 = Credentials::EmailPassword {
            email: "user2@example.com".to_string(),
            password: "password2".to_string(),
        };

        let mut client = Client::new(config.clone());

        // Authenticate as user1
        let actions = client.authenticate_with(credentials1, now);
        assert_eq!(actions.len(), 1);

        // Simulate successful authentication
        let future_expiry = current_time_ms() + 3600_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "user1_token".to_string(),
            refresh_token: "user1_refresh".to_string(),
            expires_at: future_expiry,
        });
        client.state.discovery_auth = Some(DiscoveryAuth {
            token: "user1_discovery".to_string(),
            expires_at: future_expiry,
        });

        assert!(client.is_authenticated(now));

        // Switch to user2 - should clear all tokens
        let actions = client.switch_user(credentials2, now);
        assert_eq!(actions.len(), 1);

        // Verify all tokens were cleared
        assert!(client.state.network_auth.is_none());
        assert!(client.state.discovery_auth.is_none());
        assert!(client.state.domain_accesses.is_empty());

        // Verify the action is for user2
        match &actions[0] {
            Action::HttpRequest { body, .. } => {
                let body_json: serde_json::Value = serde_json::from_str(body.as_ref().unwrap()).unwrap();
                assert_eq!(body_json["email"], "user2@example.com");
                assert_eq!(body_json["password"], "password2");
            }
            _ => panic!("Expected HttpRequest action"),
        }
    }

    #[test]
    fn test_credentials_cleared_after_successful_auth_with_refresh_token() {
        // Test that credentials are cleared after successful authentication when refresh token is received
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = create_test_credentials();
        let mut client = Client::new(config);

        // Initial state: no credentials
        assert!(!client.has_credentials());

        // Authenticate with credentials
        let actions = client.authenticate_with(credentials, now);
        assert_eq!(actions.len(), 1);

        // Credentials should now be set
        assert!(client.has_credentials());

        // Simulate successful authentication response with refresh token
        let future_expiry = (current_time_ms() / 1000) + 3600;
        let access_token = create_jwt_with_expiry(future_expiry);
        let refresh_token = create_jwt_with_expiry(future_expiry + 7200);

        let response = NetworkAuthResponse {
            access_token,
            refresh_token: refresh_token.clone(),
            expires_in: None,
        };
        let response_json = serde_json::to_string(&response).unwrap();

        let events = client.handle_response(200, &response_json);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Event::NetworkAuthSuccess { .. }));

        // Credentials should now be cleared since we have a refresh token
        assert!(!client.has_credentials(), "Credentials should be cleared after successful auth with refresh token");

        // Token should be valid
        assert!(client.is_authenticated(now));
        assert!(client.network_token().is_some());
    }

    #[test]
    fn test_credentials_not_cleared_for_appkey_auth() {
        // AppKey credentials should NOT be cleared since they don't go through HTTP auth flow
        let now = current_time_ms();
        let config = create_test_config();
        let credentials = Credentials::AppKey {
            app_key: "test_app_key".to_string(),
            app_secret: "test_app_secret".to_string(),
        };
        let mut client = Client::new(config);

        // Authenticate with app key
        let actions = client.authenticate_with(credentials, now);

        // AppKey credentials set token directly (no HTTP request)
        assert_eq!(actions.len(), 0);
        assert!(client.is_authenticated(now));

        // AppKey credentials should still be present since they don't go through handle_response
        // where credentials are cleared
        assert!(client.has_credentials(), "AppKey credentials should remain after successful auth");
    }

    #[test]
    fn test_no_reauth_when_refresh_fails_without_credentials() {
        // Test that when refresh fails and credentials have been cleared, we get AuthenticationRequired
        let now = current_time_ms();
        let config = create_test_config();
        let _credentials = create_test_credentials();
        let mut client = Client::new(config);

        // Simulate a client restored from state (has tokens but no credentials)
        let near_expiry = current_time_ms() + 60_000;
        client.state.network_auth = Some(NetworkAuth {
            token: "expired_token".to_string(),
            refresh_token: "expired_refresh_token".to_string(),
            expires_at: near_expiry,
        });
        // Important: NO credentials set
        assert!(!client.has_credentials());

        // Try to authenticate (will attempt refresh)
        let actions = client.authenticate(now);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::HttpRequest { url, .. } => {
                assert!(url.contains("/refresh"), "Should attempt token refresh");
            }
            _ => panic!("Expected HttpRequest for refresh"),
        }

        // Simulate refresh failure
        let events = client.handle_response(401, "Refresh token expired");

        // Should get NetworkTokenRefreshFailed and AuthenticationRequired events
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::NetworkTokenRefreshFailed { requires_reauth: true, .. }));
        assert!(matches!(events[1], Event::AuthenticationRequired));

        // All tokens should be invalidated
        assert!(!client.is_authenticated(now));
        assert!(client.network_token().is_none());

        // Try to authenticate again - should return empty actions since no credentials
        let actions = client.authenticate(now);
        assert_eq!(actions.len(), 0, "Should not attempt re-authentication without credentials");
    }
}
