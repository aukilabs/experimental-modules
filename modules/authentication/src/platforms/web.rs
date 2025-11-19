use crate::client::Client;
use crate::types::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Re-export types with WASM bindings
#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmConfig {
    api_url: String,
    refresh_url: String,
    dds_url: String,
    client_id: String,
    refresh_threshold_ms: u64,
}

#[wasm_bindgen]
impl WasmConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(api_url: String, refresh_url: String, dds_url: String, client_id: String) -> WasmConfig {
        WasmConfig {
            api_url,
            refresh_url,
            dds_url,
            client_id,
            refresh_threshold_ms: 300_000, // 5 minutes default
        }
    }

    #[wasm_bindgen(getter)]
    pub fn api_url(&self) -> String {
        self.api_url.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_api_url(&mut self, api_url: String) {
        self.api_url = api_url;
    }

    #[wasm_bindgen(getter)]
    pub fn refresh_url(&self) -> String {
        self.refresh_url.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_refresh_url(&mut self, refresh_url: String) {
        self.refresh_url = refresh_url;
    }

    #[wasm_bindgen(getter)]
    pub fn dds_url(&self) -> String {
        self.dds_url.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_dds_url(&mut self, dds_url: String) {
        self.dds_url = dds_url;
    }

    #[wasm_bindgen(getter)]
    pub fn client_id(&self) -> String {
        self.client_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_client_id(&mut self, client_id: String) {
        self.client_id = client_id;
    }

    #[wasm_bindgen(getter)]
    pub fn refresh_threshold_ms(&self) -> u64 {
        self.refresh_threshold_ms
    }

    #[wasm_bindgen(setter)]
    pub fn set_refresh_threshold_ms(&mut self, refresh_threshold_ms: u64) {
        self.refresh_threshold_ms = refresh_threshold_ms;
    }
}

impl From<WasmConfig> for Config {
    fn from(wasm_config: WasmConfig) -> Self {
        Config {
            api_url: wasm_config.api_url,
            refresh_url: wasm_config.refresh_url,
            dds_url: wasm_config.dds_url,
            client_id: wasm_config.client_id,
            refresh_threshold_ms: wasm_config.refresh_threshold_ms,
        }
    }
}

impl From<Config> for WasmConfig {
    fn from(config: Config) -> Self {
        WasmConfig {
            api_url: config.api_url,
            refresh_url: config.refresh_url,
            dds_url: config.dds_url,
            client_id: config.client_id,
            refresh_threshold_ms: config.refresh_threshold_ms,
        }
    }
}

// Credentials wrapper - we don't expose the internal details for security
#[wasm_bindgen]
pub struct WasmCredentials(Credentials);

#[wasm_bindgen]
impl WasmCredentials {
    #[wasm_bindgen]
    pub fn email_password(email: String, password: String) -> WasmCredentials {
        WasmCredentials(Credentials::EmailPassword { email, password })
    }

    #[wasm_bindgen]
    pub fn app_key(app_key: String, app_secret: String) -> WasmCredentials {
        WasmCredentials(Credentials::AppKey {
            app_key,
            app_secret,
        })
    }

    #[wasm_bindgen]
    pub fn opaque(
        token: String,
        refresh_token: Option<String>,
        expiry_ms: u64,
        refresh_token_expiry_ms: Option<u64>,
        oidc_client_id: Option<String>,
    ) -> WasmCredentials {
        WasmCredentials(Credentials::Opaque {
            token,
            refresh_token,
            expiry_ms,
            refresh_token_expiry_ms,
            oidc_client_id,
        })
    }
}

// Authentication state enum
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WasmAuthenticationState {
    Authenticated,
    NeedsRefresh,
    NeedsAuthentication,
    NeedsCredentials,
}

impl From<AuthenticationState> for WasmAuthenticationState {
    fn from(state: AuthenticationState) -> Self {
        match state {
            AuthenticationState::Authenticated => WasmAuthenticationState::Authenticated,
            AuthenticationState::NeedsRefresh => WasmAuthenticationState::NeedsRefresh,
            AuthenticationState::NeedsAuthentication => {
                WasmAuthenticationState::NeedsAuthentication
            }
            AuthenticationState::NeedsCredentials => WasmAuthenticationState::NeedsCredentials,
        }
    }
}

// Client wrapper
#[wasm_bindgen]
pub struct WasmClient(Client);

#[wasm_bindgen]
impl WasmClient {
    /// Create a new client with only configuration
    /// Use set_credentials() to add credentials after creation
    #[wasm_bindgen(constructor)]
    pub fn new(config: &WasmConfig) -> WasmClient {
        WasmClient(Client::new(config.clone().into()))
    }

    /// Create a new client with credentials (convenience method)
    /// This is equivalent to: new WasmClient(config); client.set_credentials(credentials)
    #[wasm_bindgen]
    pub fn with_credentials(credentials: &WasmCredentials, config: &WasmConfig) -> WasmClient {
        let mut client = Client::new(config.clone().into());
        client.set_credentials(credentials.0.clone());
        WasmClient(client)
    }

    #[wasm_bindgen]
    pub fn from_state(state_json: &str, config: &WasmConfig) -> Result<WasmClient, JsValue> {
        let state: crate::state::ClientState = serde_json::from_str(state_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid state JSON: {}", e)))?;

        Ok(WasmClient(Client::from_state(state, config.clone().into())))
    }

    #[wasm_bindgen]
    pub fn set_credentials(&mut self, credentials: &WasmCredentials) {
        self.0.set_credentials(credentials.0.clone());
    }

    #[wasm_bindgen]
    pub fn has_credentials(&self) -> bool {
        self.0.has_credentials()
    }

    #[wasm_bindgen]
    pub fn check_auth_state(&self, now_ms: u64) -> WasmAuthenticationState {
        self.0.check_auth_state(now_ms).into()
    }

    #[wasm_bindgen]
    pub fn authenticate(&mut self, now_ms: u64) -> JsValue {
        let actions = self.0.authenticate(now_ms);
        serde_wasm_bindgen::to_value(&actions).expect("Failed to serialize actions")
    }

    #[wasm_bindgen]
    pub fn authenticate_discovery(&mut self, now_ms: u64) -> JsValue {
        let actions = self.0.authenticate_discovery(now_ms);
        serde_wasm_bindgen::to_value(&actions).expect("Failed to serialize actions")
    }

    #[wasm_bindgen]
    pub fn get_domain_access(&mut self, domain_id: &str, now_ms: u64) -> JsValue {
        let actions = self.0.get_domain_access(domain_id, now_ms);
        serde_wasm_bindgen::to_value(&actions).expect("Failed to serialize actions")
    }

    #[wasm_bindgen]
    pub fn handle_response(&mut self, status: u16, body: &str) -> JsValue {
        let events = self.0.handle_response(status, body);
        serde_wasm_bindgen::to_value(&events).expect("Failed to serialize events")
    }

    #[wasm_bindgen]
    pub fn network_token(&self) -> JsValue {
        match self.0.network_token() {
            Some(token) => serde_wasm_bindgen::to_value(token).expect("Failed to serialize token"),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen]
    pub fn discovery_token(&self) -> JsValue {
        match self.0.discovery_token() {
            Some(token) => serde_wasm_bindgen::to_value(token).expect("Failed to serialize token"),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen]
    pub fn domain_access(&self, domain_id: &str) -> JsValue {
        match self.0.domain_access(domain_id) {
            Some(access) => serde_wasm_bindgen::to_value(access).expect("Failed to serialize domain access"),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen]
    pub fn domain_server(&self, domain_id: &str) -> JsValue {
        match self.0.domain_server(domain_id) {
            Some(server) => serde_wasm_bindgen::to_value(server).expect("Failed to serialize server"),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen]
    pub fn all_domains(&self) -> JsValue {
        let domains: Vec<DomainAccess> = self.0.all_domains().into_iter().cloned().collect();
        serde_wasm_bindgen::to_value(&domains).expect("Failed to serialize domains")
    }

    #[wasm_bindgen]
    pub fn is_authenticated(&self, now_ms: u64) -> bool {
        self.0.is_authenticated(now_ms)
    }

    #[wasm_bindgen]
    pub fn requires_credentials(&self, now_ms: u64) -> bool {
        self.0.requires_credentials(now_ms)
    }

    #[wasm_bindgen]
    pub fn save_state(&self) -> Result<String, JsValue> {
        self.0.save_state().map_err(|e| JsValue::from_str(&e))
    }

    #[wasm_bindgen]
    pub fn validate_state(&mut self, now_ms: u64) -> JsValue {
        let events = self.0.validate_state(now_ms);
        serde_wasm_bindgen::to_value(&events).expect("Failed to serialize events")
    }

    #[wasm_bindgen]
    pub fn force_reauth(&mut self) -> JsValue {
        let events = self.0.force_reauth();
        serde_wasm_bindgen::to_value(&events).expect("Failed to serialize events")
    }

    #[wasm_bindgen]
    pub fn clear_domain_access(&mut self, domain_id: &str) {
        self.0.clear_domain_access(domain_id);
    }

    #[wasm_bindgen]
    pub fn clear_all_domain_accesses(&mut self) {
        self.0.clear_all_domain_accesses();
    }
}

// Utility functions
#[wasm_bindgen]
pub fn current_time_ms() -> u64 {
    crate::current_time_ms()
}

#[wasm_bindgen]
pub fn is_expired(expires_at: u64, now_ms: u64) -> bool {
    crate::is_expired(expires_at, now_ms)
}

#[wasm_bindgen]
pub fn is_near_expiry(expires_at: u64, threshold_ms: u64, now_ms: u64) -> bool {
    crate::is_near_expiry(expires_at, threshold_ms, now_ms)
}
