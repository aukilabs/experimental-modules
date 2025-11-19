use crate::types::{DiscoveryAuth, DomainAccess, NetworkAuth, Operation};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Client state that can be serialized and restored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientState {
    pub(crate) network_auth: Option<NetworkAuth>,
    pub(crate) discovery_auth: Option<DiscoveryAuth>,
    pub(crate) domain_accesses: HashMap<String, DomainAccess>,

    /// Queue of pending operations (supports batching multiple actions)
    #[serde(skip)]
    pub(crate) pending_operations: VecDeque<Operation>,
}

impl ClientState {
    pub fn new() -> Self {
        Self {
            network_auth: None,
            discovery_auth: None,
            domain_accesses: HashMap::new(),
            pending_operations: VecDeque::new(),
        }
    }

    pub fn clear_all(&mut self) {
        self.network_auth = None;
        self.discovery_auth = None;
        self.domain_accesses.clear();
        self.pending_operations.clear();
    }

    pub fn clear_discovery_chain(&mut self) {
        self.discovery_auth = None;
        self.domain_accesses.clear();
    }
}

impl Default for ClientState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DomainServer;

    #[test]
    fn test_state_serialization() {
        let mut state = ClientState::new();

        state.network_auth = Some(NetworkAuth {
            token: "test_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_at: 1234567890,
        });

        state.discovery_auth = Some(DiscoveryAuth {
            token: "discovery_token".to_string(),
            expires_at: 1234567890,
        });

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ClientState = serde_json::from_str(&json).unwrap();

        assert_eq!(
            state.network_auth.as_ref().unwrap().token,
            deserialized.network_auth.as_ref().unwrap().token
        );
        assert_eq!(
            state.discovery_auth.as_ref().unwrap().token,
            deserialized.discovery_auth.as_ref().unwrap().token
        );
    }

    #[test]
    fn test_state_serialization_excludes_pending_operations() {
        let mut state = ClientState::new();
        state.pending_operations.push_back(Operation::NetworkAuth);

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ClientState = serde_json::from_str(&json).unwrap();

        // pending_operations should be skipped in serialization
        assert!(deserialized.pending_operations.is_empty());
    }

    #[test]
    fn test_clear_all() {
        let mut state = ClientState::new();
        state.network_auth = Some(NetworkAuth {
            token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: 123,
        });
        state.discovery_auth = Some(DiscoveryAuth {
            token: "test".to_string(),
            expires_at: 123,
        });

        state.clear_all();

        assert!(state.network_auth.is_none());
        assert!(state.discovery_auth.is_none());
        assert!(state.domain_accesses.is_empty());
    }

    #[test]
    fn test_clear_discovery_chain() {
        let mut state = ClientState::new();
        state.network_auth = Some(NetworkAuth {
            token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: 123,
        });
        state.discovery_auth = Some(DiscoveryAuth {
            token: "test".to_string(),
            expires_at: 123,
        });

        state.domain_accesses.insert(
            "domain1".to_string(),
            DomainAccess {
                id: "domain1".to_string(),
                name: "Test Domain".to_string(),
                organization_id: "org1".to_string(),
                domain_server_id: "server1".to_string(),
                access_token: "token".to_string(),
                expires_at: 123,
                domain_server: DomainServer {
                    id: "server1".to_string(),
                    organization_id: "org1".to_string(),
                    name: "Server 1".to_string(),
                    url: "https://server1.com".to_string(),
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

        state.clear_discovery_chain();

        // Network auth should remain
        assert!(state.network_auth.is_some());
        // Discovery and domains should be cleared
        assert!(state.discovery_auth.is_none());
        assert!(state.domain_accesses.is_empty());
    }
}
