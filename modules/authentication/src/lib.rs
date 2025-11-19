mod client;
mod jwt;
mod state;
mod types;

pub use client::Client;
pub use state::ClientState;
pub use types::*;

// Re-export for convenience
pub use jwt::{current_time_ms, is_expired, is_near_expiry};

// Platform-specific modules
#[cfg(feature = "wasm")]
pub mod platforms {
    pub mod web;
}

#[cfg(feature = "uniffi-bindings")]
pub mod platforms {
    pub mod native;
}

// UniFFI will generate the foreign language bindings from this module
#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();
