# Authentication

> **⚠️ EXPERIMENTAL:** This library is under active development and is subject to rapid changes, including breaking changes to the API. Use with caution in production environments and expect frequent updates. We recommend pinning to specific versions and reviewing changelogs before upgrading.

This library is used to authenticate to the auki network.
Because of the distributed nature of the auki network, there is a hierarchy of authentication.
See [ARCHITECTURE.md](ARCHITECTURE.md) for more details.

## Usage

```rust
use authentication::{Client, Credentials, Config, Event, Action};

// Create credentials (multiple authentication methods supported)
let credentials = Credentials::EmailPassword {
    email: "user@example.com".to_string(),
    password: "password".to_string(),
};
// let credentials = Credentials::AppKey {
//     app_key: "app_key".to_string(),
//     app_secret: "app_secret".to_string(),
// };
// let credentials = Credentials::Opaque {
//     token: "opaque_token".to_string(),
//     expiry_ms: 12345543,
// };

// Configure the client with API endpoints
let config = Config {
    api_url: "https://api.aukiverse.com".to_string(),
    dds_url: "https://dds.posemesh.org".to_string(),
};

// Create the authentication client
let mut client = Client::new(config);
client.set_credentials(credentials);

// Step 1: Authenticate to the Auki network
let actions = client.authenticate();
for action in actions {
    match action {
        Action::HttpRequest { url, method, headers, body } => {
            // Caller performs the HTTP request
            let response = your_http_client.request(method, url, headers, body).await?;

            // Feed the response back to the client
            let events = client.handle_response(response.status, response.body);
            for event in events {
                match event {
                    Event::NetworkAuthSuccess { token, expires_at } => {
                        println!("Authenticated to Auki network");
                        println!("Token expires at: {}", expires_at);
                    }
                    Event::NetworkAuthFailed { reason } => {
                        eprintln!("Network authentication failed: {}", reason);
                    }
                    _ => {}
                }
            }
        }
    }
}

// Step 2: Authenticate to the Discovery service
let actions = client.authenticate_discovery();
for action in actions {
    match action {
        Action::HttpRequest { url, method, headers, body } => {
            let response = your_http_client.request(method, url, headers, body).await?;
            let events = client.handle_response(response.status, response.body);

            for event in events {
                match event {
                    Event::DiscoveryAuthSuccess { token } => {
                        println!("Authenticated to Discovery service");
                    }
                    Event::DiscoveryAuthFailed { reason } => {
                        eprintln!("Discovery authentication failed: {}", reason);
                    }
                    _ => {}
                }
            }
        }
    }
}

// Step 3: Get domain access - cleaner API
let domain_id = "my-domain-123";
let actions = client.get_domain_access(domain_id);
for action in actions {
    match action {
        Action::HttpRequest { url, method, headers, body } => {
            let response = your_http_client.request(method, url, headers, body).await?;
            client.handle_response(response.status, response.body);
        }
    }
}

// Now you can access the domain info directly from the client state
if let Some(domain_access) = client.domain_access(domain_id) {
    println!("Access granted to domain: {}", domain_access.domain_id);
    println!("Token: {}", domain_access.token);
    println!("Available nodes: {:?}", domain_access.nodes);
    // Now you can connect to the domain nodes
} else {
    eprintln!("No access to domain: {}", domain_id);
}

// Or check network token
if let Some(network_token) = client.network_token() {
    println!("Network token: {}", network_token.token);
    println!("Expires at: {}", network_token.expires_at);
}

// Complete example with error handling
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credentials = Credentials::EmailPassword {
        email: "user@example.com".to_string(),
        password: "password".to_string(),
    };

    let config = Config {
        api_url: "https://api.aukiverse.com".to_string(),
        dds_url: "https://dds.posemesh.org".to_string(),
    };

    let mut client = Client::new(config);
    client.set_credentials(credentials);

    // Helper function to execute actions
    fn execute_actions(
        client: &mut Client,
        actions: Vec<Action>,
        http_client: &HttpClient,
    ) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
        let mut all_events = Vec::new();

        for action in actions {
            match action {
                Action::HttpRequest { url, method, headers, body } => {
                    let response = http_client.request(method, url, headers, body)?;
                    let events = client.handle_response(response.status, response.body);
                    all_events.extend(events);
                }
                Action::Wait { duration_ms } => {
                    // Caller can implement waiting/retry logic
                    std::thread::sleep(std::time::Duration::from_millis(duration_ms));
                }
            }
        }

        Ok(all_events)
    }

    let http_client = HttpClient::new();

    // Authenticate through the hierarchy
    let actions = client.authenticate();
    let events = execute_actions(&mut client, actions, &http_client)?;

    // Check if network auth succeeded
    let network_auth_success = events.iter().any(|e| {
        matches!(e, Event::NetworkAuthSuccess { .. })
    });

    if !network_auth_success {
        return Err("Failed to authenticate to Auki network".into());
    }

    // Continue with discovery and domain access...
    let actions = client.authenticate_discovery();
    execute_actions(&mut client, actions, &http_client)?;

    let actions = client.get_domain_access("my-domain");
    execute_actions(&mut client, actions, &http_client)?;

    // Check the client state instead of filtering events
    if let Some(domain_access) = client.domain_access("my-domain") {
        println!("Ready to connect to domain {} via nodes: {:?}",
                 domain_access.domain_id, domain_access.nodes);
    } else {
        return Err("Failed to get domain access".into());
    }

    Ok(())
}
```

## Running the Example

The library includes a working example that demonstrates real authentication with the Auki network.

### Setup

1. Copy the example environment file:

   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your credentials:

   ```env
   # API Configuration
   API_URL=https://api.aukiverse.com
   DDS_URL=https://dds.posemesh.org

   # Choose your authentication method
   AUTH_METHOD=email
   EMAIL=your_email@example.com
   PASSWORD=your_password

   # Domain to access
   DOMAIN_ID=your-domain-id
   ```

3. Run the example:
   ```bash
   cargo run --example basic
   ```

The example will:

- Load configuration from `.env`
- Authenticate to the Auki network
- Authenticate to the Discovery service
- Request access to the specified domain
- Display domain server information
- Show how to save/restore state

## Language bindings

For usage examples, see the following language bindings:

- [Python](pkg/python)
- [JavaScript](pkg/javascript)
- [Swift](pkg/expo)
