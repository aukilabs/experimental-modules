/// Test Auto-Authentication
///
/// This example tests that calling get_domain_access() directly
/// (without prior authenticate() or authenticate_discovery() calls)
/// automatically handles the full authentication chain.

use authentication::{current_time_ms, Action, Client, Config, Credentials, Event};
use dotenv::dotenv;
use reqwest;
use std::env;

async fn execute_actions(
    client: &mut Client,
    actions: Vec<Action>,
    http_client: &reqwest::Client,
) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
    let mut all_events = Vec::new();

    for action in actions {
        match action {
            Action::HttpRequest {
                url,
                method,
                headers,
                body,
            } => {
                let mut request = match method.as_str() {
                    "GET" => http_client.get(&url),
                    "POST" => http_client.post(&url),
                    "PUT" => http_client.put(&url),
                    "DELETE" => http_client.delete(&url),
                    _ => {
                        return Err(format!("Unsupported HTTP method: {}", method).into());
                    }
                };

                for (key, value) in headers {
                    request = request.header(&key, &value);
                }

                if let Some(body_content) = body {
                    request = request.body(body_content);
                }

                let response = request.send().await?;
                let status = response.status().as_u16();
                let body_text = response.text().await?;

                let events = client.handle_response(status, &body_text);
                all_events.extend(events);
            }
            Action::Wait { duration_ms } => {
                tokio::time::sleep(tokio::time::Duration::from_millis(duration_ms)).await;
            }
        }
    }

    Ok(all_events)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();

    println!("=== Testing Auto-Authentication ===\n");

    // Configuration
    let api_url = env::var("API_URL").unwrap_or_else(|_| "https://api.aukiverse.com".to_string());
    let config = Config {
        api_url: api_url.clone(),
        refresh_url: format!("{}/user/refresh", api_url),
        dds_url: env::var("DDS_URL").unwrap_or_else(|_| "https://dds.posemesh.org".to_string()),
        client_id: "test-auto-auth".to_string(),
        refresh_threshold_ms: 300_000,
    };

    // Credentials
    let email = env::var("EMAIL").expect("EMAIL must be set in .env");
    let password = env::var("PASSWORD").expect("PASSWORD must be set in .env");

    let credentials = Credentials::EmailPassword { email: email.clone(), password };

    let domain_id = env::var("DOMAIN_ID").expect("DOMAIN_ID must be set in .env");

    println!("Config: {:?}", config);
    println!("Email: {}", email);
    println!("Domain ID: {}\n", domain_id);

    // Create HTTP client with optional certificate validation disable for dev environments
    let http_client = if env::var("ALLOW_INSECURE_SSL").is_ok() {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?
    } else {
        reqwest::Client::new()
    };

    // Create fresh authentication client (no prior auth)
    let mut client = Client::new(config);
    client.set_credentials(credentials);

    let now = current_time_ms();

    // Check initial state - should NOT be authenticated
    println!("Initial state:");
    println!("  Is authenticated: {}", client.is_authenticated(now));
    println!("  Network token: {:?}", client.network_token().is_some());
    println!("  Discovery token: {:?}", client.discovery_token().is_some());
    println!();

    // THE TEST: Call get_domain_access() directly without prior auth
    println!("=== Calling get_domain_access() directly (no prior auth) ===");
    println!("Expected behavior:");
    println!("  - Should return actions for network auth");
    println!("  - After executing, should return actions for discovery auth");
    println!("  - After executing, should return actions for domain access");
    println!();

    // First call to get_domain_access - should return network auth action
    println!("[Call 1] get_domain_access()");
    let actions1 = client.get_domain_access(&domain_id, now);
    println!("  Returned {} actions", actions1.len());
    for (i, action) in actions1.iter().enumerate() {
        match action {
            Action::HttpRequest { url, method, .. } => {
                println!("    [{}] HttpRequest {} {}", i, method, url);
            }
            Action::Wait { duration_ms } => {
                println!("    [{}] Wait {}ms", i, duration_ms);
            }
        }
    }

    if actions1.is_empty() {
        println!("❌ FAILED: Expected at least one action for network auth");
        return Err("No actions returned".into());
    }

    let events1 = execute_actions(&mut client, actions1, &http_client).await?;
    println!("  Received {} events:", events1.len());
    for (i, event) in events1.iter().enumerate() {
        println!("    [{}] {:?}", i, event);
    }
    println!();

    // Second call - should return discovery auth action
    println!("[Call 2] get_domain_access()");
    let actions2 = client.get_domain_access(&domain_id, now);
    println!("  Returned {} actions", actions2.len());
    for (i, action) in actions2.iter().enumerate() {
        match action {
            Action::HttpRequest { url, method, .. } => {
                println!("    [{}] HttpRequest {} {}", i, method, url);
            }
            Action::Wait { duration_ms } => {
                println!("    [{}] Wait {}ms", i, duration_ms);
            }
        }
    }

    if actions2.is_empty() {
        println!("❌ FAILED: Expected at least one action for discovery auth");
        return Err("No actions returned".into());
    }

    let events2 = execute_actions(&mut client, actions2, &http_client).await?;
    println!("  Received {} events:", events2.len());
    for (i, event) in events2.iter().enumerate() {
        println!("    [{}] {:?}", i, event);
    }
    println!();

    // Third call - should return domain access action
    println!("[Call 3] get_domain_access()");
    let actions3 = client.get_domain_access(&domain_id, now);
    println!("  Returned {} actions", actions3.len());
    for (i, action) in actions3.iter().enumerate() {
        match action {
            Action::HttpRequest { url, method, .. } => {
                println!("    [{}] HttpRequest {} {}", i, method, url);
            }
            Action::Wait { duration_ms } => {
                println!("    [{}] Wait {}ms", i, duration_ms);
            }
        }
    }

    if actions3.is_empty() {
        println!("❌ FAILED: Expected at least one action for domain access");
        return Err("No actions returned".into());
    }

    let events3 = execute_actions(&mut client, actions3, &http_client).await?;
    println!("  Received {} events:", events3.len());
    for (i, event) in events3.iter().enumerate() {
        println!("    [{}] {:?}", i, event);
    }
    println!();

    // Verify final state
    println!("=== Final State ===");
    println!("  Is authenticated: {}", client.is_authenticated(now));

    if let Some(token) = client.network_token() {
        println!("  Network token: present (expires: {})", token.expires_at);
    } else {
        println!("  Network token: NULL ❌");
    }

    if let Some(token) = client.discovery_token() {
        println!("  Discovery token: present (expires: {})", token.expires_at);
    } else {
        println!("  Discovery token: NULL ❌");
    }

    if let Some(domain) = client.domain_access(&domain_id) {
        println!("  Domain access: present");
        println!("    Domain: {} ({})", domain.name, domain.id);
        println!("    Server: {}", domain.domain_server.name);
    } else {
        println!("  Domain access: NULL ❌");
    }

    println!();
    println!("✅ Test completed!");
    println!();
    println!("CONCLUSION:");
    println!("  The current implementation requires calling get_domain_access()");
    println!("  multiple times (once for each auth step). This is because the");
    println!("  sans-I/O design can only return actions based on current state.");
    println!();
    println!("  To fix this, the Rust core needs to be modified to:");
    println!("  1. Return ALL actions upfront (network + discovery + domain), OR");
    println!("  2. Return a continuation/state that indicates more calls needed");

    Ok(())
}
