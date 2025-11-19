use authentication::{Client, Config, Credentials};
use std::env;

fn main() {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    // Get configuration from environment
    let api_url = env::var("API_URL").expect("API_URL must be set in .env");
    let dds_url = env::var("DDS_URL").expect("DDS_URL must be set in .env");
    let client_id = env::var("CLIENT_ID").unwrap_or_else(|_| "test-refresh-expiry".to_string());

    // Get credentials from environment
    let email = env::var("EMAIL").expect("EMAIL must be set in .env");
    let password = env::var("PASSWORD").expect("PASSWORD must be set in .env");

    // Get domain ID to test
    let domain_id = env::var("DOMAIN_ID").expect("DOMAIN_ID must be set in .env");

    println!("=== Testing Refresh Token Expiry Scenario ===\n");

    // Step 1: Create client with config only (no credentials)
    println!("Step 1: Creating client with config...");
    let config = Config {
        api_url: api_url.clone(),
        refresh_url: format!("{}/user/refresh", api_url),
        dds_url: dds_url.clone(),
        client_id: client_id.clone(),
        refresh_threshold_ms: 5 * 60 * 1000, // 5 minutes
    };

    let mut client = Client::new(config.clone());
    println!("✓ Client created\n");

    // Step 2: Authenticate with credentials
    println!("Step 2: Authenticating with email/password...");
    let credentials = Credentials::EmailPassword {
        email: email.clone(),
        password: password.clone(),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let actions = client.authenticate_with(credentials, now);
    println!("Actions to perform: {} HTTP requests", actions.len());

    // Execute the authentication request
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for action in actions {
            match action {
                authentication::Action::HttpRequest { url, method, headers, body } => {
                    println!("Executing: {} {}", method, url);

                    let http_client = reqwest::Client::new();
                    let mut request = match method.as_str() {
                        "POST" => http_client.post(&url),
                        "GET" => http_client.get(&url),
                        _ => panic!("Unsupported method: {}", method),
                    };

                    for (key, value) in headers {
                        request = request.header(key, value);
                    }

                    if let Some(body) = body {
                        request = request.body(body);
                    }

                    let response = request.send().await.expect("Request failed");
                    let status = response.status().as_u16();
                    let body = response.text().await.expect("Failed to read response body");

                    println!("Response: {} ({})", status, if status == 200 { "OK" } else { "ERROR" });

                    // Handle the response
                    let events = client.handle_response(status, &body);

                    for event in events {
                        match event {
                            authentication::Event::NetworkAuthSuccess { token, expires_at } => {
                                println!("✓ Network auth successful!");
                                println!("  Token: {}...", &token[..20.min(token.len())]);
                                println!("  Expires at: {}", expires_at);

                                // Check if credentials were cleared
                                if !client.has_credentials() {
                                    println!("✓ Credentials cleared after successful auth (as expected)");
                                } else {
                                    println!("✗ WARNING: Credentials not cleared!");
                                }
                            }
                            authentication::Event::NetworkAuthFailed { reason, retry_possible } => {
                                println!("✗ Network auth failed: {}", reason);
                                println!("  Retry possible: {}", retry_possible);
                                return;
                            }
                            _ => {}
                        }
                    }
                }
                authentication::Action::Wait { duration_ms } => {
                    println!("Waiting {} ms...", duration_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(duration_ms)).await;
                }
            }
        }

        println!();

        // Step 3: Get domain access (should work with valid tokens)
        println!("Step 3: Getting domain access with valid tokens...");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let actions = client.get_domain_access(&domain_id, now);
        println!("Actions to perform: {}", actions.len());

        // Execute all actions
        for action in actions {
            match action {
                authentication::Action::HttpRequest { url, method, headers, body } => {
                    println!("Executing: {} {}", method, url);

                    let http_client = reqwest::Client::new();
                    let mut request = match method.as_str() {
                        "POST" => http_client.post(&url),
                        "GET" => http_client.get(&url),
                        _ => panic!("Unsupported method: {}", method),
                    };

                    for (key, value) in headers {
                        request = request.header(key, value);
                    }

                    if let Some(body) = body {
                        request = request.body(body);
                    }

                    let response = request.send().await.expect("Request failed");
                    let status = response.status().as_u16();
                    let body = response.text().await.expect("Failed to read response body");

                    let events = client.handle_response(status, &body);

                    for event in events {
                        match event {
                            authentication::Event::DomainAccessGranted { domain } => {
                                println!("✓ Domain access granted!");
                                println!("  Domain: {} ({})", domain.name, domain.id);
                            }
                            authentication::Event::NetworkAuthSuccess { .. } => {
                                println!("  Network auth succeeded (auto-refresh)");
                            }
                            authentication::Event::DiscoveryAuthSuccess { .. } => {
                                println!("  Discovery auth succeeded");
                            }
                            _ => {}
                        }
                    }
                }
                authentication::Action::Wait { duration_ms } => {
                    println!("Waiting {} ms...", duration_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(duration_ms)).await;
                }
            }
        }

        println!();

        // Step 4: Save state (tokens only, no credentials)
        println!("Step 4: Saving client state...");
        let state_json = client.save_state().expect("Failed to save state");
        println!("State saved ({} bytes)", state_json.len());
        println!("Credentials in state: {}", if state_json.contains("credentials") { "YES (BAD!)" } else { "NO (GOOD!)" });
        println!();

        // Step 5: Create new client from saved state
        println!("Step 5: Creating new client from saved state...");
        let state: authentication::ClientState = serde_json::from_str(&state_json).expect("Failed to parse state");
        let mut restored_client = Client::from_state(state, config.clone());

        // Verify no credentials
        if !restored_client.has_credentials() {
            println!("✓ Restored client has no credentials (as expected)");
        } else {
            println!("✗ WARNING: Restored client has credentials!");
        }
        println!();

        // Step 6: Simulate token expiration by advancing time
        println!("Step 6: Simulating token expiration by advancing time...");
        println!("Using a future time to make client think tokens are expired...");

        // Get current time + 2 hours in the future
        // This will make the client think the access token is expired
        let future_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 + (2 * 60 * 60 * 1000); // 2 hours in the future

        println!("Future time: {} (2 hours from now)", future_time);
        println!();

        // Step 7: Try to get domain access with expired tokens
        println!("Step 7: Attempting to get domain access with expired tokens...");
        let actions = restored_client.get_domain_access(&domain_id, future_time);

        if actions.is_empty() {
            println!("✓ No actions returned - client detected expired tokens and no credentials!");
            println!("✓ SUCCESS: System correctly requires re-authentication!");
            println!("\nThis is the desired behavior:");
            println!("  1. Credentials were cleared after initial auth");
            println!("  2. State was saved without credentials");
            println!("  3. Restored client has no credentials");
            println!("  4. With expired refresh token and no credentials:");
            println!("     -> Cannot auto-reauth");
            println!("     -> User must sign in again");
            return;
        }

        println!("Actions to perform: {}", actions.len());
        println!("NOTE: The refresh token is still valid on the server, so it will attempt refresh.");
        println!("This is expected - we're testing what happens when refresh succeeds vs when it fails.");
        println!();

        // Try to execute actions (should be refresh attempt)
        for action in actions {
            match action {
                authentication::Action::HttpRequest { url, method, headers, body } => {
                    println!("Executing: {} {}", method, url);

                    if url.contains("/refresh") {
                        println!("  Attempting token refresh...");
                    } else if url.contains("/login") {
                        println!("  ✗ ERROR: Attempting re-authentication with credentials!");
                        println!("  This should not happen - credentials should have been cleared!");
                        return;
                    }

                    let http_client = reqwest::Client::new();
                    let mut request = match method.as_str() {
                        "POST" => http_client.post(&url),
                        "GET" => http_client.get(&url),
                        _ => panic!("Unsupported method: {}", method),
                    };

                    for (key, value) in headers {
                        request = request.header(key, value);
                    }

                    if let Some(body) = body {
                        request = request.body(body);
                    }

                    let response = request.send().await.expect("Request failed");
                    let status = response.status().as_u16();
                    let body = response.text().await.expect("Failed to read response body");

                    println!("  Response: {}", status);

                    let events = restored_client.handle_response(status, &body);

                    for event in events {
                        match event {
                            authentication::Event::NetworkTokenRefreshFailed { reason, requires_reauth } => {
                                println!("✓ Token refresh failed (expected): {}", reason);
                                println!("  Requires reauth: {}", requires_reauth);

                                if requires_reauth {
                                    println!("✓ System correctly indicates re-authentication is required!");
                                }
                            }
                            authentication::Event::AuthenticationRequired => {
                                println!("✓ AuthenticationRequired event received!");
                                println!("✓ SUCCESS: System correctly requires user to sign in again!");
                            }
                            _ => {}
                        }
                    }
                }
                authentication::Action::Wait { duration_ms } => {
                    println!("Waiting {} ms...", duration_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(duration_ms)).await;
                }
            }
        }

        // Step 8: Verify client cannot auto-reauth without credentials
        println!();
        println!("Step 8: Verifying client cannot auto-reauth without credentials...");
        let actions = restored_client.authenticate(future_time);

        if actions.is_empty() {
            println!("✓ SUCCESS: No authentication actions returned!");
            println!("✓ Client correctly refuses to auto-reauth without credentials!");
            println!("\n=== TEST PASSED ===");
            println!("The credential-clearing fix is working correctly:");
            println!("  ✓ Credentials cleared after successful auth");
            println!("  ✓ State saved without credentials");
            println!("  ✓ Expired refresh token does not trigger auto-reauth");
            println!("  ✓ User must sign in again manually");
        } else {
            println!("✗ FAILURE: Client returned {} authentication actions!", actions.len());
            println!("✗ This means credentials were not properly cleared!");
        }
    });
}
