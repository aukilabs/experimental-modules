use authentication::{current_time_ms, is_near_expiry, Action, Client, Config, Credentials, Event};
use dotenv::dotenv;
use reqwest;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    dotenv().ok();

    println!("=== Token Refresh Test ===\n");

    // Load configuration from environment
    let api_url = env::var("API_URL").unwrap_or_else(|_| "https://api.aukiverse.com".to_string());
    let config = Config {
        api_url: api_url.clone(),
        refresh_url: format!("{}/user/refresh", api_url),
        dds_url: env::var("DDS_URL").unwrap_or_else(|_| "https://dds.posemesh.org".to_string()),
        client_id: env::var("CLIENT_ID").unwrap_or_else(|_| "rust-sdk".to_string()),
        // Set a very high refresh threshold so we can manually trigger refresh
        refresh_threshold_ms: 3600_000, // 1 hour
    };

    println!("Configuration:");
    println!("  API URL: {}", config.api_url);
    println!("  DDS URL: {}", config.dds_url);
    println!("  Client ID: {}", config.client_id);
    println!("  Refresh threshold: {}ms ({}h)\n", config.refresh_threshold_ms, config.refresh_threshold_ms / 3600000);

    // Load credentials from environment
    let auth_method = env::var("AUTH_METHOD").unwrap_or_else(|_| "email".to_string());

    let credentials = match auth_method.as_str() {
        "email" => {
            let email = env::var("EMAIL").expect("EMAIL must be set in .env");
            let password = env::var("PASSWORD").expect("PASSWORD must be set in .env");
            println!("Using Email/Password authentication");
            println!("  Email: {}\n", email);
            Credentials::EmailPassword { email, password }
        }
        "appkey" => {
            let app_key = env::var("APP_KEY").expect("APP_KEY must be set in .env");
            let app_secret = env::var("APP_SECRET").expect("APP_SECRET must be set in .env");
            println!("Using AppKey/AppSecret authentication");
            println!("Note: AppKey credentials don't expire, so refresh is not applicable\n");
            Credentials::AppKey {
                app_key,
                app_secret,
            }
        }
        "opaque" => {
            let token = env::var("OPAQUE_TOKEN").expect("OPAQUE_TOKEN must be set in .env");
            let expiry_ms = env::var("OPAQUE_EXPIRY_MS")
                .expect("OPAQUE_EXPIRY_MS must be set in .env")
                .parse()
                .expect("OPAQUE_EXPIRY_MS must be a valid number");
            let refresh_token = env::var("OPAQUE_REFRESH_TOKEN").ok();
            let refresh_token_expiry_ms = env::var("OPAQUE_REFRESH_TOKEN_EXPIRY_MS")
                .ok()
                .and_then(|v| v.parse().ok());
            let oidc_client_id = env::var("OIDC_CLIENT_ID").ok();
            println!("Using Opaque token authentication");
            println!("Note: Opaque tokens may or may not have refresh tokens\n");
            Credentials::Opaque {
                token,
                refresh_token,
                expiry_ms,
                refresh_token_expiry_ms,
                oidc_client_id,
            }
        }
        _ => {
            eprintln!(
                "Invalid AUTH_METHOD: {}. Must be 'email', 'appkey', or 'opaque'",
                auth_method
            );
            std::process::exit(1);
        }
    };

    // Create the HTTP client with optional certificate validation disable for dev environments
    let http_client = if env::var("ALLOW_INSECURE_SSL").is_ok() {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?
    } else {
        reqwest::Client::new()
    };

    // Create the authentication client with credentials
    let mut client = Client::new(config.clone());
    client.set_credentials(credentials);

    // Get current time for all operations
    let now = current_time_ms();

    // Step 1: Initial authentication
    println!("=== Step 1: Initial Network Authentication ===");
    let actions = client.authenticate(now);
    execute_actions(&http_client, &mut client, actions).await?;

    // Check if we got a network token
    if let Some(network_token) = client.network_token() {
        println!("✓ Network token obtained!");
        println!("  Token: {}...", &network_token.token[..50.min(network_token.token.len())]);
        println!("  Expires at: {} ({}ms from now)\n",
            network_token.expires_at,
            network_token.expires_at.saturating_sub(now));
    } else {
        println!("✗ No network token available\n");
        return Ok(());
    }

    // Step 2: Authenticate to discovery
    println!("=== Step 2: Discovery Authentication ===");
    let actions = client.authenticate_discovery(now);
    execute_actions(&http_client, &mut client, actions).await?;

    if let Some(discovery_token) = client.discovery_token() {
        println!("✓ Discovery token obtained!");
        println!("  Token: {}...", &discovery_token.token[..50.min(discovery_token.token.len())]);
        println!("  Expires at: {} ({}ms from now)\n",
            discovery_token.expires_at,
            discovery_token.expires_at.saturating_sub(now));
    }

    // Step 3: Get domain access
    let domain_id = env::var("DOMAIN_ID").unwrap_or_else(|_| {
        println!("⚠ DOMAIN_ID not set in .env, using example domain");
        "example-domain".to_string()
    });

    println!("=== Step 3: Domain Access ===");
    println!("Requesting access to domain: {}", domain_id);
    let actions = client.get_domain_access(&domain_id, now);
    execute_actions(&http_client, &mut client, actions).await?;

    if let Some(domain) = client.domain_access(&domain_id) {
        println!("✓ Domain access obtained!");
        println!("  Domain: {} ({})", domain.name, domain.id);
        println!("  Access token: {}...", &domain.access_token[..50.min(domain.access_token.len())]);
        println!("  Expires at: {} ({}ms from now)\n",
            domain.expires_at,
            domain.expires_at.saturating_sub(now));
    }

    // Step 4: Force refresh by calling authenticate again
    println!("=== Step 4: Testing Token Refresh ===");
    println!("Note: Only the network token has a refresh_token field.");
    println!("Discovery and domain tokens must be re-requested, not refreshed.\n");

    // Check if network token is near expiry (with our high threshold)
    if let Some(network_token) = client.network_token() {
        let is_near = is_near_expiry(network_token.expires_at, now, config.refresh_threshold_ms);
        println!("Network token near expiry ({}h threshold): {}",
            config.refresh_threshold_ms / 3600000, is_near);

        if !is_near {
            println!("Note: Token is not near expiry with current threshold.");
            println!("To trigger automatic refresh, the token needs to be within {}ms of expiry.\n",
                config.refresh_threshold_ms);
        }
    }

    println!("Calling authenticate() again to test refresh logic...");
    let actions = client.authenticate(now);

    if actions.is_empty() {
        println!("✓ No actions needed - token is still valid and not near expiry\n");
    } else {
        println!("Executing refresh actions...");
        execute_actions(&http_client, &mut client, actions).await?;

        if let Some(network_token) = client.network_token() {
            println!("✓ Token refresh successful (or re-authenticated)!");
            println!("  New token: {}...", &network_token.token[..50.min(network_token.token.len())]);
            println!("  Expires at: {} ({}ms from now)\n",
                network_token.expires_at,
                network_token.expires_at.saturating_sub(now));
        }
    }

    // Step 5: Test discovery token refresh/re-request
    println!("=== Step 5: Testing Discovery Token Re-request ===");
    println!("Calling authenticate_discovery() again...");
    let actions = client.authenticate_discovery(now);

    if actions.is_empty() {
        println!("✓ No actions needed - discovery token is still valid\n");
    } else {
        println!("Executing discovery auth actions...");
        execute_actions(&http_client, &mut client, actions).await?;

        if let Some(discovery_token) = client.discovery_token() {
            println!("✓ Discovery token obtained!");
            println!("  Token: {}...", &discovery_token.token[..50.min(discovery_token.token.len())]);
            println!("  Expires at: {} ({}ms from now)\n",
                discovery_token.expires_at,
                discovery_token.expires_at.saturating_sub(now));
        }
    }

    // Step 6: Test domain access re-request
    println!("=== Step 6: Testing Domain Access Re-request ===");
    println!("Calling get_domain_access() again...");
    let actions = client.get_domain_access(&domain_id, now);

    if actions.is_empty() {
        println!("✓ No actions needed - domain access is still valid\n");
    } else {
        println!("Executing domain access actions...");
        execute_actions(&http_client, &mut client, actions).await?;

        if let Some(domain) = client.domain_access(&domain_id) {
            println!("✓ Domain access obtained!");
            println!("  Domain: {} ({})", domain.name, domain.id);
            println!("  Expires at: {} ({}ms from now)\n",
                domain.expires_at,
                domain.expires_at.saturating_sub(now));
        }
    }

    // Step 7: Simulate token expiration
    println!("=== Step 7: Simulating Token Expiration ===");
    println!("Simulating that 1 hour has passed (tokens should be expired)...\n");

    // Simulate 1 hour + 1 minute has passed
    let future_time = now + 3660000; // 61 minutes

    println!("Current simulated time: {} ({}ms in the future)", future_time, future_time - now);
    println!("Authentication state at future time: {:?}\n", client.check_auth_state(future_time));

    // Check which tokens are expired
    if let Some(network_token) = client.network_token() {
        let expired = network_token.expires_at < future_time;
        println!("Network token expired: {} (expires: {}, now: {})",
            expired, network_token.expires_at, future_time);
    }

    if let Some(discovery_token) = client.discovery_token() {
        let expired = discovery_token.expires_at < future_time;
        println!("Discovery token expired: {} (expires: {}, now: {})",
            expired, discovery_token.expires_at, future_time);
    }

    if let Some(domain) = client.domain_access(&domain_id) {
        let expired = domain.expires_at < future_time;
        println!("Domain access expired: {} (expires: {}, now: {})\n",
            expired, domain.expires_at, future_time);
    }

    // Now try to get domain access with the future time - should trigger refresh
    println!("Calling get_domain_access() with future time (tokens should be expired)...");
    let actions = client.get_domain_access(&domain_id, future_time);

    if actions.is_empty() {
        println!("⚠ WARNING: No actions generated - tokens might not be recognized as expired!\n");
    } else {
        println!("✓ Actions generated to refresh/re-request expired tokens:");
        for (i, action) in actions.iter().enumerate() {
            match action {
                Action::HttpRequest { url, method, .. } => {
                    println!("  {}. {} {}", i + 1, method, url);
                }
                _ => {}
            }
        }
        println!();

        println!("Executing refresh/re-request using proper sans-io pattern (one action at a time)...");

        // Proper sans-io: call methods individually instead of batching actions
        // This ensures current_operation tracks correctly for each response

        // IMPORTANT: After each refresh, use current time (not future_time) so newly
        // refreshed tokens don't immediately appear expired

        // Step 1: Network token refresh (if needed)
        let auth_actions = client.authenticate(future_time);
        if !auth_actions.is_empty() {
            println!("  Refreshing network token...");
            execute_actions(&http_client, &mut client, auth_actions).await?;
        }

        // Step 2: Discovery token (if needed) - use NOW time after refresh
        let now_after_refresh = current_time_ms();
        let discovery_actions = client.authenticate_discovery(now_after_refresh);
        if !discovery_actions.is_empty() {
            println!("  Re-authenticating to discovery...");
            execute_actions(&http_client, &mut client, discovery_actions).await?;
        }

        // Step 3: Domain access (if needed) - use NOW time
        let domain_actions = client.get_domain_access(&domain_id, now_after_refresh);
        if !domain_actions.is_empty() {
            println!("  Requesting domain access...");
            execute_actions(&http_client, &mut client, domain_actions).await?;
        }

        // Check tokens after refresh
        println!("\n✓ Tokens after refresh/re-request:");
        if let Some(network_token) = client.network_token() {
            println!("  Network token: expires at {} ({}ms from simulated now)",
                network_token.expires_at,
                network_token.expires_at.saturating_sub(future_time));
        }

        if let Some(discovery_token) = client.discovery_token() {
            println!("  Discovery token: expires at {} ({}ms from simulated now)",
                discovery_token.expires_at,
                discovery_token.expires_at.saturating_sub(future_time));
        }

        if let Some(domain) = client.domain_access(&domain_id) {
            println!("  Domain access: expires at {} ({}ms from simulated now)",
                domain.expires_at,
                domain.expires_at.saturating_sub(future_time));
        }
    }

    // Display final state
    println!("\n=== Final State ===");
    println!("Authentication state: {:?}", client.check_auth_state(now));
    println!("Is authenticated: {}", client.is_authenticated(now));

    if let Some(network_token) = client.network_token() {
        println!("\nNetwork Token:");
        println!("  Expires at: {}", network_token.expires_at);
        let remaining_ms = network_token.expires_at.saturating_sub(now);
        println!("  Time remaining: {}ms ({}h {}m)",
            remaining_ms,
            remaining_ms / 3600000,
            (remaining_ms % 3600000) / 60000);
    }

    if let Some(discovery_token) = client.discovery_token() {
        println!("\nDiscovery Token:");
        println!("  Expires at: {}", discovery_token.expires_at);
        let remaining_ms = discovery_token.expires_at.saturating_sub(now);
        println!("  Time remaining: {}ms ({}h {}m)",
            remaining_ms,
            remaining_ms / 3600000,
            (remaining_ms % 3600000) / 60000);
    }

    if let Some(domain) = client.domain_access(&domain_id) {
        println!("\nDomain Access:");
        println!("  Domain: {} ({})", domain.name, domain.id);
        println!("  Expires at: {}", domain.expires_at);
        let remaining_ms = domain.expires_at.saturating_sub(now);
        println!("  Time remaining: {}ms ({}h {}m)",
            remaining_ms,
            remaining_ms / 3600000,
            (remaining_ms % 3600000) / 60000);
    }

    println!("\n=== Summary ===");
    println!("• Network tokens have refresh_token and can be refreshed via POST /user/refresh");
    println!("• Discovery tokens are obtained by re-authenticating with network token via POST /service/domains-access-token");
    println!("• Domain access tokens are obtained by re-requesting with discovery token via POST /api/v1/domains/{{id}}/auth");
    println!("• Only the network token can be truly 'refreshed' - others must be re-requested\n");

    println!("✓ Refresh test completed successfully!");

    Ok(())
}

async fn execute_actions(
    http_client: &reqwest::Client,
    client: &mut Client,
    actions: Vec<Action>,
) -> Result<(), Box<dyn std::error::Error>> {
    for action in actions {
        match action {
            Action::HttpRequest {
                url,
                method,
                headers,
                body,
            } => {
                println!("  {} {}", method, url);

                let mut request = match method.as_str() {
                    "GET" => http_client.get(&url),
                    "POST" => http_client.post(&url),
                    "PUT" => http_client.put(&url),
                    "DELETE" => http_client.delete(&url),
                    _ => panic!("Unsupported HTTP method: {}", method),
                };

                for (key, value) in headers {
                    request = request.header(key, value);
                }

                if let Some(body_str) = body {
                    request = request.body(body_str);
                }

                let response = request.send().await?;
                let status = response.status().as_u16();
                let body_text = response.text().await?;

                println!("  Response: {}", status);

                let events = client.handle_response(status, &body_text);

                for event in events {
                    match event {
                        Event::NetworkAuthSuccess { expires_at, .. } => {
                            println!("  ✓ Network auth successful (expires: {})", expires_at);
                        }
                        Event::NetworkAuthFailed { reason, .. } => {
                            println!("  ✗ Network auth failed: {}", reason);
                            return Err(reason.into());
                        }
                        Event::NetworkTokenRefreshed { expires_at, .. } => {
                            println!("  ✓ Network token refreshed (expires: {})", expires_at);
                        }
                        Event::NetworkTokenRefreshFailed { reason, .. } => {
                            println!("  ✗ Network token refresh failed: {}", reason);
                        }
                        Event::DiscoveryAuthSuccess { expires_at, .. } => {
                            println!("  ✓ Discovery auth successful (expires: {})", expires_at);
                        }
                        Event::DiscoveryAuthFailed { reason } => {
                            println!("  ✗ Discovery auth failed: {}", reason);
                            return Err(reason.into());
                        }
                        Event::DomainAccessGranted { domain } => {
                            println!("  ✓ Domain access granted: {} (expires: {})", domain.name, domain.expires_at);
                        }
                        Event::DomainAccessDenied { domain_id, reason } => {
                            println!("  ✗ Domain access denied for {}: {}", domain_id, reason);
                            return Err(reason.into());
                        }
                        _ => {}
                    }
                }
            }
            Action::Wait { duration_ms } => {
                println!("  Waiting {}ms...", duration_ms);
                tokio::time::sleep(tokio::time::Duration::from_millis(duration_ms)).await;
            }
        }
    }

    Ok(())
}
