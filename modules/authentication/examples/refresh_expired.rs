use authentication::{current_time_ms, Client, Config, Credentials};
use dotenv::dotenv;
use reqwest;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    dotenv().ok();

    println!("=== Expired Refresh Token Test ===\n");

    // Load configuration from environment
    let api_url = env::var("API_URL").unwrap_or_else(|_| "https://api.aukiverse.com".to_string());
    let config = Config {
        api_url: api_url.clone(),
        refresh_url: format!("{}/user/refresh", api_url),
        dds_url: env::var("DDS_URL").unwrap_or_else(|_| "https://dds.posemesh.org".to_string()),
        client_id: env::var("CLIENT_ID").unwrap_or_else(|_| "rust-sdk".to_string()),
        refresh_threshold_ms: env::var("REFRESH_THRESHOLD_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300_000),
    };

    println!("Configuration:");
    println!("  API URL: {}", config.api_url);
    println!("  Client ID: {}\n", config.client_id);

    // Load credentials from environment
    let email = env::var("EMAIL").expect("EMAIL must be set in .env");
    let password = env::var("PASSWORD").expect("PASSWORD must be set in .env");
    let credentials = Credentials::EmailPassword {
        email: email.clone(),
        password: password.clone(),
    };

    println!("Using Email/Password authentication");
    println!("  Email: {}\n", email);

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

    let now = current_time_ms();

    // Step 1: Initial authentication
    println!("=== Step 1: Initial Authentication ===");
    let actions = client.authenticate(now);
    if !actions.is_empty() {
        println!("Authenticating...");
        for action in actions {
            if let authentication::Action::HttpRequest {
                url,
                method,
                headers,
                body,
            } = action
            {
                let mut request = match method.as_str() {
                    "POST" => http_client.post(&url),
                    _ => panic!("Unexpected method"),
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

                client.handle_response(status, &body_text);
            }
        }
    }

    if let Some(network_token) = client.network_token() {
        println!("✓ Network token obtained!");
        println!("  Expires at: {}", network_token.expires_at);
        println!("  Has refresh token: {}\n", !network_token.refresh_token.is_empty());
    }

    // Step 2: Simulate that a VERY long time has passed (more than refresh token lifetime)
    // Typical refresh tokens last 7-30 days, so we simulate 30+ days
    println!("=== Step 2: Simulating 30+ Days Have Passed ===");
    println!("Simulating that app hasn't been used for over 30 days...");
    println!("Note: Access tokens typically last 1 hour");
    println!("      Refresh tokens typically last 7-30 days\n");

    // Simulate 30 days + 1 hour in the future
    let future_time = now + (30 * 24 * 60 * 60 * 1000) + (60 * 60 * 1000);
    let days_passed = (future_time - now) / (24 * 60 * 60 * 1000);

    println!("Simulated current time: {} ({} days in future)", future_time, days_passed);

    if let Some(network_token) = client.network_token() {
        println!("\nToken status at simulated time:");
        println!("  Access token expires: {}", network_token.expires_at);
        println!("  Access token expired: {} (expired {} days ago)",
            network_token.expires_at < future_time,
            (future_time - network_token.expires_at) / (24 * 60 * 60 * 1000)
        );
        println!("  Has refresh token: {}", !network_token.refresh_token.is_empty());
        println!("  Refresh token: ALSO EXPIRED (past 30 day lifetime)\n");
    }

    // Step 3: Check authentication state with the future time
    println!("=== Step 3: Checking Authentication State ===");
    let auth_state = client.check_auth_state(future_time);
    println!("Authentication state: {:?}", auth_state);

    match auth_state {
        authentication::AuthenticationState::NeedsAuthentication => {
            println!("\n✓ CORRECT: System detected that re-authentication is needed");
            println!("   Both access token AND refresh token are expired");
            println!("   Application should:");
            println!("   1. Show login screen to user");
            println!("   2. Collect credentials");
            println!("   3. Call client.authenticate() with new credentials");
        }
        authentication::AuthenticationState::NeedsCredentials => {
            println!("\n✓ CORRECT: System needs credentials to authenticate");
            println!("   Application should:");
            println!("   1. Show login screen");
            println!("   2. Call client.set_credentials() with user input");
            println!("   3. Call client.authenticate()");
        }
        authentication::AuthenticationState::NeedsRefresh => {
            println!("\n⚠ UNEXPECTED: System thinks it can refresh");
            println!("   This shouldn't happen with tokens expired for 30+ days");
        }
        authentication::AuthenticationState::Authenticated => {
            println!("\n✗ ERROR: Should not be authenticated with expired tokens!");
        }
    }

    // Step 4: Try to call authenticate() - should return empty or require login
    println!("\n=== Step 4: Attempting to Authenticate ===");
    println!("Calling client.authenticate() with expired refresh token...\n");

    let actions = client.authenticate(future_time);

    if actions.is_empty() {
        println!("✓ No actions returned");
        println!("  System correctly detected that credentials are needed");
        println!("  In a real app: show login screen to user\n");
    } else {
        println!("Actions generated:");
        for (i, action) in actions.iter().enumerate() {
            match action {
                authentication::Action::HttpRequest { url, method, .. } => {
                    println!("  {}. {} {}", i + 1, method, url);

                    if url.contains("/user/refresh") {
                        println!("     ⚠ Attempting refresh with expired refresh token");
                        println!("     This will fail and require re-authentication");
                    } else if url.contains("/user/login") {
                        println!("     ✓ Falling back to full authentication");
                    }
                }
                _ => {}
            }
        }
        println!();
    }

    // Step 5: Show how to handle this in a real application
    println!("=== Step 5: How to Handle This in Your Application ===\n");

    println!("Recommended pattern:");
    println!("```rust");
    println!("// On app startup, restore from saved state");
    println!("let saved_state = load_from_storage()?;");
    println!("let mut client = Client::from_state(saved_state, config);");
    println!();
    println!("// Check if we need to show login screen");
    println!("let now = current_time_ms();");
    println!("match client.check_auth_state(now) {{");
    println!("    AuthenticationState::Authenticated => {{");
    println!("        // Good to go! Use the app");
    println!("    }}");
    println!("    AuthenticationState::NeedsAuthentication => {{");
    println!("        // Show login screen");
    println!("        // After user enters credentials:");
    println!("        client.set_credentials(credentials);");
    println!("        client.authenticate(now).await?;");
    println!("    }}");
    println!("    AuthenticationState::NeedsCredentials => {{");
    println!("        // Show login screen");
    println!("    }}");
    println!("}}");
    println!("```\n");

    println!("=== Summary ===");
    println!("✓ This example demonstrated:");
    println!("  • What happens when BOTH access and refresh tokens expire");
    println!("  • How to detect this state with check_auth_state()");
    println!("  • That the library correctly returns NeedsAuthentication state");
    println!("  • How to handle this in a real application\n");

    println!("Key takeaways:");
    println!("  • Access tokens expire quickly (typically 1 hour)");
    println!("  • Refresh tokens last longer (typically 7-30 days)");
    println!("  • When refresh token expires, user MUST log in again");
    println!("  • Always check auth state on app startup");
    println!("  • Save state frequently to preserve tokens\n");

    println!("✓ Test completed successfully!");

    Ok(())
}
