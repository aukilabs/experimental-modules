use authentication::{current_time_ms, Action, Client, Config, Credentials, Event};
use dotenv::dotenv;
use reqwest;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    dotenv().ok();

    println!("=== Auki Authentication Example ===\n");

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
    println!("  DDS URL: {}", config.dds_url);
    println!("  Client ID: {}", config.client_id);
    println!("  Refresh threshold: {}ms\n", config.refresh_threshold_ms);

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
            println!("Using AppKey/AppSecret authentication\n");
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
            println!("Using Opaque token authentication\n");
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

    // Check initial authentication state
    println!(
        "Initial authentication state: {:?}\n",
        client.check_auth_state(now)
    );

    // Step 1: Authenticate to the Auki network
    println!("=== Step 1: Network Authentication ===");
    let actions = client.authenticate(now);
    if actions.is_empty() {
        println!("Already authenticated!\n");
    } else {
        for action in actions {
            match action {
                Action::HttpRequest {
                    url,
                    method,
                    headers,
                    body,
                } => {
                    println!("Making {} request to: {}", method, url);
                    println!("Headers:");
                    for (key, value) in &headers {
                        // Mask sensitive auth tokens in logs
                        if key == "Authorization" {
                            println!("  {}: {}...", key, &value[..20.min(value.len())]);
                        } else {
                            println!("  {}: {}", key, value);
                        }
                    }

                    let mut request = match method.as_str() {
                        "GET" => http_client.get(&url),
                        "POST" => http_client.post(&url),
                        "PUT" => http_client.put(&url),
                        "DELETE" => http_client.delete(&url),
                        _ => panic!("Unsupported HTTP method: {}", method),
                    };

                    // Add headers
                    for (key, value) in headers {
                        request = request.header(key, value);
                    }

                    // Add body if present
                    if let Some(body_str) = body {
                        request = request.body(body_str);
                    }

                    // Execute request
                    let response = request.send().await?;
                    let status = response.status().as_u16();
                    let body_text = response.text().await?;

                    println!("Response status: {}", status);

                    // Handle response
                    let events = client.handle_response(status, &body_text);

                    for event in events {
                        match event {
                            Event::NetworkAuthSuccess { expires_at, .. } => {
                                println!("✓ Network authentication successful!");
                                println!("  Token expires at: {}\n", expires_at);
                            }
                            Event::NetworkAuthFailed { reason, .. } => {
                                eprintln!("✗ Network authentication failed: {}\n", reason);
                                return Err(reason.into());
                            }
                            _ => println!("Event: {:?}", event),
                        }
                    }
                }
                Action::Wait { duration_ms } => {
                    println!("Waiting {}ms...", duration_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(duration_ms)).await;
                }
            }
        }
    }

    // Step 2: Authenticate to Discovery service
    println!("=== Step 2: Discovery Authentication ===");
    let actions = client.authenticate_discovery(now);
    if actions.is_empty() {
        println!("Already authenticated to discovery!\n");
    } else {
        for action in actions {
            if let Action::HttpRequest {
                url,
                method,
                headers,
                body,
            } = action
            {
                println!("Making {} request to: {}", method, url);
                println!("Headers:");
                for (key, value) in &headers {
                    // Mask sensitive auth tokens in logs
                    if key == "Authorization" {
                        println!("  {}: {}...", key, &value[..20.min(value.len())]);
                    } else {
                        println!("  {}: {}", key, value);
                    }
                }

                let mut request = match method.as_str() {
                    "GET" => http_client.get(&url),
                    "POST" => http_client.post(&url),
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

                println!("Response status: {}", status);

                let events = client.handle_response(status, &body_text);

                for event in events {
                    match event {
                        Event::DiscoveryAuthSuccess { expires_at, .. } => {
                            println!("✓ Discovery authentication successful!");
                            println!("  Token expires at: {}\n", expires_at);
                        }
                        Event::DiscoveryAuthFailed { reason } => {
                            eprintln!("✗ Discovery authentication failed: {}\n", reason);
                            return Err(reason.into());
                        }
                        _ => println!("Event: {:?}", event),
                    }
                }
            }
        }
    }

    // Step 3: Get domain access
    let domain_id = env::var("DOMAIN_ID").unwrap_or_else(|_| {
        println!("⚠ DOMAIN_ID not set in .env, using example domain");
        "example-domain".to_string()
    });

    println!("=== Step 3: Domain Access ===");
    println!("Requesting access to domain: {}", domain_id);

    let actions = client.get_domain_access(&domain_id, now);
    if actions.is_empty() {
        println!("Already have access to domain!\n");
    } else {
        for action in actions {
            if let Action::HttpRequest {
                url,
                method,
                headers,
                body,
            } = action
            {
                println!("Making {} request to: {}", method, url);
                println!("Headers:");
                for (key, value) in &headers {
                    // Mask sensitive auth tokens in logs
                    if key == "Authorization" {
                        println!("  {}: {}...", key, &value[..20.min(value.len())]);
                    } else {
                        println!("  {}: {}", key, value);
                    }
                }

                let mut request = match method.as_str() {
                    "GET" => http_client.get(&url),
                    "POST" => http_client.post(&url),
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

                println!("Response status: {}", status);

                let events = client.handle_response(status, &body_text);

                for event in events {
                    match event {
                        Event::DomainAccessGranted { domain } => {
                            println!("✓ Domain access granted!");
                            println!("  Domain ID: {}", domain.id);
                            println!("  Domain Name: {}", domain.name);
                            println!("  Server URL: {}", domain.domain_server.url);
                            println!("  Server Status: {}", domain.domain_server.status);
                            println!("  Server Region: {}", domain.domain_server.cloud_region);
                            println!(
                                "  Location: {}, {}",
                                domain.domain_server.latitude, domain.domain_server.longitude
                            );
                            println!("  Token expires at: {}\n", domain.expires_at);
                        }
                        Event::DomainAccessDenied { domain_id, reason } => {
                            eprintln!("✗ Domain access denied for {}: {}\n", domain_id, reason);
                            return Err(reason.into());
                        }
                        _ => println!("Event: {:?}", event),
                    }
                }
            }
        }
    }

    // Display final state
    println!("=== Final State ===");
    println!("Authentication state: {:?}", client.check_auth_state(now));
    println!("Is authenticated: {}", client.is_authenticated(now));

    if let Some(network_token) = client.network_token() {
        println!("\nNetwork Token:");
        println!(
            "  Token: {}...",
            &network_token.token[..50.min(network_token.token.len())]
        );
        println!("  Expires at: {}", network_token.expires_at);
    }

    if let Some(domain) = client.domain_access(&domain_id) {
        println!("\nDomain Access:");
        println!("  Domain: {} ({})", domain.name, domain.id);
        println!("  Server: {}", domain.domain_server.name);
        println!("  Server URL: {}", domain.domain_server.url);
        println!("  Access Token: {}", domain.access_token);
    }

    // Save state example
    println!("\n=== State Serialization ===");
    let state_json = client.save_state()?;
    println!("State serialized ({} bytes)", state_json.len());
    println!("Note: Credentials are NOT included in saved state");

    println!("\n✓ Example completed successfully!");

    Ok(())
}
