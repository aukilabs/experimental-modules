#!/usr/bin/env python3
"""
Basic Authentication Example

This example demonstrates the complete authentication flow:
- Network authentication
- Discovery service authentication
- Domain access
- State persistence
"""
import asyncio
import os
from dotenv import load_dotenv
from auki_authentication import (
    Client,
    Config,
    AuthenticationError,
)


async def main():
    print("=== Auki Authentication Example ===\n")

    # Load environment variables
    load_dotenv(dotenv_path="../../.env")

    # Configuration
    # Note: refresh_url is included in api_url/refresh endpoint
    config = Config(
        api_url=os.getenv("API_URL", "https://api.aukiverse.com"),
        refresh_url=os.getenv("REFRESH_URL", "https://api.aukiverse.com/user/refresh"),
        dds_url=os.getenv("DDS_URL", "https://dds.posemesh.org"),
        client_id=os.getenv("CLIENT_ID", "python-sdk"),
        refresh_threshold_ms=int(os.getenv("REFRESH_THRESHOLD_MS", "300000"))
    )

    print("Configuration:")
    print(f"  API URL: {config.api_url}")
    print(f"  Refresh URL: {config.refresh_url}")
    print(f"  DDS URL: {config.dds_url}")
    print(f"  Client ID: {config.client_id}")
    print(f"  Refresh threshold: {config.refresh_threshold_ms}ms\n")

    # Credentials
    credentials = {
        'type': 'email',
        'email': os.getenv("EMAIL"),
        'password': os.getenv("PASSWORD")
    }

    if not credentials['email'] or not credentials['password']:
        print("❌ EMAIL and PASSWORD must be set in .env file")
        return

    print("Using Email/Password authentication")
    print(f"  Email: {credentials['email']}\n")

    # Create the authentication client
    async with Client(config, credentials) as client:
        # Check initial authentication state
        is_auth = client.is_authenticated()
        print(f"Initial authentication state: {'Authenticated' if is_auth else 'Not authenticated'}")
        print()

        try:
            # Step 1: Authenticate to the Auki network
            print("=== Step 1: Network Authentication ===")
            network_token = await client.authenticate()
            print("✓ Network authentication successful!")
            print(f"  Token expires at: {network_token.expires_at}")
            print()

            # Step 2: Authenticate to Discovery service
            print("=== Step 2: Discovery Authentication ===")
            discovery_token = await client.authenticate_discovery()
            print("✓ Discovery authentication successful!")
            print(f"  Token expires at: {discovery_token.expires_at}")
            print()

            # Step 3: Get domain access
            domain_id = os.getenv("DOMAIN_ID")
            if not domain_id:
                print("⚠ DOMAIN_ID not set in .env, skipping domain access step")
            else:
                print("=== Step 3: Domain Access ===")
                print(f"Requesting access to domain: {domain_id}")

                domain_access = await client.get_domain_access(domain_id)
                print("✓ Domain access granted!")
                print(f"  Domain ID: {domain_access.id}")
                print(f"  Domain Name: {domain_access.name}")
                print(f"  Server URL: {domain_access.domain_server.url}")
                print(f"  Server Name: {domain_access.domain_server.name}")
                print(f"  Server Region: {domain_access.domain_server.cloud_region}")
                print(f"  Location: {domain_access.domain_server.latitude}, {domain_access.domain_server.longitude}")
                print(f"  Access token: {domain_access.access_token[:50]}...")
                print(f"  Token expires at: {domain_access.expires_at}")
                print()

            # Display final state
            print("=== Final State ===")
            print(f"Is authenticated: {client.is_authenticated()}")

            network_token_cached = client.get_network_token()
            if network_token_cached:
                print("\nNetwork Token:")
                print(f"  Token: {network_token_cached.token[:50]}...")
                print(f"  Expires at: {network_token_cached.expires_at}")

            discovery_token_cached = client.get_discovery_token()
            if discovery_token_cached:
                print("\nDiscovery Token:")
                print(f"  Token: {discovery_token_cached.token[:50]}...")
                print(f"  Expires at: {discovery_token_cached.expires_at}")

            if domain_id:
                domain_access_cached = client.get_cached_domain_access(domain_id)
                if domain_access_cached:
                    print("\nDomain Access:")
                    print(f"  Domain: {domain_access_cached.name} ({domain_access_cached.id})")
                    print(f"  Server: {domain_access_cached.domain_server.name}")
                    print(f"  Server URL: {domain_access_cached.domain_server.url}")
                    print(f"  Access token: {domain_access_cached.access_token[:50]}...")

            # Save state example
            print("\n=== State Serialization ===")
            state_json = client.save_state()
            print(f"State serialized ({len(state_json)} bytes)")
            print("Note: Credentials are NOT included in saved state")

            # Demonstrate restoring from state
            print("\n=== State Restoration ===")
            restored_client = Client.from_state(state_json, config)
            print("✓ Client restored from saved state")
            print(f"  Is authenticated: {restored_client.is_authenticated()}")

            # Clean up expired tokens
            restored_client.validate_state()
            print("✓ Validated state (removed expired tokens if any)")

            print("\n✓ Example completed successfully!")

        except AuthenticationError as error:
            print(f"\n❌ Authentication failed: {error}")
            if error.retryable:
                print("  This error is retryable")


if __name__ == "__main__":
    asyncio.run(main())
