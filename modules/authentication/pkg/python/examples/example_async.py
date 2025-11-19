#!/usr/bin/env python3
"""
Example usage of the Auki Authentication Python high-level async client.

This example demonstrates the recommended async/await API that handles
HTTP requests internally.
"""
import asyncio
import os
from dotenv import load_dotenv
from auki_authentication import Client, Config, AuthenticationError


async def main():
    print("Auki Authentication Library - Python Async Example\n")

    # Load environment variables
    load_dotenv(dotenv_path="../../.env")

    # Create configuration
    config = Config(
        api_url=os.getenv("API_URL", "https://api.aukiverse.com"),
        refresh_url=os.getenv("REFRESH_URL", "https://api.aukiverse.com/user/refresh"),
        dds_url=os.getenv("DDS_URL", "https://dds.posemesh.org"),
        client_id=os.getenv("CLIENT_ID", "python-async-example"),
        refresh_threshold_ms=int(os.getenv("REFRESH_THRESHOLD_MS", "300000"))
    )
    print(f"✓ Created config for API: {config.api_url}")

    # Credentials
    credentials = {
        'type': 'email',
        'email': os.getenv("EMAIL"),
        'password': os.getenv("PASSWORD")
    }

    if not credentials['email'] or not credentials['password']:
        print("❌ EMAIL and PASSWORD must be set in .env file")
        return

    # Create client with async context manager (automatically closes HTTP client)
    async with Client(config=config, credentials=credentials) as client:
        print("✓ Created authentication client\n")

        # Set up refresh failure callback
        def on_refresh_failed(info):
            print(f"⚠️  {info['token_type']} token refresh failed: {info['reason']}")
            if info["requires_reauth"]:
                print("   Re-authentication required!")

        client.on_refresh_failed(on_refresh_failed)

        # Check if already authenticated
        if client.is_authenticated():
            print("✓ Already authenticated")
            token = client.get_network_token()
            if token:
                print(f"  Token expires at: {token.expires_at}")
        else:
            print("  Not yet authenticated")

        # Authenticate to network
        try:
            print("\nAuthenticating to network...")
            token = await client.authenticate()
            print(f"✓ Network authentication successful!")
            print(f"  Token: {token.token[:50]}...")
            print(f"  Expires at: {token.expires_at}")
        except AuthenticationError as e:
            print(f"✗ Authentication failed: {e}")
            if e.retryable:
                print("  (Error is retryable)")
            return

        # Authenticate to discovery service
        try:
            print("\nAuthenticating to discovery service...")
            disc_token = await client.authenticate_discovery()
            print(f"✓ Discovery authentication successful!")
            print(f"  Token: {disc_token.token[:50]}...")
            print(f"  Expires at: {disc_token.expires_at}")
        except AuthenticationError as e:
            print(f"✗ Discovery authentication failed: {e}")
            return

        # Get domain access
        domain_id = os.getenv("DOMAIN_ID")
        if domain_id:
            try:
                print(f"\nRequesting domain access for: {domain_id}...")
                domain_access = await client.get_domain_access(domain_id)
                print(f"✓ Domain access granted!")
                print(f"  Domain: {domain_access.name}")
                print(f"  Access token: {domain_access.access_token[:50]}...")
                print(f"  Server: {domain_access.domain_server.name}")
                print(f"  Server URL: {domain_access.domain_server.url}")
            except AuthenticationError as e:
                print(f"✗ Domain access failed: {e}")
        else:
            print("\n⚠ DOMAIN_ID not set in .env, skipping domain access")

        # Save client state
        try:
            state = client.save_state()
            print(f"\n✓ Saved client state ({len(state)} bytes)")
            print("  State can be restored later:")
            print("    restored_client = Client.from_state(state, config)")

            # Example of validating state
            client.validate_state()
            print("✓ State validated successfully")
        except Exception as e:
            print(f"✗ Error with state: {e}")

    print("\n✓ HTTP client closed")
    print("\n✅ Example completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())
