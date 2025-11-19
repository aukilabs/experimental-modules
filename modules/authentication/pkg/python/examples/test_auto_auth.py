#!/usr/bin/env python3
"""
Test Auto-Authentication

This test verifies that calling get_domain_access() directly
(without prior authenticate() or authenticate_discovery() calls)
automatically handles the full authentication chain.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from auki_authentication import Client, Config, AuthenticationError
from dotenv import load_dotenv

# Load environment variables
load_dotenv(dotenv_path="../../.env")


async def main():
    print("=== Testing Auto-Authentication ===\n")

    # Configuration
    config = Config(
        api_url=os.getenv("API_URL", "https://api.aukiverse.com"),
        refresh_url=os.getenv("REFRESH_URL", "https://api.aukiverse.com/user/refresh"),
        dds_url=os.getenv("DDS_URL", "https://dds.posemesh.org"),
        client_id="test-auto-auth",
    )

    # Credentials
    email = os.getenv("EMAIL")
    password = os.getenv("PASSWORD")

    if not email or not password:
        print("❌ EMAIL and PASSWORD must be set in .env file")
        sys.exit(1)

    credentials = {
        "type": "email",
        "email": email,
        "password": password
    }

    domain_id = os.getenv("DOMAIN_ID")
    if not domain_id:
        print("❌ DOMAIN_ID must be set in .env file")
        sys.exit(1)

    print(f"Config: api_url={config.api_url}, dds_url={config.dds_url}")
    print(f"Email: {email}")
    print(f"Domain ID: {domain_id}\n")

    # Create client
    async with Client(config, credentials) as client:
        # Check initial state - should NOT be authenticated
        print("Initial state:")
        print(f"  Is authenticated: {client.is_authenticated()}")
        print(f"  Network token: {'present' if client.get_network_token() else 'null'}")
        print(f"  Discovery token: {'present' if client.get_discovery_token() else 'null'}")
        print()

        try:
            # THE TEST: Call get_domain_access() directly without prior auth calls
            print("=== Calling get_domain_access() directly (no prior auth) ===")
            print("This should automatically:")
            print("  1. Authenticate to network")
            print("  2. Authenticate to discovery")
            print("  3. Get domain access")
            print()

            domain_access = await client.get_domain_access(domain_id)

            print("✅ SUCCESS! Got domain access:")
            print(f"  Domain ID: {domain_access.id}")
            print(f"  Domain Name: {domain_access.name}")
            print(f"  Server: {domain_access.domain_server.name}")
            print(f"  Server URL: {domain_access.domain_server.url}")
            print(f"  Access token: {domain_access.access_token[:50]}...")
            print()

            # Verify final state
            print("Final state:")
            print(f"  Is authenticated: {client.is_authenticated()}")

            network_token = client.get_network_token()
            if network_token:
                print(f"  Network token: present (expires: {network_token.expires_at})")
            else:
                print("  Network token: NULL ❌")

            discovery_token = client.get_discovery_token()
            if discovery_token:
                print(f"  Discovery token: present (expires: {discovery_token.expires_at})")
            else:
                print("  Discovery token: NULL ❌")

            cached_domain = client.get_cached_domain_access(domain_id)
            if cached_domain:
                print("  Cached domain access: present")
            else:
                print("  Cached domain access: NULL ❌")

            print()
            print("✅ Auto-authentication test PASSED!")

        except AuthenticationError as e:
            print(f"\n❌ FAILED: {e}")
            print(f"Error type: {type(e).__name__}")
            if hasattr(e, 'retryable'):
                print(f"Retryable: {e.retryable}")
            import traceback
            print(f"\nStack: {traceback.format_exc()}")
            sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
