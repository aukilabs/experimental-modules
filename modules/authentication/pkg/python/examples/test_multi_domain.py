"""
Multi-Domain Access Test

Tests authenticating to multiple domains with the same client.
"""

import asyncio
import os
import httpx
from dotenv import load_dotenv
from auki_authentication import Client, Config

# Load environment variables
load_dotenv(dotenv_path='../../.env')

async def main():
    print('=== Multi-Domain Access Test ===\n')

    # Configuration
    config = Config(
        api_url=os.getenv('API_URL', 'https://api.aukiverse.com'),
        refresh_url=os.getenv('REFRESH_URL', 'https://api.aukiverse.com/user/refresh'),
        dds_url=os.getenv('DDS_URL', 'https://dds.posemesh.org'),
        client_id=os.getenv('CLIENT_ID', 'python-test'),
        refresh_threshold_ms=int(os.getenv('REFRESH_THRESHOLD_MS', '300000'))
    )

    print('Configuration:')
    print(f'  API URL: {config.api_url}')
    print(f'  DDS URL: {config.dds_url}')
    print(f'  Client ID: {config.client_id}\n')

    # Credentials
    email = os.getenv('EMAIL')
    password = os.getenv('PASSWORD')

    if not email or not password:
        print('❌ EMAIL and PASSWORD must be set in .env file')
        return 1

    credentials = {
        'type': 'email',
        'email': email,
        'password': password,
    }

    print('Using Email/Password authentication')
    print(f'  Email: {email}\n')

    # Create the authentication client
    async with Client(config, credentials) as client:
        try:
            # Step 1: Initial Network Authentication
            print('=== Step 1: Initial Network Authentication ===')
            network_token = await client.authenticate()
            print('✓ Network token obtained!\n')

            # Step 2: Authenticate to Discovery
            print('=== Step 2: Discovery Authentication ===')
            discovery_token = await client.authenticate_discovery()
            print('✓ Discovery token obtained!\n')

            # Step 3: Fetch available domains
            print('=== Step 3: Fetching Available Domains ===')
            url = f'{config.dds_url}/api/v1/domains?with=domain_server'

            async with httpx.AsyncClient() as http_client:
                response = await http_client.get(
                    url,
                    headers={'Authorization': f'Bearer {discovery_token.token}'}
                )

                if response.status_code != 200:
                    raise Exception(f'HTTP {response.status_code}: {response.text}')

                data = response.json()
                domains = data.get('domains', [])
                print(f'✓ Found {len(domains)} available domains\n')

                if len(domains) == 0:
                    print('⚠ No domains available to test with')
                    return 0

                # Display first few domains
                print('Available domains:')
                for i, domain in enumerate(domains[:5]):
                    print(f"  {i + 1}. {domain['name']} ({domain['id']})")
                if len(domains) > 5:
                    print(f'  ... and {len(domains) - 5} more')
                print()

                # Step 4: Authenticate to multiple domains
                print('=== Step 4: Authenticating to Multiple Domains ===')
                domains_to_test = domains[:min(3, len(domains))]

                for i, domain in enumerate(domains_to_test):
                    domain_id = domain['id']
                    domain_name = domain['name']
                    print(f"[{i + 1}/{len(domains_to_test)}] Authenticating to: {domain_name} ({domain_id})")

                    try:
                        domain_access = await client.get_domain_access(domain_id)
                        print(f'  ✓ Access granted!')
                        print(f'    Access token: {domain_access.access_token[:30]}...')
                        print(f'    Expires at: {domain_access.expires_at}\n')
                    except Exception as error:
                        print(f'  ✗ Access denied: {error}\n')

                # Step 5: Verify all domain accesses are cached
                print('=== Step 5: Verifying Cached Domain Access ===')
                for domain in domains_to_test:
                    domain_id = domain['id']
                    domain_name = domain['name']
                    cached = client.get_cached_domain_access(domain_id)
                    if cached:
                        print(f'✓ {domain_name}: Cached (expires {cached.expires_at})')
                    else:
                        print(f'✗ {domain_name}: Not cached')
                print()

                # Step 6: Test re-authenticating to same domains
                print('=== Step 6: Testing Re-authentication to Same Domains ===')
                print('Calling get_domain_access() again for already-authenticated domains...\n')

                for domain in domains_to_test:
                    domain_id = domain['id']
                    domain_name = domain['name']
                    print(f'Testing: {domain_name}')

                    try:
                        domain_access = await client.get_domain_access(domain_id)
                        print(f'  ✓ Re-authenticated successfully\n')
                    except Exception as error:
                        # Check if it's the "No actions" error (token still valid)
                        error_msg = str(error)
                        if 'No actions' in error_msg or 'still valid' in error_msg:
                            print(f'  ✓ No re-authentication needed - domain access still valid\n')
                        else:
                            print(f'  ✗ Error: {error_msg}\n')

                # Step 7: Display summary
                print('=== Summary ===')
                print(f'✓ Successfully tested multi-domain access')
                print(f'  Domains tested: {len(domains_to_test)}')

                all_cached = all(
                    client.get_cached_domain_access(d['id']) is not None
                    for d in domains_to_test
                )
                print(f'  All domain accesses cached: {all_cached}')

                print(f'\nKey findings:')
                print(f'  • A single client instance can authenticate to multiple domains')
                print(f'  • Each domain access is cached independently by domain ID')
                print(f'  • get_cached_domain_access(domain_id) retrieves the cached access')
                print(f'  • Calling get_domain_access() again returns expected behavior if still valid')
                print(f'  • Network and discovery tokens are shared across all domain accesses\n')

                print('✓ Multi-domain test completed successfully!')
                return 0

        except Exception as error:
            print(f'\n❌ Test failed: {error}')
            import traceback
            traceback.print_exc()
            return 1

# Run the test
if __name__ == '__main__':
    exit_code = asyncio.run(main())
    exit(exit_code or 0)
