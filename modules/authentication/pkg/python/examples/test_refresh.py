"""
Token Refresh Test

Tests the token refresh functionality of the authentication client.
Similar to examples/test_refresh.js but using the Python wrapper.
"""

import asyncio
import os
from dotenv import load_dotenv
from auki_authentication import Client, Config, current_time_ms

# Load environment variables
load_dotenv(dotenv_path='../../.env')

async def main():
    print('=== Token Refresh Test ===\n')

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
    print(f'  Client ID: {config.client_id}')
    print(f'  Refresh threshold: {config.refresh_threshold_ms}ms ({config.refresh_threshold_ms // 3600000}h)\n')

    # Credentials
    email = os.getenv('EMAIL')
    password = os.getenv('PASSWORD')

    if not email or not password:
        print('❌ EMAIL and PASSWORD must be set in .env file')
        return

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
            print('✓ Network token obtained!')
            print(f'  Token: {network_token.token[:50]}...')
            print(f'  Expires at: {network_token.expires_at} ({network_token.expires_at - current_time_ms()}ms from now)\n')

            # Step 2: Authenticate to Discovery
            print('=== Step 2: Discovery Authentication ===')
            discovery_token = await client.authenticate_discovery()
            print('✓ Discovery token obtained!')
            print(f'  Token: {discovery_token.token[:50]}...')
            print(f'  Expires at: {discovery_token.expires_at} ({discovery_token.expires_at - current_time_ms()}ms from now)\n')

            # Step 3: Get Domain Access
            domain_id = os.getenv('DOMAIN_ID')
            if not domain_id:
                print('⚠ DOMAIN_ID not set in .env, skipping domain access step\n')
            else:
                print('=== Step 3: Domain Access ===')
                print(f'Requesting access to domain: {domain_id}')
                domain_access = await client.get_domain_access(domain_id)
                print('✓ Domain access obtained!')
                print(f'  Domain: {domain_access.name} ({domain_access.id})')
                print(f'  Access token: {domain_access.access_token[:50]}...')
                print(f'  Expires at: {domain_access.expires_at} ({domain_access.expires_at - current_time_ms()}ms from now)\n')

            # Step 4: Test Token Refresh
            print('=== Step 4: Testing Token Refresh ===')
            print('Note: Only the network token has a refresh_token field.')
            print('Discovery and domain tokens must be re-requested, not refreshed.\n')

            print('Calling authenticate() again to test refresh logic...')

            # Get the current network token to compare
            network_token_before = client.get_network_token()
            print(f'Network token before: {network_token_before.token[:30]}...')

            # Try to authenticate again
            # Note: The Python wrapper's async API may handle this differently than JavaScript
            try:
                network_token_2 = await client.authenticate()
                print(f'Network token after: {network_token_2.token[:30]}...')
                print('✓ Token was refreshed or re-authenticated!\n')
            except Exception as error:
                # If no actions needed, wrapper may not make HTTP requests
                error_msg = str(error)
                if 'No response' in error_msg or 'No actions' in error_msg:
                    print('✓ No refresh needed - token is still valid and not near expiry\n')
                else:
                    print(f'✗ Unexpected error: {error_msg}')
                    raise

            # Step 5: Test Discovery Token Re-request
            print('=== Step 5: Testing Discovery Token Re-request ===')
            print('Calling authenticate_discovery() again...')

            try:
                discovery_token_2 = await client.authenticate_discovery()
                print('✓ Discovery token was re-requested!\n')
            except Exception as error:
                error_msg = str(error)
                if 'No response' in error_msg or 'No actions' in error_msg:
                    print('✓ No re-request needed - discovery token is still valid\n')
                else:
                    print(f'✗ Unexpected error: {error_msg}')
                    raise

            # Step 6: Simulate Token Expiration
            print('=== Step 6: Simulating Token Expiration ===')
            print('Simulating that 1 hour has passed (tokens should be expired)...\n')

            now = current_time_ms()
            future_time = now + 3660000  # 61 minutes

            print(f'Current time: {now}')
            print(f'Simulated time: {future_time} ({future_time - now}ms in the future)')
            print(f'Is authenticated: {client.is_authenticated()}\n')

            # Check which tokens are expired (relative to future time)
            network_token_current = client.get_network_token()
            if network_token_current:
                expired = network_token_current.expires_at < future_time
                print(f'Network token expired at simulated time: {expired}')
                print(f'  Expires: {network_token_current.expires_at}, Simulated now: {future_time}\n')

            discovery_token_current = client.get_discovery_token()
            if discovery_token_current:
                expired = discovery_token_current.expires_at < future_time
                print(f'Discovery token expired at simulated time: {expired}')
                print(f'  Expires: {discovery_token_current.expires_at}, Simulated now: {future_time}\n')

            if domain_id:
                domain_access_current = client.get_cached_domain_access(domain_id)
                if domain_access_current:
                    expired = domain_access_current.expires_at < future_time
                    print(f'Domain access expired at simulated time: {expired}')
                    print(f'  Expires: {domain_access_current.expires_at}, Simulated now: {future_time}\n')

            # Display Final State
            print('=== Final State ===')
            print(f'Is authenticated: {client.is_authenticated()}')

            final_network_token = client.get_network_token()
            if final_network_token:
                print('\nNetwork Token:')
                print(f'  Expires at: {final_network_token.expires_at}')
                remaining_ms = final_network_token.expires_at - now
                print(f'  Time remaining: {remaining_ms}ms ({remaining_ms // 3600000}h {(remaining_ms % 3600000) // 60000}m)')

            final_discovery_token = client.get_discovery_token()
            if final_discovery_token:
                print('\nDiscovery Token:')
                print(f'  Expires at: {final_discovery_token.expires_at}')
                remaining_ms = final_discovery_token.expires_at - now
                print(f'  Time remaining: {remaining_ms}ms ({remaining_ms // 3600000}h {(remaining_ms % 3600000) // 60000}m)')

            if domain_id:
                final_domain_access = client.get_cached_domain_access(domain_id)
                if final_domain_access:
                    print('\nDomain Access:')
                    print(f'  Domain: {final_domain_access.name} ({final_domain_access.id})')
                    print(f'  Expires at: {final_domain_access.expires_at}')
                    remaining_ms = final_domain_access.expires_at - now
                    print(f'  Time remaining: {remaining_ms}ms ({remaining_ms // 3600000}h {(remaining_ms % 3600000) // 60000}m)')

            print('\n=== Summary ===')
            print('• Network tokens have refresh_token and can be refreshed via POST /user/refresh')
            print('• Discovery tokens are obtained by re-authenticating with network token via POST /service/domains-access-token')
            print('• Domain access tokens are obtained by re-requesting with discovery token via POST /api/v1/domains/{id}/auth')
            print('• Only the network token can be truly "refreshed" - others must be re-requested\n')

            print('✓ Refresh test completed successfully!')

        except Exception as error:
            print(f'\n❌ Test failed: {error}')
            import traceback
            traceback.print_exc()
            return 1

    return 0

# Run the test
if __name__ == '__main__':
    exit_code = asyncio.run(main())
    exit(exit_code or 0)
