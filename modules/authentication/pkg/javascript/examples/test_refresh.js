/**
 * Token Refresh Test
 *
 * Tests the token refresh functionality of the authentication client.
 * Similar to examples/refresh.rs but using the JavaScript wrapper.
 */

import { Client } from '../dist/index.js';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: '../../.env' });

async function main() {
  console.log('=== Token Refresh Test ===\n');

  // Configuration
  const config = {
    apiUrl: process.env.API_URL || 'https://api.aukiverse.com',
    refreshUrl: process.env.REFRESH_URL || 'https://api.aukiverse.com/user/refresh',
    ddsUrl: process.env.DDS_URL || 'https://dds.posemesh.org',
    clientId: process.env.CLIENT_ID || 'javascript-test',
    // Set a very high refresh threshold so we can manually trigger refresh
    refreshThresholdMs: 3600000, // 1 hour
  };

  console.log('Configuration:');
  console.log(`  API URL: ${config.apiUrl}`);
  console.log(`  Refresh URL: ${config.refreshUrl}`);
  console.log(`  DDS URL: ${config.ddsUrl}`);
  console.log(`  Client ID: ${config.clientId}`);
  console.log(`  Refresh threshold: ${config.refreshThresholdMs}ms (${config.refreshThresholdMs / 3600000}h)\n`);

  // Credentials
  const credentials = {
    type: 'email',
    email: process.env.EMAIL,
    password: process.env.PASSWORD
  };

  if (!credentials.email || !credentials.password) {
    console.error('❌ EMAIL and PASSWORD must be set in .env file');
    process.exit(1);
  }

  console.log('Using Email/Password authentication');
  console.log(`  Email: ${credentials.email}\n`);

  // Create the authentication client
  const client = await Client.create(config);
  client.setCredentials(credentials);

  try {
    // Step 1: Initial Network Authentication
    console.log('=== Step 1: Initial Network Authentication ===');
    const networkToken = await client.authenticate();
    console.log('✓ Network token obtained!');
    console.log(`  Token: ${networkToken.token.substring(0, 50)}...`);
    console.log(`  Expires at: ${networkToken.expires_at} (${networkToken.expires_at - Date.now()}ms from now)\n`);

    // Step 2: Authenticate to Discovery
    console.log('=== Step 2: Discovery Authentication ===');
    const discoveryToken = await client.authenticateDiscovery();
    console.log('✓ Discovery token obtained!');
    console.log(`  Token: ${discoveryToken.token.substring(0, 50)}...`);
    console.log(`  Expires at: ${discoveryToken.expires_at} (${discoveryToken.expires_at - Date.now()}ms from now)\n`);

    // Step 3: Get Domain Access
    const domainId = process.env.DOMAIN_ID;
    if (!domainId) {
      console.log('⚠ DOMAIN_ID not set in .env, skipping domain access step\n');
    } else {
      console.log('=== Step 3: Domain Access ===');
      console.log(`Requesting access to domain: ${domainId}`);
      const domainAccess = await client.getDomainAccess(domainId);
      console.log('✓ Domain access obtained!');
      console.log(`  Domain: ${domainAccess.name} (${domainAccess.id})`);
      console.log(`  Access token: ${domainAccess.access_token.substring(0, 50)}...`);
      console.log(`  Expires at: ${domainAccess.expires_at} (${domainAccess.expires_at - Date.now()}ms from now)\n`);
    }

    // Step 4: Test Token Refresh
    console.log('=== Step 4: Testing Token Refresh ===');
    console.log('Note: Only the network token has a refresh_token field.');
    console.log('Discovery and domain tokens must be re-requested, not refreshed.\n');

    console.log('Calling authenticate() again to test refresh logic...');

    // Get the current network token to compare
    const networkTokenBefore = client.getNetworkToken();
    console.log(`Network token before: ${networkTokenBefore.token.substring(0, 30)}...`);

    // Try to authenticate again
    // Note: The JavaScript wrapper automatically executes actions and throws "No response"
    // if no actions are returned (token still valid). This is different from the Rust client
    // where you check actions.is_empty() before executing.
    try {
      const networkToken2 = await client.authenticate();
      console.log(`Network token after: ${networkToken2.token.substring(0, 30)}...`);
      console.log('✓ Token was refreshed or re-authenticated!\n');
    } catch (error) {
      // If error message is "No response", it means no actions were returned by the core,
      // which means the token is still valid and doesn't need refresh
      if (error.message && error.message.includes('No response')) {
        console.log('✓ No refresh needed - token is still valid and not near expiry\n');
      } else {
        // Real error
        console.error(`Unexpected error: ${error.message}`);
        throw error;
      }
    }

    // Step 5: Test Discovery Token Re-request
    console.log('=== Step 5: Testing Discovery Token Re-request ===');
    console.log('Calling authenticateDiscovery() again...');

    try {
      const discoveryToken2 = await client.authenticateDiscovery();
      console.log('✓ Discovery token was re-requested!\n');
    } catch (error) {
      // If error message is "No response", token is still valid
      if (error.message && error.message.includes('No response')) {
        console.log('✓ No re-request needed - discovery token is still valid\n');
      } else {
        console.error(`Unexpected error: ${error.message}`);
        throw error;
      }
    }

    // Step 6: Simulate Token Expiration
    console.log('=== Step 6: Simulating Token Expiration ===');
    console.log('Simulating that 1 hour has passed (tokens should be expired)...\n');

    const now = Date.now();
    const futureTime = now + 3660000; // 61 minutes

    console.log(`Current time: ${now}`);
    console.log(`Simulated time: ${futureTime} (${futureTime - now}ms in the future)`);
    console.log(`Is authenticated: ${client.isAuthenticated()}\n`);

    // Check which tokens are expired (relative to future time)
    const networkTokenCurrent = client.getNetworkToken();
    if (networkTokenCurrent) {
      const expired = networkTokenCurrent.expires_at < futureTime;
      console.log(`Network token expired at simulated time: ${expired}`);
      console.log(`  Expires: ${networkTokenCurrent.expires_at}, Simulated now: ${futureTime}\n`);
    }

    const discoveryTokenCurrent = client.getDiscoveryToken();
    if (discoveryTokenCurrent) {
      const expired = discoveryTokenCurrent.expires_at < futureTime;
      console.log(`Discovery token expired at simulated time: ${expired}`);
      console.log(`  Expires: ${discoveryTokenCurrent.expires_at}, Simulated now: ${futureTime}\n`);
    }

    if (domainId) {
      const domainAccessCurrent = client.getCachedDomainAccess(domainId);
      if (domainAccessCurrent) {
        const expired = domainAccessCurrent.expires_at < futureTime;
        console.log(`Domain access expired at simulated time: ${expired}`);
        console.log(`  Expires: ${domainAccessCurrent.expires_at}, Simulated now: ${futureTime}\n`);
      }
    }

    // Display Final State
    console.log('=== Final State ===');
    console.log(`Is authenticated: ${client.isAuthenticated()}`);

    const finalNetworkToken = client.getNetworkToken();
    if (finalNetworkToken) {
      console.log('\nNetwork Token:');
      console.log(`  Expires at: ${finalNetworkToken.expires_at}`);
      const remainingMs = finalNetworkToken.expires_at - now;
      console.log(`  Time remaining: ${remainingMs}ms (${Math.floor(remainingMs / 3600000)}h ${Math.floor((remainingMs % 3600000) / 60000)}m)`);
    }

    const finalDiscoveryToken = client.getDiscoveryToken();
    if (finalDiscoveryToken) {
      console.log('\nDiscovery Token:');
      console.log(`  Expires at: ${finalDiscoveryToken.expires_at}`);
      const remainingMs = finalDiscoveryToken.expires_at - now;
      console.log(`  Time remaining: ${remainingMs}ms (${Math.floor(remainingMs / 3600000)}h ${Math.floor((remainingMs % 3600000) / 60000)}m)`);
    }

    if (domainId) {
      const finalDomainAccess = client.getCachedDomainAccess(domainId);
      if (finalDomainAccess) {
        console.log('\nDomain Access:');
        console.log(`  Domain: ${finalDomainAccess.name} (${finalDomainAccess.id})`);
        console.log(`  Expires at: ${finalDomainAccess.expires_at}`);
        const remainingMs = finalDomainAccess.expires_at - now;
        console.log(`  Time remaining: ${remainingMs}ms (${Math.floor(remainingMs / 3600000)}h ${Math.floor((remainingMs % 3600000) / 60000)}m)`);
      }
    }

    console.log('\n=== Summary ===');
    console.log('• Network tokens have refresh_token and can be refreshed via POST /user/refresh');
    console.log('• Discovery tokens are obtained by re-authenticating with network token via POST /service/domains-access-token');
    console.log('• Domain access tokens are obtained by re-requesting with discovery token via POST /api/v1/domains/{id}/auth');
    console.log('• Only the network token can be truly "refreshed" - others must be re-requested\n');

    console.log('✓ Refresh test completed successfully!');

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    if (error.retryable) {
      console.error('  This error is retryable');
    }
    process.exit(1);
  }
}

// Run the test
main().catch((error) => {
  console.error('💥 Unexpected error:', error);
  process.exit(1);
});
