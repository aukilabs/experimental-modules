/**
 * Basic Authentication Example
 *
 * This example demonstrates the complete authentication flow:
 * - Network authentication
 * - Discovery service authentication
 * - Domain access
 * - State persistence
 */

import { Client } from '../dist/index.js';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: '../../.env' });

async function main() {
  console.log('=== Auki Authentication Example ===\n');

  // Configuration
  const config = {
    apiUrl: process.env.API_URL || 'https://api.aukiverse.com',
    refreshUrl: process.env.REFRESH_URL || 'https://api.aukiverse.com/user/refresh',
    ddsUrl: process.env.DDS_URL || 'https://dds.posemesh.org',
    clientId: process.env.CLIENT_ID || 'javascript-sdk',
    refreshThresholdMs: parseInt(process.env.REFRESH_THRESHOLD_MS || '300000')
  };

  console.log('Configuration:');
  console.log(`  API URL: ${config.apiUrl}`);
  console.log(`  Refresh URL: ${config.refreshUrl}`);
  console.log(`  DDS URL: ${config.ddsUrl}`);
  console.log(`  Client ID: ${config.clientId}`);
  console.log(`  Refresh threshold: ${config.refreshThresholdMs}ms\n`);

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

  // Check initial authentication state
  console.log('Initial authentication state:', client.isAuthenticated() ? 'Authenticated' : 'Not authenticated');
  console.log();

  try {
    // Step 1: Authenticate to the Auki network
    console.log('=== Step 1: Network Authentication ===');
    const networkToken = await client.authenticate();
    console.log('✓ Network authentication successful!');
    console.log(`  Token expires at: ${networkToken.expires_at}`);
    console.log();

    // Step 2: Authenticate to Discovery service
    console.log('=== Step 2: Discovery Authentication ===');
    const discoveryToken = await client.authenticateDiscovery();
    console.log('✓ Discovery authentication successful!');
    console.log(`  Token expires at: ${discoveryToken.expires_at}`);
    console.log();

    // Step 3: Get domain access
    const domainId = process.env.DOMAIN_ID;
    if (!domainId) {
      console.log('⚠ DOMAIN_ID not set in .env, skipping domain access step');
    } else {
      console.log('=== Step 3: Domain Access ===');
      console.log(`Requesting access to domain: ${domainId}`);

      const domainAccess = await client.getDomainAccess(domainId);
      console.log('✓ Domain access granted!');
      console.log(`  Domain ID: ${domainAccess.id}`);
      console.log(`  Domain Name: ${domainAccess.name}`);
      console.log(`  Server URL: ${domainAccess.domain_server.url}`);
      console.log(`  Server Name: ${domainAccess.domain_server.name}`);
      console.log(`  Server Region: ${domainAccess.domain_server.cloud_region}`);
      console.log(`  Location: ${domainAccess.domain_server.latitude}, ${domainAccess.domain_server.longitude}`);
      console.log(`  Access token: ${domainAccess.access_token.substring(0, 50)}...`);
      console.log(`  Token expires at: ${domainAccess.expires_at}`);
      console.log();
    }

    // Display final state
    console.log('=== Final State ===');
    console.log(`Is authenticated: ${client.isAuthenticated()}`);

    const networkTokenCached = client.getNetworkToken();
    if (networkTokenCached) {
      console.log('\nNetwork Token:');
      console.log(`  Token: ${networkTokenCached.token.substring(0, 50)}...`);
      console.log(`  Expires at: ${networkTokenCached.expires_at}`);
    }

    const discoveryTokenCached = client.getDiscoveryToken();
    if (discoveryTokenCached) {
      console.log('\nDiscovery Token:');
      console.log(`  Token: ${discoveryTokenCached.token.substring(0, 50)}...`);
      console.log(`  Expires at: ${discoveryTokenCached.expires_at}`);
    }

    if (domainId) {
      const domainAccessCached = client.getCachedDomainAccess(domainId);
      if (domainAccessCached) {
        console.log('\nDomain Access:');
        console.log(`  Domain: ${domainAccessCached.name} (${domainAccessCached.id})`);
        console.log(`  Server: ${domainAccessCached.domain_server.name}`);
        console.log(`  Server URL: ${domainAccessCached.domain_server.url}`);
        console.log(`  Access token: ${domainAccessCached.access_token.substring(0, 50)}...`);
      }
    }

    // Save state example
    console.log('\n=== State Serialization ===');
    const stateJson = client.saveState();
    console.log(`State serialized (${stateJson.length} bytes)`);
    console.log('Note: Credentials are NOT included in saved state');

    // Demonstrate restoring from state
    console.log('\n=== State Restoration ===');
    const restoredClient = Client.fromState(stateJson, config);
    console.log('✓ Client restored from saved state');
    console.log(`  Is authenticated: ${restoredClient.isAuthenticated()}`);

    // Clean up expired tokens
    restoredClient.validateState();
    console.log('✓ Validated state (removed expired tokens if any)');

    console.log('\n✓ Example completed successfully!');

  } catch (error) {
    console.error('\n❌ Authentication failed:', error.message);
    if (error.retryable) {
      console.error('  This error is retryable');
    }
    process.exit(1);
  }
}

// Run the example
main().catch((error) => {
  console.error('💥 Unexpected error:', error);
  process.exit(1);
});
