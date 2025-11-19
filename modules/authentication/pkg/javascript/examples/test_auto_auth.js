/**
 * Test Auto-Authentication
 *
 * This test verifies that calling getDomainAccess() directly
 * (without prior authenticate() or authenticateDiscovery() calls)
 * automatically handles the full authentication chain.
 */

import { Client } from '../dist/index.js';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: '../../.env' });

async function main() {
  console.log('=== Testing Auto-Authentication ===\n');

  // Configuration
  const config = {
    apiUrl: process.env.API_URL || 'https://api.aukiverse.com',
    refreshUrl: process.env.REFRESH_URL || 'https://api.aukiverse.com/user/refresh',
    ddsUrl: process.env.DDS_URL || 'https://dds.posemesh.org',
    clientId: 'test-auto-auth',
  };

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

  const domainId = process.env.DOMAIN_ID;
  if (!domainId) {
    console.error('❌ DOMAIN_ID must be set in .env file');
    process.exit(1);
  }

  console.log('Config:', config);
  console.log('Email:', credentials.email);
  console.log('Domain ID:', domainId);
  console.log();

  // Create client (async initialization)
  const client = await Client.create(config);
  client.setCredentials(credentials);

  // Check initial state - should NOT be authenticated
  console.log('Initial state:');
  console.log('  Is authenticated:', client.isAuthenticated());
  console.log('  Network token:', client.getNetworkToken() ? 'present' : 'null');
  console.log('  Discovery token:', client.getDiscoveryToken() ? 'present' : 'null');
  console.log();

  try {
    // THE TEST: Call getDomainAccess() directly without prior auth calls
    console.log('=== Calling getDomainAccess() directly (no prior auth) ===');
    console.log('This should automatically:');
    console.log('  1. Authenticate to network');
    console.log('  2. Authenticate to discovery');
    console.log('  3. Get domain access');
    console.log();

    const domainAccess = await client.getDomainAccess(domainId);

    console.log('✅ SUCCESS! Got domain access:');
    console.log('  Domain ID:', domainAccess.id);
    console.log('  Domain Name:', domainAccess.name);
    console.log('  Server:', domainAccess.domain_server.name);
    console.log('  Server URL:', domainAccess.domain_server.url);
    console.log('  Access token:', domainAccess.access_token.substring(0, 50) + '...');
    console.log();

    // Verify final state
    console.log('Final state:');
    console.log('  Is authenticated:', client.isAuthenticated());

    const networkToken = client.getNetworkToken();
    if (networkToken) {
      console.log('  Network token: present (expires:', networkToken.expires_at + ')');
    } else {
      console.log('  Network token: NULL ❌');
    }

    const discoveryToken = client.getDiscoveryToken();
    if (discoveryToken) {
      console.log('  Discovery token: present (expires:', discoveryToken.expires_at + ')');
    } else {
      console.log('  Discovery token: NULL ❌');
    }

    const cachedDomain = client.getCachedDomainAccess(domainId);
    if (cachedDomain) {
      console.log('  Cached domain access: present');
    } else {
      console.log('  Cached domain access: NULL ❌');
    }

    console.log();
    console.log('✅ Auto-authentication test PASSED!');

  } catch (error) {
    console.error('\n❌ FAILED:', error.message);
    console.error('Error type:', error.constructor.name);
    if (error.retryable !== undefined) {
      console.error('Retryable:', error.retryable);
    }
    console.error('\nStack:', error.stack);
    process.exit(1);
  }
}

// Run the test
main().catch((error) => {
  console.error('💥 Unexpected error:', error);
  process.exit(1);
});
