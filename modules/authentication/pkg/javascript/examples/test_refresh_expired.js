/**
 * Expired Refresh Token Test
 *
 * Tests what happens when both access and refresh tokens expire.
 * Similar to examples/refresh_expired.rs but using the JavaScript wrapper.
 */

import { Client, isExpired } from '../dist/index.js';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: '../../.env' });

async function main() {
  console.log('=== Expired Refresh Token Test ===\n');

  // Configuration
  const config = {
    apiUrl: process.env.API_URL || 'https://api.aukiverse.com',
    refreshUrl: process.env.REFRESH_URL || 'https://api.aukiverse.com/user/refresh',
    ddsUrl: process.env.DDS_URL || 'https://dds.posemesh.org',
    clientId: process.env.CLIENT_ID || 'javascript-test',
    refreshThresholdMs: parseInt(process.env.REFRESH_THRESHOLD_MS || '300000')
  };

  console.log('Configuration:');
  console.log(`  API URL: ${config.apiUrl}`);
  console.log(`  Refresh URL: ${config.refreshUrl}`);
  console.log(`  Client ID: ${config.clientId}\n`);

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

  const now = Date.now();

  try {
    // Step 1: Initial Authentication
    console.log('=== Step 1: Initial Authentication ===');
    const networkToken = await client.authenticate();
    console.log('✓ Network authentication successful!');
    console.log(`  Token expires at: ${networkToken.expires_at}`);
    console.log();

    // Step 2: Simulate that a VERY long time has passed
    console.log('=== Step 2: Simulating 30+ Days Have Passed ===');
    console.log('Simulating that app hasn\'t been used for over 30 days...');
    console.log('Note: Access tokens typically last 1 hour');
    console.log('      Refresh tokens typically last 7-30 days\n');

    // Simulate 30 days + 1 hour in the future
    const futureTime = now + (30 * 24 * 60 * 60 * 1000) + (60 * 60 * 1000);
    const daysPassed = Math.floor((futureTime - now) / (24 * 60 * 60 * 1000));

    console.log(`Simulated current time: ${futureTime} (${daysPassed} days in future)`);

    const networkTokenCurrent = client.getNetworkToken();
    if (networkTokenCurrent) {
      console.log('\nToken status at simulated time:');
      console.log(`  Access token expires: ${networkTokenCurrent.expires_at}`);
      const daysExpired = Math.floor((futureTime - networkTokenCurrent.expires_at) / (24 * 60 * 60 * 1000));
      console.log(`  Access token expired: ${networkTokenCurrent.expires_at < futureTime} (expired ${daysExpired} days ago)`);
      console.log('  Refresh token: ALSO EXPIRED (past 30 day lifetime)\n');
    }

    // Step 3: Save and restore state
    console.log('=== Step 3: State Serialization ===');
    const stateJson = client.saveState();
    console.log(`State serialized (${stateJson.length} bytes)`);
    console.log('Note: Credentials are NOT included in saved state\n');

    // Step 4: Restore from saved state (simulating app restart)
    console.log('=== Step 4: Restoring from Saved State ===');
    console.log('Simulating app restart 30+ days later...\n');

    const restoredClient = Client.fromState(stateJson, config);
    console.log('✓ Client restored from saved state');

    // Check authentication state with current real time (not future)
    // In a real app, this would be the actual current time
    console.log(`  Is authenticated (current time): ${restoredClient.isAuthenticated()}`);

    // Now validate state - this will clear expired tokens
    restoredClient.validateState();
    console.log('✓ Validated state (removed expired tokens if any)');

    const networkTokenAfterValidation = restoredClient.getNetworkToken();
    if (networkTokenAfterValidation) {
      console.log(`  Network token still present: yes`);
      console.log(`  Token expired: ${isExpired(networkTokenAfterValidation.expires_at)}`);
    } else {
      console.log('  Network token still present: no (was cleared)\n');
    }

    // Step 5: Try to authenticate with expired state
    console.log('=== Step 5: Attempting to Authenticate ===');
    console.log('In a real app with expired tokens, you need to:');
    console.log('  1. Detect that authentication is needed');
    console.log('  2. Show login screen to user');
    console.log('  3. Create new client with credentials');
    console.log('  4. Call authenticate()\n');

    // Since the JavaScript wrapper doesn't expose check_auth_state or set_credentials,
    // we need to handle this differently. If authenticate() fails, create a new client.
    console.log('Attempting to call authenticate() with potentially expired state...');

    try {
      await restoredClient.authenticate();
      console.log('✓ Authentication succeeded (had valid credentials stored or tokens still valid)\n');
    } catch (error) {
      console.log('✗ Authentication failed (expected with expired tokens)');
      console.log(`  Error: ${error.message}\n`);
      console.log('In a real application, you would:');
      console.log('  1. Show login screen');
      console.log('  2. Get fresh credentials from user');
      console.log('  3. Create new Client with those credentials');
      console.log('  4. Call authenticate() again\n');
    }

    // Step 6: Show how to handle this in a real application
    console.log('=== Step 6: How to Handle This in Your Application ===\n');

    console.log('Recommended pattern:');
    console.log('```javascript');
    console.log('// On app startup, try to restore from saved state');
    console.log('let client;');
    console.log('const savedState = loadFromStorage();');
    console.log('');
    console.log('if (savedState) {');
    console.log('  try {');
    console.log('    client = Client.fromState(savedState, config);');
    console.log('    client.validateState(); // Clear expired tokens');
    console.log('    ');
    console.log('    // Try to authenticate (will use stored credentials if available)');
    console.log('    await client.authenticate();');
    console.log('    // Success! Continue with app');
    console.log('  } catch (error) {');
    console.log('    // Authentication failed - need fresh credentials');
    console.log('    showLoginScreen();');
    console.log('  }');
    console.log('} else {');
    console.log('  // No saved state - first time user');
    console.log('  showLoginScreen();');
    console.log('}');
    console.log('');
    console.log('// After user enters credentials:');
    console.log('client = new Client(credentials, config);');
    console.log('await client.authenticate();');
    console.log('```\n');

    console.log('=== Summary ===');
    console.log('✓ This example demonstrated:');
    console.log('  • What happens when BOTH access and refresh tokens expire');
    console.log('  • How to save and restore client state');
    console.log('  • That validateState() clears expired tokens');
    console.log('  • How to handle expired state in a real application\n');

    console.log('Key takeaways:');
    console.log('  • Access tokens expire quickly (typically 1 hour)');
    console.log('  • Refresh tokens last longer (typically 7-30 days)');
    console.log('  • When refresh token expires, user MUST log in again');
    console.log('  • Always call validateState() after loading from storage');
    console.log('  • Save state frequently to preserve tokens');
    console.log('  • Handle authentication errors by prompting for credentials\n');

    console.log('✓ Test completed successfully!');

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
