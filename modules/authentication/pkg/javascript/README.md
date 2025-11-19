# @auki/authentication

Auki Network authentication library for JavaScript/TypeScript. Works in both Browser and Node.js environments.

This library provides authentication to the Auki Network's hierarchical authentication system:

1. **Network Authentication** - Authenticate to the Auki API
2. **Discovery Authentication** - Authenticate to the Discovery service
3. **Domain Access** - Get access tokens for specific domains

## Installation

```bash
npm install @auki/authentication
```

Or from a local package:

```bash
npm install /path/to/auki-authentication-0.1.0.tgz
```

## Usage

There are two ways to use this library:

1. **High-level Client API** (recommended) - Async/await API that handles HTTP requests automatically
2. **Low-level Bindings API** - Sans-I/O core for custom HTTP client integration

---

## 1. High-Level Client API (Recommended)

The `Client` class provides a convenient async API that manages HTTP requests internally.

### Quick Start

```typescript
import { Client } from "@auki/authentication";

// Create client with configuration (async for Node.js)
const client = await Client.create({
  apiUrl: "https://api.aukiverse.com",
  refreshUrl: "https://api.aukiverse.com/user/refresh",
  ddsUrl: "https://dds.posemesh.org",
  clientId: "my-app",
});

// Set credentials
client.setCredentials({
  type: "email",
  email: "user@example.com",
  password: "secret",
});

// Get domain access - automatically handles full authentication chain!
const domainAccess = await client.getDomainAccess("my-domain-id");
console.log("Connected to:", domainAccess.domain_server.url);
console.log("Access token:", domainAccess.access_token);
```

**Alternative:** Use the convenience method to create a client with credentials in one step:

```typescript
const client = await Client.withCredentials(
  { type: "email", email: "user@example.com", password: "secret" },
  {
    apiUrl: "https://api.aukiverse.com",
    refreshUrl: "https://api.aukiverse.com/user/refresh",
    ddsUrl: "https://dds.posemesh.org",
    clientId: "my-app",
  }
);
```

### Basic Usage

```typescript
import { Client } from "@auki/authentication";

// 1. Configure the client
const config = {
  apiUrl: "https://api.aukiverse.com",
  refreshUrl: "https://api.aukiverse.com/user/refresh",
  ddsUrl: "https://dds.posemesh.org",
  clientId: "my-app",
  refreshThresholdMs: 300000, // Optional: 5 minutes
};

// 2. Create client (async for Node.js)
const client = await Client.create(config);

// 3. Set credentials
const credentials =
  // Email/Password
  { type: "email", email: "user@example.com", password: "secret" };
// OR App Key
// { type: 'appKey', appKey: 'your-key', appSecret: 'your-secret' }
// OR Opaque Token
// { type: 'opaque', token: 'your-token', expiryMs: 1234567890 }
client.setCredentials(credentials);

try {
  // Get domain access - automatically handles the full chain:
  // 1. Network authentication (if needed)
  // 2. Discovery authentication (if needed)
  // 3. Domain access request
  const domainAccess = await client.getDomainAccess("my-domain-id");

  console.log("Domain access granted!");
  console.log("  Server:", domainAccess.domain_server.name);
  console.log("  URL:", domainAccess.domain_server.url);
  console.log("  Region:", domainAccess.domain_server.cloud_region);
  console.log("  Access Token:", domainAccess.access_token);
} catch (error) {
  console.error("Authentication failed:", error.message);
  if (error.retryable) {
    // This error can be retried
  }
}
```

### Manual Step-by-Step (Optional)

For advanced use cases where you need explicit control over each step:

```typescript
// Step 1: Authenticate to network only
const networkToken = await client.authenticate();
console.log("Network token expires at:", networkToken.expires_at);

// Step 2: Authenticate to discovery only
const discoveryToken = await client.authenticateDiscovery();
console.log("Discovery token expires at:", discoveryToken.expires_at);

// Step 3: Get domain access (assumes prior auth)
const domainAccess = await client.getDomainAccess("my-domain-id");
```

**Note:** In most cases, you only need `getDomainAccess()` - it automatically handles all prerequisite authentication steps.

### State Persistence

Save and restore authentication state (useful for avoiding re-authentication):

```typescript
// Save state (excludes credentials)
const stateJson = client.saveState();
localStorage.setItem("auth-state", stateJson);

// Restore state later
const savedState = localStorage.getItem("auth-state");
const client = Client.fromState(savedState, config);

// Validate state (clears expired tokens)
client.validateState();

// Check if still authenticated
if (client.isAuthenticated()) {
  console.log("Still authenticated!");
} else {
  // Need to re-authenticate
  await client.authenticate();
}
```

### Token Refresh Monitoring

```typescript
client.onRefreshFailed((info) => {
  console.log(`${info.tokenType} token refresh failed:`, info.reason);

  if (info.requiresReauth) {
    // Token expired, need full re-authentication
    client.authenticate().catch(console.error);
  }
});
```

### Checking Tokens

```typescript
// Check authentication state
const isAuth = client.isAuthenticated();

// Get cached tokens
const networkToken = client.getNetworkToken();
if (networkToken) {
  console.log("Token:", networkToken.token);
  console.log("Expires:", networkToken.expires_at);
}

const discoveryToken = client.getDiscoveryToken();
const domainAccess = client.getCachedDomainAccess("domain-id");
```

### Utility Functions

```typescript
import { currentTimeMs, isExpired, isNearExpiry } from "@auki/authentication";

// Get current time
const now = currentTimeMs();

// Check if token is expired
if (isExpired(token.expires_at)) {
  console.log("Token expired");
}

// Check if token needs refresh
if (isNearExpiry(token.expires_at, 300000)) {
  // 5 minutes
  console.log("Token expires soon");
}
```

---

## 2. Low-Level Bindings API (Advanced)

For advanced use cases where you need full control over HTTP requests, you can use the underlying WASM bindings directly. This is a sans-I/O API where you handle all I/O operations.

### Import Raw Bindings

```typescript
import {
  WasmClient,
  WasmConfig,
  WasmCredentials,
} from "@auki/authentication/dist/bindings/authentication.js";
```

### Sans-I/O Pattern

```typescript
import {
  WasmClient,
  WasmConfig,
  WasmCredentials,
} from "@auki/authentication/dist/bindings/authentication.js";

// 1. Create credentials
const credentials = WasmCredentials.email_password(
  "user@example.com",
  "password"
);

// 2. Create config
const config = new WasmConfig(
  "https://api.aukiverse.com",
  "https://dds.posemesh.org",
  "my-client-id"
);
config.refresh_threshold_ms = BigInt(300000); // 5 minutes

// 3. Create client
const client = new WasmClient(credentials, config);

// 4. Get actions to perform
const actions = client.authenticate(BigInt(Date.now()));

// 5. Execute actions (you handle HTTP)
for (const action of actions) {
  if (action.type === "HttpRequest") {
    // Use your own HTTP client
    const response = await yourHttpClient.request({
      url: action.url,
      method: action.method,
      headers: action.headers,
      body: action.body,
    });

    // 6. Feed response back to client
    const events = client.handle_response(response.status, response.text);

    // 7. Process events
    for (const event of events) {
      if (event.type === "NetworkAuthSuccess") {
        console.log("Token:", event.token);
        console.log("Expires:", event.expires_at);
      } else if (event.type === "NetworkAuthFailed") {
        console.error("Failed:", event.reason);
      }
    }
  } else if (action.type === "Wait") {
    // Handle retry delays
    await new Promise((r) => setTimeout(r, action.duration_ms));
  }
}
```

### Available Methods

```typescript
// Authentication flow
client.authenticate(now_ms: bigint): Action[]
client.authenticate_discovery(now_ms: bigint): Action[]
client.get_domain_access(domain_id: string, now_ms: bigint): Action[]

// Handle HTTP responses
client.handle_response(status: number, body: string): Event[]

// State queries
client.is_authenticated(now_ms: bigint): boolean
client.check_auth_state(now_ms: bigint): WasmAuthenticationState
client.network_token(): Token | null
client.discovery_token(): Token | null
client.domain_access(domain_id: string): DomainAccess | null
client.all_domains(): DomainAccess[]

// State management
client.save_state(): string
client.validate_state(now_ms: bigint): Event[]
WasmClient.from_state(state_json: string, config: WasmConfig): WasmClient

// Credentials
client.set_credentials(credentials: WasmCredentials): void
client.has_credentials(): boolean
client.requires_credentials(now_ms: bigint): boolean

// Control
client.force_reauth(): Event[]
client.clear_domain_access(domain_id: string): void
client.clear_all_domain_accesses(): void
```

### Action Types

```typescript
type Action =
  | {
      type: "HttpRequest";
      url: string;
      method: string;
      headers: object;
      body?: string;
    }
  | { type: "Wait"; duration_ms: number };
```

### Event Types

```typescript
type Event =
  | { type: "NetworkAuthSuccess"; token: string; expires_at: number }
  | { type: "NetworkAuthFailed"; reason: string; retry_possible: boolean }
  | { type: "NetworkTokenRefreshed"; token: string; expires_at: number }
  | {
      type: "NetworkTokenRefreshFailed";
      reason: string;
      requires_reauth: boolean;
    }
  | { type: "DiscoveryAuthSuccess"; token: string; expires_at: number }
  | { type: "DiscoveryAuthFailed"; reason: string }
  | { type: "DomainAccessGranted"; domain: DomainAccess }
  | { type: "DomainAccessDenied"; domain_id: string; reason: string }
  | { type: "AuthenticationRequired" }
  | { type: "TokensInvalidated" };
```

---

## TypeScript Support

This library is written in TypeScript and includes full type definitions.

```typescript
import type {
  Client,
  ClientConfig,
  Credentials,
  Token,
  DomainAccess,
  DomainServer,
  AuthenticationError,
  RefreshFailureInfo,
} from "@auki/authentication";
```

---

## Examples

See the `examples/` directory for complete working examples:

- **basic.js** - Complete authentication flow with all steps
- **test_refresh.js** - Token refresh testing
- **test_refresh_expired.js** - Expired token handling

### Running Examples

1. Copy environment template:

   ```bash
   cp ../../.env.example ../../.env
   ```

2. Edit `.env` with your credentials:

   ```env
   API_URL=https://api.aukiverse.com
   DDS_URL=https://dds.posemesh.org
   EMAIL=your@email.com
   PASSWORD=your-password
   DOMAIN_ID=your-domain-id
   ```

3. Run example:
   ```bash
   npm run example:basic
   ```

---

## Error Handling

```typescript
import { AuthenticationError } from "@auki/authentication";

try {
  await client.authenticate();
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error("Auth error:", error.message);
    console.log("Retryable:", error.retryable);
  }
}
```

---

## Browser vs Node.js

This library works in both environments:

**Browser:**

```html
<script type="module">
  import { Client } from "@auki/authentication";
  // Use client...
</script>
```

**Node.js:**

```javascript
import { Client } from "@auki/authentication";
// or
const { Client } = require("@auki/authentication");
```

---

## Architecture

This library uses a **sans-I/O architecture** at its core:

- The Rust core implements all authentication logic without I/O
- The TypeScript wrapper provides a convenient async API
- HTTP requests use the standard `fetch` API (works in browsers and Node.js 18+)
- You can use the low-level bindings for custom HTTP client integration

---

## Building from Source

```bash
# From repository root
make javascript

# Package it
cd pkg/javascript && npm pack
```

See the root [README.md](../../README.md) for more details.

---

## License

MIT

---

## Support

- Issues: https://github.com/aukilabs/experimental-modules/issues
- Documentation: https://github.com/aukilabs/experimental-modules
