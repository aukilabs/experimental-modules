/**
 * Auki Authentication Library
 *
 * High-level authentication client for the Auki Network.
 * Handles HTTP requests and event processing internally.
 * Works in both browser and Node.js environments.
 */

import {
  init as initWasm,
  WasmClient,
  WasmConfig,
  WasmCredentials,
  current_time_ms as wasmCurrentTimeMs,
  is_expired as wasmIsExpired,
  is_near_expiry as wasmIsNearExpiry,
} from './bindings/authentication-init.js';

// Initialize WASM module
async function ensureWasmInitialized(): Promise<void> {
  await initWasm();
}

/**
 * Actions that the client may return for the caller to execute
 */
export type Action =
  | { type: 'HttpRequest'; url: string; method: string; headers: Record<string, string>; body?: string }
  | { type: 'Wait'; duration_ms: number };

/**
 * Events emitted by the client after processing responses
 */
export type Event =
  | { type: 'NetworkAuthSuccess'; token: string; expires_at: number }
  | { type: 'NetworkAuthFailed'; reason: string; retry_possible: boolean }
  | { type: 'NetworkTokenRefreshed'; token: string; expires_at: number }
  | { type: 'NetworkTokenRefreshFailed'; reason: string; requires_reauth: boolean }
  | { type: 'DiscoveryAuthSuccess'; token: string; expires_at: number }
  | { type: 'DiscoveryAuthFailed'; reason: string }
  | { type: 'DomainAccessGranted'; domain: DomainAccess }
  | { type: 'DomainAccessDenied'; domain_id: string; reason: string }
  | { type: 'AuthenticationRequired' }
  | { type: 'TokensInvalidated' };

/**
 * Callback information for refresh failures
 */
export interface RefreshFailureInfo {
  tokenType: 'network' | 'discovery';
  reason: string;
  requiresReauth: boolean;
}

/**
 * Callback information for domain access denial
 */
export interface DomainAccessDeniedInfo {
  domainId: string;
  reason: string;
  statusCode: number;
}

/**
 * Configuration for the authentication client
 */
export interface ClientConfig {
  /** API URL (e.g., https://api.aukiverse.com) */
  apiUrl: string;
  /** Complete refresh URL for token refresh (e.g., https://api.aukiverse.com/user/refresh) */
  refreshUrl: string;
  /** DDS URL (e.g., https://dds.posemesh.org) */
  ddsUrl: string;
  /** Client identifier */
  clientId: string;
  /** Token refresh threshold in milliseconds (default: 5 minutes) */
  refreshThresholdMs?: number;
}

/**
 * Email/password credentials
 */
export interface EmailPasswordCredentials {
  type: 'email';
  email: string;
  password: string;
}

/**
 * App key/secret credentials
 */
export interface AppKeyCredentials {
  type: 'appKey';
  appKey: string;
  appSecret: string;
}

/**
 * Opaque token credentials (for OAuth/OIDC flows)
 */
export interface OpaqueCredentials {
  type: 'opaque';
  token: string;
  refreshToken?: string;
  expiryMs: number;
  refreshTokenExpiryMs?: number;
  oidcClientId?: string;
}

/**
 * Union type for all credential types
 */
export type Credentials = EmailPasswordCredentials | AppKeyCredentials | OpaqueCredentials;

/**
 * Token information
 */
export interface Token {
  token: string;
  expires_at: number;
}

/**
 * Domain server information
 */
export interface DomainServer {
  id: string;
  organization_id: string;
  name: string;
  url: string;
  version: string;
  status: string;
  mode: string;
  variants: string[];
  ip: string;
  latitude: number;
  longitude: number;
  cloud_region: string;
}

/**
 * Domain access information
 */
export interface DomainAccess {
  id: string;
  name: string;
  organization_id: string;
  domain_server_id: string;
  access_token: string;
  expires_at: number;
  domain_server: DomainServer;
  owner_wallet_address: string;
}

/**
 * Authentication error
 */
export class AuthenticationError extends Error {
  constructor(message: string, public readonly retryable: boolean = false) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

/**
 * Token refresh failure information
 */
export interface RefreshFailureInfo {
  /** Type of token that failed to refresh */
  tokenType: 'network' | 'discovery';
  /** Reason for failure */
  reason: string;
  /** Whether re-authentication is required */
  requiresReauth: boolean;
}

/**
 * Domain access denied information
 */
export interface DomainAccessDeniedInfo {
  /** Domain ID that was denied */
  domainId: string;
  /** Reason for denial */
  reason: string;
  /** HTTP status code */
  statusCode: number;
}

/**
 * Authentication client for the Auki Network
 *
 * This client provides a high-level async API that handles HTTP requests
 * and event processing internally. The underlying sans-io core is abstracted away.
 *
 * @example
 * ```typescript
 * import { Client } from '@auki/authentication';
 *
 * // Create client with config only
 * const client = new Client({
 *   apiUrl: 'https://api.aukiverse.com',
 *   refreshUrl: 'https://api.aukiverse.com/user/refresh',
 *   ddsUrl: 'https://dds.posemesh.org',
 *   clientId: 'my-app'
 * });
 *
 * // Set credentials
 * client.setCredentials({ type: 'email', email: 'user@example.com', password: 'secret' });
 *
 * // Authenticate to network
 * await client.authenticate();
 *
 * // Get domain access
 * const domainAccess = await client.getDomainAccess('my-domain-id');
 * console.log('Access token:', domainAccess.access_token);
 * ```
 */
export class Client {
  private inner: WasmClient;
  private config: ClientConfig;

  /**
   * Optional callback for refresh failures
   * Called when network or discovery token refresh fails
   */
  public refreshFailedCallback?: (info: RefreshFailureInfo) => void;

  /**
   * Optional callback for domain access denials
   * Called when domain access is denied
   */
  public domainAccessDeniedCallback?: (info: DomainAccessDeniedInfo) => void;

  /**
   * Create a new authentication client
   *
   * @param config - Client configuration
   *
   * **Note:** This constructor is synchronous but initializes WASM asynchronously.
   * For Node.js, prefer using `await Client.create(config)` to ensure WASM is ready.
   * For browsers/bundlers, the constructor can be used directly as WASM loads in background.
   */
  constructor(config: ClientConfig) {
    this.config = config;
    // WASM will be initialized on first method call
    this.inner = null as any; // Will be set after WASM init
  }

  /**
   * Create a client asynchronously (recommended for Node.js)
   *
   * @param config - Client configuration
   * @returns Promise that resolves to initialized Client
   *
   * @example
   * ```typescript
   * const client = await Client.create({
   *   apiUrl: 'https://api.aukiverse.com',
   *   refreshUrl: 'https://api.aukiverse.com/user/refresh',
   *   ddsUrl: 'https://dds.posemesh.org',
   *   clientId: 'my-app'
   * });
   * ```
   */
  static async create(config: ClientConfig): Promise<Client> {
    await ensureWasmInitialized();
    const client = new Client(config);
    await client.ensureInitialized();
    return client;
  }

  /**
   * Ensure WASM is initialized and client is ready
   * @private
   */
  private async ensureInitialized(): Promise<void> {
    if (this.inner) {
      return; // Already initialized
    }

    await ensureWasmInitialized();

    // Convert config to WASM format
    const wasmConfig = new WasmConfig(
      this.config.apiUrl,
      this.config.refreshUrl,
      this.config.ddsUrl,
      this.config.clientId
    );

    if (this.config.refreshThresholdMs !== undefined) {
      wasmConfig.refresh_threshold_ms = BigInt(this.config.refreshThresholdMs);
    }

    // Create client with config only (no credentials yet)
    this.inner = new WasmClient(wasmConfig);
  }

  /**
   * Create a client with credentials (convenience method)
   *
   * @param credentials - User credentials
   * @param config - Client configuration
   *
   * @example
   * ```typescript
   * const client = await Client.withCredentials(
   *   { type: 'email', email: 'user@example.com', password: 'secret' },
   *   {
   *     apiUrl: 'https://api.aukiverse.com',
   *     refreshUrl: 'https://api.aukiverse.com/user/refresh',
   *     ddsUrl: 'https://dds.posemesh.org',
   *     clientId: 'my-app'
   *   }
   * );
   * ```
   */
  static async withCredentials(credentials: Credentials, config: ClientConfig): Promise<Client> {
    const client = await Client.create(config);
    client.setCredentials(credentials);
    return client;
  }

  /**
   * Set or update credentials
   *
   * @param credentials - User credentials
   */
  setCredentials(credentials: Credentials): void {
    // Convert credentials to WASM format
    let wasmCredentials: WasmCredentials;
    switch (credentials.type) {
      case 'email':
        wasmCredentials = WasmCredentials.email_password(credentials.email, credentials.password);
        break;
      case 'appKey':
        wasmCredentials = WasmCredentials.app_key(credentials.appKey, credentials.appSecret);
        break;
      case 'opaque':
        wasmCredentials = WasmCredentials.opaque(
          credentials.token,
          credentials.refreshToken || null,
          BigInt(credentials.expiryMs),
          credentials.refreshTokenExpiryMs ? BigInt(credentials.refreshTokenExpiryMs) : null,
          credentials.oidcClientId || null
        );
        break;
    }

    this.inner.set_credentials(wasmCredentials);
  }

  /**
   * Create a client from saved state (without credentials)
   *
   * @param stateJson - Saved state as JSON string
   * @param config - Client configuration
   */
  static fromState(stateJson: string, config: ClientConfig): Client {
    const wasmConfig = new WasmConfig(
      config.apiUrl,
      config.refreshUrl,
      config.ddsUrl,
      config.clientId
    );

    if (config.refreshThresholdMs !== undefined) {
      wasmConfig.refresh_threshold_ms = BigInt(config.refreshThresholdMs);
    }

    const client = Object.create(Client.prototype);
    client.config = config;
    client.inner = WasmClient.from_state(stateJson, wasmConfig);
    return client;
  }

  /**
   * Execute actions returned by the core client and process events
   * @private
   */
  private async executeActions(actions: Action[]): Promise<Event[]> {
    const events: Event[] = [];

    for (const action of actions) {
      if (action.type === 'HttpRequest') {
        try {
          const response = await fetch(action.url, {
            method: action.method,
            headers: action.headers,
            body: action.body,
          });

          const text = await response.text();
          const responseEvents = this.inner.handle_response(response.status, text) as Event[];
          events.push(...responseEvents);

          // Check for events and trigger callbacks
          for (const event of responseEvents) {
            if (event.type === 'NetworkTokenRefreshFailed' && this.refreshFailedCallback) {
              this.refreshFailedCallback({
                tokenType: 'network',
                reason: event.reason,
                requiresReauth: event.requires_reauth,
              });
            } else if (event.type === 'DiscoveryAuthFailed' && this.refreshFailedCallback) {
              this.refreshFailedCallback({
                tokenType: 'discovery',
                reason: event.reason,
                requiresReauth: true,
              });
            } else if (event.type === 'DomainAccessDenied' && this.domainAccessDeniedCallback) {
              // Extract status code from reason (format: "HTTP XXX: ...")
              const statusMatch = event.reason.match(/HTTP (\d+):/);
              const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 0;
              this.domainAccessDeniedCallback({
                domainId: event.domain_id,
                reason: event.reason,
                statusCode,
              });
            }
          }
        } catch (error) {
          throw new AuthenticationError(
            `HTTP request failed: ${error instanceof Error ? error.message : String(error)}`,
            true
          );
        }
      } else if (action.type === 'Wait') {
        await new Promise(resolve => setTimeout(resolve, action.duration_ms));
      }
    }

    return events;
  }

  /**
   * Set a callback to be called when token refresh fails
   *
   * @param callback - Function to call when refresh fails
   *
   * @example
   * ```typescript
   * client.onRefreshFailed((info) => {
   *   console.log(`${info.tokenType} token refresh failed: ${info.reason}`);
   *   if (info.requiresReauth) {
   *     // Need to re-authenticate
   *     client.authenticate().catch(console.error);
   *   }
   * });
   * ```
   */
  onRefreshFailed(callback: (info: RefreshFailureInfo) => void): void {
    this.refreshFailedCallback = callback;
  }

  /**
   * Set a callback to be called when domain access is denied
   *
   * @param callback - Function to call when domain access is denied
   *
   * @example
   * ```typescript
   * client.onDomainAccessDenied((info) => {
   *   console.log(`Domain access denied: ${info.domainId}`);
   *   console.log(`Status: ${info.statusCode}, Reason: ${info.reason}`);
   *   if (info.statusCode === 402) {
   *     // Payment required - show payment dialog
   *     showPaymentDialog(info.domainId);
   *   }
   * });
   * ```
   */
  onDomainAccessDenied(callback: (info: DomainAccessDeniedInfo) => void): void {
    this.domainAccessDeniedCallback = callback;
  }

  /**
   * Authenticate to the Auki network
   *
   * @throws {AuthenticationError} If authentication fails
   */
  async authenticate(): Promise<Token> {
    await this.ensureInitialized();
    const actions = this.inner.authenticate(BigInt(Date.now())) as Action[];
    const events = await this.executeActions(actions);

    for (const event of events) {
      if (event.type === 'NetworkAuthSuccess') {
        return {
          token: event.token,
          expires_at: event.expires_at,
        };
      } else if (event.type === 'NetworkAuthFailed') {
        throw new AuthenticationError(event.reason, event.retry_possible);
      } else if (event.type === 'AuthenticationRequired') {
        throw new AuthenticationError('Authentication required. Please sign in again.', false);
      }
    }

    // For AppKey and Opaque credentials, there are no HTTP actions/events
    // The token is set directly in the core. Check if we have a valid token now.
    if (actions.length === 0) {
      const token = this.getNetworkToken();
      if (token) {
        return token;
      }
    }

    throw new AuthenticationError('Authentication failed: No response');
  }

  /**
   * Authenticate to the Discovery service
   * Requires prior network authentication
   *
   * @throws {AuthenticationError} If authentication fails
   */
  async authenticateDiscovery(): Promise<Token> {
    await this.ensureInitialized();
    const actions = this.inner.authenticate_discovery(BigInt(Date.now())) as Action[];
    const events = await this.executeActions(actions);

    for (const event of events) {
      if (event.type === 'DiscoveryAuthSuccess') {
        return {
          token: event.token,
          expires_at: event.expires_at,
        };
      } else if (event.type === 'DiscoveryAuthFailed') {
        throw new AuthenticationError(event.reason);
      }
    }

    throw new AuthenticationError('Discovery authentication failed: No response');
  }

  /**
   * Get access to a specific domain
   *
   * Automatically handles the full authentication chain if needed:
   * - Authenticates to network if not already authenticated
   * - Authenticates to discovery service if needed
   * - Requests domain access
   *
   * @param domainId - The ID of the domain to access
   * @returns Domain access information including access token
   * @throws {AuthenticationError} If any step fails
   */
  async getDomainAccess(domainId: string): Promise<DomainAccess> {
    await this.ensureInitialized();
    // The sans-I/O core can only return actions based on current state.
    // We need to keep calling get_domain_access() and processing responses
    // until we get the DomainAccessGranted event (may take 1-3 iterations
    // depending on whether network/discovery auth is needed).
    const maxIterations = 10; // Safety limit

    for (let iteration = 0; iteration < maxIterations; iteration++) {
      const actions = this.inner.get_domain_access(domainId, BigInt(Date.now())) as Action[];

      // If no actions returned, check if we already have cached access
      if (actions.length === 0) {
        const cachedAccess = this.getCachedDomainAccess(domainId);
        if (cachedAccess) {
          return cachedAccess;
        }
        // If we're authenticated (e.g., Opaque/AppKey credentials were just set),
        // loop again to let the core progress to the next step
        if (this.isAuthenticated()) {
          continue;
        }
        // No cached access, no actions, and not authenticated means we need credentials
        // (tokens are expired and we have no refresh token or credentials to re-authenticate)
        throw new AuthenticationError('Authentication required. Please sign in again.', false);
      }

      // Execute the actions and collect events
      const events = await this.executeActions(actions);

      // Check for any authentication failures
      for (const event of events) {
        if (event.type === 'NetworkAuthFailed') {
          throw new AuthenticationError(event.reason, event.retry_possible);
        } else if (event.type === 'DiscoveryAuthFailed') {
          throw new AuthenticationError(`Discovery authentication failed: ${event.reason}`);
        } else if (event.type === 'DomainAccessDenied') {
          throw new AuthenticationError(`Domain access denied: ${event.reason}`);
        } else if (event.type === 'AuthenticationRequired') {
          throw new AuthenticationError('Authentication required. Please sign in again.', false);
        }
      }

      // Check if we got the domain access
      for (const event of events) {
        if (event.type === 'DomainAccessGranted') {
          return event.domain;
        }
      }

      // Continue to next iteration - the core will return the next required action
    }

    throw new AuthenticationError('Domain access failed: Maximum iterations exceeded');
  }

  /**
   * Check if the client is authenticated
   */
  isAuthenticated(): boolean {
    return this.inner.is_authenticated(BigInt(Date.now()));
  }

  /**
   * Get the network token if available
   */
  getNetworkToken(): Token | null {
    const token = this.inner.network_token();
    return token !== null ? token : null;
  }

  /**
   * Get the discovery token if available
   */
  getDiscoveryToken(): Token | null {
    const token = this.inner.discovery_token();
    return token !== null ? token : null;
  }

  /**
   * Get cached domain access information if available
   *
   * @param domainId - The domain ID to query
   */
  getCachedDomainAccess(domainId: string): DomainAccess | null {
    const access = this.inner.domain_access(domainId);
    return access !== null ? access : null;
  }

  /**
   * Save the current state to JSON
   * Note: Credentials are not included in the saved state
   */
  saveState(): string {
    return this.inner.save_state();
  }

  /**
   * Force re-authentication (invalidate all tokens)
   */
  forceReauth(): void {
    this.inner.force_reauth();
  }

  /**
   * Validate state after loading from storage
   * Clears any expired tokens
   */
  validateState(): void {
    this.inner.validate_state(BigInt(Date.now()));
  }
}

/**
 * Get current time in milliseconds since epoch
 * Equivalent to BigInt(Date.now())
 */
export function currentTimeMs(): number {
  return Number(wasmCurrentTimeMs());
}

/**
 * Check if a timestamp is expired
 *
 * @param expiresAt - Expiration timestamp in milliseconds
 * @param nowMs - Current time in milliseconds (defaults to BigInt(Date.now()))
 */
export function isExpired(expiresAt: number, nowMs?: number): boolean {
  return wasmIsExpired(BigInt(expiresAt), BigInt(nowMs ?? BigInt(Date.now())));
}

/**
 * Check if a timestamp is near expiry
 *
 * @param expiresAt - Expiration timestamp in milliseconds
 * @param thresholdMs - Threshold in milliseconds
 * @param nowMs - Current time in milliseconds (defaults to BigInt(Date.now()))
 */
export function isNearExpiry(expiresAt: number, thresholdMs: number, nowMs?: number): boolean {
  return wasmIsNearExpiry(BigInt(expiresAt), BigInt(thresholdMs), BigInt(nowMs ?? BigInt(Date.now())));
}

/**
 * Alias for Client class for consistency with native modules
 */
export { Client as AuthenticationClient };

/**
 * Explicitly initialize the WASM module
 * This is useful when you need to initialize before creating a Client
 *
 * @returns Promise that resolves when WASM is initialized
 * @example
 * ```typescript
 * import { asyncInit } from '@auki/authentication';
 *
 * // Initialize WASM before app starts (e.g., in Expo web)
 * await asyncInit();
 * ```
 */
export async function asyncInit(): Promise<void> {
  return ensureWasmInitialized();
}
