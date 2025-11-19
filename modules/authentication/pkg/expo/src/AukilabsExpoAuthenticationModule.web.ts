import { registerWebModule, NativeModule } from 'expo';
import {
  Client as WasmClient,
  type RefreshFailureInfo,
  type DomainAccessDeniedInfo
} from '@auki/authentication';
import type {
  AukilabsExpoAuthenticationModuleEvents,
  Config,
  Credentials,
  Token,
  DomainAccess,
} from './AukilabsExpoAuthentication.types';

/**
 * Web implementation of the Auki Authentication Expo module
 * Uses the WASM client from @auki/authentication
 */
class AukilabsExpoAuthenticationModule extends NativeModule<AukilabsExpoAuthenticationModuleEvents> {
  private client: WasmClient | null = null;
  private config: Config | null = null;

  // MARK: - Client Management

  /**
   * Create a new authentication client with only configuration
   * Credentials will be provided later when calling authenticate/authenticateWith
   */
  async createClient(config: Config): Promise<void> {
    // Store config for later use
    // We'll create the actual WASM client when credentials are provided
    this.config = config;
    this.client = null;
  }

  /**
   * Create a client from saved state
   */
  async createClientFromState(stateJson: string, config: Config): Promise<void> {
    this.config = config;

    // Create client from saved state
    this.client = WasmClient.fromState(
      stateJson,
      {
        apiUrl: config.apiUrl,
        refreshUrl: config.refreshUrl,
        ddsUrl: config.ddsUrl,
        clientId: config.clientId,
        refreshThresholdMs: config.refreshThresholdMs ?? 5 * 60 * 1000,
      }
    );

    // Set up callbacks
    this.client.refreshFailedCallback = (info: RefreshFailureInfo) => {
      this.emit('onRefreshFailed', {
        tokenType: info.tokenType,
        reason: info.reason,
        requiresReauth: info.requiresReauth,
      });
    };

    this.client.domainAccessDeniedCallback = (info: DomainAccessDeniedInfo) => {
      this.emit('onDomainAccessDenied', {
        domainId: info.domainId,
        reason: info.reason,
        statusCode: info.statusCode,
      });
    };
  }

  /**
   * Release the client instance
   */
  releaseClient(): void {
    this.client = null;
    this.config = null;
  }

  // MARK: - Credential Management

  /**
   * Set or update credentials without authenticating
   * Note: In web implementation, this recreates the client with new credentials
   */
  setCredentials(credentials: Credentials): void {
    if (!this.config) {
      throw new Error('Client not initialized - call createClient first');
    }

    // WASM client doesn't have setCredentials, so we create a new client
    this.client = new WasmClient(
      credentials,
      {
        apiUrl: this.config.apiUrl,
        refreshUrl: this.config.refreshUrl,
        ddsUrl: this.config.ddsUrl,
        clientId: this.config.clientId,
        refreshThresholdMs: this.config.refreshThresholdMs ?? 5 * 60 * 1000,
      }
    );

    // Set up callbacks
    this.client.refreshFailedCallback = (info: RefreshFailureInfo) => {
      this.emit('onRefreshFailed', {
        tokenType: info.tokenType,
        reason: info.reason,
        requiresReauth: info.requiresReauth,
      });
    };

    this.client.domainAccessDeniedCallback = (info: DomainAccessDeniedInfo) => {
      this.emit('onDomainAccessDenied', {
        domainId: info.domainId,
        reason: info.reason,
        statusCode: info.statusCode,
      });
    };
  }

  // MARK: - Authentication

  /**
   * Authenticate with provided credentials (will clear existing tokens and authenticate as new user)
   */
  async authenticate(credentials: Credentials): Promise<Token> {
    if (!this.config) {
      throw new Error('Client not initialized - call createClient first');
    }

    // Create new client with credentials
    this.setCredentials(credentials);

    if (!this.client) {
      throw new Error('Failed to create client');
    }

    // Authenticate
    const token = await this.client.authenticate();

    return {
      token: token.token,
      refreshToken: '', // WASM Token doesn't have refresh_token field
      expiresAt: token.expires_at,
    };
  }

  /**
   * Switch to a different user by providing new credentials
   * This is an alias for authenticate() that makes the intent clearer
   */
  async switchUser(credentials: Credentials): Promise<Token> {
    return this.authenticate(credentials);
  }

  /**
   * Authenticate to discovery service
   */
  async authenticateDiscovery(): Promise<Token> {
    if (!this.client) {
      throw new Error('Client not initialized');
    }

    const token = await this.client.authenticateDiscovery();

    // Discovery token doesn't have a refresh token
    return {
      token: token.token,
      refreshToken: '',
      expiresAt: token.expires_at,
    };
  }

  /**
   * Get domain access (handles full auth chain automatically)
   */
  async getDomainAccess(domainId: string): Promise<DomainAccess> {
    if (!this.client) {
      throw new Error('Client not initialized');
    }

    const access = await this.client.getDomainAccess(domainId);

    // Convert from WASM format (snake_case) to Expo format (camelCase)
    return {
      id: access.id,
      name: access.name,
      organizationId: access.organization_id,
      domainServerId: access.domain_server_id,
      accessToken: access.access_token,
      expiresAt: access.expires_at,
      ownerWalletAddress: access.owner_wallet_address,
      domainServer: {
        id: access.domain_server.id,
        organizationId: access.domain_server.organization_id,
        name: access.domain_server.name,
        url: access.domain_server.url,
        version: access.domain_server.version,
        status: access.domain_server.status,
        mode: access.domain_server.mode,
        variants: access.domain_server.variants,
        ip: access.domain_server.ip,
        latitude: access.domain_server.latitude,
        longitude: access.domain_server.longitude,
        cloudRegion: access.domain_server.cloud_region,
      },
    };
  }

  // MARK: - State Queries

  /**
   * Check if authenticated
   */
  isAuthenticated(): boolean {
    return this.client?.isAuthenticated() ?? false;
  }

  /**
   * Get network token
   */
  getNetworkToken(): Token | null {
    if (!this.client) {
      return null;
    }

    const token = this.client.getNetworkToken();
    if (!token) {
      return null;
    }

    return {
      token: token.token,
      refreshToken: '', // WASM Token doesn't have refresh_token
      expiresAt: token.expires_at,
    };
  }

  /**
   * Get discovery token
   */
  getDiscoveryToken(): Token | null {
    if (!this.client) {
      return null;
    }

    const token = this.client.getDiscoveryToken();
    if (!token) {
      return null;
    }

    // Discovery token doesn't have a refresh token
    return {
      token: token.token,
      refreshToken: '',
      expiresAt: token.expires_at,
    };
  }

  /**
   * Get cached domain access
   */
  getCachedDomainAccess(domainId: string): DomainAccess | null {
    if (!this.client) {
      return null;
    }

    const access = this.client.getCachedDomainAccess(domainId);
    if (!access) {
      return null;
    }

    // Convert from WASM format (snake_case) to Expo format (camelCase)
    return {
      id: access.id,
      name: access.name,
      organizationId: access.organization_id,
      domainServerId: access.domain_server_id,
      accessToken: access.access_token,
      expiresAt: access.expires_at,
      ownerWalletAddress: access.owner_wallet_address,
      domainServer: {
        id: access.domain_server.id,
        organizationId: access.domain_server.organization_id,
        name: access.domain_server.name,
        url: access.domain_server.url,
        version: access.domain_server.version,
        status: access.domain_server.status,
        mode: access.domain_server.mode,
        variants: access.domain_server.variants,
        ip: access.domain_server.ip,
        latitude: access.domain_server.latitude,
        longitude: access.domain_server.longitude,
        cloudRegion: access.domain_server.cloud_region,
      },
    };
  }

  /**
   * Save state to JSON
   */
  saveState(): string {
    if (!this.client) {
      throw new Error('Client not initialized');
    }
    return this.client.saveState();
  }

  /**
   * Force re-authentication
   */
  forceReauth(): void {
    if (!this.client) {
      throw new Error('Client not initialized');
    }
    this.client.forceReauth();
  }

  /**
   * Validate state
   */
  validateState(): void {
    if (!this.client) {
      throw new Error('Client not initialized');
    }
    this.client.validateState();
  }
}

export default registerWebModule(AukilabsExpoAuthenticationModule, 'AukilabsExpoAuthenticationModule');
