export type AukilabsExpoAuthenticationModuleEvents = {
  onRefreshFailed: (params: RefreshFailedEvent) => void;
  onDomainAccessDenied: (params: DomainAccessDeniedEvent) => void;
};

export interface RefreshFailedEvent {
  tokenType: "network" | "discovery";
  reason: string;
  requiresReauth: boolean;
}

export interface DomainAccessDeniedEvent {
  domainId: string;
  reason: string;
  statusCode: number;
}

export interface Token {
  token: string;
  refreshToken: string;
  expiresAt: number;
}

export interface DomainServer {
  id: string;
  organizationId: string;
  name: string;
  url: string;
  version: string;
  status: string;
  mode: string;
  variants: string[];
  ip: string;
  latitude: number;
  longitude: number;
  cloudRegion: string;
}

export interface DomainAccess {
  id: string;
  name: string;
  organizationId: string;
  domainServerId: string;
  accessToken: string;
  expiresAt: number;
  ownerWalletAddress: string;
  domainServer: DomainServer;
}

export interface EmailPasswordCredentials {
  type: "email";
  email: string;
  password: string;
}

export interface AppKeyCredentials {
  type: "appKey";
  appKey: string;
  appSecret: string;
}

export interface OpaqueTokenCredentials {
  type: "opaque";
  token: string;
  refreshToken?: string;
  expiryMs: number;
  refreshTokenExpiryMs?: number;
  oidcClientId?: string;
}

export type Credentials =
  | EmailPasswordCredentials
  | AppKeyCredentials
  | OpaqueTokenCredentials;

export interface Config {
  apiUrl: string;
  refreshUrl: string;
  ddsUrl: string;
  clientId: string;
  refreshThresholdMs?: number;
}
