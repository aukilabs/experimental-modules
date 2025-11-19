import { NativeModule, requireNativeModule } from 'expo';

import {
  AukilabsExpoAuthenticationModuleEvents,
  Credentials,
  Config,
  Token,
  DomainAccess,
} from './AukilabsExpoAuthentication.types';

declare class AukilabsExpoAuthenticationModule extends NativeModule<AukilabsExpoAuthenticationModuleEvents> {
  // Client management
  createClient(config: Config): Promise<void>;
  createClientFromState(stateJson: string, config: Config): Promise<void>;
  releaseClient(): void;

  // Credential management
  setCredentials(credentials: Credentials): void;

  // Authentication
  authenticate(credentials: Credentials): Promise<Token>;
  switchUser(credentials: Credentials): Promise<Token>;
  authenticateDiscovery(): Promise<Token>;
  getDomainAccess(domainId: string): Promise<DomainAccess>;

  // State queries
  isAuthenticated(): boolean;
  getNetworkToken(): Token | null;
  getDiscoveryToken(): Token | null;
  getCachedDomainAccess(domainId: string): DomainAccess | null;
  saveState(): string;
  forceReauth(): void;
  validateState(): void;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<AukilabsExpoAuthenticationModule>('AukilabsExpoAuthentication');
