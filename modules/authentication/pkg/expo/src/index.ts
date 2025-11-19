// Reexport the native module. On web, it will be resolved to AukilabsExpoAuthenticationModule.web.ts
// and on native platforms to AukilabsExpoAuthenticationModule.ts
import AukilabsExpoAuthenticationModule from './AukilabsExpoAuthenticationModule';

export { default } from './AukilabsExpoAuthenticationModule';
export * from './AukilabsExpoAuthentication.types';

// Re-export individual functions from the native module
export const createClient = AukilabsExpoAuthenticationModule.createClient.bind(AukilabsExpoAuthenticationModule);
export const createClientFromState = AukilabsExpoAuthenticationModule.createClientFromState.bind(AukilabsExpoAuthenticationModule);
export const releaseClient = AukilabsExpoAuthenticationModule.releaseClient.bind(AukilabsExpoAuthenticationModule);
export const setCredentials = AukilabsExpoAuthenticationModule.setCredentials.bind(AukilabsExpoAuthenticationModule);
export const authenticate = AukilabsExpoAuthenticationModule.authenticate.bind(AukilabsExpoAuthenticationModule);
export const switchUser = AukilabsExpoAuthenticationModule.switchUser.bind(AukilabsExpoAuthenticationModule);
export const authenticateDiscovery = AukilabsExpoAuthenticationModule.authenticateDiscovery.bind(AukilabsExpoAuthenticationModule);
export const getDomainAccess = AukilabsExpoAuthenticationModule.getDomainAccess.bind(AukilabsExpoAuthenticationModule);
export const isAuthenticated = AukilabsExpoAuthenticationModule.isAuthenticated.bind(AukilabsExpoAuthenticationModule);
export const getNetworkToken = AukilabsExpoAuthenticationModule.getNetworkToken.bind(AukilabsExpoAuthenticationModule);
export const getDiscoveryToken = AukilabsExpoAuthenticationModule.getDiscoveryToken.bind(AukilabsExpoAuthenticationModule);
export const getCachedDomainAccess = AukilabsExpoAuthenticationModule.getCachedDomainAccess.bind(AukilabsExpoAuthenticationModule);
export const saveState = AukilabsExpoAuthenticationModule.saveState.bind(AukilabsExpoAuthenticationModule);
export const forceReauth = AukilabsExpoAuthenticationModule.forceReauth.bind(AukilabsExpoAuthenticationModule);
export const validateState = AukilabsExpoAuthenticationModule.validateState.bind(AukilabsExpoAuthenticationModule);
