# @auki/expo-authentication

> **⚠️ WIP:** This package is under active development and is subject to rapid changes, including breaking changes to the API. Use with caution in production environments and expect frequent updates. We recommend pinning to specific versions and reviewing changelogs before upgrading.

Authenticate to the Auki network and domains in Expo/React Native applications.

This module provides cross-platform authentication support for iOS, Android, and Web platforms using native modules for mobile and WebAssembly (WASM) for web.

## Installation

### Add the package to your npm dependencies

```bash
npm install @auki/expo-authentication
```

### Configure for iOS

Run `npx pod-install` after installing the npm package.

### Configure for Android

No additional configuration required.

### Configure for Web (Required)

The web platform uses WebAssembly (WASM) which requires special Metro bundler configuration.

#### 1. Update `metro.config.js`

Add the following configuration to your `metro.config.js` file:

```javascript
const { getDefaultConfig } = require("expo/metro-config");
const path = require("path");

const config = getDefaultConfig(__dirname);

// Add .wasm to asset extensions for web support
config.resolver.assetExts = [...config.resolver.assetExts, "wasm"];

// Configure Metro for proper module resolution
config.transformer.getTransformOptions = async () => ({
  transform: {
    experimentalImportSupport: false,
    inlineRequires: true,
  },
});

config.resolver = {
  ...config.resolver,
  unstable_conditionNames: ["browser", "require", "react-native"],
};

module.exports = config;
```

#### 2. Initialize WASM on Web Platform

For web platform, you must initialize the WASM module before using the authentication module. Update your app entry point (typically `index.js` or `index.tsx`):

```typescript
import { registerRootComponent } from "expo";
import { Platform } from "react-native";
import App from "./App";

if (Platform.OS === "web") {
  // On web, initialize WASM before rendering
  const { asyncInit } = require("@auki/expo-authentication");
  asyncInit()
    .then(() => {
      registerRootComponent(App);
    })
    .catch((err) => {
      console.error("Failed to initialize WASM:", err);
      // Handle initialization error (optional: render error component)
    });
} else {
  // On native platforms, register directly
  registerRootComponent(App);
}
```

## Usage

```typescript
import * as AukilabsExpoAuthentication from "@auki/expo-authentication";

// Create authentication client
const config = {
  apiUrl: "https://api.auki.io",
  refreshUrl: "https://auth.auki.io",
  ddsUrl: "https://dds.auki.io",
  clientId: "your-client-id",
  refreshThresholdMs: 300000, // Optional: 5 minutes
};

await AukilabsExpoAuthentication.createClient(config);

// Authenticate with email/password
const credentials = {
  type: "email",
  email: "user@example.com",
  password: "password",
};

const token = await AukilabsExpoAuthentication.authenticate(credentials);
console.log("Authenticated:", token);

// Get domain access
const domainAccess =
  await AukilabsExpoAuthentication.getDomainAccess("domain-id");
console.log("Domain access:", domainAccess);

// Listen for authentication events
AukilabsExpoAuthentication.addRefreshFailedListener((event) => {
  console.log("Token refresh failed:", event);
});

AukilabsExpoAuthentication.addDomainAccessDeniedListener((event) => {
  console.log("Domain access denied:", event);
});
```

## Platform-Specific Notes

### Web Platform

- **WASM Initialization**: The `asyncInit()` function must be called before using any authentication functions on web.
- **Metro Configuration**: The Metro bundler must be configured to handle `.wasm` files as assets.
- **Fetch API**: The web platform uses the Fetch API to load WASM modules, ensure your environment supports it.

### iOS and Android

- Native modules are used automatically on mobile platforms.
- No special initialization is required.

## API Reference

### `createClient(config: Config): Promise<void>`

Initialize the authentication client with configuration.

### `authenticate(credentials: Credentials): Promise<Token>`

Authenticate with the provided credentials and return an access token.

### `getDomainAccess(domainId: string): Promise<DomainAccess>`

Get access token for a specific domain.

### `asyncInit(): Promise<void>` (Web only)

Initialize the WASM module. Must be called before using authentication on web platform.

### Event Listeners

- `addRefreshFailedListener(listener)`: Called when token refresh fails
- `addDomainAccessDeniedListener(listener)`: Called when domain access is denied

## Troubleshooting

### Web: "import.meta is not defined" Error

Make sure you've:

1. Added `.wasm` to `assetExts` in `metro.config.js`
2. Added the transformer and resolver configuration
3. Called `asyncInit()` before rendering your app on web

### Web: "malloc is not a function" Error

This means the WASM module hasn't been initialized. Make sure `asyncInit()` is called and completes before using any authentication functions.

### Metro: "Unable to resolve module"

Ensure your Metro configuration includes the proper `watchFolders` and `nodeModulesPaths` if you're using a monorepo or custom project structure.

## Technical Details

### WASM on Web

The web platform uses `wasm-bindgen` with the default/bundler target to generate JavaScript bindings for the Rust authentication library. Metro bundler treats `.wasm` files as assets (URLs), so a custom initialization wrapper ([`authentication-init.js`](../javascript/src/bindings/authentication-init.js)) fetches and instantiates the WASM module at runtime.

### Build Process

The JavaScript/WASM bindings are built using:

```bash
make javascript
```

This generates:

- WASM binary (`authentication_bg.wasm`)
- JavaScript bindings (`authentication_bg.js`)
- Custom Metro-compatible wrapper (`authentication-init.js`)

## Contributing

Contributions are welcome! Please ensure:

- iOS and Android native modules work correctly
- Web WASM initialization is properly tested
- Metro configuration examples are kept up to date
