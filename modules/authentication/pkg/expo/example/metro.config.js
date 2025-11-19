// Learn more https://docs.expo.io/guides/customizing-metro
const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

const config = getDefaultConfig(__dirname);

// Add .wasm to asset extensions for web support
config.resolver.assetExts = [...config.resolver.assetExts, 'wasm'];

// Exclude WASM bindings from source transformation - treat as external
config.resolver.sourceExts = config.resolver.sourceExts.filter(ext => ext !== 'wasm');

// npm v7+ will install ../node_modules/react and ../node_modules/react-native because of peerDependencies.
// To prevent the incompatible react-native between ./node_modules/react-native and ../node_modules/react-native,
// excludes the one from the parent folder when bundling.
config.resolver.blockList = [
  ...Array.from(config.resolver.blockList ?? []),
  new RegExp(path.resolve('..', 'node_modules', 'react')),
  new RegExp(path.resolve('..', 'node_modules', 'react-native')),
];

config.resolver.nodeModulesPaths = [
  path.resolve(__dirname, './node_modules'),
  path.resolve(__dirname, '../node_modules'),
  path.resolve(__dirname, '../../javascript/node_modules'),
];

config.resolver.extraNodeModules = {
  '@aukilabs/expo-authentication': '..',
};

config.watchFolders = [
  path.resolve(__dirname, '..'),
  path.resolve(__dirname, '../../javascript'),
];

config.transformer.getTransformOptions = async () => ({
  transform: {
    experimentalImportSupport: false,
    inlineRequires: true,
  },
});

config.resolver = {
  ...config.resolver,
  unstable_conditionNames: ['browser', 'require', 'react-native'],
};

module.exports = config;
