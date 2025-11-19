import { registerRootComponent } from 'expo';
import { Platform } from 'react-native';
import App from './App';

// registerRootComponent calls AppRegistry.registerComponent('main', () => App);
// It also ensures that whether you load the app in Expo Go or in a native build,
// the environment is set up appropriately

if (Platform.OS === 'web') {
  // On web, initialize WASM before rendering
  const { asyncInit } = require('../../javascript');
  asyncInit()
    .then(() => {
      registerRootComponent(App);
    })
    .catch((err: Error) => {
      console.error('Failed to initialize WASM:', err);
      // Render error component
      const React = require('react');
      const { Text, View } = require('react-native');
      const ErrorComponent = () =>
        React.createElement(
          View,
          {
            style: {
              flex: 1,
              justifyContent: 'center',
              alignItems: 'center',
              padding: 20,
            },
          },
          React.createElement(
            Text,
            { style: { color: 'red', fontSize: 18 } },
            'Failed to initialize WASM: ' + String(err)
          )
        );
      registerRootComponent(ErrorComponent);
    });
} else {
  // On native, register directly
  registerRootComponent(App);
}
