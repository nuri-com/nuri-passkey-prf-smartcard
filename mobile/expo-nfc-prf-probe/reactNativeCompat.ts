import { StyleSheet } from 'react-native';

// @nuri/rn currently targets the pre-RN-0.86 StyleSheet export name.
// Keep the design-system runtime intact while using Expo 57 / RN 0.86.
if (!StyleSheet.absoluteFillObject) {
  Object.assign(StyleSheet, { absoluteFillObject: StyleSheet.absoluteFill });
}
