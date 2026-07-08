const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

// @nuri/spec and @nuri/rn are symlinked TS-source packages.
// Metro needs to resolve their imports (react, react-native) from THIS project's node_modules.
config.resolver.unstable_enablePackageExports = true;
config.resolver.sourceExts = [...config.resolver.sourceExts, 'ts', 'tsx'];

// Watch the DS repo directory so Metro can follow symlinks
config.watchFolders = [
  __dirname,
  '/Users/eminmahrt/Developer/nuri-design-system-official',
];

// Resolve all node_modules from this project first
config.resolver.nodeModulesPaths = [
  `${__dirname}/node_modules`,
];

module.exports = config;