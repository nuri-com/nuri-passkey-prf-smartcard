const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

const config = getDefaultConfig(__dirname);

// @nuri/spec and @nuri/rn are symlinked TS-source packages with exports maps.
// Only enable package exports for @nuri scoped packages to avoid breaking react/react-refresh.
config.resolver.unstable_enablePackageExports = true;
config.resolver.unstable_conditionNames = ['import', 'require', 'default'];

// Ensure .ts/.tsx extensions are resolved
config.resolver.sourceExts = [...config.resolver.sourceExts, 'ts', 'tsx'];

// Watch the DS repo directory so Metro can follow symlinks
config.watchFolders = [
  __dirname,
  path.resolve(__dirname, '../../.build/nuri-design-system'),
];

// Resolve all node_modules from this project first
config.resolver.nodeModulesPaths = [
  `${__dirname}/node_modules`,
];

module.exports = config;
