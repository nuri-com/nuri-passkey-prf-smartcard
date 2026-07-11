import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const screens = [
  'TerminalScreen.tsx',
  'ApproveScreen.tsx',
  'ProfileScreen.tsx',
  'NumericKeypad.tsx',
];

const forbidden = [
  [/from ['"]react-native['"]/, 'direct react-native UI import'],
  [/\bStyleSheet\b/, 'StyleSheet usage'],
  [/\bstyle\s*=/, 'inline style prop'],
  [/<(?:View|Text|Pressable|TouchableOpacity|TextInput)\b[^>]*\bstyle=/, 'styled native element'],
  [/\b(?:fontSize|fontWeight|lineHeight|paddingLeft|paddingRight|marginLeft|marginRight|borderRadius|backgroundColor)\s*:/, 'custom visual value'],
];

const failures = [];
for (const screen of screens) {
  const source = readFileSync(resolve(screen), 'utf8');
  for (const [pattern, label] of forbidden) {
    if (pattern.test(source)) failures.push(`${screen}: ${label}`);
  }
}

if (failures.length) {
  console.error(`Design-system UI guard failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Design-system UI guard passed for ${screens.length} visible screen modules.`);
