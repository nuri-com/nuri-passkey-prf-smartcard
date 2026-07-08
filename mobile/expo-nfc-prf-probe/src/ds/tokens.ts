// Nuri DS — Design Tokens (RN mirror of the Web CSS tokens)
// Source of truth: ~/Developer/nuri-ds/ds/generated/styles/tokens-*.css
// Neutral = cream (DEFAULT_NEUTRAL), accent = lilac (brand default)

// ── Spacing ──────────────────────────────────────────────────
export const space = {
  none: 0,
  '2xs': 2,
  xs: 4,
  sm: 6,
  md: 12,
  lg: 18,
  xl: 24,
  '2xl': 36,
} as const;

// ── Sizing (element dimensions) ──────────────────────────────
export const size = {
  xs: 18,
  sm: 24,
  md: 36,
  lg: 48,
  xl: 54,
  '2xl': 72,
  '3xl': 90,
} as const;

// ── Radius ───────────────────────────────────────────────────
export const radius = {
  none: 0,
  xs: 2,
  sm: 6,
  md: 9,
  lg: 18,
  xl: 16,
  '2xl': 24,
  full: 9999,
} as const;

// ── Border ───────────────────────────────────────────────────
export const border = {
  1: 1,
} as const;

// ── Aspect ratio ─────────────────────────────────────────────
export const ratio = {
  square: 1,
  card: 1.586,
} as const;

// ── Typography ───────────────────────────────────────────────
export type TypeStep = 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '3xl';

export const typeScale: Record<TypeStep, {
  size: number;
  lineHeight: number;
  tracking: number;
  weight: '400' | '500' | '600' | '700';
}> = {
  xs: { size: 13, lineHeight: 1.38, tracking: 0, weight: '400' },
  sm: { size: 15, lineHeight: 1.33, tracking: -0.15, weight: '400' },
  md: { size: 17, lineHeight: 1.29, tracking: -0.34, weight: '400' },
  lg: { size: 22, lineHeight: 1.27, tracking: -0.33, weight: '400' },
  xl: { size: 30, lineHeight: 1.2, tracking: -0.45, weight: '400' },
  '3xl': { size: 57, lineHeight: 1.19, tracking: -1.14, weight: '400' },
};

export const fontWeight = {
  regular: '400' as const,
  medium: '500' as const,
  semibold: '600' as const,
  bold: '700' as const,
};

// ── Duration ─────────────────────────────────────────────────
export const duration = {
  fast: 120,
  med: 220,
  slow: 420,
} as const;

// ── Interaction ──────────────────────────────────────────────
export const interaction = {
  pressScale: 0.97,
  disabledOpacity: 0.4,
} as const;

// ── Colors · cream neutral + lilac accent (light theme) ──────
export const colors = {
  // Chrome — cream neutral light
  bgCanvas: '#fffdf2',
  bgSubtle: '#fbf9ee',
  bgStrong: '#f3f1e2',
  bgPressed: '#ece9da',
  bgInverse: '#12110b',
  bgInverseMuted: '#666455',

  textPrimary: '#222013',
  textMuted: '#666455',
  textOnInverse: '#f0eee3',

  borderSubtle: '#dddac9',
  borderDefault: '#d2cfbf',
  borderStrong: '#bfbcac',

  focusRing: '#ae91ff',

  // Accent — lilac (brand, theme-invariant solid)
  accentFg: '#381b6a',
  accentSolid: '#beaaff',
  accentSolidPressed: '#b39ff3',
  accentOnSolid: '#381b6a',
  accentBgSubtle: '#f3f0ff',
  accentBgSubtlePressed: '#ebe3ff',
} as const;

// ── Semantic helpers ─────────────────────────────────────────
export type SpaceToken = keyof typeof space;
export type SizeToken = keyof typeof size;
export type RadiusToken = keyof typeof radius;
export type VariantToken = 'solid' | 'soft' | 'ghost' | 'subtle' | 'outline';
export type ChromeToken = 'canvas' | 'subtle' | 'strong' | 'transparent';
export type Direction = 'row' | 'column';
export type Align = 'start' | 'center' | 'end' | 'stretch' | 'baseline';
export type Justify = 'start' | 'center' | 'end' | 'between' | 'around';
export type Fill = 'grow' | 'grow-shrink' | 'even' | 'hug';