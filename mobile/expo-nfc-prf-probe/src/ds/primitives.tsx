// Nuri DS — Primitives (RN mirror of the Web custom elements)
// Stack = flex layout (direction/gap/align/justify/wrap/fill)
// Box = surface (padding/radius/variant/chrome/width/height/minHeight)
// Combined: a single View with both flex + surface props — NO box-in-box

import React from 'react';
import {
  View,
  Text,
  Pressable,
  ScrollView,
  type ViewStyle,
  type TextStyle,
  type PressableProps,
} from 'react-native';
import {
  space, size, radius, typeScale, colors, interaction,
  type SpaceToken, type SizeToken, type RadiusToken,
  type VariantToken, type ChromeToken,
  type Direction, type Align, type Justify, type Fill,
} from './tokens';

// ── Stack style resolver ─────────────────────────────────────
function stackStyle(props: {
  direction?: Direction;
  gap?: SpaceToken;
  align?: Align;
  justify?: Justify;
  wrap?: boolean;
  fill?: Fill;
}): ViewStyle {
  const s: ViewStyle = { flexDirection: props.direction ?? 'column' };
  if (props.gap) s.gap = space[props.gap];
  if (props.align) {
    s.alignItems =
      props.align === 'start' ? 'flex-start' :
      props.align === 'end' ? 'flex-end' :
      props.align;
  }
  if (props.justify) {
    s.justifyContent =
      props.justify === 'start' ? 'flex-start' :
      props.justify === 'end' ? 'flex-end' :
      props.justify === 'between' ? 'space-between' :
      props.justify === 'around' ? 'space-around' :
      props.justify;
  }
  if (props.wrap) s.flexWrap = 'wrap';
  if (props.fill === 'grow') s.flex = 1;
  else if (props.fill === 'grow-shrink') s.flex = 1;
  else if (props.fill === 'even') s.flex = 1;
  return s;
}

// ── Box style resolver ───────────────────────────────────────
function boxStyle(props: {
  padding?: SpaceToken;
  paddingX?: SpaceToken;
  paddingY?: SpaceToken;
  paddingStart?: SpaceToken;
  paddingEnd?: SpaceToken;
  paddingTop?: SpaceToken;
  paddingBottom?: SpaceToken;
  radius?: RadiusToken;
  width?: SizeToken;
  height?: SizeToken;
  minHeight?: SizeToken;
  variant?: VariantToken;
  chrome?: ChromeToken;
}): ViewStyle {
  const s: ViewStyle = {};
  if (props.padding) s.padding = space[props.padding];
  if (props.paddingX) { s.paddingHorizontal = space[props.paddingX]; }
  if (props.paddingY) { s.paddingVertical = space[props.paddingY]; }
  if (props.paddingStart) s.paddingLeft = space[props.paddingStart];
  if (props.paddingEnd) s.paddingRight = space[props.paddingEnd];
  if (props.paddingTop) s.paddingTop = space[props.paddingTop];
  if (props.paddingBottom) s.paddingBottom = space[props.paddingBottom];
  if (props.radius) s.borderRadius = radius[props.radius];
  if (props.width) s.width = size[props.width];
  if (props.height) s.height = size[props.height];
  if (props.minHeight) s.minHeight = size[props.minHeight];

  if (props.variant) {
    switch (props.variant) {
      case 'solid':
        s.backgroundColor = colors.accentSolid;
        s.borderColor = colors.accentSolid;
        break;
      case 'soft':
        s.backgroundColor = colors.bgStrong;
        break;
      case 'ghost':
        s.backgroundColor = 'transparent';
        break;
      case 'subtle':
        s.backgroundColor = 'transparent';
        break;
      case 'outline':
        s.backgroundColor = 'transparent';
        s.borderWidth = 1;
        s.borderColor = colors.borderSubtle;
        break;
    }
  }

  if (props.chrome) {
    switch (props.chrome) {
      case 'canvas': s.backgroundColor = colors.bgCanvas; break;
      case 'subtle': s.backgroundColor = colors.bgSubtle; break;
      case 'strong': s.backgroundColor = colors.bgStrong; break;
      case 'transparent': s.backgroundColor = 'transparent'; break;
    }
  }
  return s;
}

// ── Stack — combined flex + surface (NO box-in-box) ──────────
type StackProps = React.PropsWithChildren<{
  direction?: Direction;
  gap?: SpaceToken;
  align?: Align;
  justify?: Justify;
  wrap?: boolean;
  fill?: Fill;
  // box props merged directly
  padding?: SpaceToken;
  paddingX?: SpaceToken;
  paddingY?: SpaceToken;
  paddingStart?: SpaceToken;
  paddingEnd?: SpaceToken;
  paddingTop?: SpaceToken;
  paddingBottom?: SpaceToken;
  radius?: RadiusToken;
  width?: SizeToken;
  height?: SizeToken;
  minHeight?: SizeToken;
  variant?: VariantToken;
  chrome?: ChromeToken;
  style?: ViewStyle;
}>;

export function Stack(props: StackProps) {
  const { style, children, ...rest } = props;
  const merged: ViewStyle = {
    ...stackStyle(rest),
    ...boxStyle(rest),
    ...style,
  };
  return <View style={merged}>{children}</View>;
}

// ── Scroll — a Stack that scrolls ────────────────────────────
type ScrollProps = StackProps & { contentContainerStyle?: ViewStyle };

export function Scroll(props: ScrollProps) {
  const { style, children, contentContainerStyle, ...rest } = props;
  const merged: ViewStyle = {
    ...stackStyle(rest),
    ...boxStyle(rest),
    ...style,
  };
  return (
    <ScrollView style={merged} contentContainerStyle={contentContainerStyle}>
      {children}
    </ScrollView>
  );
}

// ── Typography ───────────────────────────────────────────────
type TypographyProps = React.PropsWithChildren<{
  step?: keyof typeof typeScale;
  emphasis?: boolean;
  muted?: boolean;
  align?: 'start' | 'center' | 'end';
  weight?: '400' | '500' | '600' | '700';
  style?: TextStyle;
}>;

export function Typography(props: TypographyProps) {
  const { step = 'md', emphasis, muted, align, weight, style, children } = props;
  const t = typeScale[step];
  const s: TextStyle = {
    fontSize: t.size,
    lineHeight: t.size * t.lineHeight,
    letterSpacing: t.tracking,
    fontWeight: weight ?? (emphasis ? '600' : t.weight),
    color: muted ? colors.textMuted : colors.textPrimary,
    textAlign: (align === 'start' ? 'left' : align === 'end' ? 'right' : align) as TextStyle['textAlign'],
  };
  return <Text style={[s, style]}>{children}</Text>;
}

// ── Screen — full-height flex column ─────────────────────────
export function Screen(props: React.PropsWithChildren<{ style?: ViewStyle }>) {
  return <View style={[{ flex: 1, backgroundColor: colors.bgCanvas }, props.style]}>{props.children}</View>;
}

// ── Separator ────────────────────────────────────────────────
export function Separator(props: { space?: SpaceToken }) {
  const h = props.space ? space[props.space] : 0;
  return <View style={{ height: h, borderBottomWidth: 1, borderBottomColor: colors.borderSubtle }} />;
}

// ── PressableBox — a Stack that's pressable (for buttons etc) ─
type PressableBoxProps = StackProps & {
  onPress?: PressableProps['onPress'];
  disabled?: boolean;
  pressScale?: boolean;
};

export function PressableBox(props: PressableBoxProps) {
  const { onPress, disabled, pressScale, style, children, ...rest } = props;
  const merged: ViewStyle = {
    ...stackStyle(rest),
    ...boxStyle(rest),
    ...style,
  };
  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      style={({ pressed }) => ({
        ...merged,
        opacity: disabled ? interaction.disabledOpacity : 1,
        transform: [{ scale: pressScale && pressed ? interaction.pressScale : 1 }],
      })}
    >
      {children}
    </Pressable>
  );
}