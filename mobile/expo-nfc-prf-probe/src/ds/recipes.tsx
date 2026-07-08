// Nuri DS — Recipes (component compositions from primitives)
// Mirrors the descriptor-driven web recipes

import React from 'react';
import { Pressable, type PressableProps } from 'react-native';
import { Stack, Typography, PressableBox } from './primitives';
import { colors, interaction, type SpaceToken, type VariantToken } from './tokens';

// ── Button ───────────────────────────────────────────────────
// Descriptor: pressable root, row+center+justify-center, label text
// Variants: solid (accent fill) / soft (bg strong) / ghost (transparent)
// Sizes: sm (minHeight md, paddingX lg, radius full) / lg (minHeight xl, paddingX xl, radius full)

type ButtonProps = React.PropsWithChildren<{
  variant?: VariantToken;
  size?: 'sm' | 'lg';
  onPress?: PressableProps['onPress'];
  disabled?: boolean;
  fill?: 'natural' | 'even' | 'hug';
  style?: any;
}>;

export function Button(props: ButtonProps) {
  const { variant = 'soft', size = 'lg', fill = 'natural', style, ...rest } = props;
  const minHeight = size === 'sm' ? 'md' : 'xl';
  const paddingX: SpaceToken = size === 'sm' ? 'lg' : 'xl';
  const gap: SpaceToken = size === 'sm' ? 'xs' : 'sm';
  const labelStep = size === 'sm' ? 'sm' : 'md';

  const fg = variant === 'solid' ? colors.accentOnSolid : colors.textPrimary;

  return (
    <PressableBox
      direction="row"
      align="center"
      justify="center"
      gap={gap}
      variant={variant}
      minHeight={minHeight}
      paddingX={paddingX}
      radius="full"
      fill={fill === 'even' ? 'even' : fill === 'hug' ? 'hug' : undefined}
      pressScale
      style={style}
      {...rest}
    >
      {typeof props.children === 'string' ? (
        <Typography step={labelStep} emphasis style={{ color: fg }}>
          {props.children}
        </Typography>
      ) : (
        props.children
      )}
    </PressableBox>
  );
}

// ── Topbar ───────────────────────────────────────────────────
// Descriptor: view root, row+center+gap sm, height xl, paddingStart/End lg, paddingTop sm, chrome canvas
// Three regions: leading (fill even), center (natural), trailing (fill even, justify end)

type TopbarProps = React.PropsWithChildren<{
  surface?: 'canvas' | 'transparent';
  leading?: React.ReactNode;
  center?: React.ReactNode;
  trailing?: React.ReactNode;
}>;

export function Topbar(props: TopbarProps) {
  const { surface = 'canvas', leading, center, trailing } = props;
  return (
    <Stack
      direction="row"
      align="center"
      gap="sm"
      height="xl"
      paddingStart="lg"
      paddingEnd="lg"
      paddingTop="sm"
      chrome={surface}
    >
      <Stack direction="row" align="center" fill="even">{leading}</Stack>
      <Stack direction="row" align="center" justify="center">{center}</Stack>
      <Stack direction="row" align="center" justify="end" gap="sm" fill="even">{trailing}</Stack>
    </Stack>
  );
}

// ── TabBar ───────────────────────────────────────────────────
// Descriptor: view root, row+align stretch, minHeight xl, paddingBottom md, chrome canvas
// Open container — children are TabBarItem components

type TabBarProps = React.PropsWithChildren<{
  surface?: 'canvas' | 'transparent';
}>;

export function TabBar(props: TabBarProps) {
  return (
    <Stack
      direction="row"
      align="stretch"
      minHeight="xl"
      paddingBottom="md"
      chrome={props.surface ?? 'canvas'}
    >
      {props.children}
    </Stack>
  );
}

// ── TabBarItem ───────────────────────────────────────────────
// Descriptor: pressable root, column+center+justify center+gap xs, fill even
// Parts: icon (sm box) + label (xs type, emphasis, truncate 1)
// State: selected → palette ghost (text primary), unselected → palette subtle (text muted)

type TabBarItemProps = {
  label: string;
  selected?: boolean;
  onPress?: PressableProps['onPress'];
  icon?: React.ReactNode;
};

export function TabBarItem(props: TabBarItemProps) {
  const { label, selected, onPress, icon } = props;
  return (
    <PressableBox
      direction="column"
      align="center"
      justify="center"
      gap="xs"
      fill="even"
      pressScale
      onPress={onPress}
    >
      {icon}
      <Typography
        step="xs"
        emphasis
        muted={!selected}
        style={{ color: selected ? colors.textPrimary : colors.textMuted }}
      >
        {label}
      </Typography>
    </PressableBox>
  );
}