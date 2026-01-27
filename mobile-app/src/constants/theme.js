// Design tokens matching the web app's Shadcn-style dark theme
export const colors = {
  // Core
  background: '#0a0a0a',
  foreground: '#fafafa',

  // Card
  card: '#171717',
  cardForeground: '#fafafa',

  // Muted
  muted: '#262626',
  mutedForeground: '#a1a1aa',

  // Border
  border: '#262626',

  // Primary (white in dark mode)
  primary: '#fafafa',
  primaryForeground: '#171717',

  // Accent
  accent: '#262626',
  accentForeground: '#fafafa',

  // Indigo (brand color)
  indigo: '#818cf8',
  indigoLight: '#a5b4fc',
  indigoDark: '#6366f1',

  // Category colors
  categories: {
    work: '#a855f7',      // Purple
    personal: '#ec4899',   // Pink
    social: '#06b6d4',     // Cyan
    marketing: '#f97316',  // Orange
  },

  // Status colors
  success: '#22c55e',
  warning: '#eab308',
  error: '#ef4444',

  // Transparent
  transparent: 'transparent',
};

export const spacing = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 24,
  xxxl: 32,
};

export const borderRadius = {
  sm: 6,
  md: 8,
  lg: 12,
  xl: 16,
  full: 9999,
};

export const typography = {
  // Font sizes
  xs: 11,
  sm: 13,
  base: 15,
  lg: 17,
  xl: 20,
  xxl: 24,
  xxxl: 32,

  // Font weights (as strings for React Native)
  regular: '400',
  medium: '500',
  semibold: '600',
  bold: '700',
};

export const shadows = {
  sm: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.2,
    shadowRadius: 2,
    elevation: 2,
  },
  md: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 4,
  },
  lg: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.4,
    shadowRadius: 16,
    elevation: 8,
  },
};

export default {
  colors,
  spacing,
  borderRadius,
  typography,
  shadows,
};
