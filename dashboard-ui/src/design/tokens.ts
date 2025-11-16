import brandTokens from './brand_tokens.json';

type BrandTokens = typeof brandTokens;

const tokens = brandTokens as BrandTokens;

export const colors = {
  midnight: tokens.colors.background.primary_base.value,
  surfaceHigh: tokens.colors.surface.neutral_high.value,
  surfaceMid: tokens.colors.surface.neutral_mid.value,
  accentPrimary: tokens.colors.accent.action_primary.value,
  accentSecondary: tokens.colors.accent.signal_secondary.value,
  success: tokens.colors.status.positive.value,
  danger: tokens.colors.status.negative.value,
};

const fontStackPrimary = '"Space Grotesk", "Inter", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
const fontStackMono = '"JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace';

export const typography = {
  primary: fontStackPrimary,
  mono: fontStackMono,
  headlineLg: tokens.typography.scales.headline_lg,
  headlineMd: tokens.typography.scales.headline_md,
  body: tokens.typography.scales.body_base,
  labelSm: tokens.typography.scales.label_sm,
  labelMd: tokens.typography.scales.label_md,
};

export const spacing = {
  unit: tokens.spacing.base_unit_px,
  scale: tokens.spacing.scale,
  layout: tokens.spacing.layout,
};

export const motion = tokens.motion;

export type { BrandTokens };
