# Brand Token Usage Notes

These notes explain how to apply the values in `brand_tokens.json` when designing or implementing UI components.

## Color Application
- **Primary base (`#0E1C36`)** is the only full-bleed background for app chrome. Overlay surfaces must use neutral tokens to preserve depth.
- **Accent limit:** never show more than two accent roles (`action_primary` cyan and optionally `signal_secondary` amber) within the same view. Use typography and spacing to establish hierarchy before introducing the second accent.
- **Status semantics:**
  - Success toasts, confirmation banners, and upward-trending sparklines must use `status.positive` (Proof Green `#19B37E`).
  - Errors, destructive buttons, and guard-rail notifications must use `status.negative` (Guard Rail `#FF4E4E`).
- **Neutral surfaces** separate stacked cards; alternate `neutral_high` and `neutral_mid` to create subtle layering without introducing extra hues.

## Typography Rules
- Headlines should snap to the defined 28–32px scale; avoid custom sizes so responsive typography maps cleanly to the token set.
- Body copy must remain at 16px for readability in low-light operations centers.
- Labels at 12–14px require +6% tracking and uppercase transforms to maintain legibility at small sizes.
- Inline data or code snippets should switch to `fonts.mono` to maintain numeric alignment.

## Spacing and Layout
- Maintain the 8px spacing grid. Components should be measured in multiples of 8px for padding, gaps, and border radii.
- Desktop layouts use a 12-column grid; collapse to the 4-column mobile grid while keeping gutters as 3 × the base unit (24px) wherever possible.
- Critical telemetry (balances, validator health) belongs in the upper-left quadrant of the grid to match operator scanning patterns.

## Motion Guidance
- Hover and focus transitions should last 150–200ms using the provided easing curve; longer animations impede perceived responsiveness.
- Loading states prefer neutral shimmers; avoid spinners unless motion system is unavailable.
- Auto-updating numeric data should not exceed two visual updates per second to prevent flicker.

## Contrast Requirements (QA Reference)
| Foreground | Background | Minimum Ratio | Notes |
| --- | --- | --- | --- |
| `text.on_dark` (neutral_high text) | `background.primary_base` (`#0E1C36`) | 4.5:1 | Use for body copy and icons over Deep Midnight.
| `text.on_light` (`#0E1C36`) | `surface.neutral_high` (`#F4F7FB`) | 4.5:1 | Preferred combo for tables/cards.
| `accent.action_primary` | `surface.neutral_high` | 3:1 | Meets WCAG AA for large text/buttons; add outline for smaller labels.
| `status.positive` | `surface.neutral_mid` | 3:1 | Required for success toasts and inline badges.
| `status.negative` | `surface.neutral_mid` | 3:1 | Required for destructive confirmations.

QA should record any intentional deviations in pull requests with measured contrast ratios.
