# Branding Guidelines

These branding guidelines ensure that every user-facing artifact communicates the project's values of resilience, clarity, and trust.

## Core Principles
- **Legibility first** – interfaces must remain usable in low-light trading floors and bright control rooms.
- **High-trust neutrality** – visual tone should feel neutral but precise, highlighting data integrity over hype.
- **Efficient scalability** – every element should scale across dashboards, CLI renderers, and documentation illustrations.
- **Secure, seamless delight** – every interaction must reinforce safety, reduce friction, and end with a positive confirmation
  cue so operators feel confident and delighted.

## Color System
| Role | Color | Usage | Justification |
| --- | --- | --- | --- |
| Primary base | `#0E1C36` (Deep Midnight) | Backgrounds, nav bars, modal chrome | Deep desaturated blue conveys institutional trust and gives high contrast for light text. |
| Accent | `#1BE7FF` (Ionosphere) | Links, focus states, important actionable elements | Cyan accent pairs with the primary base to feel technical and precise while meeting WCAG contrast requirements. |
| Secondary highlight | `#F5A623` (Molten Amber) | Alerts, badge counts, algorithm states | Warm accent draws attention to risk while staying distinguishable from the cyan action color. |
| Positive state | `#19B37E` (Proof Green) | Success toasts, upward trends | Saturated green signals growth and validation without overpowering primary elements. |
| Negative state | `#FF4E4E` (Guard Rail) | Errors, destructive buttons, warnings | Crisp red ensures clear risk communication at a glance. |
| Neutral surfaces | `#F4F7FB`, `#E1E6EE` | Cards, tables, code blocks | Cool grays maintain neutrality while separating layers above the deep base. |

Never exceed two accent colors in a single view; rely on neutral surfaces and typography for hierarchy before introducing additional hues.

## Typography
- **Primary typeface:** "Space Grotesk" (or "Inter" as a fallback) at 400/500/600 weights for sans-serif clarity across code-heavy screens.
- **Monospace:** "JetBrains Mono" for inline code, logs, and numeric grids to maintain alignment.
- **Hierarchy rules:**
  - Headlines: 28–32px, letter-spacing -1% to retain compactness.
  - Body: 16px regular, max 70ch line length.
  - Labels & meta: 12–14px uppercase tracking +6% for clarity in dense dashboards.
Justification: both faces are open-source, legible at micro sizes, and render consistently across browsers.

## Iconography and Illustration
- Favor stroked icons at 1.5px weight with rounded caps to reflect precision without aggression.
- Use geometric primitives (circles, rectangles) and avoid skeuomorphic details.
- Illustrations should be monochrome line art filled with the neutral surfaces, reserving accent colors for key interactions. This keeps charts readable and focused on data.

## Layout, Density, and Spacing
- Base spacing unit: 8px; stack components in multiples to simplify responsive design.
- Maintain a 12-column grid on desktop, collapsing to 4 on mobile.
- Critical data (balances, validator health) must appear in the upper-left quadrant to match scanning habits of ops teams.
- Cards should never exceed 80% viewport height; favor scrollable sub-panels to preserve situational awareness.

## Motion and Interaction
- Use 150–200ms ease-out transitions for hover/focus feedback; anything longer feels sluggish in operational contexts.
- On loading states, use progress shimmers in neutral grays rather than spinners to indicate determinate processing.
- Never animate critical numeric values faster than 2 updates per second to avoid flicker-related misreads.

## Imagery and Data Visualization
- Prefer line and area charts over pie charts to communicate temporal dynamics.
- Chart palettes must follow the color system: base lines in `#1BE7FF`, secondary in `#F5A623`, thresholds in `#FF4E4E`.
- Include annotations with monospace labels to tie metrics back to CLI outputs.

## Implementation Checklist
1. Validate color contrast (WCAG AA) for all text-over-background combinations.
2. Confirm typography tokens reference the defined typefaces and scale.
3. Ensure any new icons align with the stroke weight and rounded cap rule.
4. Audit layout spacing for adherence to the 8px grid before merging.
5. Document any deviation inside pull requests to keep the branding system evolving intentionally.
