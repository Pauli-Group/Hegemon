# HEGEMON Atlas Emblem

![HEGEMON atlas emblem](assets/hegemon-atlas-emblem.svg)

## Essence
- **Layered hex shield** – dual hexagonal frames use the brand primary base to communicate settlement-grade stability, while contrasting strokes reinforce the HGN ticker’s precision.
- **Triad of planes** – three interlocking lozenges express the fusion of privacy (shielded pool), programmable governance, and consensus telemetry. Rotations preserve symmetry so the mark remains legible at dashboard favicon sizes.
- **Central vault** – the inner hexagon keeps the privacy vault visible even when the emblem is rendered monochrome, echoing the post-quantum protections described in the README.

## Geometry & construction
- All coordinates sit on a 240 × 240 grid for predictable scaling across CLI badges, dashboards, and PDFs.
- The outer frame uses points `(120,12)`, `(214,67)`, `(214,173)`, `(120,228)`, `(26,173)`, `(26,67)` with a 10 px stroke to keep 120° turns crisp.
- The secondary frame at `(120,44) … (52,84)` adds depth and a highlight edge for motion and hover states.
- The triad shares the base polygon `[(120,36), (186,112), (120,188), (54,112)]` rotated `0°`, `60°`, and `120°` around `(120,112)` to create the woven knot without bezier distortion.
- Stroke widths: 10 px (outer frame), 6 px (secondary frame), 5 px (triad outlines), 4 px (core), aligned with the branding system’s legibility guidance.

## Palette
| Layer | Color | Hex | Usage |
| --- | --- | --- | --- |
| Outer frame & accents | Ionosphere | `#1BE7FF` | HGN action accents, nav focus, outline glow |
| Secondary frame | Molten Amber | `#F5A623` | Governance highlights and state transitions |
| Triad planes | Proof Green / Ionosphere / Molten Amber | `#19B37E`, `#1BE7FF`, `#F5A623` | Privacy, consensus, and governance planes |
| Core fill | Deep Midnight | `#0E1C36` | Settlement vault, dark UI base |

## Usage notes
1. Keep padding equal to the inner frame height (~112 px at 1×) around the mark.
2. Reference `docs/assets/hegemon-atlas-emblem.svg` directly to preserve crisp strokes on high-DPI displays.
3. For single-color lockups, set all strokes and fills to `currentColor` while maintaining the dual-hex silhouette for recognizability.
