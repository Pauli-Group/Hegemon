# Interlocking Triad Emblem

![SHC interlocking triad emblem](assets/shc-interlocking-triad.svg)

## Essence
- **Hexagonal lattice** – the perimeter hexagon anchors the mark in the language of settlement layers and Byzantine fault-tolerant topologies that rely on six-way symmetry for stability.
- **Three interlocking rhombi** – each rhombus is a rotated diamond (four equilateral triangles) that represents one of the braided subsystems: shielded pool, deterministic consensus, and programmable governance. Their overlap forms a central hexapod node that communicates unified liquidity.
- **Inner dark core** – the charcoal hexagon references the privacy-preserving pool and the PQ-safe vaulting mentioned in the README, highlighting the protected value store that everything else defends.

## Geometry & construction
- All coordinates sit on a 240 × 240 grid so the emblem scales predictably from favicons to slide headers.
- The outer frame uses radius-aligned points `(120,12)`, `(214,67)`, `(214,177)`, `(120,232)`, `(26,177)`, `(26,67)` to maintain exact 120° turns.
- The rhombi share the base polygon `[(120,28), (196,120), (120,212), (44,120)]` and are rotated by `0°`, `60°`, and `120°` around the center to create a woven impression without bezier distortion.
- Stroke widths (10 px for the frame, 6 px for the rhombi, 4 px for the core) were tuned so that overlaps produce a visible knot while remaining legible at 24 px.

## Palette
| Layer | Color | Hex | Usage |
| --- | --- | --- | --- |
| Frame | Midnight slate | `#0F172A` | Exterior anchor and typography pairings |
| Rhombus A | Signal cyan | `#38BDF8` | Shielded pool / liquidity planes |
| Rhombus B | Noctilucent indigo | `#818CF8` | Consensus and networking |
| Rhombus C | Aurora teal | `#22D3EE` | Governance + programmability |
| Core | Obsidian | `#020617` | Privacy-preserving settlement core |

## Usage notes
1. Keep a minimum padding equal to the inner hexagon height (~104 px at 1×) around the mark.
2. The SVG is resolution-independent; prefer referencing `docs/assets/shc-interlocking-triad.svg` directly instead of exporting rasters when possible.
3. When a single-color lockup is required, fill the rhombi and frame with `currentColor` and retain the core hexagon to preserve the knot silhouette.
