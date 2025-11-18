# HEGEMON Sovereignty Mark

![HEGEMON sovereignty emblem](assets/hegemon-atlas-emblem.svg)

## Essence
- **Golden throne triangle** – the open gilded wedge signals the hegemonic seat of authority while preserving negative space for readability on dark dashboards.
- **Shielded privacy core** – concentric rings echo Zcash-style zero-knowledge bubbles and STARK proofs, reinforcing the repo’s PQ privacy posture.
- **Lattice accent** – cross-hatched diagonals nod to lattice cryptography (ML-DSA/Kyber) without cluttering the mark at small sizes.
- **Serif wordmark** – the HEGEMON lockup uses a Georgia-style serif to convey institutional permanence beneath the emblem.

## Geometry & construction
- Built on a 200 × 200 grid; the throne triangle sits on `(100,40)`, `(45,160)`, `(155,160)` with 12 px strokes and a 15% interior fill.
- Shield rings center on `(100,100)` with radii `48` and `38`, using 8 px strokes to keep line contrast crisp in low-light control rooms.
- The lattice lines connect `(70,70) → (130,130)` and `(70,130) → (130,70)` at 2 px weight for subtle texture.
- Wordmark baseline sits at `y=185` with 24 px type and 2 px letter spacing to preserve legibility when scaled down for favicons.

## Palette
| Layer | Color | Hex | Usage |
| --- | --- | --- | --- |
| Background | Sovereign Night | `#0C0C0C` | Dark chassis for dashboards and document headers |
| Throne + rings | Gilded Authority | `#FFD700` | Primary accent for the emblem, UI highlights, and active nav states |
| Wordmark | Ivory Signal | `#FFFFFF` | High-contrast type over the night base |

## Usage notes
1. Keep at least 16 px padding around the triangle when used as a favicon or navbar glyph.
2. Prefer the full emblem (triangle + shield + wordmark) in documentation callouts; for micro-icons, drop the wordmark but retain the throne outline.
3. On hover or focus states in the dashboard, use `box-shadow: 0 0 0 1px rgba(255, 215, 0, 0.35)` to mirror the gilded stroke without exceeding the 8 px spacing grid.
