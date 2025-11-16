# Dashboard mockups

This folder captures the requested low-fidelity wireframes, high-fidelity executions, and state annotations for the dashboard. All layouts pin critical telemetry in the upper-left quadrant and cap each card under 80% of the 900px frame height (≤720px) to keep situational awareness per `BRAND.md`.

## Assets

| View | Low fidelity | High fidelity | Notes |
| --- | --- | --- | --- |
| Home overview | `lowfi_home.svg` | `highfi_home.svg` | Top-left "Net Liquidity" hero card anchors essential data while cards stay below 260px tall. Queue module includes a shimmer loader to communicate 150–200 ms ease-out transitions. |
| Action detail | `lowfi_action_detail.svg` | `highfi_action_detail.svg` | Metadata stack sits to the far-left, with timeline + logs honoring Space Grotesk/Inter typography and Guard Rail annotations for risk. |
| Log streaming | `lowfi_log_stream.svg` | `highfi_log_stream.svg` | Log buffer renders in JetBrains Mono with severity colors and a dedicated control shelf for acknowledgements/export. |
| Success / warning / failure states | `lowfi_states.svg` | `highfi_states.svg` | Proof Green, Molten Amber, and Guard Rail borders and copy callouts summarize state-specific copy along with brand-compliant chart palettes. |

### Chart + state annotations

`highfi_states.svg` highlights the brand chart palette: primary Ion line (`#1BE7FF`) with Molten Amber secondary fills and Guard Rail threshold strokes. Each state tile labels the color token in-text so downstream implementations can map semantic states to the correct variables.

### Motion + loading guidance

* All hover/focus transitions are specified as 150–200 ms ease-out (referenced next to controls or headers inside each frame).
* Queue placeholders in `highfi_home.svg` feature neutral shimmer bars to replace blocking spinners.

### Typography

The SVG mockups reference Space Grotesk (headlines), Inter (body + labels), and JetBrains Mono (logs/metrics). Rendering environments that already have these fonts installed will match the brand typography; otherwise, standard font fallback rules apply.

### Regenerating the assets

```bash
python scripts/generate_dashboard_mockups.py
```

The script writes fresh SVGs into this directory. Update the script if the layout or annotation rules evolve so both the wireframes and the high-fidelity comps remain in lockstep with the shared brand system.
