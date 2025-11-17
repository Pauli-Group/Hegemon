# Dashboard UI technical notes

## Node page grid layout

The Node orchestration tab uses the shared `.grid-12` utility to align cards. Any card that sits directly inside the grid needs an explicit `grid-column` span; otherwise, each card collapses to a single column and the layout becomes unreadable. Set the base span to `6` (two-up layout) and drop to `12` columns on narrower viewports to preserve the intended spacing.

If you add or reorder Node page cards, keep these spans in place or adjust them together so the layout stays consistent with the other tabs.
