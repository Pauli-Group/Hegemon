---
name: wiki-ingest
description: Ingest a raw source into the Hegemon LLM wiki — summarize, update entity/concept pages, refresh index and log. Use when the user runs /wiki-ingest, drops files into wiki/raw/, or asks to process/file a new source into the wiki.
disable-model-invocation: true
---

# Wiki ingest

Read and follow `wiki/AGENTS.md` before editing.

## Goal

Compile one immutable source from `wiki/raw/` into the persistent wiki so knowledge accumulates instead of being re-derived later.

## Preconditions

1. Source exists under `wiki/raw/` (or user points at a path to copy there first).
2. Never modify files under `wiki/raw/` after they are filed.
3. Prefer one source per ingest unless the user explicitly asks to batch.

## Workflow

Copy and track:

```
Ingest progress:
- [ ] Read schema (wiki/AGENTS.md) and recent log tail
- [ ] Read the raw source (text first; view local images in raw/assets/ separately if needed)
- [ ] Discuss key takeaways with the user when ingest is interactive
- [ ] Write/update sources/<slug>.md summary
- [ ] Create/update relevant entities/* and concepts/*
- [ ] Note contradictions explicitly on affected pages
- [ ] Update overview.md if the big picture shifted
- [ ] Update index.md
- [ ] Append log.md entry
```

### Summary page

Create `wiki/sources/<slug>.md` with frontmatter (`title`, `tags`, `updated`, `sources`) and:

- What the source is and why it matters
- Key claims / data (cite the raw path)
- Links to entity and concept pages touched
- Open questions or gaps

### Propagation

A single source may touch many pages. Update every entity/concept that the source materially informs. Strengthen or challenge existing synthesis; do not only add an orphan summary.

### Log entry

Append (never rewrite):

```markdown
## [YYYY-MM-DD] ingest | <Source Title>

- Raw: `raw/<file>`
- Summary: [[sources/<slug>]]
- Pages touched: ...
- Takeaway: ...
```

## Rules

- Immutable raw layer: read-only.
- No silent overwrite of disputed claims — use a **Contradiction** note.
- Keep `index.md` complete and one-line summaries accurate.
- Do not invent facts absent from the source or existing wiki.
