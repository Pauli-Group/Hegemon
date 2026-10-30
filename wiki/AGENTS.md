# Hegemon LLM Wiki Schema

Persistent, compounding knowledge base for Hegemon. The LLM owns all wiki pages; humans curate sources and ask questions. Pattern: `llm-wiki.md` at repo root.

## Layout

```
wiki/
  AGENTS.md          # this schema
  overview.md        # living synthesis of the whole wiki
  index.md           # catalog of every page (read first on query)
  log.md             # append-only operation log
  raw/               # immutable sources (LLM never modifies)
    assets/          # downloaded images / attachments
  sources/           # one summary page per ingested source
  entities/          # people, crates, components, products, orgs
  concepts/          # protocol ideas, mechanisms, tradeoffs
  queries/           # filed answers and insights from wiki-query
```

## Layers

| Layer | Path | Rule |
|-------|------|------|
| Raw sources | `wiki/raw/` | Immutable. Read only. Never edit, rename, or delete. |
| Wiki pages | `sources/`, `entities/`, `concepts/`, `queries/`, plus overview/index/log | LLM-owned. Create, update, cross-link freely. |
| Schema | `wiki/AGENTS.md` | Co-evolve with the human when conventions need to change. |

## Page conventions

- Markdown with optional YAML frontmatter: `title`, `tags`, `updated`, `sources` (list of wiki-relative paths or raw filenames).
- Filenames: lowercase kebab-case (`recursive-block.md`).
- Link with Obsidian-style `[[page-name]]` or relative markdown links. Prefer `[[entities/hegemon-node]]` forms that match paths without `.md`.
- Every substantive claim that came from a source should cite it (`[[sources/...]]` or the raw path).
- When new data contradicts an existing claim, update the page and leave a short **Contradiction** note with both sides and dates — do not silently overwrite history of the dispute.
- Do not invent facts. If the wiki lacks coverage, say so and suggest ingest or lint follow-ups.

## Special files

### `index.md`

Content catalog. Update on every ingest, every filed query, and after lint fixes that add/remove pages.

Organize by category (Overview, Sources, Entities, Concepts, Queries). Each entry:

```markdown
- [[path/to/page]] — one-line summary
```

On query: read `index.md` first, then open only the relevant pages.

### `log.md`

Append-only. Never rewrite old entries. Prefix every entry:

```markdown
## [YYYY-MM-DD] <op> | <title>
```

Where `<op>` is `ingest`, `query`, or `lint`. Body: short bullets of what changed (pages touched, key takeaway).

Parse recent activity with:

```bash
grep "^## \[" wiki/log.md | tail -5
```

### `overview.md`

Living synthesis — not a dump of the index. Update when major themes shift after ingest or when a filed query changes the big picture.

## Operations

Use Cursor skills (read and follow exactly):

| Op | Skill | Trigger |
|----|-------|---------|
| Ingest | `.cursor/skills/wiki-ingest/SKILL.md` | `/wiki-ingest`, new files in `wiki/raw/` |
| Query | `.cursor/skills/wiki-query/SKILL.md` | `/wiki-query`, questions against the wiki |
| Lint | `.cursor/skills/wiki-lint/SKILL.md` | `/wiki-lint`, health-check requests |

**Query → wiki:** Insights, comparisons, and non-trivial answers from wiki-query must be filed under `queries/` (and linked from `index.md`) so exploration compounds. Do not leave valuable synthesis only in chat.

## Frontmatter template

```yaml
---
title: Human-readable title
tags: [concept, consensus]
updated: YYYY-MM-DD
sources: [raw/example.md]
---
```

## Tools

- Prefer `index.md` + targeted file reads at current scale.
- Optional later: [qmd](https://github.com/tobi/qmd) for hybrid search over `wiki/` when the index is no longer enough.
- Obsidian is a fine reader (graph view, Dataview). Attachment downloads go to `wiki/raw/assets/`.

## Domain focus

Hegemon protocol: consensus, PoW, ZK/recursive blocks, networking, wallets, mining ops, design docs, and related research. Repo docs (`DESIGN.md`, `METHODS.md`, `README.md`) are authoritative for implementation; wiki pages synthesize and cross-link — they do not replace those docs.
