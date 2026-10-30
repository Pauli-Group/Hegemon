---
name: wiki-lint
description: Health-check the Hegemon LLM wiki for contradictions, orphans, stale claims, missing pages, and weak cross-references. Use when the user runs /wiki-lint, asks to audit or lint the wiki, or wants maintenance suggestions.
disable-model-invocation: true
---

# Wiki lint

Read and follow `wiki/AGENTS.md` before reporting or fixing.

## Goal

Keep the wiki healthy as it grows: consistent, linked, and honest about gaps.

## Workflow

```
Lint progress:
- [ ] Read index.md and recent log.md entries
- [ ] Sample or scan entities/, concepts/, sources/, queries/
- [ ] Check for issues in the checklist below
- [ ] Report findings with severity and suggested fixes
- [ ] Apply safe fixes only when the user wants them (or clearly requested a fix-it lint)
- [ ] Update index.md if pages were added/removed
- [ ] Append log.md entry
```

## Checklist

- **Contradictions** — same topic, conflicting claims across pages without a Contradiction note
- **Stale claims** — statements superseded by newer sources still presented as current
- **Orphans** — pages with no inbound links from index or other pages
- **Missing pages** — important concepts/entities mentioned repeatedly but lacking their own page
- **Missing cross-references** — related pages that should link and do not
- **Index drift** — pages on disk not listed in `index.md`, or index entries pointing at missing files
- **Schema drift** — filenames, frontmatter, or log prefixes that violate `AGENTS.md`
- **Data gaps** — questions the wiki cannot answer; suggest sources or web follow-ups

## Report format

```markdown
# Wiki lint — YYYY-MM-DD

## Critical
- ...

## Suggestions
- ...

## Healthy
- Short note on what looks solid

## Proposed next ingests / queries
- ...
```

## Fixes

- Safe without extra confirmation: index repairs, adding obvious cross-links, frontmatter `updated` dates, orphan→index entries.
- Confirm first: deleting pages, rewriting contested claims, large overview refactors, fetching external sources.

## Log entry

```markdown
## [YYYY-MM-DD] lint | health check

- Findings: N critical, M suggestions
- Fixes applied: ...
- Follow-ups: ...
```
