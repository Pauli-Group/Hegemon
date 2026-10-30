---
name: wiki-query
description: Answer questions against the Hegemon LLM wiki with citations, then file non-trivial insights back into wiki/queries. Use when the user runs /wiki-query, asks a question against the wiki, or wants synthesis from existing wiki pages.
disable-model-invocation: true
---

# Wiki query

Read and follow `wiki/AGENTS.md` before answering or filing.

## Goal

Answer from the **compiled wiki**, not by rediscovering everything from raw sources. File valuable answers back so exploration compounds.

## Workflow

```
Query progress:
- [ ] Read wiki/index.md
- [ ] Open only relevant pages (entities, concepts, sources, prior queries)
- [ ] Synthesize an answer with citations to wiki pages
- [ ] Decide whether the answer should be filed
- [ ] If filing: write queries/<slug>.md, update index.md, update linked pages if the insight changes them
- [ ] Append log.md entry
```

### Answering

1. Start at `index.md` — do not scan the whole tree unless the index is insufficient.
2. Cite wiki pages (`[[concepts/...]]`, `[[sources/...]]`). Quote or paraphrase with clear attribution.
3. If coverage is thin, say what is missing and suggest `/wiki-ingest` or a targeted source search.
4. Match output shape to the question when asked: markdown, comparison table, Marp slides, chart, or canvas. Default is concise markdown.

### Filing insights (required for non-trivial answers)

**insights gained in the wiki-query process should be incorporated into wiki**

File when the answer is a comparison, analysis, novel connection, decision record, or anything worth finding again. Skip filing for trivial lookups ("what does page X say?").

1. Write `wiki/queries/<slug>.md` with frontmatter and the full durable answer.
2. Link out to the pages you relied on; link back from those pages when the insight materially updates them.
3. Update `index.md` under Queries.
4. Update `overview.md` only if the insight changes the top-level synthesis.

### Log entry

```markdown
## [YYYY-MM-DD] query | <Question or title>

- Filed: [[queries/<slug>]] (or: not filed — trivial lookup)
- Pages read: ...
- Answer summary: ...
```

## Rules

- Prefer wiki pages over re-reading `raw/` unless a citation must be verified at the source.
- Never leave a non-trivial synthesis only in chat.
- Do not invent facts; mark gaps explicitly.
