# Original Ligero implementation-readiness audit

This ExecPlan follows `.agent/PLANS.md`.  It is a bounded, read-only/source-only
backup audit.  It may edit only this directory, may not run proof-system builds
or fetch large dependencies, and cannot grant architecture or production
authority.

## Purpose

Determine whether a pinned, maintained implementation of original Ligero can
serve as a self-contained Rust backup for the final all-W64 HX512 relation if
Aurora's whole-IOP RBR gate fails.  Pin the exact theorem-bearing protocol,
identify what available executables actually implement, test whether the 2022
perfect-ZK simulator and protocol-specific RBR analysis transfer, and map every
missing byte-wire, hash, dependency, QROM, relation, and refinement obligation.

Success for this audit means a reproducible, source-grounded verdict with no
invented proof or security number.  It does not mean a backend has qualified.

## Constraints

- Read repository instructions, `DESIGN.md`, `METHODS.md`, `README.md`, and
  `.agent/PLANS.md` before writing.
- Start from `.agent/hardening/ligero-backup-screen` but independently inspect
  the pinned implementation source.
- Do not build, clone, install dependencies, generate proofs, or perform heavy
  work under the disk gate.
- Preserve shared and production files.
- Keep proof bytes, proof bounds, security advantages, composed bits, and
  unfrozen relation geometry null.
- Keep every authority Boolean false.

## Progress

- [x] Read repository instructions and design/method documents.
- [x] Read the backup architecture screen and retain its paper-level claim
  boundaries.
- [x] Pin Ligero ePrint 2022/1608 archive version `20221118:030830` and verify
  the local PDF SHA-512.
- [x] Inspect Lemma 4.15, Theorem 4.7, Section 5.2, Section 5.3, and Appendix C.
- [x] Inspect CMS Section 8.2, Remark 8.2, Theorem 8.6, and BCS Lemma 7.5.
- [x] Pin libiop revision
  `a2ed2ec2f3e85f29b6035951553b02cb737c817a`, license, release status,
  protocol sources, BCS sources, tests, and dependency closure.
- [x] Determine the executable protocol match and freeze the negative theorem
  inheritance verdict.
- [x] Audit the ZK mask/query-bound bug, transcript chain, statement binding,
  serializer, reported-size expression, malformed-shape behavior, hashes,
  PoW, and tests.
- [x] Inventory other available Ligero implementations and their revisions and
  licenses.
- [x] Coordinate with the HX512 and Aurora lanes; retain only the stable
  9,704-public-bit / 88,000-private-bit interface after relation red-team
  invalidation.
- [x] Map the clean-room exact-protocol Rust modules, dependencies, and
  acceptance evidence.
- [x] Add a canonical ledger, fail-closed checker, and mutation tests.
- [x] Run only dependency-free generation/check/tests and whitespace checks.

## Decisions and evidence

The implementation mismatch is decisive.  libiop's README identifies AHIV17
plus Aurora Appendix B's R1CS adaptation, while the pinned source composes that
frontend with an LDT reducer/direct LDT and custom BCS/PoW layer.  Ligero 2022
Lemma 4.15 and Section 5.2 prove the exact Section 4.7 arithmetic-circuit round
graph.  No refinement maps the executable to it.

Complete executable ZK is additionally blocked at source: the mask
independence is hardcoded to three, the solved query count is not forwarded,
and the code comments explicitly call this a bug.  The custom BCS chain is not
CMS Section 8.2, and no stronger whole-IOP RBR is proved for it.

The in-memory `size_in_bytes()` expression cannot become proof bytes.  Query
positions and wire framing are omitted; the binary/non-algebraic serializer is
unimplemented; the only round-trip test is non-ZK alt_bn128/Poseidon; and there
is no bounded byte parser.

The relation compiler did not freeze.  Red-team findings invalidated its
count-only geometry, so this package retains only the stable byte/bit interface
and keeps field, `m`, `n`, nonzeros, and source digests null.

## Implementation route if reconsidered

Do not transliterate libiop.  Implement exact Ligero 2022 Section 4.7 in an
isolated Rust crate and compile the final R1CS verifier into its
arithmetic-circuit relation with a checked refinement.  Implement CMS's exact
modified BCS chain and canonical SHAKE wire.  A direct Aurora-Appendix R1CS port
would require new simulator and whole-protocol RBR work, defeating its purpose
as a backup when that gate has already failed.

## Validation

The package is complete when all three dependency-free commands pass:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/ligero-implementation-audit/ligero_implementation_audit.py
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/ligero-implementation-audit/check_audit.py --require-local-source --require-local-pdfs
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s .agent/hardening/ligero-implementation-audit -p 'test_*.py' -v
```

Also run `git diff --check -- .agent/hardening/ligero-implementation-audit` and
record SHA-512 hashes for the retained package.

## Result

The backup remains disqualified and fail-closed.  This package changes no
runtime or production path and grants no security, proof-size, or consensus
authority.
