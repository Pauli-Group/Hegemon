# Construct root context from recorded earlier calls

Scratch-only ExecPlan under .agent/PLANS.md; no repository writes.

## Purpose and context

Prove typed root selection from actual prior Log pairs and the triggering DECS input, without supplying a desired context to selection. Integration is /Users/pldd/.codex/worktrees/premainnet-integration/Hegemon at4e5b41b916499616107f6ebe193c77bca3c7d7ce. Root context means salt4, bare-root8 and149RP06/72HTLC unrestricted u64 statement words. Root counter0 is parsed by existing parseRoot; a final reencoding guard establishes exactness. Trigger family and8word seed come from actual raw bytes, with anyu64counter.

## Progress

- [x] Draft typed parsers and roundtrips/exactness, pair-only selector and finite cover.
- [x] Strict compile and all-export axiom audit; retain failed attempts and pins.
- [x] Release heavy lane immediately after audit; no further strengthening.

## Plan of work and milestone

NativeLaunchRootPrefixSelector.lean imports the checked prefix FPP decoder, Merkle root parser, raw-output adapter and first-query stop interpreter. decodeVector reads fixed word vectors; RootContext and Trigger carry typed parsed fields. selectRoot scans only prior recorded input/output pairs, comparing raw output to full toOutput seed. prefix_cover splits actual wrapper membership and emits context equality, finite collision or actual late wrapper; stopped_root_cover derives coherence using Program.recorded_call and stop decomposition.

## Validation and recovery

Run python3 /private/tmp/native-launch-root-prefix-selector-20261005/run.py then MODE=audit python3 /private/tmp/native-launch-root-prefix-selector-20261005/run.py, with approved ps monitoring. Expect exit0 and only standard axioms. Serial j1/M3500,120s wall,4GiB process-tree RSS,10GiB disk floor. Preserve exact failed source/command/log/result before at most3narrow repairs. Do not rebuild historical unbounded-option root modules. No strengthening after final strict/audit pass; release heavy lane.

## Surprises and discoveries

Initial errors were proof simplification/elaboration (ofFn unfolded too early, monadic bind normalization and explicit source-frame roundtrip arguments); repair1 fixed them. Repair2 removed one unused simp argument. Both exact failed sources, commands, logs and results are preserved in attempt-01/attempt-02.

## Decision log

Compare raw outputs directly, avoiding unnecessary digest reverse conversion. Actual future context is only a theorem comparator/event parameter. Statement vectors do not assert semantic SourceShape. parseTrigger handles all counters and infers family, not oldRP05grammar.

## Outcomes and retrospective

All14exports pass strict compilation (2.224s, peak process-tree RSS2,662,744,064 bytes, free disk26,965,114,880 bytes) and axiom audit (2.003s, peak2,561,835,008 bytes, free26,965,053,440 bytes). Axioms only propext/Classical.choice/Quot.sound; parse exactness, infer-family roundtrip and before_coherent use propext only. Complete typed root and DECS trigger parsers with roundtrip/exactness, pair-only selector and full stopped_root_cover are proved. The cover is conditional on a successful actual trigger parse and actual wrapper hash equality, with no prior-wrapper membership/provenance success assumption. It emits equality OR a finite distinct-key raw collision OR actual late-wrapper membership failure with equality to trigger seed. Target remains generic; choosing the actual DECS-first trigger and compiling native verifier execution are separate obligations. Rust accepted-byte/arithmetic/descriptor/program refinement, matrix provenance, adaptive/QROM bounds, false-relation exclusion and all8release gates remain open. Coherence premise in internal prefix_cover is derived in the public stopped_root_cover, not a supplied positive provenance flag.

## Artifacts

Retain source, runner, Audit.lean, strict/audit results, all failed attempts, exact commands and first-resolved object/current-source pins. No build outside scratch.

Final source SHA256 838daa53f7d5d75dfe68d5b440cd772ffdc055822b6b152bed70de02312f26ae; object SHA256 8ab4089aea7d6da056ed33494d9494d0044d6c94409403288d728f949b817235. pins.json includes 286 recursively reached modules and actual first-resolved objects at integration 4e5b41b916499616107f6ebe193c77bca3c7d7ce. Final plan update records validated output and retained repair evidence; source was not strengthened after the pass.
