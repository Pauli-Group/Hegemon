# Guard-derived native point geometry

Scope: scratch-only Lean bridge from executable descriptor and adjacent-index guards to distinct sampled field points for typed 38/58 native relation wires. Integration source pin: 6e22eb6c961d695f71517aae4fc20391ecc5d5cb. No repository edits or commits.

Completed:
- Read source-shaped candidate checks in smallwood_engine.rs (canonical nonzero shift, candidate interpolation check and descriptor m bounds), plus strict adjacent windows(2) Merkle index checks.
- Reused only the cached exact Goldilocks radix-2 root/order certificate. The historical fixed shift 388 and its interpolation certificate are not used by these proofs. No rebuild of the historical unbounded-options source was attempted.
- Implemented executable shiftGuard, candidateGuard, descriptorGuard and adjacentIncreasing. Derived point injection from accepted canonical nonzero shift, adjacent chain/pairwise order, typed wire position injection and composed sampled-point injection.
- Strict warning-as-error compile passed after one source repair; all eight theorem axiom reports passed. No strengthening after final pass.

Retained attempts: attempt-01 contains the exact original failed source and compile command/result/log. The sole repair replaced a malformed Bool.and_eq_true projection with an explicit simp-derived conjunction. The sandbox monitor setup attempt was denied ps; attempt-02-sandbox-monitor-denied retains the unchanged repaired source. The final compile and audit used the approved process monitor.

Resource guard: serial Lean -j1 -M3500; process-tree RSS cap 4 GiB, 120-second wall cap, 10 GiB free disk floor. Final strict compile exit0, 2.214s, peak 2,621,849,600 bytes, 26,736,570,368 bytes free. Audit exit0, 2.006s, peak 2,622,128,128 bytes, 26,735,239,168 bytes free. Heavy lane released immediately afterward. Audit axioms only propext/Classical.choice/Quot.sound; adjacent_isChain requires propext only.

Reproduction: run python3 run.py from any directory, then MODE=audit python3 run.py, with permission for ps monitoring. Exact Lean arguments and import search order are retained in compile-command.json and audit-command.json. pins.json records first-resolved and real object paths, SHA256s, the current integration source candidates and toolchain hash for 91 total entries: 89 Hegemon modules including the component, plus two direct Mathlib imports. Source and cached-object hashes are separate provenance, not a proof of source-object correspondence.

Open boundaries: no 4096-candidate selector/search existence result, no executed descriptor instance, no proof of interpolation disjointness from the candidate loop (only its nonzero-shift component is needed here), no extraction/refinement from actual accepted Rust raw lists/field arithmetic into typed WireFields, no causal-prefix or QROM claim, no security/production authority. Typed count/range assumptions do not establish raw-list length and bounds acceptance. Accepted Rust proof refinement, chronology, release and live deployment gates stay open.
