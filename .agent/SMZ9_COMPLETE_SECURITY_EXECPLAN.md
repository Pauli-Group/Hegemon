# Complete the corrected SMZ9 security argument

This living ExecPlan follows `.agent/PLANS.md` and continues
`.agent/SMZ9_JOINT_ACCEPTANCE_EXECPLAN.md`. A checked intermediate theorem is not
completion of this plan.

## Purpose / Big Picture

The endpoint is a complete security argument for the exact transaction relation
and SMZ9/profile-6 proof selected after the two verified HGV8RP03/typed-semantics
mismatches are repaired. Privacy must use a witness-free
simulator with the adversary's persistent quantum oracle. Knowledge soundness
must construct an efficient extractor from the candidate verifier's accepted
bytes and return a witness satisfying `ExactV8RelationSemanticValid`. The
always-denying outer production gate cannot make either theorem vacuous.

The repair is not a relabeling of HGV8RP03. Constraining out-of-range sponge
padding changes the executable relation bytes and therefore requires a new
relation digest, regenerated source and Lean artifacts, new retained proofs, and
fresh review. Old proof bytes stay nonauthorizing historical evidence. Preserve
the new self-contained bytes through wallet, RPC, relay, mempool, mining,
blocks, sync, restart, reorg and fresh-node verification. Do not change the
wire, profile, primitive, authority, network or dependency merely to make an
intermediate theorem easier. No push, deployment or public submission is part
of this work. The security endpoints and resource accounting remain those in
`docs/crypto/smz9-campaign/security-contract.md`.

## Progress

- [x] (2026-09-08) Strictly qualify and exactly migrate 90 range equations:
  66 range reconstructions and 24 high-limb padding cells in ten modules,
  adding 46 declarations (2,129 total). All 983 input pins, 11 fresh outputs
  and 35 logs pass independent postflight. All 24 mathematical and nine
  parser negatives are rejected; peak child RSS is 2,413,821,952 bytes.
  Receipt SHA-256 is
  `1a60e85b14c56e309f0a5a9a6a40dfe7250be66caaaaf6f451de04afe8d1e51e`;
  migration SHA-256 is
  `279e97232e635ddce6df6122cefdf65dc09e63f5df301f32ec10b79bcb677c04`.
  Independent review confirms validity-only source bounds, odd top-bit
  readback, actual coefficient DAGs and exact indexed endpoints. The first
  unintegrated padding draft's incorrect merged address block is rejected;
  the exact six four-cell blocks are retained in the corrected source proof.
- [x] (2026-09-08 23:43 UTC) Complete the 2,129-declaration integration
  gate: all 3,141 jobs, exact axiom audits and unchanged-vector checks pass.
  Gate-log SHA-256 is
  `672254cd2af528ad5621b22cf1ff4cfa8e11666e2c23052164023fcc9576a372`.
  Retain 222 files / 38,418,652 bytes in
  `.agent/artifacts/smallwood-poseidon2-v8/formal-source-2129-672254cd2af528ad`;
  manifest SHA-256 is
  `688c4be9357a1b9301a182fb7d8f1393488c36bc20683cf2d9bff649e27116f1`.
  Independent exact-set, size and hash readback passes for every payload.
- [ ] Close the remaining numeric CSR equations and compose full execution.
  Source coverage is 20,431/20,605, leaving exactly 174 numeric equations.
  Complete CSR execution, packed acceptance, native refinement and the
  independent security/release endpoints remain open.

- [x] (2026-09-08 19:11 UTC) Strictly qualify the final 97 authorization
  nonlinear roots in ten source modules. All 230 exact declaration audits,
  10 mathematical negatives and parser controls pass with 907 frozen input
  pins and freshly rebuilt local dependencies. Independent postflight checks
  all 11 outputs and 21 logs; peak child RSS is 2,571,337,728 bytes and total
  compiler time is 530.36 seconds. Receipt SHA-256 is
  `bb567c974a7f9d6a241f7d8745767f9014abc986b28d01436d2a29a615cdbcc1`.
- [x] (2026-09-08 19:23 UTC) Strictly qualify complete coverage of all 830
  nonlinear roots and actual full nonlinear interpreter execution. Ten
  declaration audits, seven semantic negatives and nine parser negatives
  pass with 941 frozen inputs and three fresh outputs; independent postflight
  verifies every input, output and log. Receipt SHA-256 is
  `139a1b97d6db3df484b9a7286ac279d74585ab957ccdf5e387e1e382beffcbb2`.
  A separate read-only review confirms complete coverage and premise scope.
- [x] (2026-09-08) Strictly qualify 28 digest-copy CSR attempts in families
  25, 30, 32 and 34, with ten audited declarations and six semantic negatives.
  Receipt SHA-256 is
  `be666366e5998a5ba8e8f1ba4071c1a44756c48fad247fa09d7662b40ce43fe7`.
- [x] (2026-09-08 19:48 UTC) Strictly qualify 192 actual inline-policy CSR
  attempts in families 27/28. All 15 declaration audits, eight mathematical
  negatives and nine parser negatives pass with 906 frozen inputs and two
  fresh outputs. Independent postflight verifies every pin and log; receipt
  SHA-256 is `ba397f0a934ee53e75376df2de1534a6b4048394a9d154ab0291be88b26a31d0`.
  The original wrong-padding draft and all later mechanical/linter failures
  remain uncredited. The final result has no typed-validity premise.
- [x] (2026-09-08 19:57 UTC) Complete the combined full gate after exact
  import-only migration of 14 modules and addition of 265 credited entries
  (1,767 total). Source coverage is 19,365/20,605 raw CSR attempts and all
  830 nonlinear roots. The remaining 1,240 CSR attempts, complete CSR
  coefficient/interpreter execution, packed acceptance, runtime refinement
  and production security/authority remain open. The first integrated run
  builds all 3,086 jobs and regenerates byte-identical wire vectors, then
  the audit rejects a comment heading in the declaration list as an unknown
  theorem. That first run remains failed evidence. The corrected combined
  gate passes 3,087 jobs, audits all 1,767 declarations and preserves all
  three wire vectors. Log SHA-256 is
  `cb6b91b97da5517d9c7d6358e27120d5251dca9af7ff7560de92f86c6a9f1009`.
  Retain all 268 payload files byte-identically under
  `.agent/artifacts/smallwood-poseidon2-v8/formal-source-1767-cb6b91b97da5517d`.
- [x] (2026-09-08 20:54 UTC) Strictly qualify 354 further actual CSR
  attempts in eight modules: dense padding 103, base/ciphertext/inactive raw
  111, authorization initial frames 128 and inactive/shared input keys 12.
  All 95 exact declaration audits, 40 mathematical negatives and 36 parser
  negatives pass. Independent postflight checks all four frozen input sets,
  12 fresh outputs and 52 logs. Separate read-only review finds no source-
  binding defect. The failed dense draft, mechanical development failures
  and first key negative-control namespace error remain uncredited.
- [x] (2026-09-08 21:02 UTC) Complete the 1,862-declaration integration
  gate after exact import-only migration of eight modules. All 3,095 jobs,
  exact declaration audits and three unchanged wire vectors pass. Retain
  all 291 payload files (29,509,819 bytes) byte-identically under
  `.agent/artifacts/smallwood-poseidon2-v8/formal-source-1862-1191e073689038d1`.
  Full-gate log SHA-256 is
  `1191e073689038d1343296066b47439849a8e79ca6edc04a1d6ed01ce3495a9f`.
  Migration SHA-256 is
  `de6b43867f1f7c7e5c7f4ea3d63dde199852962ceaf8f65430c63024531a3fd9`.
  Source coverage at that checkpoint is 19,719/20,605; the remaining 886 equations,
  complete CSR execution, packed acceptance and downstream security/runtime
  obligations stay open.
- [x] (2026-09-08) Strictly qualify and exactly migrate 21 modules and
  134 declarations covering 290 further actual CSR equations: 216 note
  initial/inactive preimages, 32 nullifier initial equations and 42 public
  digest bindings. Three strict receipts reject 44 mathematical and 27
  parser negatives. Independent postflight verifies all frozen inputs,
  24 fresh outputs and 68 logs before migration; separate source review
  confirms forward typed/source/public bindings. Peak child RSS is
  2,889,580,544 bytes. Coverage is 20,009/20,605 with 596 stablecoin
  equations remaining. Migration SHA-256 is
  `856a98baf5706ed42dde2adb49f21bcc033c6b50352379ab399735a6cb54d4a8`.
- [x] (2026-09-08 22:00 UTC) Complete and retain the 1,996-declaration
  integration gate: all 3,116 build jobs, exact kernel axiom audits and
  unchanged-vector checks pass. Gate-log SHA-256 is
  `ed9d9e03b53fb45fbb54d306b0cb64fa53fa684713f6fb6f0e9a42df55ef7c31`.
  Retain 558 payload files (103,676,117 bytes), including failed drafts
  and all three strict receipts, under
  `.agent/artifacts/smallwood-poseidon2-v8/formal-source-1996-ed9d9e03b53fb45f`.
  Copy-manifest SHA-256 is
  `e20ed7a6fb6e987dc112839df9b64d96c43d934ad6000c4e90164efea4272644`.
- [x] (2026-09-08 22:25 UTC) Strictly qualify 304 further stablecoin CSR
  equations in ten isolated modules: configuration chunks/tree (112),
  before/after state paths (128), leaf frames (32), and issuer frames (32).
  Three receipts contain 54 unique audited declarations, reject 28
  mathematical and 27 parser negatives, and pass independent source review.
  All 2,813 input-pin occurrences, 15 fresh outputs and 43 logs pass
  independent postflight. This is qualified scratch work, not integrated
  coverage; the committed checkpoint remains 20,009/20,605 with 1,996
  declarations. The 292 not-yet-qualified CSR equations comprise 28 public
  stable digest bindings, 66 range reconstructions, and 198 numeric cells.
  Sources and evidence are in `/private/tmp/smz9-stable112-coordinator.UrdYTo`.
  Receipt SHA-256 values are
  `68105e401dda3756e9fd9885c0b95e319c4df2531a515c1e83c6568b987568fa`,
  `cb0f97422c44ed4d74a1e85182af4fd5d0daf3ba5880364b3352820922c42c88`,
  and `e237bf09dfcdbc0ffb767e5a141d06e3c4f50926b461a15de40344e8e99fbd25`.
- [x] (2026-09-08) Strictly qualify the remaining 28 stable public-root
  and issuer-output equations, then exactly migrate the combined 332-equation
  increment in 15 modules with 87 unique declarations. Four strict packets
  reject 42 mathematical and 36 parser negatives; all 3,768 input-pin
  occurrences, 27 fresh outputs and 69 logs pass independent pre-migration
  postflight. Public-output receipt SHA-256 is
  `8733a3d74d800043571cc4f46661f42655f6bd6cad6829fb7a2fb0ed7a9daed2`.
  Migration SHA-256 is
  `24ec2dadf121415fa6df8d2a718e1ba79243cb3e56a26ee1688727586add1300`.
  Source coverage is 20,341/20,605; the 264 remaining equations comprise
  66 range reconstructions and 198 numeric cells. All final source endpoints
  use the unchanged constructor and typed validity, including disabled
  root equality and mint-only issuer gates.
- [x] (2026-09-08) Complete and retain the 2,083-declaration integration
  gate: all 3,131 jobs, exact declaration audits and unchanged-vector
  checks pass. Gate-log SHA-256 is
  `a08ea36246cb35e5b1227905d880c61d3c467d79cf58a82ea7e8e99ac2022316`.
  Retain 533 payloads (88,070,836 bytes) under
  `.agent/artifacts/smallwood-poseidon2-v8/formal-source-2083-a08ea36246cb35e5`.
  All copies pass independent size/hash readback; copy-manifest SHA-256 is
  `613689183d124209fe52abf25145c62016919fac0ce56e54c9850554d1a9062d`.
- [x] (2026-09-08) Integrate seven current-qualified role-CSR modules and
  30 exact roots. All 210 actual family-47 entries `19344..19553` evaluate
  to zero on the original full typed candidate from fixed typed validity,
  preserving all 640 terms and 168 explicit zero-coefficient terms. Fresh
  strict qualification passes all seven modules, 30 exact axiom checks,
  six mathematical negatives and parser controls. Full integration passes
  3,073 build jobs, all 1,502 declaration audits and unchanged wire vectors;
  log SHA-256 `2d0ea4a4b323af3f2062f8725302611f7c0451e087d6962bfdff889f9416110b`.
  Coverage is 19,145/20,605 CSR attempts and 733/830 nonlinear roots;
  1,460 CSR attempts and 97 nonlinear roots remain.
- [x] (2026-09-08) Complete the 26-module increment: 439 additional actual
  CSR attempts and 100 nonlinear authorization roots. The full gate passes
  3,066 jobs and all 1,472 declarations, with unchanged wire/generated files.
  Coverage is 18,935/20,605 CSR attempts and 733/830 nonlinear roots;
  1,670 CSR attempts and 97 nonlinear roots within 252..448 remain. Preserve
  all 118 evidence payloads byte-for-byte in the 1,472-declaration archive.
- [x] (2026-09-08) Compile the exact generated native node Types/Funs in
  isolated Lean 4.31.0. The proposed body proof remains unrun after its V2
  runner review found dependency-directory and resource-policy guard gaps.
- [x] (2026-09-08) Correct exporter ordering with persistent per-family local
  counters and a failing-before/passing-after 90-root source-order regression.
  Independent parsing confirms exactly 45 section-4 records change, with the
  other eight sections byte-identical. Regenerate the program, Lean components,
  transcript/kernel vectors, reports and pins under `7e50eba07d84433a`.
  Ten targeted Rust tests, both report rebuilds, 21 constructor tests and the
  authorization fixtures pass. Historical fixtures recover inventory-checked
  old source bytes and retain their original relation identity.
- [x] (2026-09-08 17:03 UTC) Complete the post-metadata full formal gate:
  all 3,066 build jobs, all 1,472 declaration audits and canonical wire checks
  pass. Final log SHA-256 is
  `37e71135134ec82186b948b02aa11052cdcf324a88109cb99cfde3c503281e3e`.
  Its first rebuild rejected the old descriptor-mismatch equality, as expected
  after correcting those labels. Replace it with exact current alignment plus
  four explicit stale-record rejections, keeping the credited count at 1,472,
  and rerun the gate using completed build outputs. Both runs are preserved
  in the metadata-order evidence directory. This is not a fresh proof or
  lifecycle receipt; no additional source-semantic obligations are credited.
- [x] (2026-09-08) Generate and cross-verify the corrected proof pair under
  source inventory `2c14119da9a0705c` (1,240 files, 32,983,403 bytes).
  Two separately built generators are byte-identical; all four proof checks,
  both identical chain reports and the full 29-payload constructor checks pass.
  The primary/independent proofs are 122,735/122,479 bytes; complete actions
  are 128,394/128,138 bytes. In-process lifecycle passes in 32.15 seconds;
  actual HTTP/PQ process carriers pass both episodes in 60.35 seconds.
  Full manifest verification passes before and after the carriers. Generation
  records the informational HEAD `dfd72052` with a dirty frozen source tree;
  that commit alone is not the complete generation source. Prior proofs and
  source-forward receipts retain their original subjects. Production authority
  remains disabled; see `repaired-proof-execution.md` for receipt boundaries.
- [x] (2026-09-08) Fresh generation at `dfd72052` exposes the offline
  PendingAction codec's stale `180fca50376f7573` identity after successful
  proving/source verification; no bundle is published. Correct its digest,
  add an early generator identity preflight and a failing-before/passing-after
  actual-program regression. Eight program tests, two codec tests and native
  private-carrier conformance pass. Restart generation under a new inventory;
  do not relabel the failed source snapshot.
- [x] (2026-09-08 09:09 UTC) Integrate twelve reviewed modules and 72
  designated roots for 496 stable-tail CSR attempts, all 448 inactive
  Merkle-right attempts and 145 authorization roots. The full gate passes
  3,040 jobs and all 1,356 declarations with unchanged wire/generated files.
  Forward coverage is now 18,496/20,605 CSR attempts and 633/830 nonlinear
  roots; the remaining 197 nonlinear positions are exactly 252..448.
- [x] (2026-09-08 09:04 UTC) The exact frozen Stage5 candidate passes
  its corrected R3 fixture replay: 21 normal and 21 checks-enabled controls,
  strict original node translation, byte-identical checked node output and
  all six scalar output comparisons. All 24 owned groups are extinct and
  full postflight passes. No Lean evaluator proof is claimed; the next
  isolated native-refinement packet targets those exact generated definitions.
- [x] (2026-09-08 08:29 UTC) Integrate 19 modules and 92 exact roots
  for 64 policy-initial CSR attempts and 121 early/inline/multiplication
  nonlinear roots. The complete gate passes 3,024 jobs and all 1,255
  declarations with unchanged wire/generated artifacts. Coverage at this
  checkpoint is 17,552/20,605 CSR attempts and 484/830 nonlinear roots.
- [x] (2026-09-08 08:34 UTC) Independently review four balance modules
  and 29 roots. Actual positions 112..115 follow from the full typed
  candidate and fixed validity for every lane; native fee, mint, burn and
  padding branches are explicit. At 08:44 UTC the complete integrated gate
  passes 3,028 jobs and all 1,284 declarations; wire/generated files remain
  unchanged. Forward coverage is now 17,552 CSR attempts and 488 roots.
- [x] (2026-09-08 08:33 UTC) Independently review the conditional
  compressed-stress dimension-at-most-21 branch, giving `B/2^53<0.987571`,
  and the universal tail `<2^36+2^-16+2^-21`. Exact arithmetic passes;
  neither result supplies the unrestricted middle-support K8 bound.
- [x] (2026-09-08 08:40 UTC) Run the isolated, separately reviewed
  Stage5 two-site erasure candidate with 21 exact projector/caller controls,
  unchanged-node/scalar replays and a checks-enabled subphase. Original
  sources, assertions and R1/Stage4 evidence remain preserved. The single
  candidate build passes in 228.981 seconds, but the harness fails at the
  first compilation step: its unannotated concrete record is inferred as
  evalue instead of tvalue. No controls or translator replay ran. Preserve
  the failed R2 receipt and built binary; all ten owned groups are extinct.
  This negative run is not Rust-to-Lean refinement or permission for a retry.
- [x] Prepare and separately review the distinct R3 fixture-only annotation
  and no-rebuild harness; its successful 09:04 UTC replay is recorded above.
  Preserve the failed R2 run without relabeling it.
- [x] (2026-09-08 07:50 UTC) Integrate ten modules and 63 exact roots
  proving 1,920 actual Merkle CSR residuals and 26 stable selector/inverse/
  Boolean/radix roots on the same typed candidate. The full gate passed
  3,005 jobs and all 1,163 declarations with unchanged wire/generated
  artifacts. Coverage is 17,488/20,605 raw CSR attempts and 363/830
  nonlinear roots; the remaining 3,117/467 are still active obligations.
- [x] (2026-09-08 07:48 UTC) Complete the isolated instrumentation-only
  translator run after fresh R3 safety revalidation. Preserve the earlier
  sandbox-denied incomplete run, confirmed extinct, separately. The new
  335-second run retained the original assertion, reproduced the nodes
  failure and kept all six scalar outputs byte-identical; all 20 process
  groups exited without cleanup signals and all postflight pins passed.
  Raw expected type retains nested `RStatic` while the value and recursive
  erasure contain `RErased`. No semantic translator patch is applied.
- [x] (2026-09-08 07:46 UTC) Independently review and retain exact
  support-capped affine/rational-graph charges and the zero-stress branch
  proof. The middle-support cover allowances `2^168`/`2^184` are only
  conditional sufficient bounds; no universal cover or K8 receipt follows.
- [x] (2026-09-08; discovered 07:46 UTC) Resolve the exporter nonlinear-descriptor
  ordering defect found while tracing roots 0..115. The executable builder
  interleaves each input's bits/asset and each output's asset/ciphertext;
  metadata groups those families. Actual roots 63/98/104 are nodes
  916/1006/1023, not the operations their labels imply. Actual indexed
  expressions remain proof authority. Preserve this pinned program while
  preparing exact metadata correction/regeneration requirements; no
  expression change, automatic artifact relabeling or fresh security
  authority is justified by this finding.
  Exact read-only preparation identifies 45 changed descriptor records:
  `63..95`, `98..104`, `243..247`; six family labels and 45 local indices
  (39 local-index-only changes; six records change both fields).
  The PRF/key metadata also needs actual per-input interleaving. A correct
  exporter must keep per-family local counters across split spans. Only
  section 4 changes; executable sections 8/9 stay byte-identical, but the
  whole digest/id, vectors and generated descriptors need a fresh identity.
  The completed repair and regenerated identity are recorded above and in
  `docs/crypto/smz9-campaign/metadata-order-repair.md`.
- [x] (2026-09-08 07:33 UTC) Complete and integrate the one-input-pair
  43,904-word typed constructor with all 39 stable rows canonical, actual
  authorization digest identities, checked-subtraction/range helpers and
  all 15,561 raw replication CSR residuals. The next 18 modules and 95
  exact roots pass the full central gate: 2,995 jobs and all 1,100 credited
  roots, with unchanged wire/generated artifacts. Together with the seven
  dense attempts, 15,568 of 20,605 raw CSR attempts are discharged; 337 of
  830 nonlinear roots hold in every lane. Remaining equations, actual Rust
  execution and complete security endpoints are not inferred from shape.
- [x] (2026-09-08 07:07 UTC) Source-review and retain the conditional
  polynomial-shift stress lemma and the exact rank-six large-gcd escape
  family. The latter has `M(813)=N`, refuting an overstrong intermediate
  tail target, but its complete weighted contribution is below `2^52`.
  A separate unconditional sharp affine-response-family charge is below
  150,552; no global cover is asserted. Independent mathematical review
  and exact rational arithmetic pass. These are mathematical research
  documents, not additional Lean roots or completion of universal K8.

- [x] (2026-09-08 06:58 UTC) Pass the full central gate after integrating
  the typed 125-call schedule, authorization/inline rows, canonical 647-row
  source prefix and complete 39-row stable-tail constructor: 16 new modules,
  153 new roots, 2,977 successful build jobs and all 1,005 credited roots on
  the unchanged three-axiom allowlist. Wire vectors and all 48 generated
  relation files remain unchanged. Stable canonicality covers 27 of 39
  rows at this checkpoint; the other 12 and full equation satisfaction
  remain open. Retain the full log and original reviewed source evidence.
- [x] (2026-09-08 06:35 UTC) Build the exact unmodified pinned Aeneas/Charon
  pair in the isolated switch. The 215.77-second native build exits zero;
  original nodes LLBC reproduces the exact projector-109 failure with no
  Lean output, and all six scalar Types/Funs outputs remain byte-identical.
  The complete 264.37-second baseline stage passes source/dependency/input
  postflight. Preserve the baseline before diagnostic instrumentation;
  do not replace its assertion or count the negative node result as R0.
- [x] (2026-09-08 06:43 UTC) Integrate the five typed hash-schedule modules
  and the constructed 647-row prefix, with 27 designated roots. All six
  targeted repository builds pass. Fixed typed validity derives each of
  the 125 source initial frames using actual prior permutation results;
  source-frame canonicality is no longer an assumed complete-frame fact.
  The preceding authorization/inline increment adds four modules and 54
  roots. The full central axiom/vector gate subsequently passes at 06:58 UTC.
- [x] (2026-09-08 06:11 UTC) Construct the first 92 typed replicated rows
  with explicit real-entry admission and source-coordinate readback. Compose
  them with the dense block to derive all seven actual CSR reconstruction
  residuals, preserving the arbitrary intervening authorization region and
  suffix. Separately derive all 332 generated hash roots in every lane from
  the computed hash block and successful evaluation of the unchanged full
  expression DAG. Independent source reviews find no material issue in the
  final typed prefix or forward-hash chain. Integrate eight modules and 49
  exact roots; the full central gate passes at 06:15 UTC with 2,961 jobs and
  852 approved-axiom roots. All generated relation modules and proof-wire
  vectors are unchanged. Full typed schedule, remaining rows/equations and
  actual Rust execution remain separate obligations.
- [x] (2026-09-08 05:43 UTC) Construct the actual five-row dense range block
  from the seven typed/public source values, prove its explicit global
  placement, and derive all five generated nonlinear range roots in every
  lane without an accepted-packed premise. Construct the complete hash
  block from 125 canonical live initial states plus three actual zero-start
  traces, including source-owned coordinate readback and the nonzero dummy
  permutation output. Independently review both components and the exact
  remaining-count batch/first-accept trace bijection and ideal law transport.
  Integrate eight research modules and 58 exact roots; the complete gate
  passes at 05:50 UTC with 2,953 jobs and 803 approved-axiom roots. All 48
  generated relation modules and three proof-wire vectors are unchanged.
  Full typed assignment, live hash schedule, remaining roots/linear
  equations and real provider/Rust execution remain due.
- [x] (2026-09-08 05:47 UTC) Complete isolated pinned translator-source and
  signed OPAM bootstrap acquisition. Freeze 118 exact dependency identities
  and 113 strong-checksum source records, with no packages installed at the
  end of acquisition. Authorize only their one-job isolated installation,
  with 8 GiB maximum new-root storage, 8 GiB minimum free storage and a
  120-minute ceiling. The translator patch/build remains a separate step;
  no Hegemon dependency, original extraction, old tool or retained artifact
  is changed.
- [x] (2026-09-08 05:08 UTC) Complete the unchanged actual Rust inverse
  refinement. The extracted loop terminates for arbitrary U64 exponent/base
  with canonical accumulator and returns the exact modular power; the full
  helper matches original `fieldInverse` on every canonical input, including
  zero. Inverse-v3 freshly checks generated Types/Funs and proof, pins all
  consumed frozen v2 dependencies, and passes five unique standard-axiom roots
  and five evidence controls. Independent review agrees. Retain evidence as
  `native-refinement-inverse-v3-29670ce01aeadeb0`. The actual nodes LLBC
  extracts, but Aeneas fails on the static error-reference return before
  producing Lean; no evaluator theorem or semantic substitution is credited.
- [x] (2026-09-08 04:41 UTC) Complete isolated actual-source scalar
  refinements: canonical-input subtraction and all-U64 addition/multiplication
  succeed and equal the unchanged original Lean field definitions. V2
  rebuilds eight exact generated/Hegemon imports, checks both proof modules,
  enforces nine unique exact roots/axiom sets and passes five evidence-string
  controls. Peak serial child RSS is 2.077 GiB. Retain the receipt and proof
  closure under `native-refinement-scalars-v2-4050e54ee1c381c4`; document the
  trusted translation/standard-library mapping and isolated Lean 4.31.0
  boundary in `native-scalar-refinement.md`. No whole-evaluator/R0 credit.
- [x] (2026-09-08 04:39 UTC) Complete fresh two-build generation at
  `cee3cb8123d87d85d97e6db12f0262baacf0e1a7`, source root
  `aaea3c80e8f5d9ff`: both proofs 122,543 bytes and both complete actions
  128,202 bytes. Four cross-verifications, equal two-build binaries/chain
  reports and all full manifest pre/post gates pass. The in-process lifecycle
  passes in 34.63 seconds; the real HTTP/PQ socket lifecycle passes both
  episodes in 53.70 seconds, including exact locator/body imports, clean
  same-identity restart and fresh-node sync. Eight children exit unforced
  with closed listeners. Independent receipt processing confirms exact
  action/leaf/proof bytes and all canonical blocks/typed rows across four
  processes per episode. Retain the complete receipt and exact executable
  under `.agent/artifacts/smallwood-poseidon2-v8/carrier-aaea3c80e8f5d9ff`.
  This closes this local artifact/carrier milestone, not P7/K8/R0 or release.
- [x] (2026-09-08 04:29 UTC) Pass the four new caller-boundary tests, the
  extended paced-announcement regression (including a hashless same-peer
  repeat and announcement-driven dispatch after the hold), and the focused
  pacing, cursor, target-growth, peer-failover and unverified-target groups.
  All 13 carrier controls, the ordinary no-feature native library check and
  whole-workspace formatting pass. Independent review finds no new
  peer/hash/parent-binding defect; existing snapshot/lookup non-atomicity is
  not claimed solved. Freeze this source for a new independent proof pair.
- [x] (2026-09-08 04:21 UTC) Reproduce the production caller's recovery-page
  overwrite in the exact pacing regression: a repeated tip replaces
  `[257,320]` by `[1,64]`. Prefer the compatible admitted recovery cursor in
  `request_missing_blocks` and preserve its parent/recovery context. The next
  source-frozen carrier run remains due; positive tests are recorded above.
- [x] (2026-09-08 04:21 UTC) Independently review and retain the finite
  additive-local-rank obstruction in
  `docs/crypto/smz9-campaign/weighted-mca-local-rank-barrier.md`. For the
  displayed Proposition 3.7 interpolation space, even exact individual ranks
  cannot meet its rank-sum certificate through agreement 2,892. Exact
  arithmetic checks pass. This excludes that proof route, not global kernels
  or the universal weighted MCA theorem; K8 remains open.
- [x] (2026-09-08 04:13 UTC) Generate another independent two-build pair at
  `ed893a1f54503e903dd6a2ff47579998b8d27bff`, source root
  `38714873e4d04181`. The proofs measure 122,543 and 122,735 bytes; complete
  actions measure 128,202 and 128,394 bytes. Four cross-verifications, full
  constructor checks, and the 26.90-second in-process lifecycle pass. The
  real-socket run reaches HTTP mutation rejection and valid admission, PQ
  peer relay, exact durable/in-memory pending bytes, and proof-block mining,
  but times out before the relay imports height three. Preserve its failure
  receipt; it is not a completed actual-socket lifecycle.
- [x] (2026-09-08 04:13 UTC) Narrow the source-only carrier selection to
  inline the exact non-proof coinbase prefix and select a single locator
  only when the byte-identified retained action is first in the requested
  range. No receiver check, proof byte, production threshold or production
  behavior changes. Fail closed on a poisoned observation lock; add plain
  stage diagnostics. All 13 carrier controls and full formatting pass.
  Independent review found no normal-path selector/init bypass. The
  separately source-confirmed paced-announcement recovery-range overwrite
  is being checked before the next freeze and fresh generation.
- [x] (2026-09-08 03:46 UTC) Generate and cross-verify two fresh proofs at
  `c890e84350d14117beb5d83118dff8b8c4a9deb4`, with byte-identical independent
  generator builds and frozen 1,112-file source root `3e26e0e66e57d8c8`.
  The exact 29-payload candidate passes full constructor verification and
  the retained in-process lifecycle passes. The actual-socket attempt stops
  before service startup: its CLI selects normal development difficulty,
  whereas the retained fixture and guard require easy test difficulty.
  Preserve this pair and failure receipt as historical snapshot evidence;
  neither credits a successful socket lifecycle for the corrected source.
- [x] (2026-09-08 03:46 UTC) Correct that fixture-only configuration path.
  Ordinary `run(cli)` retains its configuration and delegates to the same
  native service body. The child now passes the exact adjusted configuration
  checked by its guard into that shared body. Production difficulty and all
  guard predicates are unchanged. All 12 carrier controls pass, including
  actual CLI-derived configurations under both sanitized seed modes and a
  check that exactly one named child ran. Independent source review found no
  second deterministic startup mismatch. Regeneration and socket execution
  against the new source freeze remain due.
- [x] (2026-09-08 03:22 UTC) Complete and integrate the actual modeled
  source-lifetime privacy endpoint: all-request leaf/final/hidden comparisons,
  literal persistent byte/error histories, derived query/event/mass bounds,
  direct witness-free public-policy simulator, exact source erasure, and the
  two-witness triangle. The final module has no endpoint equality or distance
  premise. Under the explicit universal external reprogramming theorem and
  analysis indices `q <= 2^65`, `r <= 2^21`, the source/simulator gap is at
  most `2^-167`, and the two-witness gap is below `2^-128`. Independent static
  review found no public-input, chronology or arithmetic defect. The full
  integrated gate passes 2,945 build jobs and audits all 745 roots under the
  existing three-axiom allowlist; the 139 new modules preserve exact generated
  relation and wire artifacts. Concrete hash/RNG/source/binary refinement,
  approved resource policy, universal K8 soundness and production authority
  remain separate; this is not a full P7/K8/R0 completion claim.
- [x] (2026-09-08 03:22 UTC) Reconcile the stale proof-existence wording:
  repaired-digest proofs and an in-process lifecycle are preserved for the
  earlier `b1e5c143f7abf052` snapshot, but do not bind the current inventory.
  The final two-build generation wrapper, exact constructor pre/post gates,
  and actual socket/process harness are ready for the source freeze. The
  latest disk observation is 24 GiB available; no withdrawn 40-GiB stop is
  reintroduced. No fresh generation has yet been credited for this snapshot.
- [x] (2026-09-08 02:30 UTC) Integrate the history/byte/public-program
  adapters, exact quadratic scaling for measured branch states, and fixed
  future/public simulator query accounting. The first four modules centrally
  build in 2,746 jobs; fixed-future accounting also centrally builds. The
  public byte simulator strictly checks at at most 117 raw queries plus the
  original future count, with no selected programming events. Current inventory:
  112 new modules and 636 roots, pending the next full gate. The one-pivot
  theorem uses an actual shared prior history, but its source-stage provenance
  and repeated-request telescope are still being connected separately.
- [x] (2026-09-08 02:30 UTC) Freeze the native carrier sources after all
  eleven guard/control tests pass, including compile-pinned checker/policy
  mutations. Full workspace formatting and embedded Python checks pass.
  Independent pre-generation review corrected the original-build-path
  requirement for prover provenance and added pre-build inventory and final
  post-construction HEAD/tool stability checks. No fresh generation or actual
  socket episode has yet run against the pending final source snapshot.
- [x] (2026-09-08 02:06 UTC) Pass the next full integrated formal-crypto
  gate: 106 new modules, 2,912 build jobs and 603 credited declarations,
  all within the three-axiom allowlist; generated relation and proof-wire
  artifacts remain exact. This includes literal post-final proof/error bytes,
  physical single-tape to measured-oracle equality, a witness-free byte
  reference bound, actual 24-level source-tree geometry and checked compact
  path lookup ranges. The complete source request has at most 16,790,291
  raw reads plus its full byte/error continuation. Final selected-write and
  whole-history/lifetime composition remain in separate active lanes.
- [x] (2026-09-08 02:06 UTC) Fix the mempool value projection and verify all
  ten carrier guard/control tests, including owned process-group descendant
  cleanup and rejection of inherited/unconfirmed groups. The managed sandbox
  denied process inspection before startup; the tool-approved isolated rerun
  passed. Full formatting passes. Final review found that inventory scripts
  are outside the release inventory, so compile-time pins and exact-byte
  execution of both checker and policy are being added before source freeze.
- [x] (2026-09-08 01:45 UTC) Integrate the strictly checked collision-exact
  mixed-write compiler. It carries a finite correction log, charges fixed
  writes, handles repeated-key collisions, and reduces to the existing
  adaptive-reprogramming theorem without a new distance premise. All three
  modules centrally build. The source-prefix query lemmas also strictly pass:
  all leaves, the complete Merkle tree, actual DECS/PIOP field-XOF caps and the
  final digest use at most 16,790,194 raw calls, plus the complete future's
  query count. Only the current 8,388,608 leaf events are selected after the
  honest-future compiler. Integrated inventory: 100 new modules, 566 roots;
  this is pending the next full gate, not a new full-gate pass.
- [x] (2026-09-08 01:45 UTC) Complete and compile the process-carrier driver
  and pass seven guard/control tests. Require new proof-verifier events after
  each pre-mine boundary, naming the actual final block hash. Independent
  review then caught the in-memory BTreeMap snapshot encoding key/value tuples
  instead of action values; its narrowly scoped correction/regression is
  underway before source freeze. Actual fresh-pair socket execution remains due.
- [x] (2026-09-08 01:24 UTC) Integrate and centrally build the seven measured
  oracle modules, actual nonce/index adjacent comparison, chronological
  computed DECS/PIOP prefix, same-oracle Q/M transport, and its actual physical
  interpreter equality. The coordinator also proved and independently reviewed
  the honest-future compiler: it removes fresh programming events from later
  requests without changing honest execution or query counts. The pending
  integrated inventory is 96 new modules and 549 roots; the most recent full
  gate remains the separately recorded 515-root pass. The mixed-write compiler
  and final returned proof/error-view binding are still in progress.
- [x] (2026-09-08 01:24 UTC) Implement the test-only process guard and actual
  native service observations/locator selection; its five isolation tests pass.
  The production library `cargo check --locked --offline -j1 -p hegemon-node
  --lib` also passes with test hooks excluded. The parent process-carrier driver
  is still being completed; no socket lifecycle pass is claimed yet.
- [x] (2026-09-08 00:56 UTC) Finish the complete arbitrary-packed-witness
  implication to the unchanged `ExactV8RelationSemanticValid`, including every
  authorization mode and the full enabled stable transition. The integrated
  84-module addition passed the full formal-crypto gate: 2,890 build jobs,
  515 credited declarations, and only the three allowed kernel axioms. The
  full-action wrapper additionally uses explicit context/ciphertext matches;
  Rust execution refinement, reverse lowerer completeness, and proof-byte
  extraction are not supplied by this theorem. Three independently reviewed
  measured-oracle modules are now integrated for the next gate, raising the
  current inventory to 87 new modules and 519 roots, not yet a new full pass.
- [x] (2026-09-08 00:28 UTC) Strictly prove the full stable transition for
  arbitrary accepted packed assignments under canonical public admission:
  disabled, mint, burn, issuer/config/state hashes, all counters, policy,
  freshness, collateral products and both state roots. Integrate its 26-module
  dependency closure (including the shared compression helper), exact note,
  input Merkle, all-mode nullifier and authorization hash chains, and the
  physical honest-input privacy-game helpers. The repository now contains 66
  new modules and 488 designated audit roots. The final authorization
  conjunction and central strict build are running; this is not yet a fresh
  full-gate result or the complete P7/K8/R0 security argument.
- [x] (2026-09-07) Rechecked the selected checkout and preserved the three
  unrelated AGENTS/testnet-skill edits. Existing local checkpoints are
  `814b68fb` and `f4abcede`; the latter passed 2,754 jobs and 145 credited roots.
- [x] Derived and independently reviewed an eager witness-free privacy
  construction and an arbitrary-source, sample-weighted recovery reduction.
- [x] (2026-09-07 16:15 UTC) Mechanized the joint 3,105 PIOP / 1,940 DECS
  mask inverse, actual cross-column PCS map, and dependent 7,156-coordinate
  opening transport, including selector failure. Constructed the public eager
  algebraic fields and checked all row/DECS reconstruction round trips.
- [x] Proved the physical complex-linear hidden-program query bound and its
  complete raw-domain indexed 512-bit-tape specialization, with no domain-size
  union factor. Composed the classical context/opened-tape mixture with the
  persistent full-versus-opened oracle transition.
- [x] Proved the arbitrary-source recovery reduction in the exact joint
  coefficient/query product. Specified an interpolation decoder before later
  queries/challenges; the maximum weighted line constant is defined, not assumed.
- [x] Proved packed-program Boolean/radix constraints and seven exact dense
  61-bit value bounds from arbitrary accepted assignments. Corrected the
  reserved asset in the semantic specification and separated frontend public
  admission from raw packed constraints.
- [x] Proved fixed-pre-batching-candidate PIOP soundness for adversarial
  post-batching transcripts and fresh six-point admissible queries, with
  omitted linear constants restored from public targets.
- [x] Proved the exact actual 8,271-node field-expression degree certificate,
  all 830 root degrees at most 552, and successful-source-evaluation
  correspondence, including canonical representatives and equality selection.
- [x] Constructed the actual total typed source projection and proved note
  value, direction/position and one-hot authorization-mode properties from
  arbitrary packed acceptance; the full semantic conjunction remains open.
- [x] Derived the full unchanged canonical-witness predicate and per-asset
  integer balance from the actual accepted packed program. The balance proof
  includes native, ordinary nonnative, mint and burn branches with no-wrap
  bounds; hash/authorization/stable-transition families remain separate.
- [x] Constructed the current unbatched PIOP candidate from arbitrary decoded
  source polynomials and proved full candidate satisfaction implies actual
  unchanged packed-interpreter acceptance, including total Option evaluation
  and the impossible-empty normalized-CSR fallback case.
- [x] (2026-09-07 19:19 UTC) Ran the integrated formal-crypto build and axiom
  audit over 308 designated declarations: 2,797 build jobs passed, every audited
  declaration used only `propext`, `Classical.choice`, and `Quot.sound`, and all
  generated proof-wire files remained byte-identical.
- [x] Proved exact finite capped-sampler tails: DECS abort at most `2^-976`,
  successor maximum-size gamma abort at most `2^-773`, and every permitted retained-row
  gamma abort at most `2^-629`. The `Q^2` result is arithmetic over fixed-vector
  laws, not an adaptive-QROM theorem; a later `(2*Q_raw)^2` use pays its factor
  four explicitly.
- [x] Strictly checked the non-single authorization source prefix and the
  current repeated-request compiler. The former binds Boolean/one-hot bitmap
  transitions and the raw signer tag but not yet the complete canonical
  authorization relation. The latter compiles retained updates and charges two
  raw calls per logical read, but does not yet supply the external adaptive
  reprogramming theorem.
- [x] (2026-09-07 19:35 UTC) Kernel-proved that the old universal
  typed-to-HGV8RP03 completeness claim is false: a typed-valid stable burn whose
  stable asset is omitted from `balanceAssets` is rejected for every packed
  witness by public source root 1042.
- [x] (2026-09-07 20:17 UTC) Daybreak independently constructed a raw HGV8RP03
  counterexample for the final partial output-note sponge block. It preserves
  the decoded typed witness and passes all 20,569 CSR attempts and 53,120
  nonlinear evaluations, while violating canonical chaining at call 75 lane 2.
  The honest materializer rejects it only at `NonCanonicalTypedLowering`.
- [x] Traced the independent profile-6 verifier and confirmed it checks the
  HGV8RP03 CSR/nonlinear relation but never invokes the prover-side canonical
  typed-lowering guard. Production remains fail-closed because the source
  capability is absent.
- [x] Repair the two relation mismatches: bind every out-of-range sponge rate
  lane to canonical no-absorption chaining, and require an enabled stable asset
  exactly once in the typed/public balance list. Explicit in-range private
  sponge holes remain unbound. The focused Rust regressions pass.
- [x] Regenerate the exact source-owned relation program and digest-dependent
  source/Lean, conformance, policy and transport fixtures under the 853,429-byte
  program SHA-512 `180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.
  `HGV8RP03` remains only the format-lineage magic; the 48-byte digest prefix is
  the relation discriminator. Never reinterpret old HGV8RP03-format proofs
  under the repaired digest.
- [x] (2026-09-07 21:38 UTC) Integrate the repaired relation, non-single
  authorization, disabled stable transition, bounded enabled-stable arithmetic,
  whole-view observation, coherent extraction, and source-codec endpoints. The
  complete formal-crypto gate passed 2,806 jobs and audited all 376 designated
  declarations under the existing axiom allowlist; three wire vectors and 48
  generated relation modules (2,266,857 source bytes) matched exactly.
- [x] (2026-09-07 21:44 UTC) Run the post-review Rust coverage: the focused
  first-block private-hole and wrong-new-signer-tag regressions each passed,
  the exhaustive relation target passed 10/10, and `cargo fmt --all -- --check`
  passed.
- [x] Record the endpoint decision dossier: P7, K8, and R0 are unavailable in
  the current proof graph, their constructor-free premise records cannot be
  bypassed by local gate results, and production stays fail-closed.
- [x] (2026-09-07 22:50 UTC) Preserve the final formal-core boundary exactly.
  Preflight passed. The vector script passed its repaired-relation/source and
  early consumer checks, then was interrupted at phase 4/14 when it reached a
  native-node SIGTERM smoke step because the coordinator incorrectly imposed
  a no-node restriction (exit 130); no listener or `hegemon-node` process remained, and the
  whole vector script is not recorded as passing. The policy script passed the
  dependency, inventory, system-model, 121-claim, 121-node blueprint and 2/2
  bridge-vector stages, then failed closed at phase 12/14 because the native
  BLAKE2b-384 Boolean transaction relation is unsupported and legacy Poseidon
  review bundles cannot authorize production (exit 1); phases 13/14 were not
  reached. Neither script was bypassed or weakened. The vector interruption
  did not come from a user prohibition; the local isolated check remains due.
- [x] (2026-09-07 23:01 UTC) Correct the premature completion report and the
  coordinator's false assertion that local proof generation lacked authority.
  The user had explicitly required producing the proofs and finishing the
  work. Fresh generation and isolated local lifecycle tests are required work.
  The primary repaired proof has now been generated and separately verified;
  a clean second generator build is in progress. Freeze inventory-covered
  source files and HEAD while the two generation receipts are produced.
- [x] (2026-09-07 23:15 UTC) Generate, independently rebuild, cross-verify and
  retain two fresh 122,735-byte proofs for the repaired digest. Their complete
  actions are 128,394 bytes. Seal the new b1e5c143f7abf052 candidate without
  changing the historical fixed pointer. The native retained-proof lifecycle
  harness passed in 42.23 seconds; post-lifecycle verification reproduced the
  exact inventory and all 29 sealed payload files. This covers native API,
  storage, reorg and fresh import, not HTTP/libp2p or process restart. Keep
  production capability and release selection disabled.
- [x] (2026-09-07 23:24 UTC) Derive a deterministic raw SHA-512 call budget:
  each attempted engine prover/verifier uses fewer than 2^26 evaluations,
  and the canonical frontend with both replay verifiers uses fewer than 2^28.
  Charge exhausted XOF calls from static bounds rather than their incomplete
  failure trace counter. This is source accounting, not execution refinement.
- [x] (2026-09-07 23:44 UTC) Finish the formal-core vector gate: the complete
  script passed, including isolated loopback SIGTERM/durability. Correct the
  three stale exact-test references, regenerate the four ciphertext fixture
  hashes for the actual BLAKE2b-384 runtime, and compare the node's active
  default-version predicate rather than historical decoder availability.
  These are harness/fixture corrections, not verifier acceptance changes;
  historical Level-5 codec vectors remain labeled historical. The policy
  gate's independently recorded native-backend refusal remains unchanged.
- [ ] Mechanize the joint PIOP/DECS mask change of variables and compose the
  generated whole view with actual opening maps and abort branches.
- [ ] Prove the physical hidden-program removal inequality, its indexed-tape
  specialization, and its use in the complete persistent-oracle experiment.
- [ ] Prove the general recovery reduction and its required concrete finite
  bound, rather than assume a small candidate family or source cover.
- [x] Construct packed-program-to-typed-semantics soundness for arbitrary
  accepted assignments under actual canonical public admission, not only
  honest lowering fixtures. Reverse lowerer completeness and Rust execution
  refinement remain separate outstanding obligations.
- [ ] Construct the actual quantum commitment/extraction and raw-oracle
  transfer, with resource overhead and all losses explicitly derived.
- [ ] Verify and locally land each integrated change without crediting it as
  completion; continue until both endpoint theorems are established or a
  concrete obstruction requires a material user decision.

## Surprises & Discoveries

The initial high-limb padding draft merged two four-cell groups and omitted
the final right-output group. The qualified theorem follows the six actual
source starts and generated entries; the wrong draft remains uncredited.
A full-table finite lookup hit the unchanged 2,800-MiB Lean allocation cap.
Bounded generated-chunk membership plus the complete-list lookup theorem
closes the same indexed statement below the cap. This was a proof-development
resource failure, not a discovered runtime defect.

- Observation (2026-09-08): the existing note/nullifier/Merkle acceptance
  theorems have the wrong direction for honest construction. New source
  proofs must first derive exact scheduled digests, including the 32-step
  Merkle fold and active own-spend-key selection, before using typed
  cryptographic links to bind public output fields.
  Evidence: the 42 public-digest equations are qualified from typed
  validity alone; no accepted-packed premise appears in their dependency
  endpoint. Failed development imports, arithmetic normalization and
  linter attempts remain retained without relaxing compiler flags.

The complete nonlinear endpoint needs both exact indexed root coverage and
the actual interpreter bridge; zero field expressions alone are not an
execution receipt. The all-830 proof obtains real list membership for the
hash slice and instantiates the bridge's public/row lengths and canonical
DAG premise internally. A negative-control attempt initially hit Lean's
default recursion-depth limit and was not credited as a semantic rejection.
The fresh v3 run raises that limit explicitly and rejects all seven false
statements mathematically. Earlier failed sources and logs are retained.

The shell gate's initial declaration-count check ignores comment headings,
but the Lean audit reads every nonempty line as a theorem name. A heading
added during the final authorization migration therefore stopped the
1,752-declaration audit after a successful build and wire generation.
The correction removes the heading, preserves all 1,752 declaration names
and retains the failed full-gate log under SHA-256
`f988bcab301557abf747f671a2eb199227e36708e3c185ea91f313825564c2c4`.

The source's remaining-count refill has an exact finite-trace interpretation:
its final batch must accept every candidate, so the last word is the last
required acceptance. A proof by remaining raw length handles arbitrarily many
all-reject rounds without pretending the remaining output count decreases.
The resulting ideal probability law still does not establish actual provider
freshness, error conditioning, allocation or concurrent scheduling.

Forward materialization must preserve global offsets and nonzero helpers.
Dense data is only a 320-word local block, so using a global-row decoder on
that local list would silently read defaults. The explicit embedding proves
the actual 15,808-word offset. Likewise the three hash dummy calls start at
zero but their first final word is `0x60cffc11a095a4f6`; their trace blocks
cannot be replaced by zeros. The new constructors preserve both distinctions.
The typed 92-row prefix also proves actual entry presence before crediting
canonical source values: list defaults are not typed inputs. Its composition
with the dense block discharges all four private reconstruction cells, not
only the three public identities. The hash forward proof uses the full
generated expression DAG and only a selected exact root slice; interpreter
success for that slice is not full packed acceptance.

The first real-socket proof-block import attempt made genuine earlier
progress but repeatedly fetched coinbase heights one and two. A first-only
locator is a legal requested prefix; selecting the last locator would violate
the receiver's exact requested-start check. The narrowed fixture preserves
coinbase prefixes inline and reserves the locator/body path for the actual
retained proof block. Source review separately found that repeated same-target
announcements can replace a paced recovery request with an ordinary backfill
range. The receipt lacks the request/context timestamps needed to prove that
specific interleaving caused this failure; do not state it as observed fact.

The pure manually constructed guard fixture did not exercise CLI difficulty
selection. `NativeConfig::from_cli` uses the normal development genesis bits
`0x1e10c6f7`, while the retained coinbase fixture deliberately uses
`0x207fffff`. The first actual child therefore correctly rejected before
opening a service. The new regression uses the actual sanitized child
environment and CLI constructor, checks ordinary rejection and retained
admission, and passes the same admitted configuration to the real service.

The collision-exact compiler does not treat a fixed programmed entry as an
authoritative overlay that can shadow a later refresh. It maintains the
effective table as the raw table XOR a newest-first finite correction log.
Fixed writes read the current raw value; selected refreshes translate both the
logical answer and the continued effective table. The exact execution theorem
covers arbitrary collisions and subnormalized measured branches. The protocol's
actual sampling law and Rust execution correspondence remain distinct duties.

The old PCS unstack coordinate formula was not the source randomization map:
Rust subtracts a coin polynomial from the next column. The corrected map is
still bijective at distinct nonzero points. The verifier's old stronger
admissibility restrictions are conservative and remain unchanged. Existing
model theorems about the old map must not be credited as source refinement.

The semantic model's reserved asset was incorrectly `p-1`; the source uses
`u64::MAX mod p = 4294967294`. Raw packed acceptance also does not enforce the
entire canonical public-word shape: the frontend performs that admission.
The semantic receipt now uses the actual admitted-public domain instead of
asking for a false raw-acceptance implication. This is not a proof that all
remaining private semantic families follow from acceptance.

Two authorization-specification mismatches were independently source-checked.
The transaction PRF selects the first active input, including the admitted
second-input-only case, rather than always reading input zero. The approval
predicate also omitted the source's binding from the newly approved bitmap
slot to all five words of the transaction signer's policy tag. The source
membership/bitmap constraints enforce that identity at
`smallwood_poseidon2_v8_semantics.rs:800-825`. The semantic model now includes
`ApprovalSignerBound`; it is strengthened to reflect existing execution, not
used to change the accepted protocol. Both corrections require fresh base
formal checks and source-content digests.

The old `ProductionConstraintExpression` and the actual 8,271-node
`FieldExpression` DAG are different interfaces. Generic public PIOP recovery
and eager laws must retain this boundary until the current-program polynomial
and opening adapters are proved; source dimensions alone do not establish it.

The privacy feedback cycle has an explicit inverse. In the independently
randomized-leaf experiment, let D be the full DECS response and T the full
PIOP polynomial message. Given D, derive the PIOP challenge, recover the PIOP
masks from T and the witness polynomials, rebuild the PCS rows, then recover
the DECS masks. This is a joint bijection, so the remaining witness-opening,
PCS and LVCS coins remain fresh. It does not preserve concrete unprogrammed
leaf hashes.

An eager simulator can retain D throughout. After constructing its opened
LVCS values, it computes mask openings as D(J) minus their challenged linear
combination. There is no need to claim independent DECS high coefficients and
mask openings. A full random leaf tree costs the same order of work as the
honest prover and avoids assuming the existing compact simulator has the
right joint law.

Each encoded leaf input identifies its own index. For independent unopened
512-bit tapes, a fixed raw input hits at most one hidden program with probability
at most 2^-512, without a tree-size union factor. The stronger averaged-state
query bound requires discarding the hidden tapes; it is not a bound for an
adversary later given them. Actual aborts, subsequent proof queries and oracle
overwrites must be retained.

The five DECS rows can be viewed as one extension-field word using the same
700 sampled base-field coefficients. Reversing the 140 column combinations
reduces arbitrary-source recovery to a sample-weighted, exact-support line
agreement bound. The desired finite bound at agreement threshold 416 is not
proved. No asymptotic capacity statement supplies its missing constant.

The executable sponge builder conflated an in-range `None` (a deliberately
private absorbed word) with `inputs.get(input_index) = None` beyond the final
input. For an 18-word output note, final call 75 rate lanes 2 through 7 were
therefore unconstrained instead of copied from call 74. A synthetic one-output
assignment changes lane 2, recomputes its hash trace and dependent action intent,
and still satisfies the entire pinned HGV8RP03 CSR/nonlinear program. The
canonical typed-lowering comparison is not part of independent proof
verification, so HGV8RP03 knowledge cannot be promoted to knowledge of the
typed relation.

The opposite-direction mismatch is public and independent of private witness
choices. The typed public predicate allowed an enabled stable asset to be absent
from all four canonical balance slots, while HGV8RP03 root 1042 requires
membership. A concrete asset-1001 burn is fully typed-valid but has root value
1001 for every packed assignment. This is a completeness rejection, not
inflation. Strengthening typed/public admission to the already-enforced packed
membership rule preserves the intended balance semantics.

## Decision Log

- Decision: integrate all ten range modules as one 90-equation packet and
  one complete 2,129-declaration gate. Use bounded generated-chunk membership
  for exact padding lookup after whole-table reduction exceeds the existing
  cap. Preserve all unsuccessful drafts and compile logs; do not weaken
  compiler settings, source bounds or the final typed-validity statement.
  Date/Author: 2026-09-08, coordinator.

- Decision: integrate the four stablecoin packets together after their
  strict source checks and independent reviews, then run one complete
  2,083-declaration gate. Reuse only unchanged development dependencies
  during drafting; strict qualification freshly rebuilds every selected
  scratch dependency. This reduces repeated development work without
  weakening source/output pinning or final acceptance gates.
  Date/Author: 2026-09-08, coordinator.

- Decision: batch all 290 remaining input/output CSR equations into one
  exact 21-module migration and one 1,996-declaration integration gate.
  Rationale: three independently qualified packets now cover every note,
  nullifier and public-digest attempt in the two remaining base-I/O ranges.
  Repeating a full gate after each small packet would not add evidence for
  a new integrated state. All 596 outstanding CSR equations are stablecoin
  families; complete CSR execution, security and release authority stay
  separate.
  Date/Author: 2026-09-08, coordinator.

Compose and credit the actual complete nonlinear interpreter endpoint after
qualifying all 97 remaining authorization roots; do not infer full CSR or
packed acceptance from it. Keep raw CSR attempt counts distinct from
public-dependent normalized rows. Preserve the original scratch receipts
and compare import-only migrated sources byte for byte before the combined
gate. Date: 2026-09-08 19:27 UTC.

Continue reverse semantic adequacy through named concrete row constructors,
not through an existential accepted witness or a successful-evaluator input.
The current independent components and exact batch law are documented in
`docs/crypto/smz9-campaign/honest-construction-and-batch-law.md`. Assemble
remaining rows, the typed live hash schedule and generated equations before
claiming full admission. Keep the isolated translator dependency build out
of Hegemon's runtime/dependency graph and preserve its original failing
extraction inputs for before/after regression. Date: 2026-09-08.

Derive the complete hash-root component by exact earlier-row replay and
source trace scheduling, then transfer those identities to the constructed
block. Keep the selected-root interpreter endpoint explicitly partial.
Bind dense reconstruction to concrete first-prefix readbacks instead of
adding raw-cell equality premises. Date: 2026-09-08 06:11 UTC.

The announcement caller must use the same compatible recovery cursor as the
periodic scheduler. Guard its mutating lookup by the current admitted full
peer/height/hash tuple; retain the existing sender pacing and receiver checks.
The deterministic failing request-state test establishes this caller bug,
but does not retroactively establish the unrecorded cause of the socket stall.

The isolated retained fixture may select its existing easy test difficulty;
the ordinary CLI and production difficulty must not change. Factor the service
body into `run_with_config` so the guarded configuration is the executed one,
without a second CLI parse. Any covered-source change, including this test
repair, requires a new source-frozen retained pair; prior proof bytes and
failure diagnostics remain preserved and are never resealed as fresh.

The 2026-09-08 local carrier test uses one exact ignored library-test child
process, numeric loopback listeners/seeds, an isolated temporary database and
persisted identity, and a live-source-verified candidate manifest. Its process
binding and transport selector exist only under `cfg(all(test, feature =
"poseidon2-v8-retained-test-support"))`; ordinary tests retain thread-local
bindings and production retains no capability. Select an existing one-body
locator response and tip-only announcements because the small retained action
would otherwise take the inline path. Do not change its bytes, production
thresholds, wire grammar, or receiver checks. Keep result/progress documents
outside inventory-covered Rust source so post-run documentation cannot stale
the freshly generated source manifest.

The final process harness uses inventory-only Python preflights, not nested
native verifier subprocesses. The coordinator runs the full constructor before
and after the actual carrier episodes. Newly created process groups, validated
before private startup frames are released, contain metadata descendants on
failure. Successful-stop evidence is tracked proof/import/fallback worker
idleness, stable tip, actual service shutdown, successful OS exit and closed
listeners; it is not a claim that all active transport internals were observed
quiescent. The scripts implementing inventory policy must be pinned to the
test binary and executed from their checked bytes because `scripts/` is not
covered by the release-source inventory itself.

Use the complete eager simulator as the first privacy target. Its public proof
format is unchanged; proving the compact simulator's different sampling law is
not necessary to exhibit a witness-free simulator. Retain all correlated oracle
entries until an explicit quantum transition removes them.

After the user instructed the team to complete the work on 2026-09-07, repair
the verified relation/specification mismatches rather than attempt to prove a
false unchanged-refinement statement. The padding repair strengthens the
executable relation and creates a successor identity. The stable-membership
repair strengthens typed/public admission to match the existing packed rule.
Neither repair authorizes production or permits old artifacts to be relabeled.

The coordinator owns this plan, shared imports, inventory, builds and git.
Authors own only the new files assigned below. Initial review checkpoints are
twenty minutes, not automatic stopping conditions. Each lane has at most 40 MiB
of new source and scratch space. Monitor disk to sustain proof production and
keep the computer operational. The coordinator-invented 40 GiB cutoff is
removed following the user's correction; it is not a user constraint or a
stopping condition. Reclaim verified disposable build/scratch data as needed,
preserving sources, retained proofs, node/wallet state and unrelated work.
Reuse cached Lean 4.32.2 and
mathlib, with one direct Lean process per lane and coordinator-only package
builds. Source-bound retained proofs also require their exact Rust generator
builds and isolated lifecycle checks. Schedule those alongside the mathematical
work, keeping source files frozen during generation and storing prospective
formal changes in separate scratch directories until the snapshot is sealed.

## Outcomes & Retrospective

The source-lifetime privacy endpoint now exists for the explicitly modeled
ideal oracle under its external theorem and analysis budgets. Concrete P7,
universal K8 and full R0 remain open. Fresh repaired proofs exist for several
frozen snapshots. The `cee3cb81` snapshot now has both a complete real-socket
receipt and the separate in-process reorg receipt, with exact post-run source
and artifact verification. The narrow production sync bug has a failing-before
regression and passing caller tests, not only a source hypothesis.
Actual source extraction also now establishes all four scalar helper
refinements, including inverse-loop termination, in an isolated,
exact-root-checked Lean 4.31.0 lane. The expression loop, caller/array binding
and production binary remain separate
R0 obligations; these results are not added to the formal-crypto integrated gate.

The forward construction now includes one full 43,904-word candidate,
canonical from fixed typed validity alone, exact dense and same-schedule
stable/hash blocks, all five dense nonlinear roots, seven actual sparse
reconstruction residuals, 15,561 actual raw replication residuals, 1,920
actual Merkle CSR residuals, 64 policy-initial CSR attempts, 26 stable
selector/inverse/Boolean/radix roots, all early/balance/inline/multiplication
roots and all 332 generated hash roots.
The partial hash-root program has derived successful interpreter execution
on the unchanged full expression DAG. The ideal batch-trace probability law
is constructed separately. These are named constructions with derived
properties, not populated adequacy receipts. The additional 496 stable-tail
and 448 inactive-Merkle-right CSR attempts and 145 authorization roots now
first leave 2,109 raw CSR attempts and 197 nonlinear positions 252..448.
The next 439 CSR attempts and 100 authorization roots reduce the remaining
counts to 1,670 and 97 respectively. The next 210 actual role-CSR residuals
first reduce those counts to 1,460 and 97. The final 97-root authorization
packet and indexed composition now establish all 830 nonlinear roots and
successful actual nonlinear interpreter execution. Another 28 digest-copy
CSR attempts first leave 1,432; the 192 inline-policy copy and padding
attempts first reduce that to 1,240. The next 354 dense/base/key and
authorization-initial equations first reduce the gap to 886. The next
290 note/nullifier/public-digest equations reduce it to 596. Another 332
stablecoin frame, path and public-output equations reduce it to 264. The next
90 range and padding equations reduce it to 174. Actual Rust execution, complete CSR execution
and full packed acceptance remain active.

The prior commits establish local mathematical ingredients, not either
endpoint. This continuation explicitly retains the unfinished complete proof as
the acceptance condition. Record subsequent validation and substantive
obstructions here; never populate a receipt with the desired conclusion.

The 1,767-declaration combined gate now passes with unchanged wire vectors.
Its retained increment contains 14 integrated source modules and 265 added
audited declarations, with exact source migration and 268 byte-verified
evidence payloads. It completes nonlinear source execution, not the full
security or production objective. Parent review rejected the first dense-
padding draft's confusion between packed addresses and coefficient-node
indices; the replacement uses the actual dense-constructor padding readback.
It and seven further modules are now strict-qualified with 95 declarations
and 354 actual CSR attempts. The 1,862-declaration integration gate passes
all 3,095 jobs, exact audits and unchanged vectors; 291 evidence payloads
are retained byte-identically with an exact copy manifest.
The next 290 equations are strictly qualified in 21 modules with 134
audited declarations and exact import-only migration. Their source digest
proofs construct the full note/nullifier sponges and 32-step Merkle fold
from typed validity, rather than reversing an acceptance theorem. The
1,996-declaration integration gate passes all 3,116 jobs, exact axiom
audits and unchanged vectors; 558 evidence payloads are retained with
hash-verified copies. No production
capability, runtime program or wire bytes change in this increment.

The following 332-equation stablecoin increment is strict-qualified and
exactly migrated with 87 new declarations. It derives all configuration,
leaf, state-path and issuer frames and their public/private digest bindings.
The 2,083-declaration integration gate passes all 3,131 jobs, exact axiom
audits and unchanged vectors. Its 533 retained payloads pass independent
byte-size and hash readback. The remaining 264 equations
are numeric/range families at that checkpoint, not a complete-interpreter
or release claim. The following 90-equation range packet now passes strict
qualification, exact ten-module migration and the 2,129-declaration complete
gate. Its 222 evidence payloads pass independent exact-set, size and hash
readback. Coverage is 20,431/20,605, with only globals `20320..20493` still
open. This does not close actual CSR execution, packed acceptance, Rust
refinement or either complete security endpoint.

The final report for `4a0acb9b` incorrectly led with "Completed". It completed
a local repair checkpoint only. Empty Lean receipt types deliberately prevent
unsupported claims; proving those types uninhabited does not establish that
the protocol's mathematical security statements are false or impossible to
prove. Neither those sentinels nor previously invented operational restrictions
are a reason to stop the authorized endpoint work.

## Context and Orientation

The active geometry is 686 witness rows, 368 columns, 120 public words,
five DECS rows over 140 committed data rows, degree 387, a 2^23-point Goldilocks
coset and twenty DECS openings. The PIOP has five repetitions and six openings.
The proof maximum remains 122,863 bytes.

`SmallWoodV8Smz9HonestHybrid.lean` establishes the earlier DECS-mask translation.
`SmallWoodV8Smz9HiddenLeafQrom.lean` supplies exact leaf framing and physical
oracle-domain operations. `SmallWoodV8Smz9SingleProofPrivacy.lean` contains the
source-shaped LVCS opening law. `SmallWoodV8Smz9JointQuerySampling.lean` counts
actual independent twenty-subset queries. The packed semantic obligations are
in `formal/lean/Hegemon/Transaction/Poseidon2V8SemanticAdequacy.lean`; that receipt
is currently uninhabited.

## Plan of Work

The current raw CSR gap is the inclusive index range `20320..20493` (174),
disjoint from the 20,431 derived attempts. The 66 range-reconstruction and
24 high-limb padding equations are now strictly qualified and migrated.
The remaining equations contain stablecoin numeric helpers. The exact parsed
program and source-module anchors are recorded in
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-2129-672254cd2af528ad/integration/CSR-REMAINDER-174.json`,
with SHA-256 `1c0692a7d66d4eb2ffde1af628dbceac53fad8ab5cb78b5bea27dd9f17e6ec1a`.
The prior 1,240-, 886-, 596- and 264-gap inventories remain retained for their checkpoints.
Descriptor names are navigation aids, not satisfaction evidence. Derive
actual residuals from the unchanged constructor, qualify each packet, then
compose complete CSR execution and packed acceptance; do not confuse this
arithmetic inventory with either endpoint.

The privacy author owns new `formal/crypto/HegemonCrypto/SmallWoodV8Smz9EagerPrivacy.lean`
and `docs/crypto/smz9-campaign/eager-privacy-proof.md`. Derive the joint mask
bijection using the actual dimensions and then compose generated view laws.

The physical-oracle author owns new `SmallWoodV8Smz9HiddenPatch.lean` and
`hidden-patch-proof.md` in those respective directories. Define complex-linear
query operations, derive support and distance bounds, and prove their tape
specialization. An arbitrary norm-preserving nonlinear operation is forbidden.

The recovery researcher owns `weighted-mca-research.md` in the dossier and
attacks the concrete sample-weighted coefficient bound. The coordinator owns
`SmallWoodV8Smz9McaRecovery.lean`, defining polynomial agreement and proving the
reverse recovery and finite sampling reductions without a source-cover premise.

The semantic author owns new `SmallWoodV8Smz9SemanticBinding.lean` and
`semantic-adequacy-proof.md`. Trace actual accepted expression/linear constraints
to universal typed properties and construct genuine witnesses to the refinement
obligations. An executable check run only by the honest prover is not verifier
enforcement.

The native carrier lane owns `node/src/native/poseidon2_v8_verifier.rs`, its
included `poseidon2_v8_carrier_tests.rs`, and the narrowly test-gated service
hooks. Finish the parent driver that starts the actual service in separate
processes, submits the wallet request over HTTP, waits for authenticated PQ
peer relay, mines the exact stored pending action, restarts the relay on its
same database and identity, and synchronizes an empty third database through
real locator/body messages. Control messages may inspect state or mine only
the fixed fixture coinbases/current pending proof; they may not import or
stage supplied block/action bytes. Run the primary and independent retained
proofs as separate episodes because they spend identical notes.

After all inventory-covered changes pass their gates, freeze the source and
HEAD, independently build the two generators, generate a new proof pair, and
seal a new candidate manifest without modifying historical artifacts or the
fixed pointer. The constructor must recompute live source inventory before
and after the carrier run; the native artifact loader alone does not do that.

## Concrete Steps

Read the corresponding existing modules before editing. Use `apply_patch` and
distinct temporary output directories. Direct checks from `formal/crypto` use:

    lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/NEW_MODULE.lean

The coordinator integrates frozen, independently reviewed files and runs:

    bash scripts/check_formal_crypto.sh
    python3 -B scripts/smz9_joint_acceptance_probe.py --self-test
    python3 -B scripts/smz9_hidden_leaf_qrom_screen.py --self-test
    git diff --check

Monitor actual resource use while running the gate. Do not turn a discretionary
free-space target into a reason to stop bounded proof checks. Stage only
explicit owned paths after successful current validation.

## Validation and Acceptance

Every new theorem must compile under the existing strict policy, use only the
permitted kernel axioms, and survive independent quantifier/source review.
Wire vectors and the 48 generated program modules must remain unchanged.
Numerical probes test arithmetic and small instances; they cannot certify the
current-field research bound or replace a proof of the defined experiment.

Final acceptance additionally requires generated real/simulated quantum games,
an efficient extractor operating on actual accepted bytes, proved semantic
adequacy, and a composed resource-bound result meeting the security contract.
Explicit primitive and implementation assumptions must not disguise an
unproved protocol lemma. Passing the local gate is necessary, not sufficient.

## Idempotence and Recovery

Keep prior committed sources and retained evidence. Control resource-intensive
operations to avoid exhausting disk while continuing safe proof work. Do not
reset unrelated edits. No authority flag changes as a side effect of testing.

## Artifacts and Notes

Record exact newly checked roots, commands, results and commit identifiers
after each integration. Research derivations remain labeled until their
statements and intended game instantiations are verified.

At 16:15 UTC, strict module checks and coordinator cached builds have passed
for EagerPrivacy, HiddenPatch, SemanticBinding, SemanticDenseRange,
PiopOpeningRecovery, PrivacyGameComposition, McaRecovery, EagerSimulator, and
PiopSoundness. The largest completed central build reported 2,658 jobs; this
is not the complete integrated crypto gate. All endpoint axiom inventories
returned so far contain only `propext`, `Classical.choice`, and `Quot.sound`.
No local commit has yet been made for this continuation.

Additional exclusive lanes now own McaDecoder (coordinator), SemanticDecoder
(semantic author), ProgramPolynomials (semantic constraint author),
CurrentProgramPiop (privacy author), and EagerOracleGame (physical-oracle
author). A separate read-only quantum-extraction bridge review traces the
required source extraction and raw-oracle schedule. The numerical MCA lane
has checked the weighted bound through global quotient dimension four using
finite incidence and a primary-source list-correlated-agreement theorem;
dimensions five and six remain open. That research deduction is not a Lean
certificate and does not establish the general constant.

Historical interruption at approximately 16:18 UTC: the coordinator stopped
new checks at 39.445 GiB free based on an invented 40 GiB threshold. The user
explicitly corrected that error at approximately 16:27 UTC. Work resumed;
only two independently verified unused incremental Cargo caches were removed
(about 560 MiB, reproducible from source). See the disk-maintenance record.
There is no 40 GiB stop condition. Per-process memory limits and small
certificate chunks are used where an actual oversized elaboration is found.

At about 18:11 UTC, the root-owned CurrentSourceAcceptance module passed
strict Lean. Its complete decoded-candidate-to-packed-acceptance theorem does
not take evaluator success or decoded witness validity as an assumption. It
uses the source's unconditional zero-coordinate attempt 19262 to eliminate
the impossible-empty normalized CSR case. The full balance endpoint passed
strict Lean independently; both await current-base cache/axiom integration.

A third independent semantic-target mismatch was verified against actual
hash-schedule lines 965–981, CSR lines 1405–1422, and the single-key public
shape validator: V8AuthorizationValid always selected input zero's key even
when only input one was active. The coordinator corrected the target to the
source's first-active key selection (four zeros if neither is active) and
added three strict-passing regression lemmas. No Rust/wire behavior changed.
Refresh the base caches, affected theorem inventory, semantic-source digest,
blueprint content hashes and relevant gates before the next local commit.

At approximately 16:46 UTC, the complete crypto gate passed: 2,770 jobs,
207 credited declarations under the standard axiom allowlist, unchanged wire
vectors, and all 48 generated HGV8RP03 files (2,263,766 bytes). This includes
the completed EagerOracleGame comparison, CurrentProgramPiop and actual
McaSourceBinding. The base formal Lean stage checked all 2,745 claimed
theorems: 1,198 axiom-free and 1,547 standard-axiom-dependent, no violations.
The corrected public-admission domain and padding constant passed the relevant
generated semantic vectors. The source-content digest was refreshed, not its
authority/status. Fourteen governance tests and the active-goal check passed.

At approximately 17:13 UTC, four further frozen modules have passed independent
source review and cached checks: CurrentProgramOpeningBinding (actual PCS and
all-index source rows), CurrentPrivacyGame (actual finite randomized-label
source/reference experiments), SemanticAssetMembership (actual root constraints
to typed selectors), and CoherentMerkleGeometry (exact framed raw input and
classical insertion instability). Their 17 added roots bring the proposed
integrated inventory to 224; the next whole crypto gate is still required.
RandomDirectionRecovery has separately proved the factor-free finite numerator
bound; its exact probability/source adapter is in progress and not yet credited.

Subsequent integration passed: 2,776 jobs, 237 credited declarations under the
standard kernel-axiom allowlist, unchanged wire vectors and all 48 generated
program files. This adds the complete exact source-layout random-direction
probability bound and the literal raw-counter compiler to the preceding four
modules. The 11-test joint-acceptance probe and three-test hidden-leaf arithmetic
screen also pass. No runtime protocol or production-authority predicate changed.
Unfrozen CoherentMerkleInstrument, CurrentPublicContext, CappedRawSampler,
SemanticCanonicalWitness, SemanticCryptographicLinks and current unrestricted
MCA research remain outside this integration and outside the local checkpoint.

The public CSR binding then exposed a source gamma-count error before landing
at the pre-repair checkpoint:
`derive_gamma_prime` uses five times the maximum of nonlinear and retained
linear counts, not five times 830. The 15,561 raw-replication rows already
exceed 830; that program's upper bound was 20,569 attempts.
The old 4,150-word RawCounterCompiler numerical facts remain true only as
examples and are renamed as such. The historical corrected conditional cap was
9,730–12,860 blocks. After
the successor relation added 36 canonical padding attempts, the current upper
bound is 20,605 attempts and the current conditional cap is 9,730–12,883
blocks. The generic two-query law remains valid, with larger workspace. Recheck
the modified compiler and integrated inventory before committing this
checkpoint.

The corrected compiler and its added cap endpoint now pass the full gate:
2,776 jobs and 238 allowed-axiom declarations, unchanged wire/generated
program artifacts. All previously frozen files remain unchanged except the
explicit gamma-count correction described above.

The refreshed full policy run passed the dependency audit, formal inventory,
six system-model gates, 121 claims, 121-node blueprint (all nodes still pending
independent external review), and two bridge vectors. Step 12 then failed at
the unchanged `validate_review_bundle_contract` in superneo-bench: production
BLAKE2b-384 support is absent, so the existing guard refuses legacy Poseidon
review bundles. Both that source and the gate script are unchanged from HEAD.
Steps 13/14 were not reached by this run. Preserve the refusal and do not
misreport the whole policy script as passing. This does not block independent
SMZ9 mathematics or authorize changes to production capability.

The substantive mathematical blockers remain:
the unrestricted weighted line budget (quotient dimensions five and six),
coherent current-profile Merkle substitution with explicit raw-oracle loss,
and full typed semantic adequacy. The research cannot substitute a classical
measured database for a commitment that may first appear inside a coherent
Fiat--Shamir query. No complete security theorem or production authority has
been constructed by this continuation.

At approximately 17:39 UTC the reviewed 238-root checkpoint landed locally as
`9f3e8aea` (58 files). It was not pushed or deployed. The three pre-existing
instruction/skill edits were excluded. The full unchanged canonical-witness
predicate has subsequently passed strict checks and its seven principal
standard-axiom audits; it is no longer an open semantic-shape obligation.
CurrentPublicContext and CoherentMerkleInstrument also passed source review
and central cache builds and are being added to the next integrated inventory.

The coordinator owns the new DecodedPolynomialSource module and its dossier:
arbitrary calculated DECS rows now produce exact source heads, degree-69
witness columns, degree-488/132 masks, canonical packed evaluations, and a
current unbatched PIOP candidate built from all actual nonlinear roots and
retained public CSR rows. The full module passed strict Lean at about 17:49
UTC. Its finite soundness endpoint is `p^-5 + epsilon3` for failure of the
explicit generated normalized source relation. Accepted-byte opening binding
and the normalized-relation/interpreter converse are still separate work.

The full coherent multi-answer Partition commutator also passed strict Lean:
the proved conservative constant is `192 I`, giving `576t/2^512` for the
actual raw source partition, with arbitrary superposed target/answer/workspace
and no target-count factor. This does not silently adopt the sharper external
`80 I` or claim an efficient answer encoding. Its source review is complete;
central caching and axiom integration are next.

Actual aggregate memory pressure was observed at about 17:48 UTC with seven
simultaneous bounded Lean checks and over 11 GiB of compressed memory. The
coordinator reduced verification to at most two global processes. Other lanes
continue source work, with serialized check grants. This is a measured RAM
constraint, not the withdrawn free-disk cutoff. No source or retained artifact
was lost. Interpolation's central cache passed 1,861 jobs and is available to
the actual integer-balance lane.

At approximately 18:31 UTC the hash dependency and root certificates and their
arbitrary-acceptance source replay passed central caches (1,863 jobs). The local
Poseidon2 templates and complete 31-step composition also passed (1,649 jobs),
with all sixteen output lanes related to the pinned kernel. Actual generated
DAG instantiation is the next checked boundary. The 466-line authorization
prefix separately passed strict Lean for single-key zeros, approval/final
activity, shared opening fields, and final-next accumulator zeros; the full
authorization predicate is not yet proved.

The coordinator owns new `SmallWoodV8Smz9CurrentSourceAcceptance.lean` and
`current-source-acceptance-proof.md`, including all interpreter Option paths,
the independently forced normalized-CSR fallback zero, and canonical field
lifting. It passed strict Lean before the later authorization-specification
correction; cache refresh and integrated audits remain necessary.

The coordinator also owns new `SmallWoodV8Smz9PiopReconstruction.lean` and
`piop-reconstruction-proof.md`: construct the actual six-point restore and
linear correction from the transmitted 483/126 high coefficients, then relate
the reconstructed 489/132 hash transcript to the current candidate equations.
This does not assume that a post-opening reconstructed transcript was already
fixed before the opening challenge. That hash/chronology binding and the
decoded PCS evaluation-trace binding remain explicit separate obligations.

The capped sampler's maximum-size gamma case is not its uniform worst case:
capacity minus requested count plus one varies between 33 and 40. For example,
102,840 requested words have 102,872 candidates and rejection threshold 33,
whereas 102,845 words have threshold 36. The numerical tail follow-up therefore
uses threshold 33 and capacity at most 102,880 for the all-public-context bound.

## Interfaces and Dependencies

At approximately 19:18 UTC the integrated crypto gate passed 2,797 jobs and
audited 308 designated declarations against the existing kernel-axiom allowlist.
That historical checkpoint was superseded at approximately 21:38 UTC: the
complete repaired-relation gate passed 2,806 jobs and all 376 credited
declarations, with the same allowed axiom sets, three unchanged wire-vector
files, and exact agreement across 48 generated modules totaling 2,266,857
source bytes. Newly integrated endpoints include the actual packed-to-integer
balance proof, accepted hash-call equality to the pinned Poseidon2 permutation,
current decoded-candidate-to-interpreter acceptance, exact six-opening PIOP
reconstruction, executed chronological privacy comparison, literal capped byte
sampler, coherent vector extraction, bounded trace codec, disabled stable
transition, and bounded enabled-stable arithmetic. These are intermediate
mathematical results; the complete security contract remains unproved and
production unauthorized.

The source-to-sponge obstruction was confirmed by an active-output
countermodel against the historical 852,305-byte relation. The repaired source
now distinguishes explicit in-range private holes from out-of-range padding and
binds all 36 missing padding attempts. A focused regression preserves the
private-hole behavior. This changes the executable relation to 853,429 bytes and
SHA-512 `180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`;
historical proofs cannot be reused.

The enabled-stable completeness mismatch was also confirmed and repaired at the
typed/public admission boundary: mint and burn now require the stable asset
exactly once in the canonical balance list, matching packed root 1042. The old
asset-1001 burn remains historical counterexample evidence, not a counterexample
to the repaired relation. Integrated stablecoin lemmas prove the disabled full
transition and bounded enabled arithmetic/coordinate consequences; full enabled
policy, collateral, epoch/mint-base, and hash composition remain open.

User correction (2026-09-07, approximately 16:27 UTC): the 40 GiB cutoff was
invented by the coordinator, not imposed by the user. Its earlier description
as mandatory was incorrect. The user explicitly authorizes managing disk space
to sustain proof production and directs immediate continued work. Bounded warm
Lean builds/checks have resumed at about 39.45 GiB free; verified disposable-cache
reclamation runs independently. No proof obligation or production acceptance
condition is relaxed. CurrentProgramPiop has since passed its strict check and
eight standard-axiom audits; the actual-program adapter is no longer unverified.

Use existing polynomial, finite-field, finite-PMF and complex-linear operator
interfaces. Mathematical events may have explicit hypotheses defining local
agreement or physical adversary behavior; no interface may assume the whole
privacy distance, extraction success or final soundness probability it claims
to establish. No new dependency or primitive is permitted.

Revision note (2026-09-07): retained the complete security proof as the endpoint
after the user's correction; added exclusive implementation lanes for the new
whole-argument constructions and their remaining universal obligations.

Revision note (2026-09-08 01:45 UTC): record the checked mixed-write compiler,
exact chronological-prefix query/program budgets, strengthened block-context
carrier evidence, and the independently detected map-snapshot correction.
The source is not yet frozen and no fresh socket-lifecycle pass is claimed.

Revision note (2026-09-08 02:06 UTC): record the complete 603-root gate, the
byte-level physical privacy and source query/path endpoints, and the final
isolated-carrier containment and checker-pin corrections. Prior timestamps
remain historical checkpoints, not current source-inventory authorization.

Revision note (2026-09-08 02:30 UTC): record the measured prior-history
lifting and operational witness-free byte program, exact source/public
query accounting, eleven native controls and reviewed fresh-generation
wrapper corrections. Final source-stage and lifetime composition remain active.

Revision note (2026-09-08 04:21 UTC): record the completed modeled lifetime
endpoint, the independently reproduced recovery-cursor caller bug and scoped
fix, and the finite additive-local-rank obstruction. Retain the separate
concrete security and actual-socket acceptance requirements.

Revision note (2026-09-08 05:47 UTC): integrate constructive dense/hash
components and the exact finite ideal batch law, record the missing typed
schedule and full generated-equation links, and keep the isolated translator
dependency installation bounded and distinct from a reviewed translator fix.

Revision note (2026-09-08 06:11 UTC): integrate the typed prefix, concrete
seven-residual dense composition and exact forward hash-root/evaluator
component; preserve full packed acceptance and actual source refinement as
remaining obligations. Record the completed 852-root central gate at 06:15 UTC.

Revision note (2026-09-08 06:58 UTC): record the canonical typed source
prefix, full stable-tail construction and 1,005-root central gate, preserving
the explicit remaining canonicality/equation and actual-Rust boundaries.

Revision note (2026-09-08 07:33 UTC): retain the full typed candidate,
15,561-entry raw replication proof and 1,100-root central checkpoint.
Preserve the remaining 5,037 CSR/493 nonlinear and native-refinement gaps.
Record the legal large-gcd counterfamily and sharp affine-family charge
without claiming a universal cover or completed weighted soundness bound.

Revision note (2026-09-08 07:50 UTC): retain the 1,163-root checkpoint,
1,920 actual Merkle CSR and 26 stable-root increment, and reviewed
zero-stress/capped-cover mathematics. Record the metadata ordering defect
without changing the pinned executable relation. Complete the bounded
translator instrumentation run, preserving the failed sandbox attempt and
isolating any later semantic correction from this diagnostic evidence.

Revision note (2026-09-08 09:09 UTC): retain the reviewed twelve-module
increment and complete 1,356-root gate, with 18,496 actual CSR attempts and
633 nonlinear roots derived from the fixed full source candidate. Preserve
the remaining 2,109 CSR and 197 authorization positions as open. Record
the corrected native translator fixture's successful normal/checks replay
without treating generated Lean output as an already checked evaluator
theorem or relabeling earlier failed runs.

Revision note (2026-09-08): preserve the completed 1,472-declaration gate
before any descriptor-identity correction. Record the actual remaining
1,670 CSR/97 nonlinear obligations and the separately successful generated
native Lean compilation; keep the unrun body proof and security endpoints
open. The user requires lightweight or medium-effort agents and bounded
work: this follow-up uses one Luna/medium worker for bounded review and one
exclusively assigned test-file edit, no child agents,
serial focused checks, and a stop at 5 percent reported weekly usage.

Revision note (2026-09-08 19:27 UTC): retain strict qualification of the
final 97 nonlinear roots, all-830 composition, actual complete nonlinear
interpreter execution and 28 digest-copy CSR attempts. Record exact source
migration and the running 1,752-declaration gate. Keep the remaining 1,432
CSR attempts and all downstream runtime/security/authorization gaps open.

Revision note (2026-09-08 19:49 UTC): record the declaration-list heading
failure without crediting the first full gate. Remove the heading, integrate
the newly strict-qualified 192 inline-policy attempts, and rerun the complete
1,767-declaration gate. Current source coverage leaves 1,240 raw CSR attempts;
neither the closed nonlinear interpreter nor constructor copy equations
authorize a security or production claim.

Revision note (2026-09-08 19:57 UTC): record the successful 3,087-job,
1,767-declaration combined gate, unchanged vectors and byte-verified evidence
archive. Preserve the failed first gate and wrong-domain dense draft as
uncredited work. Production authority remains absent.

Revision note (2026-09-08 20:54 UTC): integrate eight strict-qualified
modules adding 354 actual CSR attempts and 95 audited declarations. Record
all four exact receipts, postflight, failed draft/control evidence and the
running combined gate. Replace the obsolete dense-draft next step with the
exact remaining 886-equation inventory and note-initial construction work.

Revision note (2026-09-08 21:02 UTC): record the complete 1,862-declaration
gate and exact 291-file retained increment. Keep all prior failed evidence,
source-freeze identities and production barriers unchanged. Begin isolated
note-frame drafts without counting them toward integrated coverage.

Revision note (2026-09-08): integrate the strictly qualified note-216,
nullifier-32 and public-digest-42 packets. Record exact forward digest
bindings, the 596-equation disjoint inventory and the completed combined
1,996-declaration gate with 558 exact retained payloads. Preserve all prior
snapshots and failed evidence. Continue with stablecoin source equations;
the formal increment does not authorize production.

Revision note (2026-09-08 22:25 UTC): record three isolated, independently
reviewed strict packets for 304 stablecoin equations. Keep the committed
1,996-declaration checkpoint separate from scratch qualification. Reject
the first issuer draft's incorrect commitment capacity words; the reviewed
replacement derives both actual domains and markers from source frames.
For range reconstruction, preserve the top Boolean for odd widths rather
than assuming a stronger bound that drops that bit. Next complete the 28
public stable digest bindings and then the 264 numeric/range equations.

Revision note (2026-09-08): complete the 28 public digest bindings and
exactly migrate the combined 332-equation increment. Record the four
strict receipts and independent postflight/review, update the disjoint
gap to 264, and record the completed 2,083-declaration full gate and exact
533-payload archive separately from production authority.

Revision note (2026-09-08): strictly qualify and migrate the next 90 range
and high-limb padding equations. Derive all widths from typed/source bounds,
preserve odd top bits, reject incorrect padding coordinates, and use bounded
generated-chunk membership after a whole-table development check reaches the
unchanged compiler memory cap. Record the new 174-equation disjoint gap and
record the completed 2,129-declaration integration gate and exact 222-file
evidence archive after the actual audit and vector results pass.
