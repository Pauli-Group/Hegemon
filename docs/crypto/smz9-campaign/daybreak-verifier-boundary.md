# Historical Daybreak verifier boundary: pre-repair HGV8RP03-format program versus canonical typed lowering

## Scope and lineage

This dossier records the verifier boundary of the historical 852,305-byte
program at SHA-512
`8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e46a8b7cadc557dba4a1e4ccdfe572e5b2833879dd465079b12b6044a51a5612c3`.
`HGV8RP03` is the eight-byte format magic shared by that program and its repaired
successor; it is a lineage marker, not a relation identity. The current program
is instead 853,429 bytes at SHA-512
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`,
with relation id
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984`.
That repaired program is outside the source snapshot audited below. No retained
proof or lifecycle receipt exists for its digest, and production remains
disabled.

## Verdict

The independent profile-6 SMZ9 candidate verifier in this pre-repair snapshot
did **not** enforce the full canonical typed-lowering guard. It reconstructed the
source-owned adapter from the public statement and verified the proof against
that adapter's specialized CSR plus nonlinear expression DAG. The canonical
packed-to-typed decode/re-lower/equality check ran on an honest full witness
during compilation, but the proof verifier never possessed that full witness
and never called it.

This was fail-closed at the audited product boundary and remains fail-closed:
the protocol production capability is `None`, and the native source binding
rejects absent or inactive capability before a production verifier can be
constructed. The historical defect therefore blocked safe authorization; it was
not evidence of a reachable production inflation path.

## Historical enforcement map

The source locations below identify the audited pre-repair snapshot. They are
retained as evidence and are not a claim that the repaired successor has the
same omission.

| Boundary | Enforced | Not enforced |
| --- | --- | --- |
| Honest typed compilation | `compile_smallwood_poseidon2_v8_relation` builds the canonical assignment and calls `adapter.verify_packed_witness` (`smallwood_poseidon2_v8_semantics.rs:4283-4291`). That method checks field canonicality, every specialized CSR row, every nonlinear expression root, and finally `verify_canonical_smallwood_poseidon2_v8_typed_lowering` (`:4106-4171`). The final guard decodes the packed witness, rebuilds the typed assignment, and compares every word (`:3900-3913`). | This is prover-side/full-witness checking, not an accepted-proof verifier check. |
| Candidate relation construction | The source-only factory reconstructs the typed public statement and `SmallwoodPoseidon2V8ConstraintAdapter` (`smallwood_poseidon2_v8_frontend.rs:185-218`), while the public verifier seam prevents caller-supplied relation authority (`:1027-1051`). | `from_public_statement` has no private packed witness, so it cannot decode or compare a typed lowering. |
| Candidate SMZ9 verification | The frontend checks input/relation identity, wire and size, then calls the accepted-proof refinement (`smallwood_poseidon2_v8_frontend.rs:1004-1024`). That refinement canonical-decodes the **proof wire**, rebuilds an accepting trace, calls the production verifier, and checks honest-map shape (`smallwood_poseidon2_v8_zk_refinement.rs:607-678`). The engine checks profile/domain/config, derives opened row scalars, recomputes PCS and PIOP transcripts, and accepts on transcript-hash equality (`smallwood_engine.rs:5256-5300`, `:5303-5404`). PIOP evaluation asks the adapter for nonlinear evaluations and effective linear targets (`:10049-10158`); the adapter supplies only `evaluate_all_constraints` over row scalars plus its specialized CSR (`smallwood_poseidon2_v8_semantics.rs:4175-4264`). | Neither the frontend refinement nor engine calls `verify_packed_witness` or `verify_canonical_smallwood_poseidon2_v8_typed_lowering`. Canonical proof-byte decoding is not canonical private-witness lowering. Opened evaluations are not the complete 43,904-word witness. |
| Native leaf verification | Exact leaf/context/ciphertext parsing precedes candidate verification; native reconstructs the public input and invokes `verify_smallwood_poseidon2_v8_candidate` (`node/src/native/poseidon2_v8_verifier.rs:680-726`). | The native caller adds public/context checks but has no complete private witness and adds no packed-to-typed projection check. |
| Production authority | `smallwood_poseidon2_production_capability()` returns `None` (`protocol/versioning/src/lib.rs:502-505`). Native `from_source_at` returns no binding and `require_source_at` fails (`node/src/native/poseidon2_v8_verifier.rs:486-505`). | Passing the candidate verifier cannot substitute for the absent capability. |

## Padding omission

`bind_sponge` calculates the number of calls from the declared input length. For
each rate lane it uses
`inputs.get(input_index).and_then(Clone::clone)`; both an explicit `None` inside
the vector and an index beyond the final vector element reach the same branch
(`smallwood_poseidon2_v8_semantics.rs:1203-1227`). On later blocks that branch
emits no rate-lane equation and describes the omitted word as private. This is
appropriate for deliberately private holes represented by in-range `None`, but
not automatically for nonexistent tail words. A nonexistent final-rate input can
therefore behave as an additional private absorbed word rather than the canonical
padding/chaining value.

The typed compiler's final equality comparison caught such drift for the
canonical assignment it built. The independent proof verifier did not: it
checked only the relation encoded by the CSR and nonlinear DAG. Consequently
that historical source did not establish the theorem

> every packed witness accepted under the historical relation id
> `8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e46a8b7cadc557dba4a1e4ccdfe572e5b2`
> decodes to, and equals the canonical lowering of, a valid typed witness.

That was an exact packed-to-typed projection/refinement obstruction. It must not
be silently promoted to a complete existential-knowledge break: a concrete
security claim additionally needed either an accepting noncanonical witness for
that historical relation (and, for an executable exploit, a corresponding proof
under the cryptographic assumptions) or a theorem that one existed. The
separately owned synthetic padding regression was the right place to settle that
existence question.

Conversely, proof-system knowledge soundness for **that historical program**
would not have closed the product claim. It would yield knowledge of a witness
for its encoded CSR/DAG relation. If that relation admitted a noncanonical
padding witness, it would not yield knowledge of a witness for the intended
canonical typed relation.

## Separate completeness counterexample

The checked `SmallWoodV8Smz9SemanticCompletenessCounterexample.lean` dossier
established the opposite-direction mismatch in the same historical lineage for
a concrete burn: the unchanged typed target accepted stable asset `1001` while
the public balance list omitted it, but generated nonlinear root 1042 evaluated
to `1001`, so every packed witness was rejected. That was semantic-to-packed
**completeness** failure and rejected the transaction; it was not inflation, not
verifier over-acceptance, and not evidence for the padding witness-existence
question. The two mismatches jointly showed that the typed semantics and that
pre-repair relation could not be treated as one relation. This dossier does not
re-audit the repaired successor.

## Historical repair choices and current disposition

1. **Correct the executable relation (the selected repair).** Split
   `bind_sponge`'s cases: retain in-range `Some(None)` as an intentional private
   absorbed word, but constrain `input_index >= inputs.len()` to the canonical
   zero/padding-and-chaining value. The current 853,429-byte successor implements
   that source repair and has a new digest and relation id despite retaining the
   HGV8RP03 format magic. Its CSR/program and vectors were regenerated, but fresh
   proofs, retained artifacts, the full lifecycle, transport receipts, and
   accepted-proof projection still require evidence for the repaired digest. Old
   proofs cannot acquire authority under the new relation.

2. **Change the typed relation to match the extra private tail words.** This is a
   semantic/protocol change, not a helper fix. It requires an explicit decision
   that those words are genuine witness inputs, typed representation and
   validation for them, cryptographic review of the altered sponge preimages,
   regenerated relation identity and proofs, and fresh release authority. It is
   inappropriate as an implicit compatibility patch.

3. **Add an outer verifier check without changing the proof relation.** The
   audited verifier could not do this because it lacked the full committed witness.
   Making enough witness data public/open, or adding a proof of canonical
   projection, changes the proof statement/protocol and needs a new relation or
   separately sound proof layer plus fresh authority. A prover-side call to
   `verify_packed_witness`, a retained-artifact receipt, or a cache flag is not a
   consensus check.

Independently, the historical stable-asset membership completeness disagreement
needed an authorized semantic choice: require an enabled stable asset in the
typed public balance list, or remove/alter the stronger membership root. The
current source took the former path, but this historical dossier does not supply
its proof, refinement, or release review. It should not be bundled conceptually
with the padding over-acceptance boundary.

## Claim boundary

Static source tracing established the missing verifier call and relation
distinction for the historical 852,305-byte program with high confidence. No
proof generation, synthetic witness, runtime test, node test, or cryptographic
soundness experiment was performed in that review. The repaired successor is a
different digest and was not re-audited here. Production remains denied by the
independent capability gate.
