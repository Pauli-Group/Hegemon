import SmzaRp05ExecutablePcsClosureStatement
import SmzaRp05ExecutableMerklePaths
import SmzaRp05ExecutablePcsClosureStages

/-!
# Source-order boundary for RP05 oracle calls

The checked `Program` has an actual order: the PCS opening hash drives the
q38 sampler before the Merkle core computes its root; root-seeded coefficient
sampling and `hash_fpp` follow; final transcript recomputation reads its hash
last. This file proves the final-read suffix from the ordinary Program log.
The physical CMS read trace is a separate key-list semantics, so this theorem
does not transport source-call order into physical role reads.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05OrderedPrequeryTrace

open SmzaRp05ExecutablePcsClosure (transcriptProgram verifierProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (finalInput finalize)
open SmzaRp05ExecutableMerkleVerifier (Oracle Log Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open V8SmzaOracleParser (RawDigest RawInput)
open HegemonCrypto.CanonicalBytes (Byte)

set_option autoImplicit false

/-- Bind records preserve source execution order: the left program's calls
are followed by the successful continuation's calls. -/
theorem record_bind_success_preserves_order {α β : Type}
    (oracle : Oracle) (program : Program α) (next : α → Program β)
    (value : α) (succeeded : program.eval oracle = some value) :
    (program.bind next).record oracle =
      (((next value).record oracle).1,
        ((program.record oracle).2 ++ ((next value).record oracle).2)) :=
  Program.record_bind_success oracle program next value succeeded

/-- The ordinary accepted verifier's recomputation read is the last call in
the source Program log. The prefix is exactly the actual transcript-program
log from the same oracle evaluation; the final value equals the existing
proof's `h_piop`. -/
theorem accepted_final_recomputation_is_ordered_suffix
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (binding : List Byte)
    (statementBinding : List Nat) (nonce : Fin (2 ^ 32))
    (wire : ExistingProofFieldView) (oracle : Oracle)
    (accepted : (verifierProgram ns dsl statement pending binding statementBinding
      nonce wire).eval oracle = some ()) :
    ∃ transcript priorLog,
      (transcriptProgram ns dsl statement pending binding statementBinding
        nonce wire).eval oracle = some transcript ∧
      transcript.pendingXofFailure = false ∧
      oracle (finalInput transcript) = wire.hPiop ∧
      ((verifierProgram ns dsl statement pending binding statementBinding
        nonce wire).record oracle).2 =
        priorLog ++ [(finalInput transcript, wire.hPiop)] := by
  obtain ⟨transcript, transcriptSuccess, clean, hashEqual, _member⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript
      ns dsl statement pending binding statementBinding nonce wire oracle accepted
  refine ⟨transcript, ((transcriptProgram ns dsl statement pending binding
    statementBinding nonce wire).record oracle).2, transcriptSuccess, clean,
    hashEqual, ?_⟩
  rw [SmzaRp05ExecutablePcsClosure.verifierProgram,
    Program.record_bind_success oracle
    (transcriptProgram ns dsl statement pending binding statementBinding nonce wire)
    (finalize wire.hPiop) transcript transcriptSuccess]
  simp [SmzaRp05ExecutableFinalVerifier.finalize_records, hashEqual]

/-- The source's stage object explicitly distinguishes the q38 query seed
(`openingDigest`) from the post-Merkle root that seeds coefficient sampling.
The q38 execution field is tied to the former; the post-Merkle execution
field is tied to the computed Merkle input. -/
theorem same_run_challenge_inputs
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool}
    {hPiop : RawDigest} {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire
      decs points salt binding statementBinding tapes paths oracle hashFpp finalPending) :
    SmzaRp05PcsWireProjection.decsOpeningInput hPiop 12 368 38 stages.heads
        wire.pcs.rcombiTails = some stages.openingInput ∧
      oracle stages.openingInput = stages.openingDigest ∧
      (SmzaRp05ExecutablePcsClosure.queryProgram pending stages.openingDigest).eval oracle =
        some (stages.indexes, stages.sampledPending) ∧
      (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns stages.merkleInput).eval
        oracle = some stages.post := by
  have digestRead : oracle stages.openingInput = stages.openingDigest := by
    simpa [SmzaRp05ExecutableMerkleVerifier.ask,
      SmzaRp05ExecutableMerkleVerifier.Program.eval] using stages.openingRead
  exact ⟨stages.openingBuilt, digestRead, stages.queryExecuted, stages.postExecuted⟩

end HegemonCrypto.SmallWood.SmzaRp05OrderedPrequeryTrace
