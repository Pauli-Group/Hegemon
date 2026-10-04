import SmzaRp05PhysicalAcceptedExecutionSuffix
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05CurrentAcceptedRoleSupport
import SmzaRp05CurrentResponseInputDecoder
import SmzaRp05CurrentAcceptedQuerySupport

/-! # Exact RP05 q38 pre-query log prefix

The PCS Program's source bind order is opening-hash read, q38 sampler, then
post-query reconstruction/Merkle/response hashing. This module exposes that
order as an exact record split for the same `PcsStages` oracle, so retained
preimages can be tested against the prefix that actually precedes q38.
Absence remains only a classical-log fact here; quantum freshness is a
separate event obligation.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPrequeryChronology

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaRp05ExecutablePcsClosure
  (pcsProgram queryProgram transcriptProgram canonicalOpening widths deltas
    nativeFiveMcaGate406 currentTwelveLvcsGate406)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableChallengeStage (postMerkleProgram)
open SmzaRp05PcsWireProjection (DecodedMiddleWire fieldWordsToGoldilocks)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.SmallWood (Goldilocks)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)

set_option autoImplicit false
noncomputable section

/-- The literal continuation after the q38 sample inside `pcsProgram`. -/
def afterQ38 (ns : Namespace) (wire : DecodedMiddleWire)
    (decs : DecodedDecsResponseFields) (points : List Goldilocks)
    (heads : List (List Goldilocks))
    (salt binding : List Byte) (statementBinding : List Nat)
    (tapes : List (List Byte)) (paths : List (List RawDigest)) :
    List Nat × Bool → Program (RawDigest × Bool)
  | (indexes, sampledPending) =>
      match SmzaRp05DecsPointProjection.fieldPoints 406 indexes with
      | none => .done none
      | some decsPoints =>
          match SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
              wire.pcs points decsPoints wire.rowScalars 64 widths deltas
              2 368 140 38 with
          | none => .done none
          | some rows =>
              if currentTwelveLvcsGate406 heads
                  (wire.pcs.rcombiTails.map fieldWordsToGoldilocks)
                  points decsPoints rows then
                match SmzaRp05PcsMerklePayload.makeMerkleInput salt binding
                    sampledPending indexes rows decs.maskingEvals tapes paths with
                | none => .done none
                | some input =>
                    (postMerkleProgram ns input).bind fun post =>
                      match SmzaRp05DecsResponseProjection.hashFppProgram post.root
                          decs (rows.map fun row => row.map
                            SmzaRp05ExecutableRestore.toWord)
                          (SmzaRp05PcsHashFppMiddle.gammaRows post)
                          (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                          140 368 statementBinding with
                      | none => .done none
                      | some hashProgram =>
                          match SmzaRp05DecsResponseProjection.restoredResponsePolynomials
                              decs (rows.map fun row => row.map
                                SmzaRp05ExecutableRestore.toWord)
                              (SmzaRp05PcsHashFppMiddle.gammaRows post)
                              (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                              140 368 with
                          | none => .done none
                          | some polynomials =>
                              if nativeFiveMcaGate406 salt tapes indexes
                                  (rows.map fun row => row.map
                                    SmzaRp05ExecutableRestore.toWord)
                                  (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                  decs.maskingEvals
                                  (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                                  polynomials then
                                hashProgram.bind fun digest =>
                                  .done (some (digest, post.pending))
                              else .done none
              else .done none

/-- The continuation after canonical opening in the source transcript. -/
def afterCanonicalOpening (ns : Namespace)
    (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (binding : List Byte) (statementBinding : List Nat)
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (middle : DecodedMiddleWire) (decs : DecodedDecsResponseFields)
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields) :
    V8Smz9PiopSoundness.Opening × Bool →
      Program SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript
  | (opening, openingPending) =>
      (pcsProgram ns openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop) decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points opening j)
        wire.salt binding statementBinding wire.tapes wire.paths).bind
        fun (hashFpp, pcsPending) =>
          (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
            pcsPending hashFpp).bind fun (matrix, finalPending) =>
              .done (some (SmzaRp05ExecutableReconstruction.reconstruct
                dsl statement matrix opening piop hashFpp finalPending))

/-- `pcsProgram` has exactly one verifier call before its q38 sampler: the
opening-input digest. The returned tail is the literal post-q38 continuation
record, not a caller-provided prefix or log. -/
theorem pcs_q38_record_split
    (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : DecodedMiddleWire) (decs : DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest)) (oracle : Oracle)
    (hashFpp : RawDigest) (finalPending : Bool)
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending) :
    ((pcsProgram ns pending hPiop wire decs points salt binding
      statementBinding tapes paths).record oracle).2 =
      [(stages.openingInput, stages.openingDigest)] ++
        (((queryProgram pending stages.openingDigest).record oracle).2 ++
        ((afterQ38 ns wire decs points stages.heads salt binding statementBinding
          tapes paths (stages.indexes, stages.sampledPending)).record oracle).2) := by
  have programForm : pcsProgram ns pending hPiop wire decs points salt binding
      statementBinding tapes paths =
    (ask stages.openingInput).bind fun openingDigest =>
      (queryProgram pending openingDigest).bind
        (afterQ38 ns wire decs points stages.heads salt binding statementBinding
          tapes paths) := by
    simp only [pcsProgram, stages.headsBuilt, stages.openingBuilt]
    apply congrArg (fun next => (ask stages.openingInput).bind next)
    funext openingDigest
    apply congrArg (fun next => (queryProgram pending openingDigest).bind next)
    funext sample
    rcases sample with ⟨indexes, sampledPending⟩
    rfl
  have openingOracle : oracle stages.openingInput = stages.openingDigest := by
    simpa [ask, Program.eval] using stages.openingRead
  rw [programForm,
    SmzaRp05ExecutableMerkleVerifier.Program.record_bind_success oracle
      (ask stages.openingInput)
      (fun openingDigest => (queryProgram pending openingDigest).bind
        (afterQ38 ns wire decs points stages.heads salt binding statementBinding tapes paths))
      stages.openingDigest stages.openingRead,
    SmzaRp05ExecutableMerkleVerifier.Program.record_bind_success oracle
      (queryProgram pending stages.openingDigest)
      (afterQ38 ns wire decs points stages.heads salt binding statementBinding tapes paths)
      (stages.indexes, stages.sampledPending) stages.queryExecuted]
  simp [ask, Program.record, openingOracle]

/-- Lift the PCS-local split to the complete transcript record. The prefix is
the actual `canonicalOpening` record followed by the PCS opening-input read;
the next segment is exactly the source q38 sampler record. -/
theorem transcript_q38_record_split
    (ns : Namespace) (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle) (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending) :
    ((transcriptProgram ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire).record oracle).2 =
      ((canonicalOpening pending nonce wire.hPiop).record oracle).2 ++
        [(pcs.openingInput, pcs.openingDigest)] ++
        ((queryProgram execution.openingPending pcs.openingDigest).record oracle).2 ++
        ((afterQ38 ns
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
          execution.decs
          (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
          pcs.heads wire.salt statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          wire.tapes wire.paths (pcs.indexes, pcs.sampledPending)).record oracle).2 ++
        ((SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
          execution.pcsPending execution.hashFpp).record oracle).2 := by
  have transcriptForm : transcriptProgram ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire =
    (canonicalOpening pending nonce wire.hPiop).bind
      (afterCanonicalOpening ns dsl statement statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire execution.middle execution.decs execution.piop) := by
    simp only [transcriptProgram, execution.decoded]
    apply congrArg (fun next => (canonicalOpening pending nonce wire.hPiop).bind next)
    funext openingPair
    rcases openingPair with ⟨opening, openingPending⟩
    rfl
  rw [transcriptForm,
    SmzaRp05ExecutableMerkleVerifier.Program.record_bind_success oracle
      (canonicalOpening pending nonce wire.hPiop)
      (afterCanonicalOpening ns dsl statement statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire execution.middle execution.decs execution.piop)
      (execution.opening, execution.openingPending) execution.openingExecuted]
  dsimp only [afterCanonicalOpening]
  rw [SmzaRp05ExecutableMerkleVerifier.Program.record_bind_success oracle
      (pcsProgram ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths)
      (fun pair : RawDigest × Bool =>
        (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement) pair.2 pair.1).bind
          fun (matrix, finalPending) =>
            .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
              matrix execution.opening execution.piop pair.1 finalPending)))
      (execution.hashFpp, execution.pcsPending) execution.pcsExecuted,
    pcs_q38_record_split ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs]
  rw [SmzaRp05ExecutableMerkleVerifier.Program.record_bind_success oracle
      (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
        execution.pcsPending execution.hashFpp)
      (fun pair : V8Smz9PiopSoundness.Matrix (dsl.width statement) × Bool =>
        .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
          pair.1 execution.opening execution.piop execution.hashFpp pair.2)))
      (execution.matrix, execution.finalPending) execution.matrixExecuted]
  simp [List.append_assoc, Program.record]

/-- The response-input trichotomy instantiated at the verifier's literal
pre-q38 prefix.  This prefix is derived from the same `ExecutionStages` and
`PcsStages`: canonical opening calls and the opening-input read occur before
the q38 sampler.  In particular, the retained-preimage arm is not supplied
by the caller.  The no-preimage arm remains only a classical record fact; it
does not assert quantum freshness or exclude a separate guess event. -/
theorem accepted_response_preimage_at_actual_q38_prefix
    (ns : Namespace) (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending) :
    let prequeryPrefix :=
      ((canonicalOpening pending nonce wire.hPiop).record oracle).2 ++
        [(pcs.openingInput, pcs.openingDigest)]
    ((transcriptProgram ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire).record oracle).2 =
        prequeryPrefix ++
          ((queryProgram execution.openingPending pcs.openingDigest).record oracle).2 ++
          ((afterQ38 ns
            (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
            execution.decs
            (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
            pcs.heads wire.salt statement.toBytes
            (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
            wire.tapes wire.paths (pcs.indexes, pcs.sampledPending)).record oracle).2 ++
          ((SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
            execution.pcsPending execution.hashFpp).record oracle).2 ∧
      ((¬ ∃ input, (input, execution.hashFpp) ∈ prequeryPrefix) ∨
        (¬ SmzaRecordedTracePath.RecordsCollisionFree
          ((prequeryPrefix ++ (pcs.hashProgram.record oracle).2).toFinset)) ∨
        (∃ pcsWords input, (input, execution.hashFpp) ∈ prequeryPrefix ∧
          SmzaRp05DecsResponseProjection.responseTranscriptWords pcs.post.root execution.decs
            (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
            (pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 = some pcsWords ∧
          SmzaRp05CurrentAcceptedRoleSupport.responseTranscriptInput pcs.post.root execution.decs
            (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
            (pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368
            (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement) =
              some input)) := by
  let prequeryPrefix :=
    ((canonicalOpening pending nonce wire.hPiop).record oracle).2 ++
      [(pcs.openingInput, pcs.openingDigest)]
  have ordered := transcript_q38_record_split ns dsl statement pending nonce wire
    oracle transcript execution pcs
  refine ⟨?_, ?_⟩
  · simpa [prequeryPrefix, List.append_assoc] using ordered
  · simpa [prequeryPrefix] using
      SmzaRp05CurrentAcceptedRoleSupport.accepted_stage_response_preimage_branch
        pcs prequeryPrefix

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentPrequeryChronology
