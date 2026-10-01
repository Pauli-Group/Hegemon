import SmzaRp05CurrentProofWireProgram
import SmzaRp05FinalProgramMiddleExecution
import SmzaRp05ExecutableMerklePaths
import SmzaRp05ExecutablePcsClosureMca406

/-!
# Same-state decoded PCS reconstruction and final verifier composition

This joins the existing proof-field decoder, head reconstruction, LVCS solve,
Merkle program, DECS restoration, PIOP coefficient sampler and reconstructed
final transcript. All middle values are calculated. The existing serialized
nonce is an input, not a new proof field. The canonical nonce scan retains
poison words and its pending state, checks that nonce, and repeats its field
sampling exactly as `canonical_piop_opening_points` does. DECS sampling also
retains pending failure instead of rejecting before the source finish guard.

Residual boundaries are explicit: the outer byte parser and profile/statement
binding are upstream; relation evaluation and typed opening decoding are still
the noncomputable mathematical definitions; Rust arithmetic/optimized
interpolation refinement remains unproved. This is a same-execution closure
of the mathematical program, not production soundness or Rust refinement.
The imported LVCS model uses the corrected augmented elimination (left-hand
factor on both halves). Its dimension checks and distinct-point check still
need to be discharged from successful outer decoding and derived points.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosure

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutableChallengeStage
  (FieldWord fieldXof fieldLoop returnedWords pendingFailure collectIndices)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05PcsWireProjection (DecodedMiddleWire)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript finalize finalInput)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open V8Smz9PiopSoundness (Opening)
open V8SmzaOracleParser (RawDigest)
open SmzaRp05DecsResponseProjection
  (FieldRow decodeFieldRow restoredResponsePolynomials)
open SmzaRp05ExecutablePcsClosureAlgebra (coefficientPolynomial)
open SmzaRp05TracePrefixes (fieldWordAt)
open V8Smz9OracleExtraction (wordToGoldilocks)
open SmzaRp05PcsWireProjection (fieldWordsToGoldilocks)
open scoped BigOperators

set_option autoImplicit false

/-- Fixed source configuration of the current 686-row, degree-eight profile. -/
def widths : List Nat := List.replicate 686 1 ++ List.replicate 5 8 ++ List.replicate 5 2
def deltas : List Nat := List.replicate 686 0 ++ List.replicate 5 29 ++ List.replicate 5 1

/-- Ordinary source sampling result. Failure of the field sampler is deferred;
failure to collect 38 distinct indexes remains the actual immediate guard. -/
def queryResult (pending : Bool) (sampled : Option (List FieldWord)) :
    Option (List Nat × Bool) :=
  let selected := (collectIndices (returnedWords 50 sampled) []).mergeSort
    (fun left right => decide (left ≤ right))
  if selected.length = 38 then some (selected, pendingFailure pending sampled) else none

def queryProgram (pending : Bool) (digest : RawDigest) : Program (List Nat × Bool) :=
  (fieldXof SmallWoodTranscript.decsFixedSamplingDomain 50 digest).bind
    fun sampled => .done (queryResult pending sampled)

/-- Finite Bool interpretation of the five-by-38 current-profile MCA gate.
Each bounded equation uses the restored polynomial and same-run normalized
DECS leaf, row, gamma, and masking evaluation. This remains mathematical
Lean evidence; it is not a Rust-runtime refinement claim. -/
noncomputable def nativeFiveMcaGate406 (salt : List Byte) (tapes : List (List Byte))
    (leafIndexes : List Nat) (rows gamma masks : List (List FieldWord))
    (evalPoints : List FieldWord) (polynomials : List FieldRow) : Bool :=
  (List.range 5).all fun polynomialIndex =>
    (List.range 38).all fun evaluationIndex =>
      decide (((coefficientPolynomial (polynomials.getD polynomialIndex [])).eval
          ((decodeFieldRow evalPoints).getD evaluationIndex 0)) =
        wordToGoldilocks (fieldWordAt
          (SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
            (tapes.getD evaluationIndex [])
            (leafIndexes.getD evaluationIndex 0)
            (decodeFieldRow (rows.getD evaluationIndex []))
            (masks.getD evaluationIndex []))
          (155 + polynomialIndex)) +
        ∑ column : Fin 140,
          (decodeFieldRow (gamma.getD polynomialIndex [])).getD column.val 0 *
            wordToGoldilocks (fieldWordAt
              (SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
                (tapes.getD evaluationIndex [])
                (leafIndexes.getD evaluationIndex 0)
                (decodeFieldRow (rows.getD evaluationIndex []))
                (masks.getD evaluationIndex []))
              (14 + column.val)))

/-- Finite interpretation of the current twelve LVCS checks on the same
calculated row output and DECS points. The explicit shape conjunct is the
current query-vector well-formedness requirement; all sampled equations use
the native consecutive evaluator and the corresponding two 70-word row blocks.
-/
def currentTwelveLvcsGate406 (headRows tailRows : List (List Goldilocks))
    (points samplePoints : List Goldilocks) (rows : List (List Goldilocks)) : Bool :=
  decide (headRows.length = 12) && decide (tailRows.length = 12) &&
    (List.range 12).all (fun index =>
      decide ((headRows.getD index []).length = 368 ∧
        (tailRows.getD index []).length = 38)) &&
    (List.range 6).all (fun opening =>
      (List.range 2).all (fun block =>
        (List.range samplePoints.length).all (fun sampleIndex =>
          decide
            (SmzaRp05LvcsWireProjection.evaluateConsecutive
              (SmzaRp05LvcsWireProjection.rotateLeft
                ((headRows.getD (2 * opening + block) []) ++
                  (tailRows.getD (2 * opening + block) [])) 368)
              (samplePoints.getD sampleIndex 0) =
              ∑ coefficient : Fin 70,
                points.getD opening 0 ^ coefficient.val *
                  (rows.getD sampleIndex []).getD
                    (70 * block + coefficient.val) 0))))

theorem query_pending_is_source_state (pending : Bool)
    (sampled : Option (List FieldWord)) (indices : List Nat) (nextPending : Bool)
    (success : queryResult pending sampled = some (indices, nextPending)) :
    nextPending = pendingFailure pending sampled := by
  unfold queryResult at success
  dsimp only at success
  split at success
  · exact (congrArg Prod.snd (Option.some.inj success)).symm
  · cases success

/-- PCS through hash_fpp. The same pending flag enters every later stage. -/
noncomputable def pcsProgram (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : DecodedMiddleWire) (decs : DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest)) : Program (RawDigest × Bool) :=
  match SmzaRp05PcsWireProjection.reconstructedHeadsAll wire.pcs points
      wire.rowScalars 64 widths deltas 2 368 with
  | none => .done none
  | some heads =>
      match SmzaRp05PcsWireProjection.decsOpeningInput hPiop 12 368 38 heads
          wire.pcs.rcombiTails with
      | none => .done none
      | some openingInput => (ask openingInput).bind fun openingDigest =>
          (queryProgram pending openingDigest).bind fun (indexes, sampledPending) =>
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
                          (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns input).bind
                            fun post =>
                              match SmzaRp05DecsResponseProjection.hashFppProgram post.root
                                  decs (rows.map fun row =>
                                    row.map SmzaRp05ExecutableRestore.toWord)
                                  (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                  (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                                  140 368 statementBinding with
                              | none => .done none
                              | some program =>
                                  match restoredResponsePolynomials decs
                                      (rows.map fun row =>
                                        row.map SmzaRp05ExecutableRestore.toWord)
                                      (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                      (decsPoints.map
                                        SmzaRp05ExecutableRestore.toWord)
                                      140 368 with
                                  | none => .done none
                                  | some polynomials =>
                                      if nativeFiveMcaGate406 salt tapes indexes
                                          (rows.map fun row =>
                                            row.map SmzaRp05ExecutableRestore.toWord)
                                          (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                          decs.maskingEvals
                                          (decsPoints.map
                                            SmzaRp05ExecutableRestore.toWord)
                                          polynomials then
                                        program.bind fun digest =>
                                          .done (some (digest, post.pending))
                                      else .done none
                    else .done none

noncomputable section

/-- Preserve the poison output and accumulated failure across nonce trials. -/
def openingAttempt (pending : Bool) (hPiop : RawDigest) (nonce : Nat) :
    Program (Option Opening × Bool) :=
  (fieldLoop 6 [] (SmzaRp05CurrentOpeningProgram.openingFieldInputs hPiop nonce)).bind
    fun sampled => .done (some
      (SmzaRp05CurrentOpeningProgram.decodeOpeningWords (returnedWords 6 sampled),
       pendingFailure pending sampled))

def openingScan (hPiop : RawDigest) : List Nat → Bool → Program (Nat × Opening × Bool)
  | [], _ => .done none
  | nonce :: rest, pending =>
      (openingAttempt pending hPiop nonce).bind fun (opening, nextPending) =>
        match opening with
        | none => openingScan hPiop rest nextPending
        | some points => .done (some (nonce, points, nextPending))

/-- Source first-admissible scan, existing proof-nonce comparison, then the
second sample of that nonce. The repeated queries remain in the program log. -/
def canonicalOpening (pending : Bool) (nonce : Fin (2 ^ 32))
    (hPiop : RawDigest) : Program (Opening × Bool) :=
  (openingScan hPiop (List.range 16) pending).bind fun (expected, _, nextPending) =>
    if nonce.val = expected then
      (openingAttempt nextPending hPiop nonce.val).bind fun (opening, finalPending) =>
        .done (opening.map fun points => (points, finalPending))
    else .done none

/-- No supplied PCS intermediates, coefficient arrays, opening, or matrix.
Both PCS and PIOP use the one decoded opened-row-scalar matrix. -/
def transcriptProgram (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) :
    Program ReconstructedTranscript :=
  match SmzaRp05CurrentProofWireProgram.decodeExistingProofFieldView wire with
  | none => .done none
  | some (middle, decs, piop) =>
      (canonicalOpening pending nonce wire.hPiop).bind fun (opening, openingPending) =>
        (pcsProgram ns openingPending wire.hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop) decs
          (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points opening j)
          wire.salt binding statementBinding wire.tapes wire.paths).bind
            fun (hashFpp, pcsPending) =>
              (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
                pcsPending hashFpp).bind fun (matrix, finalPending) =>
                  .done (some (SmzaRp05ExecutableReconstruction.reconstruct
                    dsl statement matrix opening piop hashFpp finalPending))

def verifierProgram (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) : Program Unit :=
  (transcriptProgram ns dsl statement pending binding statementBinding nonce wire).bind
    (finalize wire.hPiop)

/-- Ordinary outputs and their execution equations, extracted after running
the program. This is not a verifier input or an assumed success certificate. -/
structure ExecutionStages (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript) where
  middle : DecodedMiddleWire
  decs : DecodedDecsResponseFields
  piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields
  opening : Opening
  openingPending : Bool
  hashFpp : RawDigest
  pcsPending : Bool
  matrix : V8Smz9PiopSoundness.Matrix (dsl.width statement)
  finalPending : Bool
  decoded : SmzaRp05CurrentProofWireProgram.decodeExistingProofFieldView wire =
    some (middle, decs, piop)
  openingExecuted : (canonicalOpening pending nonce wire.hPiop).eval oracle =
    some (opening, openingPending)
  pcsExecuted : (pcsProgram ns openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop) decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points opening j)
    wire.salt binding statementBinding wire.tapes wire.paths).eval oracle =
      some (hashFpp, pcsPending)
  matrixExecuted : (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
    pcsPending hashFpp).eval oracle = some (matrix, finalPending)
  reconstructed : SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
    opening piop hashFpp finalPending = transcript

attribute [local irreducible] pcsProgram canonicalOpening

theorem transcript_execution_has_stages (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (executed : (transcriptProgram ns dsl statement pending binding statementBinding
      nonce wire).eval oracle = some transcript) :
    Nonempty (ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript) := by
  cases decoded : SmzaRp05CurrentProofWireProgram.decodeExistingProofFieldView wire with
  | none =>
      simp only [transcriptProgram, decoded, Program.eval] at executed
      cases executed
  | some fields =>
      rcases fields with ⟨middle, decs, piop⟩
      simp only [transcriptProgram, decoded] at executed
      obtain ⟨openingPair, openingExecuted, afterOpening⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (canonicalOpening pending nonce wire.hPiop) _ transcript executed
      rcases openingPair with ⟨opening, openingPending⟩
      obtain ⟨pcsPair, pcsExecuted, afterPcs⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (pcsProgram ns openingPending wire.hPiop
            (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop) decs
            (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points opening j)
            wire.salt binding statementBinding wire.tapes wire.paths)
          _ transcript afterOpening
      rcases pcsPair with ⟨hashFpp, pcsPending⟩
      obtain ⟨matrixPair, matrixExecuted, reconstructed⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
            pcsPending hashFpp) _ transcript afterPcs
      rcases matrixPair with ⟨matrix, finalPending⟩
      refine ⟨⟨middle, decs, piop, opening, openingPending, hashFpp, pcsPending,
        matrix, finalPending, decoded, openingExecuted, pcsExecuted,
        matrixExecuted, ?_⟩⟩
      exact Option.some.inj reconstructed

/-- Accepted execution constructs its actual transcript and its AFTER record.
The sole success premise is execution of the assembled ordinary verifier.
No successful middle computation, certificate, or accepted transcript is an
input. A BEFORE record and the probability/extraction bridge remain separate. -/
theorem accepted_execution_constructs_transcript (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (accepted : (verifierProgram ns dsl statement pending binding statementBinding
      nonce wire).eval oracle = some ()) :
    ∃ transcript,
      (transcriptProgram ns dsl statement pending binding statementBinding
        nonce wire).eval oracle = some transcript ∧
      transcript.pendingXofFailure = false ∧
      oracle (finalInput transcript) = wire.hPiop ∧
      (finalInput transcript, wire.hPiop) ∈
        ((verifierProgram ns dsl statement pending binding statementBinding
          nonce wire).record oracle).2 := by
  obtain ⟨transcript, constructed, finished⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (transcriptProgram ns dsl statement pending binding statementBinding nonce wire)
      (finalize wire.hPiop) () accepted
  obtain ⟨clean, equal, recorded⟩ :=
    SmzaRp05ExecutableFinalVerifier.accepted_final_query oracle wire.hPiop
      transcript finished
  exact ⟨transcript, constructed, clean, equal,
    Program.bind_log_right oracle
      (transcriptProgram ns dsl statement pending binding statementBinding nonce wire)
      (finalize wire.hPiop) transcript constructed recorded⟩

/-- The accepted endpoint now supplies all same-run PCS/PIOP stage outputs
alongside the clean final hash equality. None is selected independently of
the oracle used by the accepted verifier execution. -/
theorem accepted_execution_has_stages (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (accepted : (verifierProgram ns dsl statement pending binding statementBinding
      nonce wire).eval oracle = some ()) :
    ∃ transcript,
      Nonempty (ExecutionStages ns dsl statement pending binding statementBinding
        nonce wire oracle transcript) ∧
      transcript.pendingXofFailure = false ∧
      oracle (finalInput transcript) = wire.hPiop ∧
      (finalInput transcript, wire.hPiop) ∈
        ((verifierProgram ns dsl statement pending binding statementBinding
          nonce wire).record oracle).2 := by
  obtain ⟨transcript, executed, clean, equal, recorded⟩ :=
    accepted_execution_constructs_transcript ns dsl statement pending binding
      statementBinding nonce wire oracle accepted
  exact ⟨transcript, transcript_execution_has_stages ns dsl statement pending
    binding statementBinding nonce wire oracle transcript executed, clean, equal, recorded⟩

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosure
