import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05HashFppResponseExecution
import SmzaRp05ExecutableAcceptedFailureJoin
import SmzaRp05CurrentMaxAgreementRecovery

/-!
# Retained pre-query hash_fpp response input

On the retained-preimage branch, the source's later `hash_fpp` query is the
exact framed serialization of the post-Merkle root and restored DECS response
coefficients.  Collision freedom on one raw-record relation therefore pins
an earlier occurrence of that digest to this response input.  This is the
second preimage layer: it complements, and does not restate, the existing
`h_piop` final-input retention theorem.  The no-prior-`hash_fpp` branch remains
explicit for the upstream guess-event accounting.

No codeword condition is imposed on the committed row table.  This theorem
only identifies the exact finite response coefficients already serialized by
the source hash query.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRoleSupport

open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open SmzaRp05ExecutableMerkleVerifier (Log Oracle Program ask)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields FieldRow)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8SmzaOracleParser (RawDigest RawInput)
open V8Smz9CoherentMerkleGeometry (Records)

set_option autoImplicit false

/-- The exact raw input queried by `hashFppProgram`, when restoration succeeds.
The input includes the Merkle root, all five restored coefficient rows, and
the verifier-derived statement binding in source order. -/
def responseTranscriptInput (root : RawDigest)
    (decs : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (statementBinding : List Nat) : Option RawInput := do
  let pcsWords ← SmzaRp05DecsResponseProjection.responseTranscriptWords root decs
    rows gamma evalPoints rowCount highCount
  let words := pcsWords ++ statementBinding
  pure (V8SmzaOracleParser.framedInput SmallWoodTranscript.piopInputDomain
    (words.flatMap (encodeLE 8)))

/-- The chosen hash program is a single read at the exact source serialization.
This exposes the raw query without guessing at or recomputing its fields. -/
theorem selected_response_hash_program_input
    (root : RawDigest) (decs : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (statementBinding : List Nat)
    (program : Program RawDigest)
    (selected : SmzaRp05DecsResponseProjection.hashFppProgram root decs
      rows gamma evalPoints rowCount highCount statementBinding = some program) :
    ∃ pcsWords input,
      SmzaRp05DecsResponseProjection.responseTranscriptWords root decs
        rows gamma evalPoints rowCount highCount = some pcsWords ∧
      responseTranscriptInput root decs rows gamma evalPoints
        rowCount highCount statementBinding = some input ∧
      program = ask input := by
  unfold SmzaRp05DecsResponseProjection.hashFppProgram at selected
  cases words : SmzaRp05DecsResponseProjection.responseTranscriptWords root decs
      rows gamma evalPoints rowCount highCount with
  | none => simp [words] at selected
  | some pcsWords =>
      simp [words] at selected
      let input := V8SmzaOracleParser.framedInput SmallWoodTranscript.piopInputDomain
        ((pcsWords ++ statementBinding).flatMap (encodeLE 8))
      refine ⟨pcsWords, input, rfl, ?_, ?_⟩
      · simp [responseTranscriptInput, words, input]
      · simpa [input, List.flatMap_append] using selected.symm

private theorem selected_program_records_response_input
    (oracle : Oracle) (root : RawDigest) (decs : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (statementBinding : List Nat)
    (program : Program RawDigest) (digest : RawDigest)
    (selected : SmzaRp05DecsResponseProjection.hashFppProgram root decs
      rows gamma evalPoints rowCount highCount statementBinding = some program)
    (executed : program.eval oracle = some digest) :
    ∃ pcsWords input,
      SmzaRp05DecsResponseProjection.responseTranscriptWords root decs
        rows gamma evalPoints rowCount highCount = some pcsWords ∧
      responseTranscriptInput root decs rows gamma evalPoints
        rowCount highCount statementBinding = some input ∧
      (input, digest) ∈ (program.record oracle).2 := by
  obtain ⟨pcsWords, input, wordsEq, inputEq, programEq⟩ := selected_response_hash_program_input
    root decs rows gamma evalPoints rowCount highCount statementBinding program selected
  subst program
  have oracleEq : oracle input = digest := by
    simpa [ask, Program.eval] using executed
  refine ⟨pcsWords, input, wordsEq, inputEq, ?_⟩
  simp [ask, Program.record, oracleEq]

/-- Concrete second-layer retained-preimage branch for an actual accepted PCS
stage. `priorLog` is an explicit prefix supplied by the caller; this theorem
does not establish its chronology. The local record is this stage's actual
response-hash call under the same oracle. If the digest
has a prior preimage and the combined relation is
collision-free, that preimage is exactly the source serialization of the
post-query 406-term response.  The alternative is precisely the missing
prior-preimage/guess event (or the collision event), not an assumed response
family.

The returned equality is the byte-level anchor from which a pre-query response
rule can be decoded; downstream event accounting must still keep the two
exception branches explicit. -/
theorem accepted_stage_response_preimage_branch
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : DecodedDecsResponseFields} {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (priorLog : Log) :
      ((¬ ∃ input, (input, hashFpp) ∈ priorLog) ∨
      (¬ RecordsCollisionFree
        ((priorLog ++ (stages.hashProgram.record oracle).2).toFinset)) ∨
      (∃ pcsWords input, (input, hashFpp) ∈ priorLog ∧
        SmzaRp05DecsResponseProjection.responseTranscriptWords stages.post.root decs
          (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
          (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
          (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
          140 368 = some pcsWords ∧
        responseTranscriptInput stages.post.root decs
          (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
          (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
          (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
          140 368 statementBinding = some input)) := by
  classical
  by_cases prior : ∃ input, (input, hashFpp) ∈ priorLog
  · by_cases collisionFree : RecordsCollisionFree
        ((priorLog ++ (stages.hashProgram.record oracle).2).toFinset)
    · right
      right
      obtain ⟨priorInput, priorMember⟩ := prior
      obtain ⟨pcsWords, actualInput, wordsEq, expectedInput, actualMember⟩ :=
        selected_program_records_response_input oracle stages.post.root decs
          (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
          (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
          (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
          140 368 statementBinding stages.hashProgram hashFpp
          stages.responseBuilt stages.hashExecuted
      have beforeInRecords : (priorInput, hashFpp) ∈
          (priorLog ++ (stages.hashProgram.record oracle).2).toFinset := by
        simp only [List.mem_toFinset, List.mem_append]
        exact Or.inl priorMember
      have afterInRecords : (actualInput, hashFpp) ∈
          (priorLog ++ (stages.hashProgram.record oracle).2).toFinset := by
        simp only [List.mem_toFinset, List.mem_append]
        exact Or.inr actualMember
      have sameInput := collisionFree priorInput actualInput hashFpp
        beforeInRecords afterInRecords
      refine ⟨pcsWords, priorInput, priorMember, wordsEq, ?_⟩
      rw [sameInput]
      exact expectedInput
    · exact Or.inr (Or.inl collisionFree)
  · exact Or.inl prior

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRoleSupport
