import SmzaRp05CurrentFppFrameReadback
import SmzaRp05FilteredReadback

/-! Actual response-hash calls are nonleaf records. Their retention under
the authorization filter follows from the executed constructor's byte frame,
not from an assumption that every producer log call is fresh. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFppRecordFreshness

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05CurrentFppFrameReadback
open SmzaRp05LeafNamespace (Namespace leafV2Role leafStatement parseCurrentLeaf)
open SmzaRp05FilteredReadback (globalLeafStatement)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

theorem nonleaf_frame_has_no_statement
    (ns : Namespace) (input : RawInput) (roleBytes payload : List Byte)
    (parsed : V8SmzaOracleParser.parseFramed input = some (roleBytes, payload))
    (notLeaf : roleBytes ≠ leafV2Role) :
    globalLeafStatement ns input = none := by
  simp [globalLeafStatement, leafStatement, parseCurrentLeaf, parsed, notLeaf]

/-- The actual successful response-hash constructor has a single nonleaf
query. This applies to every recorded call, not just a selected witness. -/
theorem successful_response_hash_records_nonleaf
    (ns : Namespace) (root : RawDigest) (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (statementBinding : List Nat) (bindingLength : statementBinding.length = 138)
    (program : Program RawDigest)
    (selected : SmzaRp05DecsResponseProjection.hashFppProgram root fields
      rows gamma evalPoints 140 368 statementBinding = some program)
    (oracle : Oracle) :
    ∀ call ∈ (program.record oracle).2, globalLeafStatement ns call.1 = none := by
  obtain ⟨input, payload, programEq, parsed, _normalized, _edge, _suffix⟩ :=
    successful_response_program_has_current_fpp_edge ns root fields rows gamma
      evalPoints statementBinding bindingLength program selected
  have nonleaf : globalLeafStatement ns input = none :=
    nonleaf_frame_has_no_statement ns input SmallWoodTranscript.piopInputDomain
      payload parsed (by decide)
  intro call member
  rw [programEq] at member
  have callEq : call = (input, oracle input) := by
    simpa only [ask, Program.record, List.mem_singleton] using member
  simpa only [callEq] using nonleaf

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFppRecordFreshness
