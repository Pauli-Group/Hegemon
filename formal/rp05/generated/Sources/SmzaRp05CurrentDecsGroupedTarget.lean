import SmzaRp05CurrentGroupedRecordReadback
import SmzaRp05CertifiedReplayScheduleFrames
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05CurrentRoleLabels

/-! The finite grouped key of an actually recorded DECS coefficient call has
the literal counter-zero DECS representative and the selected root target.
The call is not supplied as an independent query witness. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentDecsGroupedTarget

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (included encode)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter groupBlockCap
    group_block_cap_eq groupAddress groupEncode groupRepresentative groupZero group_address_encode
    groupKeyOf)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05CurrentRoleLabels (targetOfRaw target_of_parsed_role)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery roleStage)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false

/-- A real branch-recorded DECS counter input determines its exact grouped
key.  Parsing the representative recovers the same DECS role and root, so the
current raw target function cannot fall back to its default digest. -/
theorem recorded_decs_call_has_grouped_target
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ answerLog groupedDecode program branch)
    (root : RawDigest) (index : Fin (digestCallCap 700))
    (inputEq : call.1 = counterInput decsCoefficientDomain root index.val) :
    ∃ rolePrefix : CanonicalRolePrefix,
      included program (encode program call.1) = Sum.inl rolePrefix ∧
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) =
        some ⟨.decsMatrix, root, 0, 0⟩ ∧
      targetOfRaw .decsMatrix
        (groupRepresentative (included program (encode program call.1))) =
          (roleStage .decsMatrix, root) := by
  let leading : RawInput :=
    encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
      V8SmzaOracleParser.profileDomain ++
      encodeLE 8 decsCoefficientDomain.length ++ decsCoefficientDomain ++
      encodeLE 8 8 ++ List.ofFn root
  let zeroCounter : Fin (2 ^ 64) := ⟨0, by norm_num⟩
  have parsedZero : parseStageQuery (leading ++ encodeLE 8 0) =
      some ⟨.decsMatrix, root, 0, 0⟩ := by
    change parseStageQuery (counterInput decsCoefficientDomain root 0) = _
    exact ordinary_counter_roundtrip .decsMatrix (by decide) root zeroCounter
  let rolePrefix : CanonicalRolePrefix :=
    ⟨.decsMatrix, leading, ⟨⟨.decsMatrix, root, 0, 0⟩, parsedZero, rfl⟩⟩
  have groupBound : index.val < groupBlockCap := by
    have cap : digestCallCap 700 = 92 := by decide
    have indexBound : index.val < 92 := by simpa [cap] using index.isLt
    rw [group_block_cap_eq]
    omega
  let groupIndex : GroupCounter := ⟨index.val, groupBound⟩
  have encoded : groupEncode (rolePrefix, groupIndex) =
      counterInput decsCoefficientDomain root index.val := by
    change leading ++ encodeLE 8 index.val = _
    rfl
  have represented := SmzaRp05CurrentFiniteGroupedProgram.answer_log_group_keys_represented
    groupedDecode program branch call recorded
  refine ⟨rolePrefix, ?_, ?_, ?_⟩
  · calc
      included program (encode program call.1) = groupKeyOf call.1 := represented
      _ = Sum.inl rolePrefix := by
        change (groupAddress call.1).1 = Sum.inl rolePrefix
        rw [inputEq, ← encoded]
        exact congrArg Prod.fst (group_address_encode rolePrefix groupIndex)
  · simpa only [groupRepresentative, groupEncode,
      V8Smz9CoherentVectorMerkle.canonicalRepresentative, rolePrefix,
      groupZero, V8Smz9RawCounterCompiler.boundedCounterInput,
      V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
  · have representativeRead :
        parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) =
          some ⟨.decsMatrix, root, 0, 0⟩ := by
      simpa only [groupRepresentative, groupEncode,
        V8Smz9CoherentVectorMerkle.canonicalRepresentative, rolePrefix,
        groupZero, V8Smz9RawCounterCompiler.boundedCounterInput,
        V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
    have keyIdentity :
        included program (encode program call.1) = Sum.inl rolePrefix := by
      calc
        included program (encode program call.1) = groupKeyOf call.1 := represented
        _ = Sum.inl rolePrefix := by
          change (groupAddress call.1).1 = Sum.inl rolePrefix
          rw [inputEq, ← encoded]
          exact congrArg Prod.fst (group_address_encode rolePrefix groupIndex)
    rw [keyIdentity]
    exact target_of_parsed_role .decsMatrix
      (groupRepresentative (Sum.inl rolePrefix)) ⟨.decsMatrix, root, 0, 0⟩
      representativeRead rfl

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentDecsGroupedTarget
