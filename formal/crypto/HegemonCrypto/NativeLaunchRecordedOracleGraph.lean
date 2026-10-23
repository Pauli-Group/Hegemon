import HegemonCrypto.NativeLaunchRecordedMerkleExtraction

/-! Literal word-digest/byte-output and finite oracle-graph adapter.
Selection is derived from valid key membership and finite collision exclusion.
No uniform-distribution transport, accepted compact extraction, chronology,
polynomial provenance, Rust refinement or QROM conclusion is established. -/
set_option autoImplicit false
namespace HegemonCrypto.NativeLaunchRecordedOracleGraph
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchLeafReadback
open NativeLaunchFppHistoryBinding
  (Digest Oracle History digestBytes digest_bytes_length RelevantCollision equal_of_no_relevant_collision)
open NativeLaunchMerklePathBinding
open NativeLaunchRecordedMerkleExtraction
open SmallWood.V8Smz9CoherentMerkleGeometry
  (Functional selectedInput selected_input_recorded candidateInputs)
open SmallWood.V8Smz9RawCounterCompiler (typed_word_payload_injective)
local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq
noncomputable section
open Classical

/-- All eight little-endian words, preserving the complete 64-byte digest. -/
def toOutput (value : Digest) : Output := digest (digestBytes value)

theorem toOutput_injective : Function.Injective toOutput := by
  intro left right same
  have bytes : digestBytes left = digestBytes right := by
    apply List.ext_getElem (by rw [digest_bytes_length, digest_bytes_length])
    intro index leftBound rightBound
    have bound : index < 64 := by simpa only [digest_bytes_length] using leftBound
    have equal := congrFun same ⟨index, bound⟩
    change (digestBytes left).getD index 0 = (digestBytes right).getD index 0 at equal
    exact (List.getElem_eq_getD 0).trans (equal.trans (List.getElem_eq_getD 0).symm)
  exact List.ofFn_injective (typed_word_payload_injective bytes)

theorem parse_role_rejects_other (family : Family) (wanted actual : RawInput)
    (words : List Word) (count : Nat) (roleBound : actual.length < 18446744073709551616)
    (wordBound : words.length < 18446744073709551616) (different : actual ≠ wanted) :
    parseRolePayload family wanted count (encodeRole family actual words) = none := by
  simp [parseRolePayload, role_frame_roundtrip family actual words roleBound wordBound, different]

theorem parse_node_frame (family : Family) (left right : Digest) :
    parseInput family (nodeFrame family left right) =
      some (.node (toOutput left) (toOutput right)) := by
  have rejected := parse_role_rejects_other family rootRole nodeRole
    (List.ofFn left ++ List.ofFn right) (12 + preambleWordCount family)
    (by decide) (by simp) (by decide)
  have noRoot : parseRoot family (nodeFrame family left right) = none := by
    simp only [parseRoot, nodeFrame, rejected, Option.map_none]
  simp only [parseInput, noRoot, node_roundtrip, toOutput]

theorem parse_root_frame {family : Family} (salt : Fin 4 → Word) (root : Digest)
    (statement : Statement family) :
    parseInput family (rootFrame salt root statement) =
      some (.wrapper (saltBytes salt) (toOutput root) (statementBytes statement)) := by
  simp only [parseInput, root_roundtrip, toOutput]

theorem parse_leaf_frame {family : Family} (statement : Statement family) (fields : LeafFields) :
    parseInput family (strictLeafFrame statement fields) =
      some (.leaf (decodedFields (statementBytes statement) fields)) := by
  have rootDifferent : leafRole family ≠ rootRole := by cases family <;> decide
  have nodeDifferent : leafRole family ≠ nodeRole := by cases family <;> decide
  have noRoot : parseRoot family (strictLeafFrame statement fields) = none := by
    simp [parseRoot, parseRolePayload, NativeLaunchLeafNamespace.literal_frame_roundtrip, rootDifferent]
  have noNode : parseNode family (strictLeafFrame statement fields) = none := by
    simp [parseNode, parseRolePayload, NativeLaunchLeafNamespace.literal_frame_roundtrip, nodeDifferent]
  simp only [parseInput, noRoot, noNode, complete_leaf_roundtrip, Option.map_some]

/-- Every record output is produced by the SAME supplied deterministic oracle. -/
def oracleGraph (H : Oracle) (history : History) : Database :=
  (history.map fun key => (key, toOutput (H key))).toFinset

theorem oracleGraph_mem_iff (H : Oracle) (history : History) (key : RawInput) (output : Output) :
    (key, output) ∈ oracleGraph H history ↔ key ∈ history ∧ output = toOutput (H key) := by
  constructor
  · intro member
    obtain ⟨raw, recorded, equal⟩ := List.mem_map.mp (List.mem_toFinset.mp member)
    have keyEq : raw = key := congrArg Prod.fst equal
    subst raw
    exact ⟨recorded, (congrArg Prod.snd equal).symm⟩
  · rintro ⟨recorded, rfl⟩
    exact List.mem_toFinset.mpr (List.mem_map.mpr ⟨key, recorded, rfl⟩)

theorem oracleGraph_recorded (H : Oracle) (history : History) (key : RawInput)
    (recorded : key ∈ history) : (key, toOutput (H key)) ∈ oracleGraph H history :=
  (oracleGraph_mem_iff H history key _).2 ⟨recorded, rfl⟩

theorem oracleGraph_functional (H : Oracle) (history : History) : Functional (oracleGraph H history) := by
  intro left leftMem right rightMem same
  have leftOutput := ((oracleGraph_mem_iff H history left.1 left.2).1 leftMem).2
  have rightOutput := ((oracleGraph_mem_iff H history right.1 right.2).1 rightMem).2
  exact leftOutput.trans ((congrArg (fun key => toOutput (H key)) same).trans rightOutput.symm)

/-- Collision exclusion is finite over recorded raw keys. The valid key is
selected even if unrelated malformed keys are present; no selection equality
or desired leaf readback is supplied as a premise. -/
theorem selected_valid_key (H : Oracle) (history : History) (family : Family)
    (stage : Stage family) (key : RawInput) (recorded : key ∈ history)
    (valid : (next family stage key).isSome)
    (clean : ¬ RelevantCollision H history) :
    selectedInput (next family) (oracleGraph H history) stage (toOutput (H key)) = some key := by
  have candidate : key ∈ candidateInputs (next family) (oracleGraph H history) stage (toOutput (H key)) := by
    apply Finset.mem_image.mpr
    refine ⟨(key, toOutput (H key)), ?_, rfl⟩
    exact Finset.mem_filter.mpr ⟨oracleGraph_recorded H history key recorded, rfl, valid⟩
  cases selection : selectedInput (next family) (oracleGraph H history) stage (toOutput (H key)) with
  | none =>
      unfold selectedInput at selection
      rw [dif_pos ⟨key, candidate⟩] at selection
      contradiction
  | some chosen =>
      have selectedRecord := selected_input_recorded (next family) (oracleGraph H history)
        stage (toOutput (H key)) chosen selection
      have properties := (oracleGraph_mem_iff H history chosen _).1 selectedRecord
      have hashEqual : H chosen = H key := toOutput_injective properties.2.symm
      have same := equal_of_no_relevant_collision H history clean chosen key properties.1 recorded hashEqual
      exact congrArg some same

end
end HegemonCrypto.NativeLaunchRecordedOracleGraph
