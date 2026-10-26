import HegemonCrypto.NativeLaunchOnlineFppComparisonCover

/-! Freeze the ENTIRE branch-indexed response function from earlier pairs and
trigger bytes only. Branch/wire/matrix are later lookup/comparison arguments.
Actual entry membership derives replay and key coverage; no desired binding
or successful-selection premise. Native accepted-prefix/Rust/QROM and all
production gates remain open. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchOnlineFppResponseFreeze
open NativeLaunchAdaptiveHistoryCodec (Word)
open NativeLaunchFppHistoryBinding (Digest finalFrame)
open NativeLaunchRecordedOracleGraph (toOutput)
open NativeLaunchRootPrefixSelector (RawOracle FiniteCollision)
open NativeLaunchOnlinePrefixLedger (Entry run target selected_entry_replay)
open NativeLaunchOnlineFppPrefixCover (OpeningTrigger parseOpening selectChain)
open NativeLaunchOnlineFppComparisonCover (actual_entry_key_cover)
open NativeLaunchFppResponseHistory (zeroResponse rebuiltKey)
open NativeLaunchCommitmentResponseBinding (decodeFppResponse decode_restored_commitment)
open NativeLaunchRelationModelStatement (Statement)
open NativeLaunchFirstQueryFreeze (Stopped stop)
open SmallWood
open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program Log)
open SmallWood.NativeLaunchRelationModelResponse
open SmallWood.V8Smz9McaRecovery (BoundedResponse)
noncomputable section

abbrev Responses := (branch : Branch) → BoundedResponse Goldilocks MaskRow (degree branch)
def frozenResponses (before : Log) (raw : NativeLaunchAdaptiveHistoryCodec.RawInput) : Responses := fun branch =>
  match selectChain before raw with
  | none => zeroResponse branch
  | some chain => match decodeFppResponse branch chain.key with
    | none => zeroResponse branch
    | some decoded => decoded.response

def responseSnapshot {α : Type} : Stopped α → Responses
  | .complete _ _ => fun branch => zeroResponse branch
  | .before before raw _ => frozenResponses before raw

theorem actual_entry_response_snapshot_replay {α : Type} (H G : RawOracle)
    (program : Program α) (entry : Entry α) (member : entry ∈ (run H [] program).entries)
    (agree : ∀ call ∈ entry.before, G call.1 = H call.1) :
    responseSnapshot (stop G (target entry.key) program) = frozenResponses entry.before entry.input := by
  rw [selected_entry_replay H G program entry member agree]
  rfl

theorem actual_entry_response_cover {α Position : Type} {branch : Branch}
    (H : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries)
    (trigger : OpeningTrigger) (parsed : parseOpening entry.input = some trigger)
    (familyMatches : trigger.family = NativeLaunchCommitmentReadback.family branch)
    (leading : Digest) (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix)
    (digest : Digest) (tail : List Word) (physical : 8 + tail.length < 2^64)
    (keyHash : H (rebuiltKey leading statement point wire matrix) = toOutput digest)
    (finalHash : H (finalFrame (NativeLaunchCommitmentReadback.family branch) digest tail) = toOutput trigger.seed) :
    frozenResponses entry.before entry.input branch = calculatedResponse point wire matrix ∨
    FiniteCollision H (entry.before.map Prod.fst ++ [rebuiltKey leading statement point wire matrix,
      finalFrame (NativeLaunchCommitmentReadback.family branch) digest tail]) ∨
    (finalFrame (NativeLaunchCommitmentReadback.family branch) digest tail ∉ entry.before.map Prod.fst ∧
      H (finalFrame (NativeLaunchCommitmentReadback.family branch) digest tail) = toOutput trigger.seed) ∨
    (finalFrame (NativeLaunchCommitmentReadback.family branch) digest tail ∈ entry.before.map Prod.fst ∧
      rebuiltKey leading statement point wire matrix ∉ entry.before.map Prod.fst ∧
      H (rebuiltKey leading statement point wire matrix) = toOutput digest) := by
  have covered := actual_entry_key_cover H program entry member trigger parsed
    (rebuiltKey leading statement point wire matrix) digest tail physical keyHash
    (by simpa only [familyMatches] using finalHash)
  rcases covered with recovered | events
  · obtain ⟨chain, selected, keyEq, _, _⟩ := recovered
    apply Or.inl
    simp only [frozenResponses, selected, keyEq, rebuiltKey, decode_restored_commitment]
  · exact Or.inr (by simpa only [familyMatches] using events)

end
end HegemonCrypto.NativeLaunchOnlineFppResponseFreeze
