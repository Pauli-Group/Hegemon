import HegemonCrypto.NativeLaunchOnlinePrefixLedger
import HegemonCrypto.NativeLaunchRootPrefixSelector

/-! Root selection at an ACTUAL online ledger entry. Neither the target nor
the snapshot callback/context is supplied externally. Membership derives the
first-any-counter stopping certificate and earlier-answer coherence internally.
Parsing the actual trigger and a comparator wrapper's matching hash remain
explicit; the comparator context does not select the snapshot. Classical
generic Program result only, not Rust/game/QROM or universal prefix availability. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchOnlineRootPrefixCover
open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program)
open NativeLaunchFirstQueryFreeze (Stopped stop trigger_matches triggerMatches)
open NativeLaunchOnlinePrefixLedger (Entry run target classify selected_entry_stop selected_entry_replay source_counter_classification)
open NativeLaunchRootPrefixSelector (RootContext Trigger RawOracle selectRoot parseTrigger contextFrame FiniteCollision stopped_root_cover parse_trigger_exact triggerFrame)
open NativeLaunchRecordedOracleGraph (toOutput)
noncomputable section

/-- Fixed literal selector; no oracle, chosen context or external callback. -/
def rootSnapshot {α : Type} : Stopped α → Option (Sigma RootContext)
  | .complete _ _ => none
  | .before before input _ => selectRoot before input

theorem actual_entry_snapshot {α : Type} (H : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries) :
    rootSnapshot (stop H (target entry.key) program) = selectRoot entry.before entry.input := by
  rw [selected_entry_stop H program entry member]
  rfl

theorem actual_entry_snapshot_replay {α : Type} (H G : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries)
    (agree : ∀ call ∈ entry.before, G call.1 = H call.1) :
    rootSnapshot (stop G (target entry.key) program) = selectRoot entry.before entry.input := by
  rw [selected_entry_replay H G program entry member agree]
  rfl

/-- Successful trigger parsing and the actual wrapper-to-seed hash equation
are retained. The context is only the comparison/event context; the selected
context itself is calculated from actual earlier records and trigger bytes. -/
theorem actual_entry_root_cover {α : Type} (H : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries)
    (trigger : Trigger) (parsed : parseTrigger entry.input = some trigger)
    (ctx : RootContext trigger.family) (accepted : H (contextFrame ctx) = toOutput trigger.seed) :
    selectRoot entry.before entry.input = some ⟨trigger.family, ctx⟩ ∨
      FiniteCollision H (entry.before.map Prod.fst ++ [contextFrame ctx]) ∨
      (contextFrame ctx ∉ entry.before.map Prod.fst ∧ H (contextFrame ctx) = toOutput trigger.seed) := by
  exact stopped_root_cover H (target entry.key) program entry.before entry.input entry.next
    (selected_entry_stop H program entry member) trigger parsed ctx accepted

/-- The actual entry key is precisely the parsed DECS-matrix profile/role/
eight-word seed, with the counter erased. No counter-zero assumption appears. -/
theorem actual_entry_decs_prefix {α : Type} (H : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries)
    (trigger : Trigger) (parsed : parseTrigger entry.input = some trigger) :
    entry.key = (NativeLaunchAdaptiveHistoryCodec.profileDomain trigger.family,
      NativeLaunchAdaptiveHistoryCodec.roleDomain trigger.family .decsMatrix,
      SmallWood.V8Smz9RawCounterCompiler.typedWordPayload (List.ofFn trigger.seed)) := by
  have matched := trigger_matches H (target entry.key) program
  rw [selected_entry_stop H program entry member] at matched
  change target entry.key entry.input = true at matched
  have keyed : classify entry.input = some entry.key := of_decide_eq_true matched
  have exactInput := parse_trigger_exact parsed
  rw [exactInput] at keyed
  change classify (NativeLaunchAdaptiveHistoryCodec.sourceFrame trigger.family .decsMatrix
    (List.ofFn trigger.seed) trigger.counter) = some entry.key at keyed
  rw [source_counter_classification trigger.family .decsMatrix (List.ofFn trigger.seed)
    trigger.counter (by simp)] at keyed
  exact (Option.some.inj keyed).symm

end
end HegemonCrypto.NativeLaunchOnlineRootPrefixCover
