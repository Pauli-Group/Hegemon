import HegemonCrypto.NativeLaunchFirstQueryFreeze

/-! Online first-prefix capture with a fixed, executable raw framing parser.
Every call, including repeats, malformed/complement inputs and failed runs,
remains in the ordinary record. Each decoded profile/role/payload is captured
once, before its first answer. No classifier or capture callback is supplied.
The selected-entry theorem uses actual ledger membership, not a chosen prefix
or supplied chronology certificate. Native source/context/FPP extraction,
Rust refinement and QROM remain separate; all production gates stay open. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchOnlinePrefixLedger
open CanonicalBytes (Byte)
open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program Oracle Log)
open SmallWood.SmzaRp05LeafNamespace (RawInput)
open SmallWood.V8SmzaOracleParser (RawDigest)
open NativeLaunchFirstQueryFreeze (Stopped stop priorLog stop_replay)
open NativeLaunchAdaptiveHistoryCodec (parseSourceFrame)

abbrev PrefixKey := List Byte × List Byte × List Byte
def classify (input : RawInput) : Option PrefixKey :=
  (parseSourceFrame input).map fun parts => (parts.1, parts.2.1, parts.2.2.1)
def target (key : PrefixKey) (input : RawInput) : Bool := decide (classify input = some key)
def Fresh (before : Log) (key : PrefixKey) : Prop :=
  some key ∉ before.map (fun call => classify call.1)

structure Entry (α : Type) where
  key : PrefixKey
  before : Log
  input : RawInput
  next : RawDigest → Program α

def capture {α : Type} (before : Log) (input : RawInput) (next : RawDigest → Program α) : List (Entry α) :=
  match classify input with
  | none => []
  | some key => if some key ∈ before.map (fun call => classify call.1) then []
      else [⟨key, before, input, next⟩]

structure Run (α : Type) where
  result : Option α
  log : Log
  entries : List (Entry α)

def run {α : Type} (H : Oracle) (before : Log) : Program α → Run α
  | .done result => ⟨result, [], []⟩
  | .read input next =>
      let captured := capture before input next
      let answer := H input
      let below := run H (before ++ [(input, answer)]) (next answer)
      ⟨below.result, (input, answer) :: below.log, captured ++ below.entries⟩

theorem run_record {α : Type} (H : Oracle) (before : Log) (program : Program α) :
    ((run H before program).result, (run H before program).log) = program.record H := by
  induction program generalizing before with
  | done result => rfl
  | read input next ih =>
      have below := ih (H input) (before ++ [(input, H input)])
      exact congrArg (fun pair => (pair.1, (input, H input) :: pair.2)) below

theorem fresh_append (before : Log) (call : RawInput × RawDigest) (key : PrefixKey) :
    Fresh (before ++ [call]) key ↔ Fresh before key ∧ classify call.1 ≠ some key := by
  simp [Fresh, List.map_append, eq_comm]

theorem capture_spec {α : Type} (before : Log) (input : RawInput) (next : RawDigest → Program α)
    (entry : Entry α) (member : entry ∈ capture before input next) :
    entry.before = before ∧ entry.input = input ∧ entry.next = next ∧
      classify input = some entry.key ∧ Fresh before entry.key := by
  cases parsed : classify input with
  | none => simp [capture, parsed] at member
  | some key =>
      by_cases seen : some key ∈ before.map (fun call => classify call.1)
      · simp [capture, parsed, seen] at member
      · simp only [capture, parsed, if_neg seen, List.mem_singleton] at member
        subst entry
        exact ⟨rfl, rfl, rfl, rfl, seen⟩

/-- The first-stop certificate is derived from actual online ledger membership. -/
theorem entry_stop {α : Type} (H : Oracle) (before : Log) (program : Program α)
    (entry : Entry α) (member : entry ∈ (run H before program).entries) :
    ∃ localLog, entry.before = before ++ localLog ∧
      stop H (target entry.key) program = .before localLog entry.input entry.next ∧ Fresh before entry.key := by
  induction program generalizing before with
  | done result => simp [run] at member
  | read input next ih =>
      change entry ∈ capture before input next ++ (run H (before ++ [(input, H input)]) (next (H input))).entries at member
      rcases List.mem_append.mp member with captured | later
      · obtain ⟨atBefore, atInput, atNext, parsed, fresh⟩ := capture_spec before input next entry captured
        refine ⟨[], ?_, ?_, fresh⟩
        · simpa only [List.append_nil] using atBefore
        · have hit : target entry.key input = true := by simp [target, parsed]
          simp only [stop, if_pos hit, atInput, atNext]
      · obtain ⟨localLog, atBefore, stopped, fresh⟩ := ih (H input) (before ++ [(input, H input)]) later
        obtain ⟨oldFresh, different⟩ := (fresh_append before (input, H input) entry.key).mp fresh
        refine ⟨(input, H input) :: localLog, ?_, ?_, oldFresh⟩
        · simpa only [List.append_assoc, List.singleton_append] using atBefore
        · have miss : target entry.key input ≠ true := by simp [target, different]
          simp only [stop, if_neg miss, stopped, NativeLaunchFirstQueryFreeze.prepend]

theorem selected_entry_stop {α : Type} (H : Oracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries) :
    stop H (target entry.key) program = .before entry.before entry.input entry.next := by
  obtain ⟨localLog, atBefore, stopped, _⟩ := entry_stop H [] program entry member
  simpa only [List.nil_append] using atBefore ▸ stopped

/-- Only answers on this actual entry's earlier keys are fixed. Trigger and
future answers may differ. The whole first-stop result is identical. -/
theorem selected_entry_replay {α : Type} (H G : Oracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries)
    (agree : ∀ call ∈ entry.before, G call.1 = H call.1) :
    stop G (target entry.key) program = .before entry.before entry.input entry.next := by
  have actual := selected_entry_stop H program entry member
  have replay := stop_replay H G (target entry.key) program (by simpa only [actual, priorLog] using agree)
  exact replay.trans actual

/-- Two actual entries with the same parsed prefix have the identical first
snapshot and continuation. Later occurrences cannot replace the first entry. -/
theorem same_prefix_same_entry {α : Type} (H : Oracle) (program : Program α) (left right : Entry α)
    (leftMember : left ∈ (run H [] program).entries) (rightMember : right ∈ (run H [] program).entries)
    (same : left.key = right.key) : left = right := by
  have first := selected_entry_stop H program left leftMember
  have second := selected_entry_stop H program right rightMember
  rw [same] at first
  have equal := Stopped.before.inj (first.symm.trans second)
  cases left
  cases right
  simp only [Entry.mk.injEq] at *
  exact ⟨same, equal.1, equal.2.1, equal.2.2⟩

theorem source_counter_classification (family : NativeLaunchAdaptiveHistoryCodec.Family)
    (role : NativeLaunchAdaptiveHistoryCodec.Role) (words : List NativeLaunchAdaptiveHistoryCodec.Word)
    (counter : NativeLaunchAdaptiveHistoryCodec.Word) (bound : words.length < 2^64) :
    classify (NativeLaunchAdaptiveHistoryCodec.sourceFrame family role words counter) =
      some (NativeLaunchAdaptiveHistoryCodec.profileDomain family,
        NativeLaunchAdaptiveHistoryCodec.roleDomain family role,
        SmallWood.V8Smz9RawCounterCompiler.typedWordPayload words) := by
  rw [classify, NativeLaunchAdaptiveHistoryCodec.parse_source_frame_roundtrip family role words counter bound]
  rfl

end HegemonCrypto.NativeLaunchOnlinePrefixLedger
