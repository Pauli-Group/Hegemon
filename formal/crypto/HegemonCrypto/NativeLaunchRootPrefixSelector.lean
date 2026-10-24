import HegemonCrypto.NativeLaunchPrefixFppSelector
import HegemonCrypto.NativeLaunchRecordedOracleGraph
import HegemonCrypto.NativeLaunchFirstQueryFreeze

/-! Prefix-only typed root selection. No supplied desired context or oracle
queries in the selector. Classical finite cover, not native Rust or QROM refinement. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 5000
namespace HegemonCrypto.NativeLaunchRootPrefixSelector
open CanonicalBytes NativeLaunchAdaptiveHistoryCodec
open NativeLaunchRelationModelStatement NativeLaunchMerklePathBinding
open NativeLaunchPrefixFppSelector (readWords read_words_roundtrip scan scan_sound scan_available)
open NativeLaunchFppHistoryBinding (Digest)
open NativeLaunchRecordedOracleGraph (toOutput)
open SmallWood.V8Smz9RawCounterCompiler (typedWordPayload)
open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program Log)
open SmallWood.V8SmzaOracleParser (RawDigest)
open NativeLaunchFirstQueryFreeze
noncomputable section
open Classical

structure RootContext (family : Family) where
  salt : Fin 4 → Word
  bareRoot : Digest
  statement : Statement family

def contextFrame {family : Family} (ctx : RootContext family) : RawInput :=
  rootFrame ctx.salt ctx.bareRoot ctx.statement

def decodeVector (n : Nat) (raw : RawInput) : Option (Fin n → Word) := do
  let (words, suffix) ← readWords n raw
  if words.length = n ∧ suffix = [] then some (fun i => words.getD i.val 0) else none

theorem decode_vector_roundtrip {n : Nat} (value : Fin n → Word) :
    decodeVector n (typedWordPayload (List.ofFn value)) = some value := by
  have read := read_words_roundtrip (List.ofFn value) []
  simp only [List.length_ofFn, List.append_nil] at read
  have get : (fun i : Fin n => (List.ofFn value).getD i.val 0) = value := by
    funext i
    simp [List.getD_eq_getElem?_getD, i.isLt]
  simp [decodeVector, read]

def unpackRoot (family : Family) (raw : RawInput) : Option (RootContext family) := do
  let (salt, root, statement) ← parseRoot family raw
  let salt ← decodeVector 4 salt
  let root ← decodeVector 8 root
  let statement ← decodeVector (preambleWordCount family) statement
  pure ⟨salt, root, statement⟩

def parseRootContext (family : Family) (raw : RawInput) : Option (RootContext family) := do
  let ctx ← unpackRoot family raw
  if raw = contextFrame ctx then some ctx else none

theorem unpack_root_roundtrip {family : Family} (ctx : RootContext family) :
    unpackRoot family (contextFrame ctx) = some ctx := by
  cases ctx with
  | mk salt root statement =>
    simp only [unpackRoot, contextFrame, root_roundtrip, Option.bind_eq_bind',
      Option.bind_some, saltBytes, NativeLaunchFppHistoryBinding.digestBytes,
      statementBytes, statementWords, decode_vector_roundtrip]
    rfl

theorem parse_root_roundtrip {family : Family} (ctx : RootContext family) :
    parseRootContext family (contextFrame ctx) = some ctx := by
  simp [parseRootContext, unpack_root_roundtrip]

theorem parse_root_exact {family : Family} {raw : RawInput} {ctx : RootContext family}
    (success : parseRootContext family raw = some ctx) : raw = contextFrame ctx := by
  unfold parseRootContext at success
  cases parsed : unpackRoot family raw with
  | none => simp [parsed] at success
  | some found =>
    simp only [parsed, Option.bind_eq_bind', Option.bind_some] at success
    split at success
    · next exactRaw => cases success; exact exactRaw
    · contradiction

def inferFamily (profile : RawInput) : Option Family :=
  if profile = profileDomain .rp06 then some .rp06
  else if profile = profileDomain .htlc then some .htlc else none

theorem infer_family_roundtrip (family : Family) : inferFamily (profileDomain family) = some family := by
  cases family <;> decide

structure Trigger where
  family : Family
  seed : Digest
  counter : Word

def triggerFrame (trigger : Trigger) : RawInput :=
  sourceFrame trigger.family .decsMatrix (List.ofFn trigger.seed) trigger.counter

def unpackTrigger (raw : RawInput) : Option Trigger := do
  let (profile, role, payload, counter) ← parseSourceFrame raw
  let family ← inferFamily profile
  if bound : counter < 2^64 then
    if role = roleDomain family .decsMatrix then
      let seed ← decodeVector 8 payload
      some ⟨family, seed, ⟨counter, bound⟩⟩
    else none
  else none

def parseTrigger (raw : RawInput) : Option Trigger := do
  let trigger ← unpackTrigger raw
  if raw = triggerFrame trigger then some trigger else none

theorem unpack_trigger_roundtrip (trigger : Trigger) :
    unpackTrigger (triggerFrame trigger) = some trigger := by
  cases trigger with
  | mk family seed counter =>
    unfold triggerFrame unpackTrigger
    rw [parse_source_frame_roundtrip family .decsMatrix (List.ofFn seed) counter (by simp)]
    simp only [Option.bind_eq_bind', Option.bind_some, infer_family_roundtrip,
      dif_pos counter.isLt, decode_vector_roundtrip]
    rfl

theorem parse_trigger_roundtrip (trigger : Trigger) :
    parseTrigger (triggerFrame trigger) = some trigger := by
  simp [parseTrigger, unpack_trigger_roundtrip]

theorem parse_trigger_exact {raw : RawInput} {trigger : Trigger}
    (success : parseTrigger raw = some trigger) : raw = triggerFrame trigger := by
  unfold parseTrigger at success
  cases parsed : unpackTrigger raw with
  | none => simp [parsed] at success
  | some found =>
    simp only [parsed, Option.bind_eq_bind', Option.bind_some] at success
    split at success
    · next exactRaw => cases success; exact exactRaw
    · contradiction

def candidate (family : Family) (seed : Digest) (call : RawInput × RawDigest) :
    Option (RootContext family) :=
  if call.2 = toOutput seed then parseRootContext family call.1 else none

def selectFor (before : Log) (trigger : Trigger) : Option (RootContext trigger.family) :=
  scan (candidate trigger.family trigger.seed) before

/-- Only actual earlier pairs and triggering bytes are inputs. -/
def selectRoot (before : Log) (raw : RawInput) : Option (Sigma RootContext) := do
  let trigger ← parseTrigger raw
  let ctx ← selectFor before trigger
  pure ⟨trigger.family, ctx⟩

theorem candidate_sound {family : Family} {seed : Digest} {call : RawInput × RawDigest}
    {ctx : RootContext family} (success : candidate family seed call = some ctx) :
    call.2 = toOutput seed ∧ call.1 = contextFrame ctx := by
  unfold candidate at success
  split at success
  · next same => exact ⟨same, parse_root_exact success⟩
  · contradiction

theorem selected_recorded (before : Log) (trigger : Trigger) (ctx : RootContext trigger.family)
    (selected : selectFor before trigger = some ctx) :
    ∃ call ∈ before, call.2 = toOutput trigger.seed ∧ call.1 = contextFrame ctx := by
  obtain ⟨call, member, found⟩ := scan_sound _ before ctx selected
  exact ⟨call, member, candidate_sound found⟩

abbrev RawOracle := RawInput → RawDigest

def FiniteCollision (H : RawOracle) (keys : List RawInput) : Prop :=
  ∃ left ∈ keys, ∃ right ∈ keys, left ≠ right ∧ H left = H right

theorem context_frame_injective {family : Family} : Function.Injective (@contextFrame family) := by
  intro left right same
  have eqs := root_frame_injective left.salt right.salt left.bareRoot right.bareRoot
    left.statement right.statement same
  cases left; cases right
  simp_all

theorem prefix_cover (H : RawOracle) (before : Log) (trigger : Trigger)
    (coherent : ∀ call ∈ before, call.2 = H call.1)
    (ctx : RootContext trigger.family) (accepted : H (contextFrame ctx) = toOutput trigger.seed) :
    selectFor before trigger = some ctx ∨
    FiniteCollision H (before.map Prod.fst ++ [contextFrame ctx]) ∨
    (contextFrame ctx ∉ before.map Prod.fst ∧ H (contextFrame ctx) = toOutput trigger.seed) := by
  by_cases member : contextFrame ctx ∈ before.map Prod.fst
  · obtain ⟨call, recorded, keyEq⟩ := List.mem_map.mp member
    have output : call.2 = toOutput trigger.seed := (coherent call recorded).trans (keyEq ▸ accepted)
    have found : candidate trigger.family trigger.seed call = some ctx := by
      simp [candidate, output, keyEq, parse_root_roundtrip]
    obtain ⟨chosen, selected⟩ := scan_available _ before call ctx recorded found
    obtain ⟨picked, pickedMem, pickedOutput, pickedKey⟩ := selected_recorded before trigger chosen selected
    have hashes : H picked.1 = H (contextFrame ctx) :=
      (coherent picked pickedMem).symm.trans (pickedOutput.trans accepted.symm)
    by_cases same : picked.1 = contextFrame ctx
    · have contexts : chosen = ctx := context_frame_injective (pickedKey.symm.trans same)
      exact Or.inl (contexts ▸ selected)
    · exact Or.inr (Or.inl ⟨picked.1, List.mem_append_left _ (List.mem_map.mpr ⟨picked, pickedMem, rfl⟩),
        contextFrame ctx, by simp, same, hashes⟩)
  · exact Or.inr (Or.inr ⟨member, accepted⟩)

/-- Coherence comes from the actual stopped interpreter, not a provenance flag. -/
theorem before_coherent {α : Type} (H : RawOracle) (target : RawInput → Bool) (program : Program α)
    (before : Log) (raw : RawInput) (next : RawDigest → Program α)
    (stopped : stop H target program = .before before raw next) :
    ∀ call ∈ before, call.2 = H call.1 := by
  intro call member
  apply Program.recorded_call H program call
  rw [before_record_decomposition H target program before raw next stopped]
  exact List.mem_append_left _ member

theorem stopped_root_cover {α : Type} (H : RawOracle) (target : RawInput → Bool)
    (program : Program α) (before : Log) (raw : RawInput) (next : RawDigest → Program α)
    (stopped : stop H target program = .before before raw next)
    (trigger : Trigger) (parsed : parseTrigger raw = some trigger)
    (ctx : RootContext trigger.family) (accepted : H (contextFrame ctx) = toOutput trigger.seed) :
    selectRoot before raw = some ⟨trigger.family, ctx⟩ ∨
    FiniteCollision H (before.map Prod.fst ++ [contextFrame ctx]) ∨
    (contextFrame ctx ∉ before.map Prod.fst ∧ H (contextFrame ctx) = toOutput trigger.seed) := by
  rcases prefix_cover H before trigger (before_coherent H target program before raw next stopped)
    ctx accepted with selected | collision | late
  · exact Or.inl (by simp [selectRoot, parsed, selected])
  · exact Or.inr (Or.inl collision)
  · exact Or.inr (Or.inr late)

end
end HegemonCrypto.NativeLaunchRootPrefixSelector
