import HegemonCrypto.NativeLaunchOnlineRootPrefixCover

/-! Nonce-aware PIOP-opening first-prefix chain selection. The selector sees
only earlier recorded pairs and trigger bytes, never an oracle or desired key.
Exact successful parsing, selected-chain provenance and actual-entry replay
are proved. Comparison collision/late-key coverage, response semantics, native
Rust/game refinement and QROM remain OPEN; this is not a security endpoint. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchOnlineFppPrefixCover
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec
open NativeLaunchFppHistoryBinding (Digest finalFrame)
open NativeLaunchRecordedOracleGraph (toOutput)
open NativeLaunchPrefixFppSelector (scan scan_sound parseFinal parse_final_exact)
open NativeLaunchRootPrefixSelector (inferFamily decodeVector RawOracle before_coherent)
open NativeLaunchOnlinePrefixLedger (Entry run target classify selected_entry_stop selected_entry_replay source_counter_classification)
open NativeLaunchFirstQueryFreeze (Stopped stop trigger_matches)
open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program Log)
open SmallWood.V8SmzaOracleParser (RawDigest)
noncomputable section
open Classical

structure OpeningTrigger where
  family : Family
  nonce : Fin (2^32)
  seed : Digest
  counter : Word

def nonceWord (nonce : Fin (2^32)) : Word := ⟨nonce.val, lt_trans nonce.isLt (by decide)⟩
def openingWords (trigger : OpeningTrigger) : List Word :=
  List.ofFn (Fin.cons (nonceWord trigger.nonce) trigger.seed)
def openingFrame (trigger : OpeningTrigger) : RawInput :=
  sourceFrame trigger.family .piopOpening (openingWords trigger) trigger.counter

def unpackOpening (raw : RawInput) : Option OpeningTrigger := do
  let (profile, role, payload, counter) ← parseSourceFrame raw
  let family ← inferFamily profile
  if counterBound : counter < 2^64 then
    if role = roleDomain family .piopOpening then
      let words ← decodeVector 9 payload
      if nonceBound : (words 0).val < 2^32 then
        some ⟨family, ⟨(words 0).val, nonceBound⟩, (fun i => words i.succ), ⟨counter, counterBound⟩⟩
      else none
    else none
  else none

def parseOpening (raw : RawInput) : Option OpeningTrigger := do
  let trigger ← unpackOpening raw
  if raw = openingFrame trigger then some trigger else none

theorem parse_opening_exact {raw : RawInput} {trigger : OpeningTrigger}
    (parsed : parseOpening raw = some trigger) : raw = openingFrame trigger := by
  unfold parseOpening at parsed
  cases unpacked : unpackOpening raw with
  | none => simp [unpacked] at parsed
  | some found =>
      simp only [unpacked, Option.bind_eq_bind', Option.bind_some] at parsed
      split at parsed
      · next exactRaw => cases parsed; exact exactRaw
      · contradiction

structure Chain where
  key : RawInput
  finalKey : RawInput
  digest : Digest
  tail : List Word

def pairKey (before : Log) (digest : Digest) : Option RawInput :=
  scan (fun call => if call.2 = toOutput digest then some call.1 else none) before

def chainCandidate (before : Log) (trigger : OpeningTrigger) (call : RawInput × RawDigest) : Option Chain := do
  let (digest, tail) ← parseFinal trigger.family call.1
  if call.2 = toOutput trigger.seed then
    let key ← pairKey before digest
    some ⟨key, call.1, digest, tail⟩
  else none

def selectChainFor (before : Log) (trigger : OpeningTrigger) : Option Chain :=
  scan (chainCandidate before trigger) before

/-- Only actual recorded pairs and raw triggering input are selector arguments. -/
def selectChain (before : Log) (raw : RawInput) : Option Chain := do
  let trigger ← parseOpening raw
  selectChainFor before trigger

theorem pair_key_recorded (before : Log) (digest : Digest) (key : RawInput)
    (selected : pairKey before digest = some key) : (key, toOutput digest) ∈ before := by
  obtain ⟨call, member, found⟩ := scan_sound _ before key selected
  split at found
  · next output => cases found; simpa only [← output] using member
  · contradiction

theorem selected_chain_recorded (before : Log) (trigger : OpeningTrigger) (chain : Chain)
    (selected : selectChainFor before trigger = some chain) :
    (chain.key, toOutput chain.digest) ∈ before ∧
      (chain.finalKey, toOutput trigger.seed) ∈ before ∧
      chain.finalKey = finalFrame trigger.family chain.digest chain.tail := by
  obtain ⟨call, member, found⟩ := scan_sound _ before chain selected
  unfold chainCandidate at found
  cases parsed : parseFinal trigger.family call.1 with
  | none => simp [parsed] at found
  | some parts =>
      rcases parts with ⟨digest, tail⟩
      simp only [parsed, Option.bind_eq_bind', Option.bind_some] at found
      split at found
      · next output =>
          cases keyFound : pairKey before digest with
          | none => simp [keyFound] at found
          | some key =>
              simp only [keyFound, Option.bind_some, Option.some.injEq] at found
              subst chain
              exact ⟨pair_key_recorded before digest key keyFound,
                by simpa only [← output] using member, parse_final_exact trigger.family call.1 digest tail parsed⟩
      · contradiction

def chainSnapshot {α : Type} : Stopped α → Option Chain
  | .complete _ _ => none
  | .before before raw _ => selectChain before raw

theorem actual_entry_snapshot_replay {α : Type} (H G : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries)
    (agree : ∀ call ∈ entry.before, G call.1 = H call.1) :
    chainSnapshot (stop G (target entry.key) program) = selectChain entry.before entry.input := by
  rw [selected_entry_replay H G program entry member agree]
  rfl

/-- Selected-chain hash equations are derived from actual online provenance,
not supplied as a positive chronology/coherence certificate. -/
theorem actual_selected_chain_hashes {α : Type} (H : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries) (trigger : OpeningTrigger)
    (parsed : parseOpening entry.input = some trigger) (chain : Chain)
    (selected : selectChain entry.before entry.input = some chain) :
    H chain.key = toOutput chain.digest ∧ H chain.finalKey = toOutput trigger.seed ∧
      chain.finalKey = finalFrame trigger.family chain.digest chain.tail := by
  have selectedFor : selectChainFor entry.before trigger = some chain := by
    simpa only [selectChain, parsed, Option.bind_eq_bind', Option.bind_some] using selected
  obtain ⟨keyMem, finalMem, exactFinal⟩ := selected_chain_recorded entry.before trigger chain selectedFor
  have coherent := before_coherent H (target entry.key) program entry.before entry.input entry.next
    (selected_entry_stop H program entry member)
  exact ⟨(coherent _ keyMem).symm, (coherent _ finalMem).symm, exactFinal⟩

theorem actual_entry_opening_prefix {α : Type} (H : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries) (trigger : OpeningTrigger)
    (parsed : parseOpening entry.input = some trigger) :
    entry.key = (profileDomain trigger.family, roleDomain trigger.family .piopOpening,
      SmallWood.V8Smz9RawCounterCompiler.typedWordPayload (openingWords trigger)) := by
  have matched := trigger_matches H (target entry.key) program
  rw [selected_entry_stop H program entry member] at matched
  change target entry.key entry.input = true at matched
  have keyed : classify entry.input = some entry.key := of_decide_eq_true matched
  rw [parse_opening_exact parsed] at keyed
  change classify (sourceFrame trigger.family .piopOpening (openingWords trigger) trigger.counter) = some entry.key at keyed
  rw [source_counter_classification trigger.family .piopOpening (openingWords trigger)
    trigger.counter (by simp [openingWords])] at keyed
  exact (Option.some.inj keyed).symm

end
end HegemonCrypto.NativeLaunchOnlineFppPrefixCover
