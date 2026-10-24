import HegemonCrypto.NativeLaunchFppResponseHistory
import HegemonCrypto.NativeLaunchMerklePathBinding

/-! Finite prefixHistory-derived chain selection. The selector reads H only on prefixHistory
members and has no wire/matrix/point/rebuilt-key argument. Exact native final
frames decode unrestricted 64-bit words and are checked by re-encoding. The
cover is deterministic for one instance; real chronological freezing, causal
matrix/response selection, Rust refinement, QROM and release gates stay open. -/
set_option autoImplicit false
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchPrefixFppSelector
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput profileDomain parseSourceFrame)
open NativeLaunchRelationModelStatement
open NativeLaunchFppHistoryBinding
open NativeLaunchCommitmentResponseBinding
open NativeLaunchFppResponseHistory (zeroResponse rebuiltKey)
open NativeLaunchMerklePathBinding (encodeRole role_frame_roundtrip)
open SmallWood
open SmallWood.NativeLaunchRelationModelResponse
open SmallWood.V8Smz9McaRecovery (BoundedResponse)
open SmallWood.V8Smz9RawCounterCompiler (typedWordPayload typed_word_payload_length)
noncomputable section
open Classical

/-- Full u64 words, not Goldilocks field elements. Each chunk is exactly8bytes. -/
def readWords : Nat → RawInput → Option (List Word × RawInput)
  | 0, raw => some ([], raw)
  | count+1, raw => do
      let (bytes, rest) ← readFixed 8 raw
      if bound : decodeLE bytes < 2^64 then
        let (words, suffix) ← readWords count rest
        some (⟨decodeLE bytes, bound⟩ :: words, suffix)
      else none

theorem read_words_roundtrip (words : List Word) (suffix : RawInput) :
    readWords words.length (typedWordPayload words ++ suffix) = some (words, suffix) := by
  induction words with
  | nil => rfl
  | cons word words ih =>
      have modulus : word.val % 18446744073709551616 = word.val := Nat.mod_eq_of_lt word.isLt
      simp [readWords, typedWordPayload, List.append_assoc,
        readFixed_append (encodeLE_length 8 word.val), decodeLE_encodeLE, modulus, ih,
        Option.bind_eq_bind']

def unpack (payload : RawInput) : Option (Digest × List Word) := do
  let (words, suffix) ← readWords (payload.length / 8) payload
  if suffix = [] ∧ 8 ≤ words.length then
    some ((fun index => words.getD index.val 0), words.drop 8)
  else none

theorem unpack_roundtrip (digest : Digest) (tail : List Word) :
    unpack (typedWordPayload (List.ofFn digest ++ tail)) = some (digest, tail) := by
  have words := read_words_roundtrip (List.ofFn digest ++ tail) []
  simp only [List.append_nil] at words
  have projection : (fun index : Fin 8 => (List.ofFn digest ++ tail).getD index.val 0) = digest := by
    funext index
    rw [List.getD_append _ _ _ _ (by simp)]
    simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn, dif_pos index.isLt, Option.getD_some]
  have drop : (List.ofFn digest ++ tail).drop 8 = tail := by
    simpa only [List.length_ofFn] using (List.drop_left (l₁ := List.ofFn digest) (l₂ := tail))
  unfold unpack
  rw [typed_word_payload_length, Nat.mul_div_cancel_left _ (by decide : 0 < 8), words]
  change (if ([] : RawInput) = [] ∧ 8 ≤ (List.ofFn digest ++ tail).length then
    some ((fun index : Fin 8 => (List.ofFn digest ++ tail).getD index.val 0), (List.ofFn digest ++ tail).drop 8)
    else none) = some (digest, tail)
  rw [if_pos (by simp), projection, drop]

def parseFinal (family : Family) (raw : RawInput) : Option (Digest × List Word) := do
  let (profile, role, payload, counter) ← parseSourceFrame raw
  if profile = profileDomain family ∧ role = finalRole ∧ counter = 0 then
    let (digest, tail) ← unpack payload
    if raw = finalFrame family digest tail then some (digest, tail) else none
  else none

theorem parse_final_roundtrip (family : Family) (digest : Digest) (tail : List Word)
    (physical : 8 + tail.length < 2^64) :
    parseFinal family (finalFrame family digest tail) = some (digest, tail) := by
  have raw : finalFrame family digest tail = encodeRole family finalRole (List.ofFn digest ++ tail) :=
    final_frame_is_raw_preimage family digest tail
  have framed := role_frame_roundtrip family finalRole (List.ofFn digest ++ tail)
    (by decide) (by simpa only [List.length_append, List.length_ofFn, Nat.reducePow] using physical)
  have parsed : parseSourceFrame (finalFrame family digest tail) =
      some (profileDomain family, finalRole, typedWordPayload (List.ofFn digest ++ tail), 0) := by
    rw [raw]
    exact framed
  simp only [parseFinal, parsed, Option.bind_eq_bind', Option.bind_some, and_self, if_true, unpack_roundtrip]

theorem parse_final_exact (family : Family) (raw : RawInput) (digest : Digest) (tail : List Word)
    (success : parseFinal family raw = some (digest, tail)) : raw = finalFrame family digest tail := by
  unfold parseFinal at success
  cases framing : parseSourceFrame raw with
  | none => simp [framing] at success
  | some parts =>
      rcases parts with ⟨profile, role, payload, counter⟩
      simp only [framing, Option.bind_eq_bind', Option.bind_some] at success
      split at success
      · cases parsed : unpack payload with
        | none => simp [parsed] at success
        | some result =>
            rcases result with ⟨d, t⟩
            simp only [parsed, Option.bind_some] at success
            split at success
            · next exactRaw => cases success; exact exactRaw
            · contradiction
      · contradiction

def scan {α β : Type} (f : α → Option β) : List α → Option β
  | [] => none
  | value :: rest => match f value with | some result => some result | none => scan f rest

theorem scan_sound {α β : Type} (f : α → Option β) (values : List α) (result : β)
    (success : scan f values = some result) : ∃ value ∈ values, f value = some result := by
  induction values with
  | nil => simp [scan] at success
  | cons value rest ih =>
      cases found : f value with
      | none =>
          have tail := ih (by simpa only [scan, found] using success)
          obtain ⟨chosen, member, same⟩ := tail
          exact ⟨chosen, List.mem_cons_of_mem _ member, same⟩
      | some chosen =>
          have same : chosen = result := by simpa only [scan, found, Option.some.injEq] using success
          exact ⟨value, List.mem_cons_self, same ▸ found⟩

theorem scan_none {α β : Type} (f : α → Option β) (values : List α) :
    scan f values = none ↔ ∀ value ∈ values, f value = none := by
  induction values with
  | nil => simp [scan]
  | cons value rest ih =>
      cases found : f value <;> simp [scan, found, ih]

theorem scan_available {α β : Type} (f : α → Option β) (values : List α) (value : α) (result : β)
    (member : value ∈ values) (found : f value = some result) : ∃ chosen, scan f values = some chosen := by
  cases resultScan : scan f values with
  | none => have impossible := (scan_none f values).mp resultScan value member; rw [found] at impossible; contradiction
  | some chosen => exact ⟨chosen, rfl⟩

def keyFor (H : Oracle) (prefixHistory : History) (digest : Digest) : Option RawInput :=
  scan (fun key => if H key = digest then some key else none) prefixHistory

def candidate (H : Oracle) (prefixHistory : History) (family : Family) (claimed : Digest) (final : RawInput) :
    Option (RawInput × List Word) := do
  let (digest, tail) ← parseFinal family final
  if H final = claimed then
    let key ← keyFor H prefixHistory digest
    some (key, tail)
  else none

def select (H : Oracle) (prefixHistory : History) (family : Family) (claimed : Digest) : Option (RawInput × List Word) :=
  scan (candidate H prefixHistory family claimed) prefixHistory

theorem key_for_sound (H : Oracle) (prefixHistory : History) (digest : Digest) (key : RawInput)
    (success : keyFor H prefixHistory digest = some key) : key ∈ prefixHistory ∧ H key = digest := by
  obtain ⟨found, member, selected⟩ := scan_sound _ prefixHistory key success
  split at selected
  · next same => cases selected; exact ⟨member, same⟩
  · contradiction

theorem select_recorded (H : Oracle) (prefixHistory : History) (family : Family) (claimed : Digest)
    (key : RawInput) (tail : List Word) (success : select H prefixHistory family claimed = some (key, tail)) :
    RecordedChain H prefixHistory family key tail claimed := by
  obtain ⟨final, member, found⟩ := scan_sound _ prefixHistory (key, tail) success
  unfold candidate at found
  cases parsed : parseFinal family final with
  | none => simp [parsed] at found
  | some result =>
      rcases result with ⟨digest, priorTail⟩
      simp only [parsed, Option.bind_eq_bind', Option.bind_some] at found
      split at found
      · next accepted =>
          cases chosen : keyFor H prefixHistory digest with
          | none => simp [chosen] at found
          | some priorKey =>
              simp only [chosen, Option.bind_some, Option.some.injEq, Prod.mk.injEq] at found
              rcases found with ⟨rfl, rfl⟩
              obtain ⟨keyMember, hash⟩ := key_for_sound H prefixHistory digest priorKey chosen
              have exactFinal := parse_final_exact family final digest priorTail parsed
              rw [← hash] at exactFinal
              exact ⟨keyMember, exactFinal ▸ member, exactFinal ▸ accepted⟩
      · contradiction

theorem select_available (H : Oracle) (prefixHistory : History) (family : Family) (key : RawInput)
    (tail : List Word) (claimed : Digest) (physical : 8 + tail.length < 2^64)
    (keyMember : key ∈ prefixHistory) (finalMember : finalFrame family (H key) tail ∈ prefixHistory)
    (accepted : H (finalFrame family (H key) tail) = claimed) :
    ∃ result, select H prefixHistory family claimed = some result := by
  obtain ⟨chosen, selected⟩ := scan_available (fun k => if H k = H key then some k else none)
    prefixHistory key key keyMember (by simp)
  apply scan_available (candidate H prefixHistory family claimed) prefixHistory (finalFrame family (H key) tail)
    (chosen, tail) finalMember
  simp [candidate, parse_final_roundtrip family (H key) tail physical, accepted, keyFor, selected]

theorem scan_congr_on {α β : Type} (f g : α → Option β) (values : List α)
    (agree : ∀ value ∈ values, f value = g value) : scan f values = scan g values := by
  induction values with
  | nil => rfl
  | cons value rest ih =>
      rw [scan, scan, agree value List.mem_cons_self]
      cases found : g value with
      | none => exact ih (fun item member => agree item (List.mem_cons_of_mem _ member))
      | some result => rfl

theorem key_for_prefix_invariant (H G : Oracle) (prefixHistory : History) (digest : Digest)
    (agree : ∀ key ∈ prefixHistory, H key = G key) :
    keyFor H prefixHistory digest = keyFor G prefixHistory digest := by
  apply scan_congr_on
  intro key member
  rw [agree key member]

/-- Checked extensional locality: oracle changes outside the supplied finite
prefixHistory cannot affect the selected key/tail. No chronological law is inferred. -/
theorem select_prefix_invariant (H G : Oracle) (prefixHistory : History) (family : Family) (claimed : Digest)
    (agree : ∀ key ∈ prefixHistory, H key = G key) :
    select H prefixHistory family claimed = select G prefixHistory family claimed := by
  apply scan_congr_on
  intro final member
  unfold candidate
  cases parsed : parseFinal family final with
  | none => rfl
  | some result =>
      rcases result with ⟨digest, tail⟩
      simp only [Option.bind_eq_bind', Option.bind_some]
      rw [agree final member, key_for_prefix_invariant H G prefixHistory digest agree]

def selectedResponse (H : Oracle) (prefixHistory : History) (branch : Branch) (claimed : Digest) :
    BoundedResponse Goldilocks (Fin 5) (degree branch) :=
  match select H prefixHistory (NativeLaunchCommitmentReadback.family branch) claimed with
  | none => zeroResponse branch
  | some (key, _) => match decodeFppResponse branch key with
    | none => zeroResponse branch
    | some decoded => decoded.response

/-- No supplied selected chain, prior key/tail, response equality or provenance
success premise. The two late cases concern the actual reconstructed keys. -/
theorem response_or_collision_or_late {branch : Branch} {Position : Type*}
    (H : Oracle) (prefixHistory : History) (leading : Digest)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix)
    (tail : List Word) (claimed : Digest) (physical : 8 + tail.length < 2^64)
    (accepted : reconstructedDigest H (NativeLaunchCommitmentReadback.family branch)
      (rebuiltKey leading statement point wire matrix) tail = claimed) :
    selectedResponse H prefixHistory branch claimed = calculatedResponse point wire matrix ∨
    RelevantCollision H (relevantInputs H prefixHistory (NativeLaunchCommitmentReadback.family branch)
      (rebuiltKey leading statement point wire matrix) tail) ∨
    (reconstructedFinal H (NativeLaunchCommitmentReadback.family branch)
      (rebuiltKey leading statement point wire matrix) tail ∉ prefixHistory ∧
      reconstructedDigest H (NativeLaunchCommitmentReadback.family branch)
        (rebuiltKey leading statement point wire matrix) tail = claimed) ∨
    (reconstructedFinal H (NativeLaunchCommitmentReadback.family branch)
      (rebuiltKey leading statement point wire matrix) tail ∈ prefixHistory ∧
      rebuiltKey leading statement point wire matrix ∉ prefixHistory ∧
      parseFinal (NativeLaunchCommitmentReadback.family branch)
        (reconstructedFinal H (NativeLaunchCommitmentReadback.family branch)
          (rebuiltKey leading statement point wire matrix) tail) =
        some (H (rebuiltKey leading statement point wire matrix), tail)) := by
  by_cases finalMember : reconstructedFinal H (NativeLaunchCommitmentReadback.family branch)
      (rebuiltKey leading statement point wire matrix) tail ∈ prefixHistory
  · by_cases keyMember : rebuiltKey leading statement point wire matrix ∈ prefixHistory
    · by_cases collision : RelevantCollision H (relevantInputs H prefixHistory
          (NativeLaunchCommitmentReadback.family branch) (rebuiltKey leading statement point wire matrix) tail)
      · exact Or.inr (Or.inl collision)
      · obtain ⟨⟨key, priorTail⟩, selected⟩ := select_available H prefixHistory
          (NativeLaunchCommitmentReadback.family branch) (rebuiltKey leading statement point wire matrix)
          tail claimed physical keyMember finalMember accepted
        have chain := select_recorded H prefixHistory (NativeLaunchCommitmentReadback.family branch) claimed key priorTail selected
        have same := accepted_digest_binds_raw_fpp H prefixHistory (NativeLaunchCommitmentReadback.family branch)
          key (rebuiltKey leading statement point wire matrix) priorTail tail claimed chain accepted collision
        apply Or.inl
        simp only [selectedResponse, selected]
        rw [same]
        simp only [rebuiltKey, decode_restored_commitment]
    · exact Or.inr (Or.inr (Or.inr ⟨finalMember, keyMember,
        parse_final_roundtrip _ _ tail physical⟩))
  · exact Or.inr (Or.inr (Or.inl ⟨finalMember, accepted⟩))

end
end HegemonCrypto.NativeLaunchPrefixFppSelector
