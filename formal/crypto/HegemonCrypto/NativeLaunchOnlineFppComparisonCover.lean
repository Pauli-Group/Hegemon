import HegemonCrypto.NativeLaunchOnlineFppPrefixCover

/-! Remove successful selection as a premise at an actual nonce-aware online
entry. Comparator keys never enter the selector. Actual trigger parsing, the
physical final-tail bound and both raw hash equations remain explicit.
The conclusion retains concrete finite collision, late-final and late-FPP
events. No native accepted-prefix availability, response semantic binding,
Rust/game/QROM refinement or production authority is claimed. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchOnlineFppComparisonCover
open NativeLaunchAdaptiveHistoryCodec (RawInput Word)
open NativeLaunchFppHistoryBinding (Digest finalFrame final_frame_digest_injective)
open NativeLaunchRecordedOracleGraph (toOutput)
open NativeLaunchPrefixFppSelector (scan_available parse_final_roundtrip)
open NativeLaunchRootPrefixSelector (RawOracle FiniteCollision before_coherent)
open NativeLaunchOnlinePrefixLedger (Entry run target selected_entry_stop)
open NativeLaunchOnlineFppPrefixCover
open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program Log)
noncomputable section
open Classical

theorem pair_available (H : RawOracle) (before : Log)
    (coherent : ∀ call ∈ before, call.2 = H call.1)
    (key : RawInput) (digest : Digest) (recorded : key ∈ before.map Prod.fst)
    (hash : H key = toOutput digest) : ∃ selected, pairKey before digest = some selected := by
  obtain ⟨call, member, same⟩ := List.mem_map.mp recorded
  have output : call.2 = toOutput digest := (coherent call member).trans (same ▸ hash)
  exact scan_available _ before call call.1 member (by simp [output])

theorem chain_available (H : RawOracle) (before : Log)
    (coherent : ∀ call ∈ before, call.2 = H call.1)
    (trigger : OpeningTrigger) (key : RawInput) (digest : Digest) (tail : List Word)
    (physical : 8 + tail.length < 2^64)
    (keyRecorded : key ∈ before.map Prod.fst)
    (finalRecorded : finalFrame trigger.family digest tail ∈ before.map Prod.fst)
    (keyHash : H key = toOutput digest)
    (finalHash : H (finalFrame trigger.family digest tail) = toOutput trigger.seed) :
    ∃ chain, selectChainFor before trigger = some chain := by
  obtain ⟨selected, keySelected⟩ := pair_available H before coherent key digest keyRecorded keyHash
  obtain ⟨call, member, same⟩ := List.mem_map.mp finalRecorded
  have output : call.2 = toOutput trigger.seed := (coherent call member).trans (same ▸ finalHash)
  apply scan_available (chainCandidate before trigger) before call
    ⟨selected, call.1, digest, tail⟩ member
  simp only [chainCandidate, same, parse_final_roundtrip trigger.family digest tail physical,
    Option.bind_eq_bind', Option.bind_some, output, if_true, keySelected]

theorem raw_equal_of_no_collision (H : RawOracle) (keys : List RawInput)
    (clean : ¬ FiniteCollision H keys) (left right : RawInput)
    (leftMem : left ∈ keys) (rightMem : right ∈ keys) (same : H left = H right) : left = right := by
  by_contra different
  exact clean ⟨left, leftMem, right, rightMem, different, same⟩

/-- No prior selected key, successful selection, positive recorded chain or
coherence premise. The actual online entry supplies coherence internally. -/
theorem actual_entry_key_cover {α : Type} (H : RawOracle) (program : Program α) (entry : Entry α)
    (member : entry ∈ (run H [] program).entries)
    (trigger : OpeningTrigger) (parsed : parseOpening entry.input = some trigger)
    (key : RawInput) (digest : Digest) (tail : List Word) (physical : 8 + tail.length < 2^64)
    (keyHash : H key = toOutput digest)
    (finalHash : H (finalFrame trigger.family digest tail) = toOutput trigger.seed) :
    (∃ chain, selectChain entry.before entry.input = some chain ∧ chain.key = key ∧
      chain.finalKey = finalFrame trigger.family digest tail ∧ chain.digest = digest) ∨
    FiniteCollision H (entry.before.map Prod.fst ++ [key, finalFrame trigger.family digest tail]) ∨
    (finalFrame trigger.family digest tail ∉ entry.before.map Prod.fst ∧
      H (finalFrame trigger.family digest tail) = toOutput trigger.seed) ∨
    (finalFrame trigger.family digest tail ∈ entry.before.map Prod.fst ∧
      key ∉ entry.before.map Prod.fst ∧ H key = toOutput digest) := by
  by_cases finalRecorded : finalFrame trigger.family digest tail ∈ entry.before.map Prod.fst
  · by_cases keyRecorded : key ∈ entry.before.map Prod.fst
    · by_cases collision : FiniteCollision H (entry.before.map Prod.fst ++ [key, finalFrame trigger.family digest tail])
      · exact Or.inr (Or.inl collision)
      · have coherent := before_coherent H (target entry.key) program entry.before entry.input entry.next
          (selected_entry_stop H program entry member)
        obtain ⟨chain, selected⟩ := chain_available H entry.before coherent trigger key digest tail
          physical keyRecorded finalRecorded keyHash finalHash
        obtain ⟨keyPair, finalPair, exactFinal⟩ := selected_chain_recorded entry.before trigger chain selected
        have finalEq : chain.finalKey = finalFrame trigger.family digest tail := by
          apply raw_equal_of_no_collision H _ collision
          · exact List.mem_append_left _ (List.mem_map.mpr ⟨_, finalPair, rfl⟩)
          · simp
          · exact (coherent _ finalPair).symm.trans finalHash.symm
        have digestEq : chain.digest = digest := final_frame_digest_injective trigger.family
          chain.digest digest chain.tail tail (exactFinal.symm.trans finalEq)
        have keyEq : chain.key = key := by
          apply raw_equal_of_no_collision H _ collision
          · exact List.mem_append_left _ (List.mem_map.mpr ⟨_, keyPair, rfl⟩)
          · simp
          · exact (coherent _ keyPair).symm.trans ((congrArg toOutput digestEq).trans keyHash.symm)
        apply Or.inl
        refine ⟨chain, ?_, keyEq, finalEq, digestEq⟩
        simp only [selectChain, parsed, Option.bind_eq_bind', Option.bind_some, selected]
    · exact Or.inr (Or.inr (Or.inr ⟨finalRecorded, keyRecorded, keyHash⟩))
  · exact Or.inr (Or.inr (Or.inl ⟨finalRecorded, finalHash⟩))

end
end HegemonCrypto.NativeLaunchOnlineFppComparisonCover
