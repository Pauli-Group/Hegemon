import HegemonCrypto.NativePrivateSpendSpongeBridge
import HegemonCrypto.NativePrivateSpendCompffPrimitiveGames

/-! Pure COMPFF01 evaluator transport. Staged, uncompiled. No acceptance,
output law, collision resistance or compiler-refinement premise. -/
namespace HegemonCrypto.NativePrivateSpendCurrentEvaluatorIdentity
open NativePrivateSpendSymbolicBridge NativePrivateSpendLocalSemantics
open NativeLaunchConstraintAdapterBridge
namespace P
export Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives
  (compressionFrame compressionModeMarker rawPermutation compress14)
end P
noncomputable section
set_option autoImplicit false
variable [Fact (Nat.Prime modulus)]

def digestNaturals (z : Nat → K) (digest : DigestWords) : List Nat :=
  List.ofFn fun lane => (read z (digest lane)).val

omit [Fact (Nat.Prime modulus)] in
theorem digestNaturals_getD (z : Nat → K) (digest : DigestWords)
    (i : Nat) (hi : i < 7) :
    (digestNaturals z digest).getD i 0 = (read z (digest ⟨i, hi⟩)).val := by
  simp only [digestNaturals, List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    dif_pos hi, Option.getD_some]

/-- Both frames read the same canonical source operands, domain and COMPFF01
marker. In particular this is not the historical raw-compressor suite marker. -/
theorem compression_frame_exact (z : Nat → K) (domain : K)
    (left right : DigestWords) :
    stateNaturals z (compressFrame domain left right) =
      P.compressionFrame domain.val (digestNaturals z left) (digestNaturals z right) := by
  change (List.range 16).map _ = (List.range 16).map _
  apply List.map_congr_left
  intro i hi
  have bound : i < 16 := List.mem_range.mp hi
  simp only [stateValue, words, dif_pos bound, compressFrame]
  dsimp only [Hegemon.Transaction.Poseidon2V8SemanticSpecification.digestWords]
  by_cases first : i < 7
  · simpa only [dif_pos first, if_pos first] using
      (digestNaturals_getD z left i first).symm
  · by_cases second : i < 14
    · have offset : i - 7 < 7 := by omega
      simpa only [dif_neg first, dif_pos second, if_neg first, if_pos second] using
        (digestNaturals_getD z right (i-7) offset).symm
    · by_cases tag : i = 14
      · simp only [dif_neg first, dif_neg second, if_neg first, if_neg second,
          if_pos tag, NativeLaunchConstraintAdapterBridge.read]
      · simpa only [dif_neg first, dif_neg second, if_neg first, if_neg second,
          if_neg tag, NativeLaunchConstraintAdapterBridge.read,
          P.compressionModeMarker] using
          (ZMod.val_ofNat_of_lt (by decide : 0x434f4d5046463031 < modulus))

/-- Extraction adds the ORIGINAL left operand after the common permutation. -/
theorem compression_feedforward_exact (z : Nat → K) (domain : K)
    (left right : DigestWords) :
    (List.range 7).map (fun lane =>
      Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd
        ((Hegemon.Transaction.Poseidon2Width16Kernel.permutation
          (stateNaturals z (compressFrame domain left right))).getD lane 0)
        ((digestNaturals z left).getD lane 0)) =
      P.compress14 domain.val (digestNaturals z left) (digestNaturals z right) := by
  rw [compression_frame_exact]
  rfl
end
end HegemonCrypto.NativePrivateSpendCurrentEvaluatorIdentity
