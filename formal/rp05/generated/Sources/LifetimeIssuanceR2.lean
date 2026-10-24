import HegemonCrypto.NativeMonetaryCap

/-! Compatibility entry point for the RP05 monetary conservation consumers.
The public cap statements are unchanged. Their proofs now use the maintained
exact epoch-budget and floor-prefix schedule, whose two levels telescope.
The prior constant-per-epoch halving approximation is not used as an issuance
premise. Historical proof sources and their receipts remain unchanged.
-/
set_option maxRecDepth 10000
open scoped BigOperators
namespace Hegemon.Consensus

/-- Retained numerical diagnostic, not the current issuance formula. -/
theorem subsidy_epoch63_zero : initialSubsidy / pow2 63 = 0 := by decide

theorem subsidy_after_last_epoch {h : Nat}
    (late : 63 ≤ (h - 1) / halvingInterval) : blockSubsidy h = 0 :=
  HegemonCrypto.NativeMonetaryCap.subsidy_after_last_epoch (by omega)

/-- Retained numerical inequality for the legacy schedule only. Current supply
conservation below uses exact epoch-budget telescoping instead. -/
theorem halving_bucket_budget :
    halvingInterval * (∑ epoch ∈ Finset.range 63, initialSubsidy / pow2 epoch)
      ≤ maxMonetarySupply := by decide

/-- A finite set counts each height once; no schedule-supply bound is assumed. -/
theorem blockSubsidy_finset_sum_le (heights : Finset Nat) :
    (∑ height ∈ heights, blockSubsidy height) ≤ maxMonetarySupply :=
  HegemonCrypto.NativeMonetaryCap.blockSubsidy_finset_sum_le_cap heights

theorem blockSubsidy_prefix_sum_le (length : Nat) :
    (∑ height ∈ Finset.range length, blockSubsidy height) ≤ maxMonetarySupply :=
  blockSubsidy_finset_sum_le _

end Hegemon.Consensus

#print axioms Hegemon.Consensus.blockSubsidy_finset_sum_le
