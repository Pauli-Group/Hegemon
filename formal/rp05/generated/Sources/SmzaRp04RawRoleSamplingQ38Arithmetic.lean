import SmzaRp04RawRoleSamplingCore
import SmzaQ38McaSourceBindingR2

/-!
# Actual RP04 q38 rejection arithmetic

This module isolates the power-of-two factorization used by the 50-word,
first-38-distinct decoder.  Division and remainder are proved through generic
natural-number identities rather than evaluating the Goldilocks modulus.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling

open HegemonCrypto.CmsClassicalDatabase
open V8Smz9RuntimeDistribution V8Smz9RuntimeRandomness
open V8Smz9RuntimeFieldLayout V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8Smz9HiddenLeafQrom
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdmissibleRootProbability
open SmzaQ38OracleExtraction SmzaQ38McaSourceBinding
open scoped BigOperators Classical

noncomputable section

set_option maxHeartbeats 1500000
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024
set_option Elab.async false

def q38DomainSize : Nat := SmzaQ38OracleExtraction.decsDomainSize
def q38OpeningCount : Nat := 38
def q38CandidateCount : Nat := 50
def q38Quotient : Nat := fieldModulus / q38DomainSize
def q38AcceptedCandidateCount : Nat := q38Quotient * q38DomainSize

/-- The power-of-two quotient in
`(2^64 - 2^32 + 1) = 2^23 * (2^41 - 2^9) + 1`. -/
def q38GoldilocksFactor : Nat := 2 ^ 41 - 2 ^ 9

theorem q38_sampling_geometry :
    q38DomainSize = 8388608 ∧ q38OpeningCount = 38 ∧
      q38CandidateCount = 50 := by
  refine ⟨?_, rfl, rfl⟩
  simpa [q38DomainSize] using
    SmzaQ38OracleExtraction.exact_extraction_geometry.2.2.1

theorem q38_domain_power : q38DomainSize = 2 ^ 23 := by
  calc
    q38DomainSize = 8388608 := q38_sampling_geometry.1
    _ = 2 ^ 23 := by rfl

theorem q38_goldilocks_power_formula :
    fieldModulus = 2 ^ 64 - 2 ^ 32 + 1 := by
  calc
    fieldModulus = 18446744069414584321 :=
      exact_runtime_rejection_geometry.2.1
    _ = 2 ^ 64 - 2 ^ 32 + 1 := by rfl

theorem q38_goldilocks_factorization :
    fieldModulus = q38DomainSize * q38GoldilocksFactor + 1 := by
  rw [q38_goldilocks_power_formula, q38_domain_power]
  unfold q38GoldilocksFactor
  have split64 : 64 = 23 + 41 := by rfl
  have split32 : 32 = 23 + 9 := by rfl
  rw [split64, split32, pow_add, pow_add, Nat.mul_sub_left_distrib]

theorem q38_one_lt_domain : 1 < q38DomainSize := by
  rw [q38_domain_power]
  exact Nat.pow_lt_pow_right (a := 2) (m := 0) (n := 23)
    (by omega) (by omega)

theorem q38_domain_size_positive : 0 < q38DomainSize :=
  Nat.zero_lt_of_lt q38_one_lt_domain

theorem q38_goldilocks_factor_positive : 0 < q38GoldilocksFactor := by
  unfold q38GoldilocksFactor
  exact Nat.sub_pos_iff_lt.mpr
    (Nat.pow_lt_pow_right (a := 2) (m := 9) (n := 41)
      (by omega) (by omega))

theorem q38_goldilocks_mod_domain_is_one :
    fieldModulus % q38DomainSize = 1 := by
  calc
    fieldModulus % q38DomainSize =
        (q38DomainSize * q38GoldilocksFactor + 1) % q38DomainSize :=
      congrArg (fun value => value % q38DomainSize)
        q38_goldilocks_factorization
    _ = 1 % q38DomainSize :=
      Nat.mul_add_mod q38DomainSize q38GoldilocksFactor 1
    _ = 1 := Nat.mod_eq_of_lt q38_one_lt_domain

theorem q38_quotient_eq_factor :
    q38Quotient = q38GoldilocksFactor := by
  unfold q38Quotient
  calc
    fieldModulus / q38DomainSize =
        (q38DomainSize * q38GoldilocksFactor + 1) / q38DomainSize :=
      congrArg (fun value => value / q38DomainSize)
        q38_goldilocks_factorization
    _ = q38GoldilocksFactor + 1 / q38DomainSize :=
      Nat.mul_add_div q38_domain_size_positive q38GoldilocksFactor 1
    _ = q38GoldilocksFactor + 0 :=
      congrArg (fun remainder => q38GoldilocksFactor + remainder)
        (Nat.div_eq_of_lt q38_one_lt_domain)
    _ = q38GoldilocksFactor := Nat.add_zero _

theorem q38_accepted_candidate_count_is_modulus_minus_one :
    q38AcceptedCandidateCount = fieldModulus - 1 := by
  calc
    q38AcceptedCandidateCount =
        q38GoldilocksFactor * q38DomainSize := by
      rw [q38AcceptedCandidateCount, q38_quotient_eq_factor]
    _ = q38DomainSize * q38GoldilocksFactor := Nat.mul_comm _ _
    _ = (q38DomainSize * q38GoldilocksFactor + 1) - 1 :=
      (Nat.add_sub_cancel _ _).symm
    _ = fieldModulus - 1 :=
      congrArg (fun value => value - 1)
        q38_goldilocks_factorization.symm

theorem q38_quotient_positive : 0 < q38Quotient := by
  rw [q38_quotient_eq_factor]
  exact q38_goldilocks_factor_positive

theorem position_lt_q38_domain (index : Position) :
    index.val < q38DomainSize := by
  change index.val < SmzaQ38OracleExtraction.decsDomainSize
  exact index.isLt

end
end HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling
