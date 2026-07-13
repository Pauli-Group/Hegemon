import Hegemon.Bytes

set_option exponentiation.threshold 512

namespace Hegemon
namespace Native
namespace NativeBackendAlgebra

def goldilocksModulus : Nat := 18446744069414584321
def activeChallengeBits : Nat := 63
def activeChallengeValueCount : Nat := 9223372036854775807
def activeFoldChallengeCount : Nat := 5
def activeRingDegree : Nat := 54
def activeDigitBound : Nat := 255
def activeMatrixRows : Nat := 11
def activeMaxCommitmentMessageRingElements : Nat := 76
def activeMaxClaimedReceiptRootLeaves : Nat := 128
def activeTuplePreimageBound : Nat := 3 ^ activeFoldChallengeCount
def activeTupleSampleSpace : Nat := 2 ^ (64 * activeFoldChallengeCount)
def activeTranscriptSoundnessBits : Nat := 312
def activeCompositionLossBits : Nat := 7
def activeTranscriptFloorBits : Nat := 305
def activeAmbientCoefficientDimension : Nat :=
  activeMaxCommitmentMessageRingElements * activeRingDegree
def activeConservativeEuclideanBound : Nat := 16336
def activeLiveMessageRingElements : Nat := 12
def activeLiveCoefficientDimension : Nat :=
  activeLiveMessageRingElements * activeRingDegree
def activeLiveEuclideanBound : Nat := 6492

theorem active_tuple_preimage_bound_is_243 :
    activeTuplePreimageBound = 243 := by
  decide

theorem active_tuple_probability_bound_supports_312_bits :
    activeTuplePreimageBound * 2 ^ activeTranscriptSoundnessBits ≤
      activeTupleSampleSpace := by
  decide

theorem active_tuple_probability_bound_does_not_support_313_bits :
    activeTupleSampleSpace < activeTuplePreimageBound * 2 ^ 313 := by
  decide

theorem active_receipt_root_composition_loss_is_exact :
    activeMaxClaimedReceiptRootLeaves = 2 ^ activeCompositionLossBits := by
  decide

theorem active_composed_probability_bound_supports_305_bits :
    activeTuplePreimageBound
        * activeMaxClaimedReceiptRootLeaves
        * 2 ^ activeTranscriptFloorBits ≤
      activeTupleSampleSpace := by
  decide

theorem active_composed_probability_bound_does_not_support_306_bits :
    activeTupleSampleSpace <
      activeTuplePreimageBound
        * activeMaxClaimedReceiptRootLeaves
        * 2 ^ 306 := by
  decide

theorem active_ambient_coefficient_dimension_is_4104 :
    activeAmbientCoefficientDimension = 4104 := by
  decide

theorem active_conservative_euclidean_bound_is_sound :
    activeDigitBound ^ 2 * activeAmbientCoefficientDimension ≤
      activeConservativeEuclideanBound ^ 2 := by
  decide

theorem active_live_coefficient_dimension_is_648 :
    activeLiveCoefficientDimension = 648 := by
  decide

theorem active_live_euclidean_bound_is_sound :
    activeDigitBound ^ 2 * activeLiveCoefficientDimension ≤
      activeLiveEuclideanBound ^ 2 := by
  decide

def reduceActiveFoldChallenge (raw : Nat) : Nat :=
  raw % activeChallengeValueCount + 1

theorem active_reducer_preimage_quotient_at_most_two
    {raw : Nat}
    (rawBound : raw < 2 ^ 64) :
    raw / activeChallengeValueCount ≤ 2 := by
  unfold activeChallengeValueCount
  omega

theorem active_reducer_preimage_has_one_of_three_representatives
    {raw : Nat}
    (rawBound : raw < 2 ^ 64) :
    raw = raw % activeChallengeValueCount
      ∨ raw = raw % activeChallengeValueCount + activeChallengeValueCount
      ∨ raw = raw % activeChallengeValueCount + 2 * activeChallengeValueCount := by
  have quotientBound :=
    active_reducer_preimage_quotient_at_most_two rawBound
  have decomposition :=
    Nat.mod_add_div raw activeChallengeValueCount
  unfold activeChallengeValueCount at quotientBound decomposition ⊢
  omega

theorem reduced_active_fold_challenge_positive (raw : Nat) :
    0 < reduceActiveFoldChallenge raw := by
  unfold reduceActiveFoldChallenge
  omega

theorem reduced_active_fold_challenge_at_most_value_count (raw : Nat) :
    reduceActiveFoldChallenge raw ≤ activeChallengeValueCount := by
  have reduced :=
    Nat.mod_lt raw (by decide : 0 < activeChallengeValueCount)
  unfold reduceActiveFoldChallenge
  omega

def activeChallengePolynomial
    (raw0 raw1 raw2 raw3 raw4 : Nat) : Nat -> Nat
  | 0 => reduceActiveFoldChallenge raw0
  | 1 => reduceActiveFoldChallenge raw1
  | 2 => reduceActiveFoldChallenge raw2
  | 3 => reduceActiveFoldChallenge raw3
  | 4 => reduceActiveFoldChallenge raw4
  | _ => 0

theorem active_challenge_polynomial_is_nonzero
    (raw0 raw1 raw2 raw3 raw4 : Nat) :
    ∃ coefficientIndex,
      coefficientIndex < activeFoldChallengeCount
        ∧ activeChallengePolynomial raw0 raw1 raw2 raw3 raw4 coefficientIndex ≠ 0 := by
  refine ⟨0, by decide, ?_⟩
  unfold activeChallengePolynomial
  exact Nat.ne_of_gt (reduced_active_fold_challenge_positive raw0)

def PolynomialSupportedBelowActiveFoldDegree
    (polynomial : Nat -> Nat) : Prop :=
  ∀ coefficientIndex,
    activeFoldChallengeCount ≤ coefficientIndex ->
      polynomial coefficientIndex = 0

theorem active_challenge_polynomial_supported_below_active_fold_degree
    (raw0 raw1 raw2 raw3 raw4 : Nat) :
    PolynomialSupportedBelowActiveFoldDegree
      (activeChallengePolynomial raw0 raw1 raw2 raw3 raw4) := by
  intro coefficientIndex outsideSupport
  unfold activeFoldChallengeCount at outsideSupport
  have notZero : coefficientIndex ≠ 0 := by omega
  have notOne : coefficientIndex ≠ 1 := by omega
  have notTwo : coefficientIndex ≠ 2 := by omega
  have notThree : coefficientIndex ≠ 3 := by omega
  have notFour : coefficientIndex ≠ 4 := by omega
  simp [activeChallengePolynomial]

def ActiveLowDegreeUnitAssumption
    (isUnit : (Nat -> Nat) -> Prop) : Prop :=
  ∀ polynomial,
    PolynomialSupportedBelowActiveFoldDegree polynomial ->
    (∃ coefficientIndex,
      coefficientIndex < activeFoldChallengeCount
        ∧ polynomial coefficientIndex ≠ 0) ->
    isUnit polynomial

theorem active_challenge_polynomial_is_unit_under_low_degree_unit_assumption
    (isUnit : (Nat -> Nat) -> Prop)
    (lowDegreeUnits : ActiveLowDegreeUnitAssumption isUnit)
    (raw0 raw1 raw2 raw3 raw4 : Nat) :
    isUnit (activeChallengePolynomial raw0 raw1 raw2 raw3 raw4) :=
  lowDegreeUnits
    (activeChallengePolynomial raw0 raw1 raw2 raw3 raw4)
    (active_challenge_polynomial_supported_below_active_fold_degree
      raw0 raw1 raw2 raw3 raw4)
    (active_challenge_polynomial_is_nonzero raw0 raw1 raw2 raw3 raw4)

def canonicalGoldilocksCoefficient (value : Nat) : Nat :=
  value % goldilocksModulus

theorem canonical_goldilocks_coefficient_below_modulus (value : Nat) :
    canonicalGoldilocksCoefficient value < goldilocksModulus := by
  exact Nat.mod_lt value (by decide : 0 < goldilocksModulus)

theorem canonical_goldilocks_coefficient_idempotent (value : Nat) :
    canonicalGoldilocksCoefficient (canonicalGoldilocksCoefficient value) =
      canonicalGoldilocksCoefficient value := by
  unfold canonicalGoldilocksCoefficient
  exact Nat.mod_eq_of_lt (Nat.mod_lt value (by decide : 0 < goldilocksModulus))

def digitDifference (left right : Nat) : Int :=
  (left : Int) - (right : Int)

theorem bounded_digits_have_bounded_centered_difference
    {left right : Nat}
    (leftBound : left ≤ activeDigitBound)
    (rightBound : right ≤ activeDigitBound) :
    (-255 : Int) ≤ digitDifference left right
      ∧ digitDifference left right ≤ (255 : Int) := by
  unfold digitDifference activeDigitBound at *
  have leftInt : (left : Int) ≤ (255 : Int) :=
    Int.ofNat_le.mpr leftBound
  have rightInt : (right : Int) ≤ (255 : Int) :=
    Int.ofNat_le.mpr rightBound
  omega

structure FoldOutputData where
  challenges : List Nat
  parentRows : List (List Nat)
  parentCommitmentDigest : List Nat
  parentStatementDigest : List Nat
  proofDigest : List Nat
deriving DecidableEq, Repr

def foldOutputMatchesRecomputed
    (recomputed candidate : FoldOutputData) : Bool :=
  decide (candidate = recomputed)

theorem fold_output_matches_recomputed_iff_equality
    (recomputed candidate : FoldOutputData) :
    foldOutputMatchesRecomputed recomputed candidate = true ↔ candidate = recomputed := by
  simp [foldOutputMatchesRecomputed]

theorem matching_fold_outputs_are_unique
    {recomputed first second : FoldOutputData}
    (firstAccepted : foldOutputMatchesRecomputed recomputed first = true)
    (secondAccepted : foldOutputMatchesRecomputed recomputed second = true) :
    first = second := by
  have firstEq :=
    (fold_output_matches_recomputed_iff_equality recomputed first).mp firstAccepted
  have secondEq :=
    (fold_output_matches_recomputed_iff_equality recomputed second).mp secondAccepted
  rw [firstEq, secondEq]

structure ChallengeReductionCase where
  name : String
  raw : Nat
deriving DecidableEq, Repr

def challengeReductionCases : List ChallengeReductionCase :=
  [ { name := "zero", raw := 0 },
    { name := "one", raw := 1 },
    { name := "last-in-range", raw := activeChallengeValueCount - 1 },
    { name := "range-boundary", raw := activeChallengeValueCount },
    { name := "range-boundary-plus-one", raw := activeChallengeValueCount + 1 },
    { name := "u64-max", raw := 18446744073709551615 } ]

structure CanonicalCoefficientCase where
  name : String
  value : Nat
deriving DecidableEq, Repr

def canonicalCoefficientCases : List CanonicalCoefficientCase :=
  [ { name := "zero", value := 0 },
    { name := "modulus-minus-one", value := goldilocksModulus - 1 },
    { name := "modulus", value := goldilocksModulus },
    { name := "modulus-plus-one", value := goldilocksModulus + 1 },
    { name := "u64-max", value := 18446744073709551615 } ]

theorem challenge_reduction_cases_stay_in_active_range :
    ∀ testCase ∈ challengeReductionCases,
      0 < reduceActiveFoldChallenge testCase.raw
        ∧ reduceActiveFoldChallenge testCase.raw ≤ activeChallengeValueCount := by
  decide

theorem canonical_coefficient_cases_are_canonical :
    ∀ testCase ∈ canonicalCoefficientCases,
      canonicalGoldilocksCoefficient testCase.value < goldilocksModulus := by
  decide

end NativeBackendAlgebra
end Native
end Hegemon
