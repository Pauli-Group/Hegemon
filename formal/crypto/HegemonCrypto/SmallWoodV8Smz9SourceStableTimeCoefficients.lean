import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericCoefficients
import HegemonCrypto.SmallWoodV8Smz9StableRetirementEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTimeCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRetirementEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F radixFourSum)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packedWord)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_timeLowPos_coefficient (pub : Nat → F) (digit : Fin 16) :
    actualCsrCoefficients pub (timeLowPos digit.val) = (liveMint pub) * ((4^digit.val : Nat) : F) := by
  fin_cases digit <;>
    norm_num only [timeLowPos,
      live_coefficient_304,actual_csr_coefficient_450,actual_csr_coefficient_451,actual_csr_coefficient_452,actual_csr_coefficient_453,actual_csr_coefficient_454,actual_csr_coefficient_455,actual_csr_coefficient_456,actual_csr_coefficient_457,actual_csr_coefficient_458,actual_csr_coefficient_459,actual_csr_coefficient_460,actual_csr_coefficient_461,actual_csr_coefficient_462,actual_csr_coefficient_463,actual_csr_coefficient_464,
      Nat.reduceAdd,Nat.reduceMul,Nat.reducePow,Nat.cast_ofNat,ite_true,ite_false]
  all_goals ring

theorem actual_timeLowNeg_coefficient (pub : Nat → F) (digit : Fin 16) :
    actualCsrCoefficients pub (timeLowNeg digit.val) = (-liveMint pub) * ((4^digit.val : Nat) : F) := by
  fin_cases digit <;>
    norm_num only [timeLowNeg,
      actual_csr_coefficient_432,actual_csr_coefficient_465,actual_csr_coefficient_466,actual_csr_coefficient_467,actual_csr_coefficient_468,actual_csr_coefficient_469,actual_csr_coefficient_470,actual_csr_coefficient_471,actual_csr_coefficient_472,actual_csr_coefficient_473,actual_csr_coefficient_474,actual_csr_coefficient_475,actual_csr_coefficient_476,actual_csr_coefficient_477,actual_csr_coefficient_478,actual_csr_coefficient_479,
      Nat.reduceAdd,Nat.reduceMul,Nat.reducePow,Nat.cast_ofNat,ite_true,ite_false]
  all_goals ring

theorem actual_timeHighPos_coefficient (pub : Nat → F) (digit : Fin 16) :
    actualCsrCoefficients pub (timeHighPos digit.val) = (liveMint pub) * ((4^digit.val : Nat) : F) := by
  fin_cases digit <;>
    norm_num only [timeHighPos,
      live_coefficient_304,actual_csr_coefficient_450,actual_csr_coefficient_481,actual_csr_coefficient_482,actual_csr_coefficient_483,actual_csr_coefficient_484,actual_csr_coefficient_485,actual_csr_coefficient_486,actual_csr_coefficient_487,actual_csr_coefficient_488,actual_csr_coefficient_489,actual_csr_coefficient_490,actual_csr_coefficient_491,actual_csr_coefficient_492,actual_csr_coefficient_493,actual_csr_coefficient_494,
      Nat.reduceAdd,Nat.reduceMul,Nat.reducePow,Nat.cast_ofNat,ite_true,ite_false]
  all_goals ring

theorem actual_timeHighNeg_coefficient (pub : Nat → F) (digit : Fin 16) :
    actualCsrCoefficients pub (timeHighNeg digit.val) = (-liveMint pub) * ((4^digit.val : Nat) : F) := by
  fin_cases digit <;>
    norm_num only [timeHighNeg,
      actual_csr_coefficient_432,actual_csr_coefficient_465,actual_csr_coefficient_495,actual_csr_coefficient_496,actual_csr_coefficient_497,actual_csr_coefficient_498,actual_csr_coefficient_499,actual_csr_coefficient_500,actual_csr_coefficient_501,actual_csr_coefficient_502,actual_csr_coefficient_503,actual_csr_coefficient_504,actual_csr_coefficient_505,actual_csr_coefficient_506,actual_csr_coefficient_507,actual_csr_coefficient_508,
      Nat.reduceAdd,Nat.reduceMul,Nat.reducePow,Nat.cast_ofNat,ite_true,ite_false]
  all_goals ring

theorem actual_retiredLowPos_coefficient (pub : Nat → F) (digit : Fin 16) :
    actualCsrCoefficients pub (retiredLowPos digit.val) = (1) * ((4^digit.val : Nat) : F) := by
  fin_cases digit <;>
    norm_num only [retiredLowPos,
      live_coefficient_265,actual_csr_coefficient_509,actual_csr_coefficient_510,actual_csr_coefficient_511,actual_csr_coefficient_512,actual_csr_coefficient_513,actual_csr_coefficient_514,actual_csr_coefficient_515,actual_csr_coefficient_516,actual_csr_coefficient_517,actual_csr_coefficient_518,actual_csr_coefficient_519,actual_csr_coefficient_520,actual_csr_coefficient_521,actual_csr_coefficient_522,actual_csr_coefficient_523,
      Nat.reduceAdd,Nat.reduceMul,Nat.reducePow,Nat.cast_ofNat,ite_true,ite_false]

theorem actual_retiredLowNeg_coefficient (pub : Nat → F) (digit : Fin 16) :
    actualCsrCoefficients pub (retiredLowNeg digit.val) = (-1) * ((4^digit.val : Nat) : F) := by
  fin_cases digit <;>
    norm_num only [retiredLowNeg,
      live_coefficient_158,actual_csr_coefficient_159,actual_csr_coefficient_160,actual_csr_coefficient_161,actual_csr_coefficient_162,actual_csr_coefficient_163,actual_csr_coefficient_164,actual_csr_coefficient_165,actual_csr_coefficient_166,actual_csr_coefficient_167,actual_csr_coefficient_168,actual_csr_coefficient_169,actual_csr_coefficient_170,actual_csr_coefficient_171,actual_csr_coefficient_172,actual_csr_coefficient_173,
      Nat.reduceAdd,Nat.reduceMul,Nat.reducePow,Nat.cast_ofNat,ite_true,ite_false]

theorem actual_retiredHighPos_coefficient (pub : Nat → F) (digit : Fin 16) :
    actualCsrCoefficients pub (retiredHighPos digit.val) = (1) * ((4^digit.val : Nat) : F) := by
  fin_cases digit <;>
    norm_num only [retiredHighPos,
      live_coefficient_265,actual_csr_coefficient_509,actual_csr_coefficient_525,actual_csr_coefficient_526,actual_csr_coefficient_527,actual_csr_coefficient_528,actual_csr_coefficient_529,actual_csr_coefficient_530,actual_csr_coefficient_531,actual_csr_coefficient_532,actual_csr_coefficient_533,actual_csr_coefficient_534,actual_csr_coefficient_535,actual_csr_coefficient_536,actual_csr_coefficient_537,actual_csr_coefficient_538,
      Nat.reduceAdd,Nat.reduceMul,Nat.reducePow,Nat.cast_ofNat,ite_true,ite_false]

theorem actual_retiredHighNeg_coefficient (pub : Nat → F) (digit : Fin 16) :
    actualCsrCoefficients pub (retiredHighNeg digit.val) = (-1) * ((4^digit.val : Nat) : F) := by
  fin_cases digit <;>
    norm_num only [retiredHighNeg,timeHighNegativePower,
      live_coefficient_158,actual_csr_coefficient_159,actual_csr_coefficient_210,actual_csr_coefficient_214,actual_csr_coefficient_218,actual_csr_coefficient_222,actual_csr_coefficient_226,actual_csr_coefficient_230,actual_csr_coefficient_234,actual_csr_coefficient_238,actual_csr_coefficient_242,actual_csr_coefficient_246,actual_csr_coefficient_250,actual_csr_coefficient_254,actual_csr_coefficient_258,actual_csr_coefficient_262,
      Nat.reduceAdd,Nat.reduceMul,Nat.reducePow,Nat.cast_ofNat,ite_true,ite_false]

theorem actual_terms_append (pub : Nat → F) (packed : List Nat) (left right : List (Nat × Nat)) :
    actualCsrTerms pub packed (left++right) = actualCsrTerms pub packed left + actualCsrTerms pub packed right := by
  simp only [actualCsrTerms,List.map_append,List.sum_append]

theorem actual_time_digit_terms (pub : Nat → F) (packed : List Nat) (start count : Nat)
    (coefficient : Nat → Nat) (scalar : F)
    (coefficients : ∀ i, i<count → actualCsrCoefficients pub (coefficient i) = scalar * ((4^i : Nat) : F)) :
    actualCsrTerms pub packed (timeDigitTerms start count coefficient) =
      scalar * (radixFourSum (fun i => packedWord packed (42432+start+i)) count : F) := by
  induction count with
  | zero => simp [timeDigitTerms,actualCsrTerms,radixFourSum]
  | succ n ih =>
    have prior := ih (by intro i bound; exact coefficients i (by omega))
    have expand : actualCsrTerms pub packed (timeDigitTerms start (n+1) coefficient) =
        actualCsrTerms pub packed (timeDigitTerms start n coefficient) +
          actualCsrCoefficients pub (coefficient n) * (packedWord packed (42432+start+n) : F) := by
      simp [timeDigitTerms,actualCsrTerms,List.range_succ,packedWord]
    rw [expand,prior,coefficients n (by omega),radix_four_sum_succ]
    simp only [Nat.cast_add,Nat.cast_mul]
    ring

theorem actual_time_high_terms (pub : Nat → F) (packed : List Nat) (start top : Nat)
    (coefficient : Nat → Nat) (scalar : F)
    (coefficients : ∀ i, i<16 → actualCsrCoefficients pub (coefficient i) = scalar * ((4^i : Nat) : F)) :
    actualCsrTerms pub packed (timeHighTerms start top coefficient) = scalar * (timeHigh packed start top : F) := by
  unfold timeHighTerms
  rw [actual_terms_append,actual_time_digit_terms pub packed (start+16) 15 coefficient scalar
    (by intro i bound; exact coefficients i (by omega))]
  simp only [actualCsrTerms,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    coefficients 15 (by decide),add_zero,timeHigh,Nat.cast_add,Nat.cast_mul,packedWord,Nat.add_assoc]
  ring
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableTimeCoefficients
