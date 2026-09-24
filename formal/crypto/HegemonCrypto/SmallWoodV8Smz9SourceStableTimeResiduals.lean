import HegemonCrypto.SmallWoodV8Smz9SourceStableTimeCoefficients

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTimeResiduals
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceStableTimeCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRetirementEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_timeLowPos_terms (pub : Nat → F) (packed : List Nat) (start : Nat) :
    actualCsrTerms pub packed (timeDigitTerms start 16 timeLowPos) =
      (liveMint pub) * (timeLow packed start : F) := by
  simpa only [timeLow] using actual_time_digit_terms pub packed start 16 timeLowPos (liveMint pub)
    (by intro i bound; exact actual_timeLowPos_coefficient pub ⟨i,bound⟩)

theorem actual_timeLowNeg_terms (pub : Nat → F) (packed : List Nat) (start : Nat) :
    actualCsrTerms pub packed (timeDigitTerms start 16 timeLowNeg) =
      (-liveMint pub) * (timeLow packed start : F) := by
  simpa only [timeLow] using actual_time_digit_terms pub packed start 16 timeLowNeg (-liveMint pub)
    (by intro i bound; exact actual_timeLowNeg_coefficient pub ⟨i,bound⟩)

theorem actual_timeHighPos_terms (pub : Nat → F) (packed : List Nat) (start top : Nat) :
    actualCsrTerms pub packed (timeHighTerms start top timeHighPos) =
      (liveMint pub) * (timeHigh packed start top : F) := by
  exact actual_time_high_terms pub packed start top timeHighPos (liveMint pub)
    (by intro i bound; exact actual_timeHighPos_coefficient pub ⟨i,bound⟩)

theorem actual_timeHighNeg_terms (pub : Nat → F) (packed : List Nat) (start top : Nat) :
    actualCsrTerms pub packed (timeHighTerms start top timeHighNeg) =
      (-liveMint pub) * (timeHigh packed start top : F) := by
  exact actual_time_high_terms pub packed start top timeHighNeg (-liveMint pub)
    (by intro i bound; exact actual_timeHighNeg_coefficient pub ⟨i,bound⟩)

theorem actual_retiredLowPos_terms (pub : Nat → F) (packed : List Nat) (start : Nat) :
    actualCsrTerms pub packed (timeDigitTerms start 16 retiredLowPos) =
      (1) * (timeLow packed start : F) := by
  simpa only [timeLow] using actual_time_digit_terms pub packed start 16 retiredLowPos (1)
    (by intro i bound; exact actual_retiredLowPos_coefficient pub ⟨i,bound⟩)

theorem actual_retiredLowNeg_terms (pub : Nat → F) (packed : List Nat) (start : Nat) :
    actualCsrTerms pub packed (timeDigitTerms start 16 retiredLowNeg) =
      (-1) * (timeLow packed start : F) := by
  simpa only [timeLow] using actual_time_digit_terms pub packed start 16 retiredLowNeg (-1)
    (by intro i bound; exact actual_retiredLowNeg_coefficient pub ⟨i,bound⟩)

theorem actual_retiredHighPos_terms (pub : Nat → F) (packed : List Nat) (start top : Nat) :
    actualCsrTerms pub packed (timeHighTerms start top retiredHighPos) =
      (1) * (timeHigh packed start top : F) := by
  exact actual_time_high_terms pub packed start top retiredHighPos (1)
    (by intro i bound; exact actual_retiredHighPos_coefficient pub ⟨i,bound⟩)

theorem actual_retiredHighNeg_terms (pub : Nat → F) (packed : List Nat) (start top : Nat) :
    actualCsrTerms pub packed (timeHighTerms start top retiredHighNeg) =
      (-1) * (timeHigh packed start top : F) := by
  exact actual_time_high_terms pub packed start top retiredHighNeg (-1)
    (by intro i bound; exact actual_retiredHighNeg_coefficient pub ⟨i,bound⟩)

theorem actual_time_low_residual (pub : Nat → F) (packed : List Nat) (index : Nat) :
    actualCsrResidual pub packed (timeAdditionLowAttempt index) =
      let spec := timeAddition index
      liveMint pub * ((timeLow packed (timeSpec spec.x).start : F) +
        (timeLow packed (timeSpec spec.y).start : F) -
        (timeLow packed (timeSpec spec.z).start : F) - 4294967296 * (packed.getD (42112+spec.carry) 0 : F)) := by
  simp only [actualCsrResidual,timeAdditionLowAttempt,attempt,actual_terms_append,
    actual_timeLowPos_terms,actual_timeLowNeg_terms]
  simp only [actualCsrTerms,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    actual_csr_coefficient_480,live_coefficient_0]
  ring

theorem actual_time_high_residual (pub : Nat → F) (packed : List Nat) (index : Nat) :
    actualCsrResidual pub packed (timeAdditionHighAttempt index) =
      let spec := timeAddition index
      liveMint pub * ((timeHigh packed (timeSpec spec.x).start (timeSpec spec.x).topLane : F) +
        (timeHigh packed (timeSpec spec.y).start (timeSpec spec.y).topLane : F) +
        (packed.getD (42112+spec.carry) 0 : F) -
        (timeHigh packed (timeSpec spec.z).start (timeSpec spec.z).topLane : F)) := by
  simp only [actualCsrResidual,timeAdditionHighAttempt,attempt,actual_terms_append,
    actual_timeHighPos_terms,actual_timeHighNeg_terms]
  simp only [actualCsrTerms,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    live_coefficient_304,live_coefficient_0]
  ring

theorem actual_retirement_low_residual (pub : Nat → F) (packed : List Nat) (index : Nat) :
    actualCsrResidual pub packed (retirementLowAttempt index) =
      let spec := retirementAddition index
      (packed.getD (42329+2*index) 0 : F) -
        (timeLow packed (timeSpec spec.x).start : F) -
        (timeLow packed (timeSpec spec.y).start : F) +
        (timeLow packed (timeSpec spec.z).start : F) +
        4294967296 * (packed.getD (42112+spec.carry) 0 : F) - 1 := by
  simp only [actualCsrResidual,retirementLowAttempt,attempt,actual_terms_append,
    actual_retiredLowPos_terms,actual_retiredLowNeg_terms]
  simp only [actualCsrTerms,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    actual_csr_coefficient_524,live_coefficient_1]
  ring

theorem actual_retirement_high_residual (pub : Nat → F) (packed : List Nat) (index : Nat) :
    actualCsrResidual pub packed (retirementHighAttempt index) =
      let spec := retirementAddition index
      (packed.getD (42330+2*index) 0 : F) -
        (timeHigh packed (timeSpec spec.x).start (timeSpec spec.x).topLane : F) -
        (timeHigh packed (timeSpec spec.y).start (timeSpec spec.y).topLane : F) -
        (packed.getD (42112+spec.carry) 0 : F) +
        (timeHigh packed (timeSpec spec.z).start (timeSpec spec.z).topLane : F) := by
  simp only [actualCsrResidual,retirementHighAttempt,attempt,actual_terms_append,
    actual_retiredHighPos_terms,actual_retiredHighNeg_terms]
  simp only [actualCsrTerms,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    live_coefficient_158,live_coefficient_1,live_coefficient_0]
  ring

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableTimeResiduals
