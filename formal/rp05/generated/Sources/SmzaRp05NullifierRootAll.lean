import SmzaRp05NullifierRootChunk00
import SmzaRp05NullifierRootChunk01
import SmzaRp05NullifierRootChunk02
import SmzaRp05NullifierRootChunk03
import SmzaRp05NullifierRootChunk04
import SmzaRp05NullifierRootChunk05
import SmzaRp05NullifierRootChunk06
import SmzaRp05NullifierRootChunk07
import SmzaRp05NullifierRootChunk08
import SmzaRp05NullifierRootChunk09
import SmzaRp05NullifierRootChunk10

/-! Exact all-wire aggregator for the independently checked finite root chunks. -/
namespace HegemonCrypto.SmallWood.SmzaRp05NullifierRootAll

open HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk00

set_option autoImplicit false

private theorem offset_bound {wire offset count : Nat}
    (lower : offset ≤ wire) (upper : wire < count + offset) :
    wire - offset < count := by
  rw [Nat.sub_lt_iff_lt_add lower]
  exact upper

theorem root_shape_all (wire : Nat) (bound : wire < 332) : RootShape wire := by
  by_cases h16 : wire < 16
  · exact HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk00.root_shape wire h16
  · by_cases h96 : wire < 96
    · have lower : 16 ≤ wire := Nat.le_of_not_gt h16
      have upper : wire < 80 + 16 := by simpa using h96
      have offsetBound := offset_bound lower upper
      have reconstruct := Nat.add_sub_of_le lower
      simpa [reconstruct] using
        HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk01.root_shape
          (wire - 16) offsetBound
    · by_cases h176 : wire < 176
      · have lower : 96 ≤ wire := Nat.le_of_not_gt h96
        have upper : wire < 80 + 96 := by simpa using h176
        have offsetBound := offset_bound lower upper
        have reconstruct := Nat.add_sub_of_le lower
        simpa [reconstruct] using
          HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk02.root_shape
            (wire - 96) offsetBound
      · by_cases h196 : wire < 196
        · have lower : 176 ≤ wire := Nat.le_of_not_gt h176
          have upper : wire < 20 + 176 := by simpa using h196
          have offsetBound := offset_bound lower upper
          have reconstruct := Nat.add_sub_of_le lower
          simpa [reconstruct] using
            HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk03.root_shape
              (wire - 176) offsetBound
        · by_cases h216 : wire < 216
          · have lower : 196 ≤ wire := Nat.le_of_not_gt h196
            have upper : wire < 20 + 196 := by simpa using h216
            have offsetBound := offset_bound lower upper
            have reconstruct := Nat.add_sub_of_le lower
            simpa [reconstruct] using
              HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk04.root_shape
                (wire - 196) offsetBound
          · by_cases h236 : wire < 236
            · have lower : 216 ≤ wire := Nat.le_of_not_gt h216
              have upper : wire < 20 + 216 := by simpa using h236
              have offsetBound := offset_bound lower upper
              have reconstruct := Nat.add_sub_of_le lower
              simpa [reconstruct] using
                HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk05.root_shape
                  (wire - 216) offsetBound
            · by_cases h256 : wire < 256
              · have lower : 236 ≤ wire := Nat.le_of_not_gt h236
                have upper : wire < 20 + 236 := by simpa using h256
                have offsetBound := offset_bound lower upper
                have reconstruct := Nat.add_sub_of_le lower
                simpa [reconstruct] using
                  HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk06.root_shape
                    (wire - 236) offsetBound
              · by_cases h276 : wire < 276
                · have lower : 256 ≤ wire := Nat.le_of_not_gt h256
                  have upper : wire < 20 + 256 := by simpa using h276
                  have offsetBound := offset_bound lower upper
                  have reconstruct := Nat.add_sub_of_le lower
                  simpa [reconstruct] using
                    HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk07.root_shape
                      (wire - 256) offsetBound
                · by_cases h296 : wire < 296
                  · have lower : 276 ≤ wire := Nat.le_of_not_gt h276
                    have upper : wire < 20 + 276 := by simpa using h296
                    have offsetBound := offset_bound lower upper
                    have reconstruct := Nat.add_sub_of_le lower
                    simpa [reconstruct] using
                      HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk08.root_shape
                        (wire - 276) offsetBound
                  · by_cases h316 : wire < 316
                    · have lower : 296 ≤ wire := Nat.le_of_not_gt h296
                      have upper : wire < 20 + 296 := by simpa using h316
                      have offsetBound := offset_bound lower upper
                      have reconstruct := Nat.add_sub_of_le lower
                      simpa [reconstruct] using
                        HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk09.root_shape
                          (wire - 296) offsetBound
                    · have lower : 316 ≤ wire := Nat.le_of_not_gt h316
                      have upper : wire < 16 + 316 := by simpa using bound
                      have offsetBound := offset_bound lower upper
                      have reconstruct := Nat.add_sub_of_le lower
                      simpa [reconstruct] using
                        HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk10.root_shape
                          (wire - 316) offsetBound

end HegemonCrypto.SmallWood.SmzaRp05NullifierRootAll
