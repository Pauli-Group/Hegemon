import HegemonCrypto.SmallWoodV8Smz9SourceLiveCsrTable
import HegemonCrypto.SmallWoodV8Smz9SourceDenseCsr

namespace HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients

open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

def liveMint (pub : Nat → F) : F := if pub 83 = 1 then 1 else 0
def liveBurn (pub : Nat → F) : F := if pub 83 = 2 then 1 else 0
def liveEnabled (pub : Nat → F) : F := liveMint pub + liveBurn pub
def liveAnyInput (pub : Nat → F) : F := pub 0 + pub 1 - pub 0 * pub 1


@[simp] theorem live_coefficient_0 (pub : Nat → F) :
    actualCsrCoefficients pub 0 = 0 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[0]? = some (.constant 0) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_1 (pub : Nat → F) :
    actualCsrCoefficients pub 1 = 1 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[1]? = some (.constant 1) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_2 (pub : Nat → F) :
    actualCsrCoefficients pub 2 = 2 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[2]? = some (.constant 2) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_4 (pub : Nat → F) :
    actualCsrCoefficients pub 4 = pub 0 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[4]? = some (.publicWord 0) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_5 (pub : Nat → F) :
    actualCsrCoefficients pub 5 = pub 1 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[5]? = some (.publicWord 1) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_87 (pub : Nat → F) :
    actualCsrCoefficients pub 87 = pub 83 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[87]? = some (.publicWord 83) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_88 (pub : Nat → F) :
    actualCsrCoefficients pub 88 = pub 84 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[88]? = some (.publicWord 84) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_89 (pub : Nat → F) :
    actualCsrCoefficients pub 89 = pub 85 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[89]? = some (.publicWord 85) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_90 (pub : Nat → F) :
    actualCsrCoefficients pub 90 = pub 86 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[90]? = some (.publicWord 86) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_91 (pub : Nat → F) :
    actualCsrCoefficients pub 91 = pub 87 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[91]? = some (.publicWord 87) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_92 (pub : Nat → F) :
    actualCsrCoefficients pub 92 = pub 88 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[92]? = some (.publicWord 88) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_93 (pub : Nat → F) :
    actualCsrCoefficients pub 93 = pub 89 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[93]? = some (.publicWord 89) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_94 (pub : Nat → F) :
    actualCsrCoefficients pub 94 = pub 90 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[94]? = some (.publicWord 90) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_95 (pub : Nat → F) :
    actualCsrCoefficients pub 95 = pub 91 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[95]? = some (.publicWord 91) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_96 (pub : Nat → F) :
    actualCsrCoefficients pub 96 = pub 92 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[96]? = some (.publicWord 92) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_97 (pub : Nat → F) :
    actualCsrCoefficients pub 97 = pub 93 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[97]? = some (.publicWord 93) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_117 (pub : Nat → F) :
    actualCsrCoefficients pub 117 = pub 113 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[117]? = some (.publicWord 113) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_118 (pub : Nat → F) :
    actualCsrCoefficients pub 118 = pub 114 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[118]? = some (.publicWord 114) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_119 (pub : Nat → F) :
    actualCsrCoefficients pub 119 = pub 115 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[119]? = some (.publicWord 115) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_120 (pub : Nat → F) :
    actualCsrCoefficients pub 120 = pub 116 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[120]? = some (.publicWord 116) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_121 (pub : Nat → F) :
    actualCsrCoefficients pub 121 = pub 117 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[121]? = some (.publicWord 117) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_122 (pub : Nat → F) :
    actualCsrCoefficients pub 122 = pub 118 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[122]? = some (.publicWord 118) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_123 (pub : Nat → F) :
    actualCsrCoefficients pub 123 = pub 119 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[123]? = some (.publicWord 119) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_124 (pub : Nat → F) :
    actualCsrCoefficients pub 124 = 1 - pub 0 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[124]? = some (.sub 1 4) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_1,live_coefficient_4,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_158 (pub : Nat → F) :
    actualCsrCoefficients pub 158 = -1 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[158]? = some (.sub 0 1) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_0,live_coefficient_1,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_193 (pub : Nat → F) :
    actualCsrCoefficients pub 193 = pub 0 * pub 1 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[193]? = some (.mul 4 5) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_4,live_coefficient_5,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_195 (pub : Nat → F) :
    actualCsrCoefficients pub 195 = pub 1 * (1 - pub 0) := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[195]? = some (.mul 5 124) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_5,live_coefficient_124,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_265 (pub : Nat → F) :
    actualCsrCoefficients pub 265 = 1 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[265]? = some (.sub 0 158) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_0,live_coefficient_158,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_304 (pub : Nat → F) :
    actualCsrCoefficients pub 304 = liveMint pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[304]? = some (.selectEqual 87 1 1 0) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_87,live_coefficient_1,live_coefficient_0,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_305 (pub : Nat → F) :
    actualCsrCoefficients pub 305 = liveBurn pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[305]? = some (.selectEqual 87 2 1 0) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_87,live_coefficient_2,live_coefficient_1,live_coefficient_0,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_306 (pub : Nat → F) :
    actualCsrCoefficients pub 306 = liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[306]? = some (.add 304 305) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_304,live_coefficient_305,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_307 (pub : Nat → F) :
    actualCsrCoefficients pub 307 = 1 - liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[307]? = some (.sub 1 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_1,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_308 (pub : Nat → F) :
    actualCsrCoefficients pub 308 = 1 - liveMint pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[308]? = some (.sub 1 304) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_1,live_coefficient_304,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_309 (pub : Nat → F) :
    actualCsrCoefficients pub 309 = pub 113 * liveBurn pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[309]? = some (.mul 117 305) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_117,live_coefficient_305,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_310 (pub : Nat → F) :
    actualCsrCoefficients pub 310 = pub 114 * liveBurn pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[310]? = some (.mul 118 305) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_118,live_coefficient_305,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_311 (pub : Nat → F) :
    actualCsrCoefficients pub 311 = pub 115 * liveBurn pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[311]? = some (.mul 119 305) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_119,live_coefficient_305,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_312 (pub : Nat → F) :
    actualCsrCoefficients pub 312 = pub 116 * liveBurn pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[312]? = some (.mul 120 305) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_120,live_coefficient_305,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_313 (pub : Nat → F) :
    actualCsrCoefficients pub 313 = pub 117 * liveBurn pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[313]? = some (.mul 121 305) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_121,live_coefficient_305,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_314 (pub : Nat → F) :
    actualCsrCoefficients pub 314 = pub 118 * liveBurn pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[314]? = some (.mul 122 305) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_122,live_coefficient_305,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_315 (pub : Nat → F) :
    actualCsrCoefficients pub 315 = pub 119 * liveBurn pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[315]? = some (.mul 123 305) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_123,live_coefficient_305,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_316 (pub : Nat → F) :
    actualCsrCoefficients pub 316 = (((pub 84).val / 2 ^ 0) % 2 : Nat) := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[316]? = some (.bit 88 0) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_88,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_317 (pub : Nat → F) :
    actualCsrCoefficients pub 317 = (((pub 84).val / 2 ^ 1) % 2 : Nat) := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[317]? = some (.bit 88 1) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_88,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_318 (pub : Nat → F) :
    actualCsrCoefficients pub 318 = (((pub 84).val / 2 ^ 2) % 2 : Nat) := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[318]? = some (.bit 88 2) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_88,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_319 (pub : Nat → F) :
    actualCsrCoefficients pub 319 = (((pub 84).val / 2 ^ 3) % 2 : Nat) := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[319]? = some (.bit 88 3) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_88,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_320 (pub : Nat → F) :
    actualCsrCoefficients pub 320 = -liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[320]? = some (.sub 0 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_0,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_321 (pub : Nat → F) :
    actualCsrCoefficients pub 321 = -liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[321]? = some (.mul 158 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_158,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_322 (pub : Nat → F) :
    actualCsrCoefficients pub 322 = liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[322]? = some (.sub 0 321) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_0,live_coefficient_321,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_323 (pub : Nat → F) :
    actualCsrCoefficients pub 323 = -liveMint pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[323]? = some (.sub 0 304) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_0,live_coefficient_304,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_324 (pub : Nat → F) :
    actualCsrCoefficients pub 324 = pub 86 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[324]? = some (.mul 90 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_90,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_325 (pub : Nat → F) :
    actualCsrCoefficients pub 325 = 1 - liveEnabled pub + pub 86 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[325]? = some (.add 307 324) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_307,live_coefficient_324,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_326 (pub : Nat → F) :
    actualCsrCoefficients pub 326 = pub 87 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[326]? = some (.mul 91 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_91,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_327 (pub : Nat → F) :
    actualCsrCoefficients pub 327 = 1 - liveEnabled pub + pub 87 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[327]? = some (.add 307 326) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_307,live_coefficient_326,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_328 (pub : Nat → F) :
    actualCsrCoefficients pub 328 = pub 88 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[328]? = some (.mul 92 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_92,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_329 (pub : Nat → F) :
    actualCsrCoefficients pub 329 = pub 89 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[329]? = some (.mul 93 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_93,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_330 (pub : Nat → F) :
    actualCsrCoefficients pub 330 = pub 90 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[330]? = some (.mul 94 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_94,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_331 (pub : Nat → F) :
    actualCsrCoefficients pub 331 = pub 91 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[331]? = some (.mul 95 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_95,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_332 (pub : Nat → F) :
    actualCsrCoefficients pub 332 = pub 92 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[332]? = some (.mul 96 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_96,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_333 (pub : Nat → F) :
    actualCsrCoefficients pub 333 = pub 93 * liveEnabled pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[333]? = some (.mul 97 306) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_97,live_coefficient_306,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_334 (pub : Nat → F) :
    actualCsrCoefficients pub 334 = pub 0 + pub 1 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[334]? = some (.add 4 5) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_4,live_coefficient_5,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_335 (pub : Nat → F) :
    actualCsrCoefficients pub 335 = liveAnyInput pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[335]? = some (.sub 334 193) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_334,live_coefficient_193,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_336 (pub : Nat → F) :
    actualCsrCoefficients pub 336 = pub 0 * liveAnyInput pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[336]? = some (.mul 4 335) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_4,live_coefficient_335,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_337 (pub : Nat → F) :
    actualCsrCoefficients pub 337 = pub 1 * (1 - pub 0) * liveAnyInput pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[337]? = some (.mul 195 335) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_195,live_coefficient_335,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_338 (pub : Nat → F) :
    actualCsrCoefficients pub 338 = 1 - liveAnyInput pub := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[338]? = some (.sub 1 335) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_1,live_coefficient_335,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_339 (pub : Nat → F) :
    actualCsrCoefficients pub 339 = -(pub 0 * liveAnyInput pub) := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[339]? = some (.sub 0 336) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_0,live_coefficient_336,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

@[simp] theorem live_coefficient_340 (pub : Nat → F) :
    actualCsrCoefficients pub 340 = -(pub 1 * (1 - pub 0) * liveAnyInput pub) := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[340]? = some (.sub 0 337) by decide)
  simpa only [expressionField,Nat.cast_zero,Nat.cast_one,Nat.cast_ofNat,live_coefficient_0,live_coefficient_337,
    liveMint,liveBurn,liveEnabled,liveAnyInput,zero_sub,neg_neg,neg_one_mul,mul_one,mul_comm] using equation

def selectedLiveCoefficientNodes : List Nat := [0,1,2,4,5,87,88,89,90,91,92,93,94,95,96,97,117,118,119,120,121,122,123,124,158,193,195,265,304,305,306,307,308,309,310,311,312,313,314,315,316,317,318,319,320,321,322,323,324,325,326,327,328,329,330,331,332,333,334,335,336,337,338,339,340]

def liveCoefficientValue (pub : Nat → F) : Nat → F
  | 0 => 0
  | 1 => 1
  | 2 => 2
  | 4 => pub 0
  | 5 => pub 1
  | 87 => pub 83
  | 88 => pub 84
  | 89 => pub 85
  | 90 => pub 86
  | 91 => pub 87
  | 92 => pub 88
  | 93 => pub 89
  | 94 => pub 90
  | 95 => pub 91
  | 96 => pub 92
  | 97 => pub 93
  | 117 => pub 113
  | 118 => pub 114
  | 119 => pub 115
  | 120 => pub 116
  | 121 => pub 117
  | 122 => pub 118
  | 123 => pub 119
  | 124 => 1 - pub 0
  | 158 => -1
  | 193 => pub 0 * pub 1
  | 195 => pub 1 * (1 - pub 0)
  | 265 => 1
  | 304 => liveMint pub
  | 305 => liveBurn pub
  | 306 => liveEnabled pub
  | 307 => 1 - liveEnabled pub
  | 308 => 1 - liveMint pub
  | 309 => pub 113 * liveBurn pub
  | 310 => pub 114 * liveBurn pub
  | 311 => pub 115 * liveBurn pub
  | 312 => pub 116 * liveBurn pub
  | 313 => pub 117 * liveBurn pub
  | 314 => pub 118 * liveBurn pub
  | 315 => pub 119 * liveBurn pub
  | 316 => (((pub 84).val / 2 ^ 0) % 2 : Nat)
  | 317 => (((pub 84).val / 2 ^ 1) % 2 : Nat)
  | 318 => (((pub 84).val / 2 ^ 2) % 2 : Nat)
  | 319 => (((pub 84).val / 2 ^ 3) % 2 : Nat)
  | 320 => -liveEnabled pub
  | 321 => -liveEnabled pub
  | 322 => liveEnabled pub
  | 323 => -liveMint pub
  | 324 => pub 86 * liveEnabled pub
  | 325 => 1 - liveEnabled pub + pub 86 * liveEnabled pub
  | 326 => pub 87 * liveEnabled pub
  | 327 => 1 - liveEnabled pub + pub 87 * liveEnabled pub
  | 328 => pub 88 * liveEnabled pub
  | 329 => pub 89 * liveEnabled pub
  | 330 => pub 90 * liveEnabled pub
  | 331 => pub 91 * liveEnabled pub
  | 332 => pub 92 * liveEnabled pub
  | 333 => pub 93 * liveEnabled pub
  | 334 => pub 0 + pub 1
  | 335 => liveAnyInput pub
  | 336 => pub 0 * liveAnyInput pub
  | 337 => pub 1 * (1 - pub 0) * liveAnyInput pub
  | 338 => 1 - liveAnyInput pub
  | 339 => -(pub 0 * liveAnyInput pub)
  | 340 => -(pub 1 * (1 - pub 0) * liveAnyInput pub)
  | _ => 0

theorem actual_live_coefficient (pub : Nat → F) (node : Nat)
    (member : node ∈ selectedLiveCoefficientNodes) :
    actualCsrCoefficients pub node = liveCoefficientValue pub node := by
  simp only [selectedLiveCoefficientNodes,List.mem_cons,List.not_mem_nil,or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact live_coefficient_0 pub
  · exact live_coefficient_1 pub
  · exact live_coefficient_2 pub
  · exact live_coefficient_4 pub
  · exact live_coefficient_5 pub
  · exact live_coefficient_87 pub
  · exact live_coefficient_88 pub
  · exact live_coefficient_89 pub
  · exact live_coefficient_90 pub
  · exact live_coefficient_91 pub
  · exact live_coefficient_92 pub
  · exact live_coefficient_93 pub
  · exact live_coefficient_94 pub
  · exact live_coefficient_95 pub
  · exact live_coefficient_96 pub
  · exact live_coefficient_97 pub
  · exact live_coefficient_117 pub
  · exact live_coefficient_118 pub
  · exact live_coefficient_119 pub
  · exact live_coefficient_120 pub
  · exact live_coefficient_121 pub
  · exact live_coefficient_122 pub
  · exact live_coefficient_123 pub
  · exact live_coefficient_124 pub
  · exact live_coefficient_158 pub
  · exact live_coefficient_193 pub
  · exact live_coefficient_195 pub
  · exact live_coefficient_265 pub
  · exact live_coefficient_304 pub
  · exact live_coefficient_305 pub
  · exact live_coefficient_306 pub
  · exact live_coefficient_307 pub
  · exact live_coefficient_308 pub
  · exact live_coefficient_309 pub
  · exact live_coefficient_310 pub
  · exact live_coefficient_311 pub
  · exact live_coefficient_312 pub
  · exact live_coefficient_313 pub
  · exact live_coefficient_314 pub
  · exact live_coefficient_315 pub
  · exact live_coefficient_316 pub
  · exact live_coefficient_317 pub
  · exact live_coefficient_318 pub
  · exact live_coefficient_319 pub
  · exact live_coefficient_320 pub
  · exact live_coefficient_321 pub
  · exact live_coefficient_322 pub
  · exact live_coefficient_323 pub
  · exact live_coefficient_324 pub
  · exact live_coefficient_325 pub
  · exact live_coefficient_326 pub
  · exact live_coefficient_327 pub
  · exact live_coefficient_328 pub
  · exact live_coefficient_329 pub
  · exact live_coefficient_330 pub
  · exact live_coefficient_331 pub
  · exact live_coefficient_332 pub
  · exact live_coefficient_333 pub
  · exact live_coefficient_334 pub
  · exact live_coefficient_335 pub
  · exact live_coefficient_336 pub
  · exact live_coefficient_337 pub
  · exact live_coefficient_338 pub
  · exact live_coefficient_339 pub
  · exact live_coefficient_340 pub

end


end HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
