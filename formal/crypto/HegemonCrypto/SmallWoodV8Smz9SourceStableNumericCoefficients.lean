import HegemonCrypto.SmallWoodV8Smz9SourceDenseCsr
import HegemonCrypto.SmallWoodV8Smz9SourceLiveCsrCoefficients

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableNumericCoefficients
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem actual_csr_coefficient_98 (pub : Nat → F) :
 actualCsrCoefficients pub 98 = pub 94 := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[98]? = some (.publicWord 94) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_113 (pub : Nat → F) :
 actualCsrCoefficients pub 113 = pub 109 := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[113]? = some (.publicWord 109) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_114 (pub : Nat → F) :
 actualCsrCoefficients pub 114 = pub 110 := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[114]? = some (.publicWord 110) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_115 (pub : Nat → F) :
 actualCsrCoefficients pub 115 = pub 111 := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[115]? = some (.publicWord 111) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_116 (pub : Nat → F) :
 actualCsrCoefficients pub 116 = pub 112 := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[116]? = some (.publicWord 112) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_128 (pub : Nat → F) :
 actualCsrCoefficients pub 128 = (4 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[128]? = some (.constant 4) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_129 (pub : Nat → F) :
 actualCsrCoefficients pub 129 = (16 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[129]? = some (.mul 128 128) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_130 (pub : Nat → F) :
 actualCsrCoefficients pub 130 = (64 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[130]? = some (.mul 128 129) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_129, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_131 (pub : Nat → F) :
 actualCsrCoefficients pub 131 = (256 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[131]? = some (.mul 128 130) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_130, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_132 (pub : Nat → F) :
 actualCsrCoefficients pub 132 = (1024 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[132]? = some (.mul 128 131) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_131, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_133 (pub : Nat → F) :
 actualCsrCoefficients pub 133 = (4096 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[133]? = some (.mul 128 132) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_132, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_134 (pub : Nat → F) :
 actualCsrCoefficients pub 134 = (16384 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[134]? = some (.mul 128 133) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_133, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_135 (pub : Nat → F) :
 actualCsrCoefficients pub 135 = (65536 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[135]? = some (.mul 128 134) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_134, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_136 (pub : Nat → F) :
 actualCsrCoefficients pub 136 = (262144 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[136]? = some (.mul 128 135) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_135, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_137 (pub : Nat → F) :
 actualCsrCoefficients pub 137 = (1048576 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[137]? = some (.mul 128 136) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_136, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_138 (pub : Nat → F) :
 actualCsrCoefficients pub 138 = (4194304 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[138]? = some (.mul 128 137) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_137, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_139 (pub : Nat → F) :
 actualCsrCoefficients pub 139 = (16777216 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[139]? = some (.mul 128 138) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_138, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_140 (pub : Nat → F) :
 actualCsrCoefficients pub 140 = (67108864 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[140]? = some (.mul 128 139) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_139, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_141 (pub : Nat → F) :
 actualCsrCoefficients pub 141 = (268435456 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[141]? = some (.mul 128 140) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_140, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_142 (pub : Nat → F) :
 actualCsrCoefficients pub 142 = (1073741824 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[142]? = some (.mul 128 141) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, actual_csr_coefficient_141, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_159 (pub : Nat → F) :
 actualCsrCoefficients pub 159 = (-4 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[159]? = some (.sub 0 128) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_128, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_160 (pub : Nat → F) :
 actualCsrCoefficients pub 160 = (-16 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[160]? = some (.sub 0 129) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_129, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_161 (pub : Nat → F) :
 actualCsrCoefficients pub 161 = (-64 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[161]? = some (.sub 0 130) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_130, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_162 (pub : Nat → F) :
 actualCsrCoefficients pub 162 = (-256 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[162]? = some (.sub 0 131) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_131, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_163 (pub : Nat → F) :
 actualCsrCoefficients pub 163 = (-1024 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[163]? = some (.sub 0 132) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_132, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_164 (pub : Nat → F) :
 actualCsrCoefficients pub 164 = (-4096 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[164]? = some (.sub 0 133) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_133, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_165 (pub : Nat → F) :
 actualCsrCoefficients pub 165 = (-16384 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[165]? = some (.sub 0 134) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_134, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_166 (pub : Nat → F) :
 actualCsrCoefficients pub 166 = (-65536 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[166]? = some (.sub 0 135) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_135, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_167 (pub : Nat → F) :
 actualCsrCoefficients pub 167 = (-262144 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[167]? = some (.sub 0 136) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_136, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_168 (pub : Nat → F) :
 actualCsrCoefficients pub 168 = (-1048576 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[168]? = some (.sub 0 137) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_137, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_169 (pub : Nat → F) :
 actualCsrCoefficients pub 169 = (-4194304 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[169]? = some (.sub 0 138) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_138, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_170 (pub : Nat → F) :
 actualCsrCoefficients pub 170 = (-16777216 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[170]? = some (.sub 0 139) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_139, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_171 (pub : Nat → F) :
 actualCsrCoefficients pub 171 = (-67108864 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[171]? = some (.sub 0 140) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_140, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_172 (pub : Nat → F) :
 actualCsrCoefficients pub 172 = (-268435456 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[172]? = some (.sub 0 141) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_141, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_173 (pub : Nat → F) :
 actualCsrCoefficients pub 173 = (-1073741824 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[173]? = some (.sub 0 142) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_142, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_206 (pub : Nat → F) :
 actualCsrCoefficients pub 206 = (-2 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[206]? = some (.sub 0 2) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, live_coefficient_2, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_207 (pub : Nat → F) :
 actualCsrCoefficients pub 207 = (8 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[207]? = some (.constant 8) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_208 (pub : Nat → F) :
 actualCsrCoefficients pub 208 = (-8 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[208]? = some (.sub 0 207) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_207, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_209 (pub : Nat → F) :
 actualCsrCoefficients pub 209 = (16 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[209]? = some (.constant 16) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_210 (pub : Nat → F) :
 actualCsrCoefficients pub 210 = (-16 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[210]? = some (.sub 0 209) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_209, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_213 (pub : Nat → F) :
 actualCsrCoefficients pub 213 = (64 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[213]? = some (.constant 64) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_214 (pub : Nat → F) :
 actualCsrCoefficients pub 214 = (-64 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[214]? = some (.sub 0 213) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_213, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_217 (pub : Nat → F) :
 actualCsrCoefficients pub 217 = (256 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[217]? = some (.constant 256) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_218 (pub : Nat → F) :
 actualCsrCoefficients pub 218 = (-256 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[218]? = some (.sub 0 217) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_217, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_221 (pub : Nat → F) :
 actualCsrCoefficients pub 221 = (1024 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[221]? = some (.constant 1024) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_222 (pub : Nat → F) :
 actualCsrCoefficients pub 222 = (-1024 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[222]? = some (.sub 0 221) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_221, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_225 (pub : Nat → F) :
 actualCsrCoefficients pub 225 = (4096 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[225]? = some (.constant 4096) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_226 (pub : Nat → F) :
 actualCsrCoefficients pub 226 = (-4096 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[226]? = some (.sub 0 225) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_225, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_229 (pub : Nat → F) :
 actualCsrCoefficients pub 229 = (16384 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[229]? = some (.constant 16384) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_230 (pub : Nat → F) :
 actualCsrCoefficients pub 230 = (-16384 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[230]? = some (.sub 0 229) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_229, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_233 (pub : Nat → F) :
 actualCsrCoefficients pub 233 = (65536 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[233]? = some (.constant 65536) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_234 (pub : Nat → F) :
 actualCsrCoefficients pub 234 = (-65536 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[234]? = some (.sub 0 233) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_233, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_237 (pub : Nat → F) :
 actualCsrCoefficients pub 237 = (262144 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[237]? = some (.constant 262144) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_238 (pub : Nat → F) :
 actualCsrCoefficients pub 238 = (-262144 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[238]? = some (.sub 0 237) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_237, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_241 (pub : Nat → F) :
 actualCsrCoefficients pub 241 = (1048576 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[241]? = some (.constant 1048576) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_242 (pub : Nat → F) :
 actualCsrCoefficients pub 242 = (-1048576 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[242]? = some (.sub 0 241) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_241, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_245 (pub : Nat → F) :
 actualCsrCoefficients pub 245 = (4194304 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[245]? = some (.constant 4194304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_246 (pub : Nat → F) :
 actualCsrCoefficients pub 246 = (-4194304 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[246]? = some (.sub 0 245) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_245, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_249 (pub : Nat → F) :
 actualCsrCoefficients pub 249 = (16777216 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[249]? = some (.constant 16777216) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_250 (pub : Nat → F) :
 actualCsrCoefficients pub 250 = (-16777216 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[250]? = some (.sub 0 249) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_249, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_253 (pub : Nat → F) :
 actualCsrCoefficients pub 253 = (67108864 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[253]? = some (.constant 67108864) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_254 (pub : Nat → F) :
 actualCsrCoefficients pub 254 = (-67108864 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[254]? = some (.sub 0 253) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_253, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_257 (pub : Nat → F) :
 actualCsrCoefficients pub 257 = (268435456 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[257]? = some (.constant 268435456) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_258 (pub : Nat → F) :
 actualCsrCoefficients pub 258 = (-268435456 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[258]? = some (.sub 0 257) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_257, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_261 (pub : Nat → F) :
 actualCsrCoefficients pub 261 = (1073741824 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[261]? = some (.constant 1073741824) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_262 (pub : Nat → F) :
 actualCsrCoefficients pub 262 = (-1073741824 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[262]? = some (.sub 0 261) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_261, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_409 (pub : Nat → F) :
 actualCsrCoefficients pub 409 = (0 - pub 109) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[409]? = some (.sub 0 113) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_113, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_411 (pub : Nat → F) :
 actualCsrCoefficients pub 411 = (0 - pub 110) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[411]? = some (.sub 0 114) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_114, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_413 (pub : Nat → F) :
 actualCsrCoefficients pub 413 = (0 - pub 84) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[413]? = some (.sub 0 88) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, live_coefficient_88, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_414 (pub : Nat → F) :
 actualCsrCoefficients pub 414 = (18 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[414]? = some (.constant 18) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_415 (pub : Nat → F) :
 actualCsrCoefficients pub 415 = (liveEnabled pub * (18 : F)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[415]? = some (.mul 306 414) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_306, actual_csr_coefficient_414, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_416 (pub : Nat → F) :
 actualCsrCoefficients pub 416 = (0 - (liveEnabled pub * (18 : F))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[416]? = some (.sub 0 415) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_415, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_417 (pub : Nat → F) :
 actualCsrCoefficients pub 417 = (0 - (0 - (liveEnabled pub * (18 : F)))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[417]? = some (.sub 0 416) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_416, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_418 (pub : Nat → F) :
 actualCsrCoefficients pub 418 = (0 - (0 - pub 109)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[418]? = some (.sub 0 409) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_409, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_419 (pub : Nat → F) :
 actualCsrCoefficients pub 419 = (pub 109 * (4096 : F)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[419]? = some (.mul 113 225) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_113, actual_csr_coefficient_225, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_420 (pub : Nat → F) :
 actualCsrCoefficients pub 420 = (pub 94 - (pub 109 * (4096 : F))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[420]? = some (.sub 98 419) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_98, actual_csr_coefficient_419, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_421 (pub : Nat → F) :
 actualCsrCoefficients pub 421 = (liveEnabled pub * (pub 94 - (pub 109 * (4096 : F)))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[421]? = some (.mul 306 420) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_306, actual_csr_coefficient_420, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_422 (pub : Nat → F) :
 actualCsrCoefficients pub 422 = (0 - (liveEnabled pub * (pub 94 - (pub 109 * (4096 : F))))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[422]? = some (.sub 0 421) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_421, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_423 (pub : Nat → F) :
 actualCsrCoefficients pub 423 = (pub 86 * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[423]? = some (.mul 90 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_90, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_424 (pub : Nat → F) :
 actualCsrCoefficients pub 424 = (pub 110 - (pub 86 * liveMint pub)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[424]? = some (.sub 114 423) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_114, actual_csr_coefficient_423, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_425 (pub : Nat → F) :
 actualCsrCoefficients pub 425 = (0 - (pub 110 - (pub 86 * liveMint pub))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[425]? = some (.sub 0 424) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_424, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_426 (pub : Nat → F) :
 actualCsrCoefficients pub 426 = (liveMint pub - liveBurn pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[426]? = some (.sub 304 305) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_304, live_coefficient_305, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_427 (pub : Nat → F) :
 actualCsrCoefficients pub 427 = (pub 86 * (liveMint pub - liveBurn pub)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[427]? = some (.mul 90 426) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_90, actual_csr_coefficient_426, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_428 (pub : Nat → F) :
 actualCsrCoefficients pub 428 = (pub 111 - (pub 86 * (liveMint pub - liveBurn pub))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[428]? = some (.sub 115 427) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_115, actual_csr_coefficient_427, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_429 (pub : Nat → F) :
 actualCsrCoefficients pub 429 = (0 - (pub 111 - (pub 86 * (liveMint pub - liveBurn pub)))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[429]? = some (.sub 0 428) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_428, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_430 (pub : Nat → F) :
 actualCsrCoefficients pub 430 = (pub 112 - liveEnabled pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[430]? = some (.sub 116 306) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_116, live_coefficient_306, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_431 (pub : Nat → F) :
 actualCsrCoefficients pub 431 = (0 - (pub 112 - liveEnabled pub)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[431]? = some (.sub 0 430) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_430, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_432 (pub : Nat → F) :
 actualCsrCoefficients pub 432 = (-1 * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[432]? = some (.mul 158 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_158, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_433 (pub : Nat → F) :
 actualCsrCoefficients pub 433 = (0 - (-1 * liveMint pub)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[433]? = some (.sub 0 432) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_432, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_434 (pub : Nat → F) :
 actualCsrCoefficients pub 434 = (1000000 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[434]? = some (.constant 1000000) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_435 (pub : Nat → F) :
 actualCsrCoefficients pub 435 = (-1000000 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[435]? = some (.sub 0 434) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_434, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_436 (pub : Nat → F) :
 actualCsrCoefficients pub 436 = (liveMint pub * (-1000000 : F)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[436]? = some (.mul 304 435) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_304, actual_csr_coefficient_435, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_437 (pub : Nat → F) :
 actualCsrCoefficients pub 437 = (0 - (liveMint pub * (-1000000 : F))) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[437]? = some (.sub 0 436) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_436, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_438 (pub : Nat → F) :
 actualCsrCoefficients pub 438 = (9 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[438]? = some (.constant 9) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_439 (pub : Nat → F) :
 actualCsrCoefficients pub 439 = (-9 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[439]? = some (.sub 0 438) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_438, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_440 (pub : Nat → F) :
 actualCsrCoefficients pub 440 = (99 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[440]? = some (.constant 99) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_441 (pub : Nat → F) :
 actualCsrCoefficients pub 441 = (-99 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[441]? = some (.sub 0 440) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_440, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_442 (pub : Nat → F) :
 actualCsrCoefficients pub 442 = (9999 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[442]? = some (.constant 9999) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_443 (pub : Nat → F) :
 actualCsrCoefficients pub 443 = (-9999 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[443]? = some (.sub 0 442) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_442, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_444 (pub : Nat → F) :
 actualCsrCoefficients pub 444 = (99999999 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[444]? = some (.constant 99999999) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_445 (pub : Nat → F) :
 actualCsrCoefficients pub 445 = (-99999999 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[445]? = some (.sub 0 444) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_444, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_446 (pub : Nat → F) :
 actualCsrCoefficients pub 446 = (9999999999999999 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[446]? = some (.constant 9999999999999999) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_447 (pub : Nat → F) :
 actualCsrCoefficients pub 447 = (-9999999999999999 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[447]? = some (.sub 0 446) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_446, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_448 (pub : Nat → F) :
 actualCsrCoefficients pub 448 = (4294967296 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[448]? = some (.constant 4294967296) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_449 (pub : Nat → F) :
 actualCsrCoefficients pub 449 = (-4294967296 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[449]? = some (.sub 0 448) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_448, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_450 (pub : Nat → F) :
 actualCsrCoefficients pub 450 = ((4 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[450]? = some (.mul 128 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_128, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_451 (pub : Nat → F) :
 actualCsrCoefficients pub 451 = ((16 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[451]? = some (.mul 129 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_129, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_452 (pub : Nat → F) :
 actualCsrCoefficients pub 452 = ((64 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[452]? = some (.mul 130 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_130, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_453 (pub : Nat → F) :
 actualCsrCoefficients pub 453 = ((256 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[453]? = some (.mul 131 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_131, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_454 (pub : Nat → F) :
 actualCsrCoefficients pub 454 = ((1024 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[454]? = some (.mul 132 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_132, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_455 (pub : Nat → F) :
 actualCsrCoefficients pub 455 = ((4096 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[455]? = some (.mul 133 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_133, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_456 (pub : Nat → F) :
 actualCsrCoefficients pub 456 = ((16384 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[456]? = some (.mul 134 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_134, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_457 (pub : Nat → F) :
 actualCsrCoefficients pub 457 = ((65536 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[457]? = some (.mul 135 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_135, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_458 (pub : Nat → F) :
 actualCsrCoefficients pub 458 = ((262144 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[458]? = some (.mul 136 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_136, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_459 (pub : Nat → F) :
 actualCsrCoefficients pub 459 = ((1048576 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[459]? = some (.mul 137 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_137, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_460 (pub : Nat → F) :
 actualCsrCoefficients pub 460 = ((4194304 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[460]? = some (.mul 138 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_138, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_461 (pub : Nat → F) :
 actualCsrCoefficients pub 461 = ((16777216 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[461]? = some (.mul 139 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_139, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_462 (pub : Nat → F) :
 actualCsrCoefficients pub 462 = ((67108864 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[462]? = some (.mul 140 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_140, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_463 (pub : Nat → F) :
 actualCsrCoefficients pub 463 = ((268435456 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[463]? = some (.mul 141 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_141, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_464 (pub : Nat → F) :
 actualCsrCoefficients pub 464 = ((1073741824 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[464]? = some (.mul 142 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_142, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_465 (pub : Nat → F) :
 actualCsrCoefficients pub 465 = ((-4 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[465]? = some (.mul 159 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_159, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_466 (pub : Nat → F) :
 actualCsrCoefficients pub 466 = ((-16 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[466]? = some (.mul 160 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_160, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_467 (pub : Nat → F) :
 actualCsrCoefficients pub 467 = ((-64 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[467]? = some (.mul 161 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_161, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_468 (pub : Nat → F) :
 actualCsrCoefficients pub 468 = ((-256 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[468]? = some (.mul 162 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_162, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_469 (pub : Nat → F) :
 actualCsrCoefficients pub 469 = ((-1024 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[469]? = some (.mul 163 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_163, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_470 (pub : Nat → F) :
 actualCsrCoefficients pub 470 = ((-4096 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[470]? = some (.mul 164 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_164, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_471 (pub : Nat → F) :
 actualCsrCoefficients pub 471 = ((-16384 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[471]? = some (.mul 165 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_165, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_472 (pub : Nat → F) :
 actualCsrCoefficients pub 472 = ((-65536 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[472]? = some (.mul 166 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_166, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_473 (pub : Nat → F) :
 actualCsrCoefficients pub 473 = ((-262144 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[473]? = some (.mul 167 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_167, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_474 (pub : Nat → F) :
 actualCsrCoefficients pub 474 = ((-1048576 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[474]? = some (.mul 168 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_168, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_475 (pub : Nat → F) :
 actualCsrCoefficients pub 475 = ((-4194304 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[475]? = some (.mul 169 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_169, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_476 (pub : Nat → F) :
 actualCsrCoefficients pub 476 = ((-16777216 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[476]? = some (.mul 170 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_170, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_477 (pub : Nat → F) :
 actualCsrCoefficients pub 477 = ((-67108864 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[477]? = some (.mul 171 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_171, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_478 (pub : Nat → F) :
 actualCsrCoefficients pub 478 = ((-268435456 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[478]? = some (.mul 172 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_172, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_479 (pub : Nat → F) :
 actualCsrCoefficients pub 479 = ((-1073741824 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[479]? = some (.mul 173 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_173, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_480 (pub : Nat → F) :
 actualCsrCoefficients pub 480 = (liveMint pub * (-4294967296 : F)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[480]? = some (.mul 304 449) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_304, actual_csr_coefficient_449, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_481 (pub : Nat → F) :
 actualCsrCoefficients pub 481 = ((16 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[481]? = some (.mul 209 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_209, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_482 (pub : Nat → F) :
 actualCsrCoefficients pub 482 = ((64 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[482]? = some (.mul 213 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_213, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_483 (pub : Nat → F) :
 actualCsrCoefficients pub 483 = ((256 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[483]? = some (.mul 217 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_217, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_484 (pub : Nat → F) :
 actualCsrCoefficients pub 484 = ((1024 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[484]? = some (.mul 221 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_221, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_485 (pub : Nat → F) :
 actualCsrCoefficients pub 485 = ((4096 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[485]? = some (.mul 225 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_225, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_486 (pub : Nat → F) :
 actualCsrCoefficients pub 486 = ((16384 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[486]? = some (.mul 229 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_229, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_487 (pub : Nat → F) :
 actualCsrCoefficients pub 487 = ((65536 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[487]? = some (.mul 233 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_233, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_488 (pub : Nat → F) :
 actualCsrCoefficients pub 488 = ((262144 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[488]? = some (.mul 237 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_237, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_489 (pub : Nat → F) :
 actualCsrCoefficients pub 489 = ((1048576 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[489]? = some (.mul 241 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_241, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_490 (pub : Nat → F) :
 actualCsrCoefficients pub 490 = ((4194304 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[490]? = some (.mul 245 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_245, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_491 (pub : Nat → F) :
 actualCsrCoefficients pub 491 = ((16777216 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[491]? = some (.mul 249 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_249, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_492 (pub : Nat → F) :
 actualCsrCoefficients pub 492 = ((67108864 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[492]? = some (.mul 253 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_253, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_493 (pub : Nat → F) :
 actualCsrCoefficients pub 493 = ((268435456 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[493]? = some (.mul 257 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_257, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_494 (pub : Nat → F) :
 actualCsrCoefficients pub 494 = ((1073741824 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[494]? = some (.mul 261 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_261, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_495 (pub : Nat → F) :
 actualCsrCoefficients pub 495 = ((-16 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[495]? = some (.mul 210 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_210, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_496 (pub : Nat → F) :
 actualCsrCoefficients pub 496 = ((-64 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[496]? = some (.mul 214 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_214, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_497 (pub : Nat → F) :
 actualCsrCoefficients pub 497 = ((-256 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[497]? = some (.mul 218 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_218, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_498 (pub : Nat → F) :
 actualCsrCoefficients pub 498 = ((-1024 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[498]? = some (.mul 222 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_222, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_499 (pub : Nat → F) :
 actualCsrCoefficients pub 499 = ((-4096 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[499]? = some (.mul 226 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_226, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_500 (pub : Nat → F) :
 actualCsrCoefficients pub 500 = ((-16384 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[500]? = some (.mul 230 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_230, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_501 (pub : Nat → F) :
 actualCsrCoefficients pub 501 = ((-65536 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[501]? = some (.mul 234 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_234, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_502 (pub : Nat → F) :
 actualCsrCoefficients pub 502 = ((-262144 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[502]? = some (.mul 238 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_238, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_503 (pub : Nat → F) :
 actualCsrCoefficients pub 503 = ((-1048576 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[503]? = some (.mul 242 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_242, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_504 (pub : Nat → F) :
 actualCsrCoefficients pub 504 = ((-4194304 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[504]? = some (.mul 246 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_246, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_505 (pub : Nat → F) :
 actualCsrCoefficients pub 505 = ((-16777216 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[505]? = some (.mul 250 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_250, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_506 (pub : Nat → F) :
 actualCsrCoefficients pub 506 = ((-67108864 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[506]? = some (.mul 254 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_254, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_507 (pub : Nat → F) :
 actualCsrCoefficients pub 507 = ((-268435456 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[507]? = some (.mul 258 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_258, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_508 (pub : Nat → F) :
 actualCsrCoefficients pub 508 = ((-1073741824 : F) * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[508]? = some (.mul 262 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_262, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_509 (pub : Nat → F) :
 actualCsrCoefficients pub 509 = (4 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[509]? = some (.sub 0 159) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_159, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_510 (pub : Nat → F) :
 actualCsrCoefficients pub 510 = (16 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[510]? = some (.sub 0 160) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_160, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_511 (pub : Nat → F) :
 actualCsrCoefficients pub 511 = (64 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[511]? = some (.sub 0 161) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_161, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_512 (pub : Nat → F) :
 actualCsrCoefficients pub 512 = (256 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[512]? = some (.sub 0 162) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_162, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_513 (pub : Nat → F) :
 actualCsrCoefficients pub 513 = (1024 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[513]? = some (.sub 0 163) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_163, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_514 (pub : Nat → F) :
 actualCsrCoefficients pub 514 = (4096 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[514]? = some (.sub 0 164) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_164, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_515 (pub : Nat → F) :
 actualCsrCoefficients pub 515 = (16384 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[515]? = some (.sub 0 165) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_165, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_516 (pub : Nat → F) :
 actualCsrCoefficients pub 516 = (65536 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[516]? = some (.sub 0 166) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_166, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_517 (pub : Nat → F) :
 actualCsrCoefficients pub 517 = (262144 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[517]? = some (.sub 0 167) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_167, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_518 (pub : Nat → F) :
 actualCsrCoefficients pub 518 = (1048576 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[518]? = some (.sub 0 168) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_168, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_519 (pub : Nat → F) :
 actualCsrCoefficients pub 519 = (4194304 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[519]? = some (.sub 0 169) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_169, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_520 (pub : Nat → F) :
 actualCsrCoefficients pub 520 = (16777216 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[520]? = some (.sub 0 170) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_170, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_521 (pub : Nat → F) :
 actualCsrCoefficients pub 521 = (67108864 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[521]? = some (.sub 0 171) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_171, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_522 (pub : Nat → F) :
 actualCsrCoefficients pub 522 = (268435456 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[522]? = some (.sub 0 172) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_172, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_523 (pub : Nat → F) :
 actualCsrCoefficients pub 523 = (1073741824 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[523]? = some (.sub 0 173) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_173, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_524 (pub : Nat → F) :
 actualCsrCoefficients pub 524 = (4294967296 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[524]? = some (.sub 0 449) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_449, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_525 (pub : Nat → F) :
 actualCsrCoefficients pub 525 = (16 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[525]? = some (.sub 0 210) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_210, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_526 (pub : Nat → F) :
 actualCsrCoefficients pub 526 = (64 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[526]? = some (.sub 0 214) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_214, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_527 (pub : Nat → F) :
 actualCsrCoefficients pub 527 = (256 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[527]? = some (.sub 0 218) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_218, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_528 (pub : Nat → F) :
 actualCsrCoefficients pub 528 = (1024 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[528]? = some (.sub 0 222) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_222, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_529 (pub : Nat → F) :
 actualCsrCoefficients pub 529 = (4096 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[529]? = some (.sub 0 226) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_226, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_530 (pub : Nat → F) :
 actualCsrCoefficients pub 530 = (16384 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[530]? = some (.sub 0 230) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_230, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_531 (pub : Nat → F) :
 actualCsrCoefficients pub 531 = (65536 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[531]? = some (.sub 0 234) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_234, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_532 (pub : Nat → F) :
 actualCsrCoefficients pub 532 = (262144 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[532]? = some (.sub 0 238) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_238, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_533 (pub : Nat → F) :
 actualCsrCoefficients pub 533 = (1048576 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[533]? = some (.sub 0 242) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_242, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_534 (pub : Nat → F) :
 actualCsrCoefficients pub 534 = (4194304 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[534]? = some (.sub 0 246) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_246, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_535 (pub : Nat → F) :
 actualCsrCoefficients pub 535 = (16777216 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[535]? = some (.sub 0 250) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_250, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_536 (pub : Nat → F) :
 actualCsrCoefficients pub 536 = (67108864 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[536]? = some (.sub 0 254) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_254, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_537 (pub : Nat → F) :
 actualCsrCoefficients pub 537 = (268435456 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[537]? = some (.sub 0 258) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_258, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_538 (pub : Nat → F) :
 actualCsrCoefficients pub 538 = (1073741824 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[538]? = some (.sub 0 262) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_262, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_539 (pub : Nat → F) :
 actualCsrCoefficients pub 539 = (pub 111 * liveMint pub) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[539]? = some (.mul 115 304) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, actual_csr_coefficient_115, live_coefficient_304, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_540 (pub : Nat → F) :
 actualCsrCoefficients pub 540 = (0 - (pub 111 * liveMint pub)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[540]? = some (.sub 0 539) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_0, actual_csr_coefficient_539, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_541 (pub : Nat → F) :
 actualCsrCoefficients pub 541 = (liveMint pub * (4294967296 : F)) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[541]? = some (.mul 304 448) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, live_coefficient_304, actual_csr_coefficient_448, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

theorem actual_csr_coefficient_542 (pub : Nat → F) :
 actualCsrCoefficients pub 542 = (4294967295 : F) := by
 have equation := actual_csr_node_field_equation pub
  (show exactCsrExpressions[542]? = some (.constant 4294967295) by decide)
 norm_num only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat, zero_sub, neg_neg, neg_one_mul, mul_one, mul_comm] at equation ⊢
 exact equation

end HegemonCrypto.SmallWood.V8Smz9SourceStableNumericCoefficients
