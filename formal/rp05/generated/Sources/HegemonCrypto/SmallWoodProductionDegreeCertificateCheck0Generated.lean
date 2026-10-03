import HegemonCrypto.SmallWoodProductionDegreeCertificateDataGenerated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-! Generated bounded formal-degree checks, module 0. -/

def productionDegreeExpressionChunk0 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 0).take 128

def productionFormalDegreeChunk0CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 0
    productionDegreeExpressionChunk0

def productionDegreeExpressionChunk1 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 128).take 128

def productionFormalDegreeChunk1CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 128
    productionDegreeExpressionChunk1

def productionDegreeExpressionChunk2 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 256).take 128

def productionFormalDegreeChunk2CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 256
    productionDegreeExpressionChunk2

def productionDegreeExpressionChunk3 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 384).take 128

def productionFormalDegreeChunk3CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 384
    productionDegreeExpressionChunk3

def productionDegreeExpressionChunk4 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 512).take 128

def productionFormalDegreeChunk4CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 512
    productionDegreeExpressionChunk4

def productionDegreeExpressionChunk5 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 640).take 128

def productionFormalDegreeChunk5CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 640
    productionDegreeExpressionChunk5

def productionDegreeExpressionChunk6 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 768).take 128

def productionFormalDegreeChunk6CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 768
    productionDegreeExpressionChunk6

def productionDegreeExpressionChunk7 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 896).take 128

def productionFormalDegreeChunk7CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 896
    productionDegreeExpressionChunk7

def productionDegreeExpressionChunk8 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 1024).take 128

def productionFormalDegreeChunk8CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 1024
    productionDegreeExpressionChunk8

def productionDegreeExpressionChunk9 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 1152).take 128

def productionFormalDegreeChunk9CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 1152
    productionDegreeExpressionChunk9

theorem production_formal_degree_check_module_0_checked :
    productionFormalDegreeChunk0CheckedB = true
      ∧ productionDegreeExpressionChunk0.length = 128
      ∧ productionFormalDegreeChunk1CheckedB = true
      ∧ productionDegreeExpressionChunk1.length = 128
      ∧ productionFormalDegreeChunk2CheckedB = true
      ∧ productionDegreeExpressionChunk2.length = 128
      ∧ productionFormalDegreeChunk3CheckedB = true
      ∧ productionDegreeExpressionChunk3.length = 128
      ∧ productionFormalDegreeChunk4CheckedB = true
      ∧ productionDegreeExpressionChunk4.length = 128
      ∧ productionFormalDegreeChunk5CheckedB = true
      ∧ productionDegreeExpressionChunk5.length = 128
      ∧ productionFormalDegreeChunk6CheckedB = true
      ∧ productionDegreeExpressionChunk6.length = 128
      ∧ productionFormalDegreeChunk7CheckedB = true
      ∧ productionDegreeExpressionChunk7.length = 128
      ∧ productionFormalDegreeChunk8CheckedB = true
      ∧ productionDegreeExpressionChunk8.length = 128
      ∧ productionFormalDegreeChunk9CheckedB = true
      ∧ productionDegreeExpressionChunk9.length = 128 := by
  decide

theorem production_formal_degree_chunk_0_checked :
    productionFormalDegreeChunk0CheckedB = true :=
  production_formal_degree_check_module_0_checked.1

theorem production_degree_expression_chunk_0_length :
    productionDegreeExpressionChunk0.length = 128 :=
  production_formal_degree_check_module_0_checked.2.1

theorem production_formal_degree_chunk_1_checked :
    productionFormalDegreeChunk1CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.1

theorem production_degree_expression_chunk_1_length :
    productionDegreeExpressionChunk1.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.1

theorem production_formal_degree_chunk_2_checked :
    productionFormalDegreeChunk2CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.2.2.1

theorem production_degree_expression_chunk_2_length :
    productionDegreeExpressionChunk2.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.1

theorem production_formal_degree_chunk_3_checked :
    productionFormalDegreeChunk3CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_3_length :
    productionDegreeExpressionChunk3.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_4_checked :
    productionFormalDegreeChunk4CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_4_length :
    productionDegreeExpressionChunk4.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_5_checked :
    productionFormalDegreeChunk5CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_5_length :
    productionDegreeExpressionChunk5.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_6_checked :
    productionFormalDegreeChunk6CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_6_length :
    productionDegreeExpressionChunk6.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_7_checked :
    productionFormalDegreeChunk7CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_7_length :
    productionDegreeExpressionChunk7.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_8_checked :
    productionFormalDegreeChunk8CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_8_length :
    productionDegreeExpressionChunk8.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_9_checked :
    productionFormalDegreeChunk9CheckedB = true :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_9_length :
    productionDegreeExpressionChunk9.length = 128 :=
  production_formal_degree_check_module_0_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

end HegemonCrypto.SmallWood.ProductionPolynomials
