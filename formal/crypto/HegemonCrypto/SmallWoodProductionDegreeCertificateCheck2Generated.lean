import HegemonCrypto.SmallWoodProductionDegreeCertificateCheck1Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-! Generated bounded formal-degree checks, module 2. -/

def productionDegreeExpressionChunk20 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 2560).take 128

def productionFormalDegreeChunk20CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 2560
    productionDegreeExpressionChunk20

def productionDegreeExpressionChunk21 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 2688).take 128

def productionFormalDegreeChunk21CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 2688
    productionDegreeExpressionChunk21

def productionDegreeExpressionChunk22 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 2816).take 128

def productionFormalDegreeChunk22CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 2816
    productionDegreeExpressionChunk22

def productionDegreeExpressionChunk23 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 2944).take 128

def productionFormalDegreeChunk23CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 2944
    productionDegreeExpressionChunk23

def productionDegreeExpressionChunk24 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 3072).take 128

def productionFormalDegreeChunk24CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 3072
    productionDegreeExpressionChunk24

def productionDegreeExpressionChunk25 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 3200).take 128

def productionFormalDegreeChunk25CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 3200
    productionDegreeExpressionChunk25

def productionDegreeExpressionChunk26 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 3328).take 128

def productionFormalDegreeChunk26CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 3328
    productionDegreeExpressionChunk26

def productionDegreeExpressionChunk27 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 3456).take 128

def productionFormalDegreeChunk27CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 3456
    productionDegreeExpressionChunk27

def productionDegreeExpressionChunk28 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 3584).take 128

def productionFormalDegreeChunk28CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 3584
    productionDegreeExpressionChunk28

def productionDegreeExpressionChunk29 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 3712).take 128

def productionFormalDegreeChunk29CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 3712
    productionDegreeExpressionChunk29

theorem production_formal_degree_check_module_2_checked :
    productionFormalDegreeChunk20CheckedB = true
      ∧ productionDegreeExpressionChunk20.length = 128
      ∧ productionFormalDegreeChunk21CheckedB = true
      ∧ productionDegreeExpressionChunk21.length = 128
      ∧ productionFormalDegreeChunk22CheckedB = true
      ∧ productionDegreeExpressionChunk22.length = 128
      ∧ productionFormalDegreeChunk23CheckedB = true
      ∧ productionDegreeExpressionChunk23.length = 128
      ∧ productionFormalDegreeChunk24CheckedB = true
      ∧ productionDegreeExpressionChunk24.length = 128
      ∧ productionFormalDegreeChunk25CheckedB = true
      ∧ productionDegreeExpressionChunk25.length = 128
      ∧ productionFormalDegreeChunk26CheckedB = true
      ∧ productionDegreeExpressionChunk26.length = 128
      ∧ productionFormalDegreeChunk27CheckedB = true
      ∧ productionDegreeExpressionChunk27.length = 128
      ∧ productionFormalDegreeChunk28CheckedB = true
      ∧ productionDegreeExpressionChunk28.length = 128
      ∧ productionFormalDegreeChunk29CheckedB = true
      ∧ productionDegreeExpressionChunk29.length = 128 := by
  decide

theorem production_formal_degree_chunk_20_checked :
    productionFormalDegreeChunk20CheckedB = true :=
  production_formal_degree_check_module_2_checked.1

theorem production_degree_expression_chunk_20_length :
    productionDegreeExpressionChunk20.length = 128 :=
  production_formal_degree_check_module_2_checked.2.1

theorem production_formal_degree_chunk_21_checked :
    productionFormalDegreeChunk21CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.1

theorem production_degree_expression_chunk_21_length :
    productionDegreeExpressionChunk21.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.1

theorem production_formal_degree_chunk_22_checked :
    productionFormalDegreeChunk22CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.2.2.1

theorem production_degree_expression_chunk_22_length :
    productionDegreeExpressionChunk22.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.1

theorem production_formal_degree_chunk_23_checked :
    productionFormalDegreeChunk23CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_23_length :
    productionDegreeExpressionChunk23.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_24_checked :
    productionFormalDegreeChunk24CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_24_length :
    productionDegreeExpressionChunk24.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_25_checked :
    productionFormalDegreeChunk25CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_25_length :
    productionDegreeExpressionChunk25.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_26_checked :
    productionFormalDegreeChunk26CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_26_length :
    productionDegreeExpressionChunk26.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_27_checked :
    productionFormalDegreeChunk27CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_27_length :
    productionDegreeExpressionChunk27.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_28_checked :
    productionFormalDegreeChunk28CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_28_length :
    productionDegreeExpressionChunk28.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_29_checked :
    productionFormalDegreeChunk29CheckedB = true :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_29_length :
    productionDegreeExpressionChunk29.length = 128 :=
  production_formal_degree_check_module_2_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

end HegemonCrypto.SmallWood.ProductionPolynomials
