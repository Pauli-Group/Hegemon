import HegemonCrypto.SmallWoodProductionDegreeCertificateCheck5Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-! Generated bounded formal-degree checks, module 6. -/

def productionDegreeExpressionChunk60 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 7680).take 128

def productionFormalDegreeChunk60CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 7680
    productionDegreeExpressionChunk60

def productionDegreeExpressionChunk61 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 7808).take 128

def productionFormalDegreeChunk61CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 7808
    productionDegreeExpressionChunk61

def productionDegreeExpressionChunk62 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 7936).take 128

def productionFormalDegreeChunk62CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 7936
    productionDegreeExpressionChunk62

def productionDegreeExpressionChunk63 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 8064).take 128

def productionFormalDegreeChunk63CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 8064
    productionDegreeExpressionChunk63

def productionDegreeExpressionChunk64 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 8192).take 128

def productionFormalDegreeChunk64CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 8192
    productionDegreeExpressionChunk64

def productionDegreeExpressionChunk65 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 8320).take 128

def productionFormalDegreeChunk65CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 8320
    productionDegreeExpressionChunk65

def productionDegreeExpressionChunk66 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 8448).take 128

def productionFormalDegreeChunk66CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 8448
    productionDegreeExpressionChunk66

def productionDegreeExpressionChunk67 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 8576).take 128

def productionFormalDegreeChunk67CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 8576
    productionDegreeExpressionChunk67

def productionDegreeExpressionChunk68 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 8704).take 128

def productionFormalDegreeChunk68CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 8704
    productionDegreeExpressionChunk68

def productionDegreeExpressionChunk69 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 8832).take 9

def productionFormalDegreeChunk69CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 8832
    productionDegreeExpressionChunk69

theorem production_formal_degree_check_module_6_checked :
    productionFormalDegreeChunk60CheckedB = true
      ∧ productionDegreeExpressionChunk60.length = 128
      ∧ productionFormalDegreeChunk61CheckedB = true
      ∧ productionDegreeExpressionChunk61.length = 128
      ∧ productionFormalDegreeChunk62CheckedB = true
      ∧ productionDegreeExpressionChunk62.length = 128
      ∧ productionFormalDegreeChunk63CheckedB = true
      ∧ productionDegreeExpressionChunk63.length = 128
      ∧ productionFormalDegreeChunk64CheckedB = true
      ∧ productionDegreeExpressionChunk64.length = 128
      ∧ productionFormalDegreeChunk65CheckedB = true
      ∧ productionDegreeExpressionChunk65.length = 128
      ∧ productionFormalDegreeChunk66CheckedB = true
      ∧ productionDegreeExpressionChunk66.length = 128
      ∧ productionFormalDegreeChunk67CheckedB = true
      ∧ productionDegreeExpressionChunk67.length = 128
      ∧ productionFormalDegreeChunk68CheckedB = true
      ∧ productionDegreeExpressionChunk68.length = 128
      ∧ productionFormalDegreeChunk69CheckedB = true
      ∧ productionDegreeExpressionChunk69.length = 9
      ∧ productionNonlinearExpressions.drop 8841 = [] := by
  decide

theorem production_formal_degree_chunk_60_checked :
    productionFormalDegreeChunk60CheckedB = true :=
  production_formal_degree_check_module_6_checked.1

theorem production_degree_expression_chunk_60_length :
    productionDegreeExpressionChunk60.length = 128 :=
  production_formal_degree_check_module_6_checked.2.1

theorem production_formal_degree_chunk_61_checked :
    productionFormalDegreeChunk61CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.1

theorem production_degree_expression_chunk_61_length :
    productionDegreeExpressionChunk61.length = 128 :=
  production_formal_degree_check_module_6_checked.2.2.2.1

theorem production_formal_degree_chunk_62_checked :
    productionFormalDegreeChunk62CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.2.2.1

theorem production_degree_expression_chunk_62_length :
    productionDegreeExpressionChunk62.length = 128 :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.1

theorem production_formal_degree_chunk_63_checked :
    productionFormalDegreeChunk63CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_63_length :
    productionDegreeExpressionChunk63.length = 128 :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_64_checked :
    productionFormalDegreeChunk64CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_64_length :
    productionDegreeExpressionChunk64.length = 128 :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_65_checked :
    productionFormalDegreeChunk65CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_65_length :
    productionDegreeExpressionChunk65.length = 128 :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_66_checked :
    productionFormalDegreeChunk66CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_66_length :
    productionDegreeExpressionChunk66.length = 128 :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_67_checked :
    productionFormalDegreeChunk67CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_67_length :
    productionDegreeExpressionChunk67.length = 128 :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_68_checked :
    productionFormalDegreeChunk68CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_68_length :
    productionDegreeExpressionChunk68.length = 128 :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_69_checked :
    productionFormalDegreeChunk69CheckedB = true :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_69_length :
    productionDegreeExpressionChunk69.length = 9 :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_nonlinear_expressions_exhausted :
    productionNonlinearExpressions.drop 8841 = [] :=
  production_formal_degree_check_module_6_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

end HegemonCrypto.SmallWood.ProductionPolynomials
