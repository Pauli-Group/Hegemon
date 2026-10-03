import HegemonCrypto.SmallWoodProductionDegreeCertificateCheck3Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-! Generated bounded formal-degree checks, module 4. -/

def productionDegreeExpressionChunk40 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 5120).take 128

def productionFormalDegreeChunk40CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 5120
    productionDegreeExpressionChunk40

def productionDegreeExpressionChunk41 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 5248).take 128

def productionFormalDegreeChunk41CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 5248
    productionDegreeExpressionChunk41

def productionDegreeExpressionChunk42 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 5376).take 128

def productionFormalDegreeChunk42CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 5376
    productionDegreeExpressionChunk42

def productionDegreeExpressionChunk43 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 5504).take 128

def productionFormalDegreeChunk43CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 5504
    productionDegreeExpressionChunk43

def productionDegreeExpressionChunk44 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 5632).take 128

def productionFormalDegreeChunk44CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 5632
    productionDegreeExpressionChunk44

def productionDegreeExpressionChunk45 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 5760).take 128

def productionFormalDegreeChunk45CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 5760
    productionDegreeExpressionChunk45

def productionDegreeExpressionChunk46 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 5888).take 128

def productionFormalDegreeChunk46CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 5888
    productionDegreeExpressionChunk46

def productionDegreeExpressionChunk47 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 6016).take 128

def productionFormalDegreeChunk47CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 6016
    productionDegreeExpressionChunk47

def productionDegreeExpressionChunk48 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 6144).take 128

def productionFormalDegreeChunk48CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 6144
    productionDegreeExpressionChunk48

def productionDegreeExpressionChunk49 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 6272).take 128

def productionFormalDegreeChunk49CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 6272
    productionDegreeExpressionChunk49

theorem production_formal_degree_check_module_4_checked :
    productionFormalDegreeChunk40CheckedB = true
      ∧ productionDegreeExpressionChunk40.length = 128
      ∧ productionFormalDegreeChunk41CheckedB = true
      ∧ productionDegreeExpressionChunk41.length = 128
      ∧ productionFormalDegreeChunk42CheckedB = true
      ∧ productionDegreeExpressionChunk42.length = 128
      ∧ productionFormalDegreeChunk43CheckedB = true
      ∧ productionDegreeExpressionChunk43.length = 128
      ∧ productionFormalDegreeChunk44CheckedB = true
      ∧ productionDegreeExpressionChunk44.length = 128
      ∧ productionFormalDegreeChunk45CheckedB = true
      ∧ productionDegreeExpressionChunk45.length = 128
      ∧ productionFormalDegreeChunk46CheckedB = true
      ∧ productionDegreeExpressionChunk46.length = 128
      ∧ productionFormalDegreeChunk47CheckedB = true
      ∧ productionDegreeExpressionChunk47.length = 128
      ∧ productionFormalDegreeChunk48CheckedB = true
      ∧ productionDegreeExpressionChunk48.length = 128
      ∧ productionFormalDegreeChunk49CheckedB = true
      ∧ productionDegreeExpressionChunk49.length = 128 := by
  decide

theorem production_formal_degree_chunk_40_checked :
    productionFormalDegreeChunk40CheckedB = true :=
  production_formal_degree_check_module_4_checked.1

theorem production_degree_expression_chunk_40_length :
    productionDegreeExpressionChunk40.length = 128 :=
  production_formal_degree_check_module_4_checked.2.1

theorem production_formal_degree_chunk_41_checked :
    productionFormalDegreeChunk41CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.1

theorem production_degree_expression_chunk_41_length :
    productionDegreeExpressionChunk41.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.1

theorem production_formal_degree_chunk_42_checked :
    productionFormalDegreeChunk42CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.2.2.1

theorem production_degree_expression_chunk_42_length :
    productionDegreeExpressionChunk42.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.1

theorem production_formal_degree_chunk_43_checked :
    productionFormalDegreeChunk43CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_43_length :
    productionDegreeExpressionChunk43.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_44_checked :
    productionFormalDegreeChunk44CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_44_length :
    productionDegreeExpressionChunk44.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_45_checked :
    productionFormalDegreeChunk45CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_45_length :
    productionDegreeExpressionChunk45.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_46_checked :
    productionFormalDegreeChunk46CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_46_length :
    productionDegreeExpressionChunk46.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_47_checked :
    productionFormalDegreeChunk47CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_47_length :
    productionDegreeExpressionChunk47.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_48_checked :
    productionFormalDegreeChunk48CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_48_length :
    productionDegreeExpressionChunk48.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_49_checked :
    productionFormalDegreeChunk49CheckedB = true :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_49_length :
    productionDegreeExpressionChunk49.length = 128 :=
  production_formal_degree_check_module_4_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

end HegemonCrypto.SmallWood.ProductionPolynomials
