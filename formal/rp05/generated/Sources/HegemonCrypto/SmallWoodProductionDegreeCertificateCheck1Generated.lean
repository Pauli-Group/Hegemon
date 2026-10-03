import HegemonCrypto.SmallWoodProductionDegreeCertificateCheck0Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-! Generated bounded formal-degree checks, module 1. -/

def productionDegreeExpressionChunk10 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 1280).take 128

def productionFormalDegreeChunk10CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 1280
    productionDegreeExpressionChunk10

def productionDegreeExpressionChunk11 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 1408).take 128

def productionFormalDegreeChunk11CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 1408
    productionDegreeExpressionChunk11

def productionDegreeExpressionChunk12 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 1536).take 128

def productionFormalDegreeChunk12CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 1536
    productionDegreeExpressionChunk12

def productionDegreeExpressionChunk13 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 1664).take 128

def productionFormalDegreeChunk13CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 1664
    productionDegreeExpressionChunk13

def productionDegreeExpressionChunk14 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 1792).take 128

def productionFormalDegreeChunk14CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 1792
    productionDegreeExpressionChunk14

def productionDegreeExpressionChunk15 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 1920).take 128

def productionFormalDegreeChunk15CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 1920
    productionDegreeExpressionChunk15

def productionDegreeExpressionChunk16 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 2048).take 128

def productionFormalDegreeChunk16CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 2048
    productionDegreeExpressionChunk16

def productionDegreeExpressionChunk17 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 2176).take 128

def productionFormalDegreeChunk17CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 2176
    productionDegreeExpressionChunk17

def productionDegreeExpressionChunk18 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 2304).take 128

def productionFormalDegreeChunk18CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 2304
    productionDegreeExpressionChunk18

def productionDegreeExpressionChunk19 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 2432).take 128

def productionFormalDegreeChunk19CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 2432
    productionDegreeExpressionChunk19

theorem production_formal_degree_check_module_1_checked :
    productionFormalDegreeChunk10CheckedB = true
      ∧ productionDegreeExpressionChunk10.length = 128
      ∧ productionFormalDegreeChunk11CheckedB = true
      ∧ productionDegreeExpressionChunk11.length = 128
      ∧ productionFormalDegreeChunk12CheckedB = true
      ∧ productionDegreeExpressionChunk12.length = 128
      ∧ productionFormalDegreeChunk13CheckedB = true
      ∧ productionDegreeExpressionChunk13.length = 128
      ∧ productionFormalDegreeChunk14CheckedB = true
      ∧ productionDegreeExpressionChunk14.length = 128
      ∧ productionFormalDegreeChunk15CheckedB = true
      ∧ productionDegreeExpressionChunk15.length = 128
      ∧ productionFormalDegreeChunk16CheckedB = true
      ∧ productionDegreeExpressionChunk16.length = 128
      ∧ productionFormalDegreeChunk17CheckedB = true
      ∧ productionDegreeExpressionChunk17.length = 128
      ∧ productionFormalDegreeChunk18CheckedB = true
      ∧ productionDegreeExpressionChunk18.length = 128
      ∧ productionFormalDegreeChunk19CheckedB = true
      ∧ productionDegreeExpressionChunk19.length = 128 := by
  decide

theorem production_formal_degree_chunk_10_checked :
    productionFormalDegreeChunk10CheckedB = true :=
  production_formal_degree_check_module_1_checked.1

theorem production_degree_expression_chunk_10_length :
    productionDegreeExpressionChunk10.length = 128 :=
  production_formal_degree_check_module_1_checked.2.1

theorem production_formal_degree_chunk_11_checked :
    productionFormalDegreeChunk11CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.1

theorem production_degree_expression_chunk_11_length :
    productionDegreeExpressionChunk11.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.1

theorem production_formal_degree_chunk_12_checked :
    productionFormalDegreeChunk12CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.2.2.1

theorem production_degree_expression_chunk_12_length :
    productionDegreeExpressionChunk12.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.1

theorem production_formal_degree_chunk_13_checked :
    productionFormalDegreeChunk13CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_13_length :
    productionDegreeExpressionChunk13.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_14_checked :
    productionFormalDegreeChunk14CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_14_length :
    productionDegreeExpressionChunk14.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_15_checked :
    productionFormalDegreeChunk15CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_15_length :
    productionDegreeExpressionChunk15.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_16_checked :
    productionFormalDegreeChunk16CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_16_length :
    productionDegreeExpressionChunk16.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_17_checked :
    productionFormalDegreeChunk17CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_17_length :
    productionDegreeExpressionChunk17.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_18_checked :
    productionFormalDegreeChunk18CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_18_length :
    productionDegreeExpressionChunk18.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_19_checked :
    productionFormalDegreeChunk19CheckedB = true :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_19_length :
    productionDegreeExpressionChunk19.length = 128 :=
  production_formal_degree_check_module_1_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

end HegemonCrypto.SmallWood.ProductionPolynomials
