import HegemonCrypto.SmallWoodProductionDegreeCertificateCheck2Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-! Generated bounded formal-degree checks, module 3. -/

def productionDegreeExpressionChunk30 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 3840).take 128

def productionFormalDegreeChunk30CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 3840
    productionDegreeExpressionChunk30

def productionDegreeExpressionChunk31 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 3968).take 128

def productionFormalDegreeChunk31CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 3968
    productionDegreeExpressionChunk31

def productionDegreeExpressionChunk32 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 4096).take 128

def productionFormalDegreeChunk32CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 4096
    productionDegreeExpressionChunk32

def productionDegreeExpressionChunk33 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 4224).take 128

def productionFormalDegreeChunk33CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 4224
    productionDegreeExpressionChunk33

def productionDegreeExpressionChunk34 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 4352).take 128

def productionFormalDegreeChunk34CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 4352
    productionDegreeExpressionChunk34

def productionDegreeExpressionChunk35 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 4480).take 128

def productionFormalDegreeChunk35CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 4480
    productionDegreeExpressionChunk35

def productionDegreeExpressionChunk36 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 4608).take 128

def productionFormalDegreeChunk36CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 4608
    productionDegreeExpressionChunk36

def productionDegreeExpressionChunk37 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 4736).take 128

def productionFormalDegreeChunk37CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 4736
    productionDegreeExpressionChunk37

def productionDegreeExpressionChunk38 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 4864).take 128

def productionFormalDegreeChunk38CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 4864
    productionDegreeExpressionChunk38

def productionDegreeExpressionChunk39 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 4992).take 128

def productionFormalDegreeChunk39CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 4992
    productionDegreeExpressionChunk39

theorem production_formal_degree_check_module_3_checked :
    productionFormalDegreeChunk30CheckedB = true
      ∧ productionDegreeExpressionChunk30.length = 128
      ∧ productionFormalDegreeChunk31CheckedB = true
      ∧ productionDegreeExpressionChunk31.length = 128
      ∧ productionFormalDegreeChunk32CheckedB = true
      ∧ productionDegreeExpressionChunk32.length = 128
      ∧ productionFormalDegreeChunk33CheckedB = true
      ∧ productionDegreeExpressionChunk33.length = 128
      ∧ productionFormalDegreeChunk34CheckedB = true
      ∧ productionDegreeExpressionChunk34.length = 128
      ∧ productionFormalDegreeChunk35CheckedB = true
      ∧ productionDegreeExpressionChunk35.length = 128
      ∧ productionFormalDegreeChunk36CheckedB = true
      ∧ productionDegreeExpressionChunk36.length = 128
      ∧ productionFormalDegreeChunk37CheckedB = true
      ∧ productionDegreeExpressionChunk37.length = 128
      ∧ productionFormalDegreeChunk38CheckedB = true
      ∧ productionDegreeExpressionChunk38.length = 128
      ∧ productionFormalDegreeChunk39CheckedB = true
      ∧ productionDegreeExpressionChunk39.length = 128 := by
  decide

theorem production_formal_degree_chunk_30_checked :
    productionFormalDegreeChunk30CheckedB = true :=
  production_formal_degree_check_module_3_checked.1

theorem production_degree_expression_chunk_30_length :
    productionDegreeExpressionChunk30.length = 128 :=
  production_formal_degree_check_module_3_checked.2.1

theorem production_formal_degree_chunk_31_checked :
    productionFormalDegreeChunk31CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.1

theorem production_degree_expression_chunk_31_length :
    productionDegreeExpressionChunk31.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.1

theorem production_formal_degree_chunk_32_checked :
    productionFormalDegreeChunk32CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.2.2.1

theorem production_degree_expression_chunk_32_length :
    productionDegreeExpressionChunk32.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.1

theorem production_formal_degree_chunk_33_checked :
    productionFormalDegreeChunk33CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_33_length :
    productionDegreeExpressionChunk33.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_34_checked :
    productionFormalDegreeChunk34CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_34_length :
    productionDegreeExpressionChunk34.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_35_checked :
    productionFormalDegreeChunk35CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_35_length :
    productionDegreeExpressionChunk35.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_36_checked :
    productionFormalDegreeChunk36CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_36_length :
    productionDegreeExpressionChunk36.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_37_checked :
    productionFormalDegreeChunk37CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_37_length :
    productionDegreeExpressionChunk37.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_38_checked :
    productionFormalDegreeChunk38CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_38_length :
    productionDegreeExpressionChunk38.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_39_checked :
    productionFormalDegreeChunk39CheckedB = true :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_39_length :
    productionDegreeExpressionChunk39.length = 128 :=
  production_formal_degree_check_module_3_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

end HegemonCrypto.SmallWood.ProductionPolynomials
