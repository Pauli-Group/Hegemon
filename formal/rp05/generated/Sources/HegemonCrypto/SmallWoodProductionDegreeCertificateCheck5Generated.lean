import HegemonCrypto.SmallWoodProductionDegreeCertificateCheck4Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-! Generated bounded formal-degree checks, module 5. -/

def productionDegreeExpressionChunk50 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 6400).take 128

def productionFormalDegreeChunk50CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 6400
    productionDegreeExpressionChunk50

def productionDegreeExpressionChunk51 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 6528).take 128

def productionFormalDegreeChunk51CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 6528
    productionDegreeExpressionChunk51

def productionDegreeExpressionChunk52 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 6656).take 128

def productionFormalDegreeChunk52CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 6656
    productionDegreeExpressionChunk52

def productionDegreeExpressionChunk53 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 6784).take 128

def productionFormalDegreeChunk53CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 6784
    productionDegreeExpressionChunk53

def productionDegreeExpressionChunk54 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 6912).take 128

def productionFormalDegreeChunk54CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 6912
    productionDegreeExpressionChunk54

def productionDegreeExpressionChunk55 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 7040).take 128

def productionFormalDegreeChunk55CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 7040
    productionDegreeExpressionChunk55

def productionDegreeExpressionChunk56 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 7168).take 128

def productionFormalDegreeChunk56CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 7168
    productionDegreeExpressionChunk56

def productionDegreeExpressionChunk57 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 7296).take 128

def productionFormalDegreeChunk57CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 7296
    productionDegreeExpressionChunk57

def productionDegreeExpressionChunk58 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 7424).take 128

def productionFormalDegreeChunk58CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 7424
    productionDegreeExpressionChunk58

def productionDegreeExpressionChunk59 : List ProductionConstraintExpression :=
  (productionNonlinearExpressions.drop 7552).take 128

def productionFormalDegreeChunk59CheckedB : Bool :=
  formalDegreeCertificateAtB productionFormalDegreeAt 7552
    productionDegreeExpressionChunk59

theorem production_formal_degree_check_module_5_checked :
    productionFormalDegreeChunk50CheckedB = true
      ∧ productionDegreeExpressionChunk50.length = 128
      ∧ productionFormalDegreeChunk51CheckedB = true
      ∧ productionDegreeExpressionChunk51.length = 128
      ∧ productionFormalDegreeChunk52CheckedB = true
      ∧ productionDegreeExpressionChunk52.length = 128
      ∧ productionFormalDegreeChunk53CheckedB = true
      ∧ productionDegreeExpressionChunk53.length = 128
      ∧ productionFormalDegreeChunk54CheckedB = true
      ∧ productionDegreeExpressionChunk54.length = 128
      ∧ productionFormalDegreeChunk55CheckedB = true
      ∧ productionDegreeExpressionChunk55.length = 128
      ∧ productionFormalDegreeChunk56CheckedB = true
      ∧ productionDegreeExpressionChunk56.length = 128
      ∧ productionFormalDegreeChunk57CheckedB = true
      ∧ productionDegreeExpressionChunk57.length = 128
      ∧ productionFormalDegreeChunk58CheckedB = true
      ∧ productionDegreeExpressionChunk58.length = 128
      ∧ productionFormalDegreeChunk59CheckedB = true
      ∧ productionDegreeExpressionChunk59.length = 128 := by
  decide

theorem production_formal_degree_chunk_50_checked :
    productionFormalDegreeChunk50CheckedB = true :=
  production_formal_degree_check_module_5_checked.1

theorem production_degree_expression_chunk_50_length :
    productionDegreeExpressionChunk50.length = 128 :=
  production_formal_degree_check_module_5_checked.2.1

theorem production_formal_degree_chunk_51_checked :
    productionFormalDegreeChunk51CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.1

theorem production_degree_expression_chunk_51_length :
    productionDegreeExpressionChunk51.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.1

theorem production_formal_degree_chunk_52_checked :
    productionFormalDegreeChunk52CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.2.2.1

theorem production_degree_expression_chunk_52_length :
    productionDegreeExpressionChunk52.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.1

theorem production_formal_degree_chunk_53_checked :
    productionFormalDegreeChunk53CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_53_length :
    productionDegreeExpressionChunk53.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_54_checked :
    productionFormalDegreeChunk54CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_54_length :
    productionDegreeExpressionChunk54.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_55_checked :
    productionFormalDegreeChunk55CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_55_length :
    productionDegreeExpressionChunk55.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_56_checked :
    productionFormalDegreeChunk56CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_56_length :
    productionDegreeExpressionChunk56.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_57_checked :
    productionFormalDegreeChunk57CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_57_length :
    productionDegreeExpressionChunk57.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_58_checked :
    productionFormalDegreeChunk58CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_58_length :
    productionDegreeExpressionChunk58.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_formal_degree_chunk_59_checked :
    productionFormalDegreeChunk59CheckedB = true :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem production_degree_expression_chunk_59_length :
    productionDegreeExpressionChunk59.length = 128 :=
  production_formal_degree_check_module_5_checked.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

end HegemonCrypto.SmallWood.ProductionPolynomials
