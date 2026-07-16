import Hegemon.Transaction.SmallWoodProductionConstraintRefinement
import HegemonCrypto.CCS

/-!
# Exact SmallWood relation adapter

The cryptographic input relation reuses the production constraint map directly. Serialization,
proof-wrapper admission, and Rust verifier equivalence remain separate refinement obligations.
-/

namespace HegemonCrypto.SmallWood

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

abbrev Statement := ProductionConstraintMap
abbrev Witness := List Nat

/-- The exact bounded production constraint relation used as the PoK input relation. -/
def Relation : Set (Statement × Witness) :=
  { pair |
      ProductionConstraintMapBound pair.1 ∧
        ExactProductionConstraintMapEvaluates pair.1 pair.2 }

/-- Executable form of the exact production relation. -/
def relationB (statement : Statement) (witness : Witness) : Bool :=
  productionConstraintMapBoundB statement &&
    exactProductionConstraintMapEvaluatesB statement witness

theorem relationB_iff
    (statement : Statement)
    (witness : Witness) :
    relationB statement witness = true ↔ (statement, witness) ∈ Relation := by
  simp [relationB, Relation, ProductionConstraintMapBound,
    ExactProductionConstraintMapEvaluates]

/--
Target interface for a lossless conversion from the generated production program to canonical
CCS. This package deliberately provides no inhabitant until that conversion is implemented and
proved for every production map.
-/
structure ExactCCSRefinement (F : Type*) [Field F] where
  system : HegemonCrypto.CCS.System F
  encode : Statement → Witness → Fin system.variableCount → F
  exact : ∀ statement witness,
    (statement, witness) ∈ Relation ↔ system.Satisfies (encode statement witness)

end HegemonCrypto.SmallWood
