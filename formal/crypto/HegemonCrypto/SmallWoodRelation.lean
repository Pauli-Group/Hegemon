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

/-- Directional exact refinement between each statement-specific production relation and CCS. -/
structure ExactCCSRefinement (F : Type*) [CommRing F] where
  system : Statement → HegemonCrypto.CCS.System F
  encode : (statement : Statement) → Witness → Fin (system statement).variableCount → F
  decode : (statement : Statement) →
    (Fin (system statement).variableCount → F) → Witness
  complete : ∀ statement witness,
    (statement, witness) ∈ Relation →
      (system statement).Satisfies (encode statement witness)
  sound : ∀ statement assignment,
    ProductionConstraintMapBound statement →
      (system statement).Satisfies assignment →
        (statement, decode statement assignment) ∈ Relation

end HegemonCrypto.SmallWood
