import HegemonCrypto.CmsAdaptiveClaimBridge

/-! Equality transports for CMS events over equal finite input types.  The
event correspondence is only predicate naturality along the database cast;
states themselves are transported by equality, not related by an assumption.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CmsEventEqualityTransport

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsAdaptiveClaimBridge
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Input₁ Input₂ Output Phase Workspace : Type}
variable [fintypeInput₁ : Fintype Input₁] [decEqInput₁ : DecidableEq Input₁]
variable [fintypeInput₂ : Fintype Input₂] [decEqInput₂ : DecidableEq Input₂]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- The database-function carrier follows the input type equality. -/
theorem databaseTypeEq (sameInput : Input₁ = Input₂) :
    Database Input₁ Output = Database Input₂ Output :=
  congrArg (fun input => Database input Output) sameInput

/-- The CMS basis carrier follows the input type equality. -/
theorem basisTypeEq (sameInput : Input₁ = Input₂) :
    Basis Input₁ Output Phase Workspace = Basis Input₂ Output Phase Workspace :=
  congrArg (fun input => Basis input Output Phase Workspace) sameInput

/-- The state-function carrier follows the input type equality. -/
theorem stateTypeEq (sameInput : Input₁ = Input₂) :
    State Input₁ Output Phase Workspace = State Input₂ Output Phase Workspace :=
  congrArg (fun input => State input Output Phase Workspace) sameInput

/-- Squared norm is invariant under equality transport of the input type. -/
theorem normSquared_cast_input (sameInput : Input₁ = Input₂)
    (state : State Input₁ Output Phase Workspace) :
    normSquared (cast (stateTypeEq sameInput) state) = normSquared state := by
  cases sameInput
  have sameFintype : fintypeInput₁ = fintypeInput₂ := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqInput₁ = decEqInput₂ := Subsingleton.elim _ _
  cases sameDecEq
  rfl

/-- If two workspace-selected predicates agree after transporting a database,
their coherent CMS event projections agree after transporting the whole state.

The only event-side premise is pointwise semantic compatibility of the
predicates. The theorem does not assume equality of independently prepared
states or any relation between the two input universes beyond `sameInput`.
-/
theorem workspaceEventProjection_cast_input
    (sameInput : Input₁ = Input₂)
    (event₁ : Workspace → Database Input₁ Output → Prop)
    (event₂ : Workspace → Database Input₂ Output → Prop)
    (sameEvent : ∀ workspace database,
      event₂ workspace (cast (databaseTypeEq sameInput) database) ↔
        event₁ workspace database)
    (state : State Input₁ Output Phase Workspace) :
    cast (stateTypeEq sameInput)
        (workspaceEventProjection event₁ state) =
      workspaceEventProjection event₂ (cast (stateTypeEq sameInput) state) := by
  classical
  cases sameInput
  have sameFintype : fintypeInput₁ = fintypeInput₂ := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqInput₁ = decEqInput₂ := Subsingleton.elim _ _
  cases sameDecEq
  have sameEvent' : ∀ workspace database,
      event₂ workspace database ↔ event₁ workspace database := by
    intro workspace database
    simpa [databaseTypeEq] using sameEvent workspace database
  funext basis
  change
    (if event₁ basis.workspace basis.database then state basis else 0) =
      (if event₂ basis.workspace basis.database then state basis else 0)
  rcases sameEvent' basis.workspace basis.database with ⟨event₂_to_event₁,
    event₁_to_event₂⟩
  by_cases accepted₁ : event₁ basis.workspace basis.database
  · have accepted₂ : event₂ basis.workspace basis.database :=
      event₁_to_event₂ accepted₁
    simp only [if_pos accepted₁, if_pos accepted₂]
  · have rejected₂ : ¬ event₂ basis.workspace basis.database := by
      intro accepted₂
      exact accepted₁ (event₂_to_event₁ accepted₂)
    simp only [if_neg accepted₁, if_neg rejected₂]

/-- The same event compatibility preserves the squared mass of the selected
workspace projection. This follows from projection naturality and norm
invariance under the state cast. -/
theorem workspaceEventProjection_normSquared_cast_input
    (sameInput : Input₁ = Input₂)
    (event₁ : Workspace → Database Input₁ Output → Prop)
    (event₂ : Workspace → Database Input₂ Output → Prop)
    (sameEvent : ∀ workspace database,
      event₂ workspace (cast (databaseTypeEq sameInput) database) ↔
        event₁ workspace database)
    (state : State Input₁ Output Phase Workspace) :
    normSquared
        (workspaceEventProjection event₂ (cast (stateTypeEq sameInput) state)) =
      normSquared (workspaceEventProjection event₁ state) := by
  rw [← workspaceEventProjection_cast_input sameInput event₁ event₂ sameEvent state]
  exact normSquared_cast_input sameInput (workspaceEventProjection event₁ state)

end
end HegemonCrypto.SmallWood.SmzaRp05CmsEventEqualityTransport
