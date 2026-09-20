import SmzaChallengeStageTargets
import HegemonCrypto.CmsAdaptiveClaimBridge
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle
import HegemonCrypto.SmallWoodV8Smz9HiddenLeafQrom

/-!
# Exact conditioning on the other RP04 challenge-role tables

For one selected Fiat--Shamir role, the active domain contains that role and
the complete live complement.  Only the consumed counter blocks in the other
three recognized role domains are placed in fixed advice; higher counters
remain live.  The split below is a finite equivalence of whole oracle tables,
so conditioning and averaging do not assume a stage-security statement or a
readout distribution.

The final lemmas union events as projections of one unchanged physical state.
They do not identify the four role-conditioned proof experiments with one
joint-advice experiment.
-/
namespace HegemonCrypto.SmallWood.SmzaRoleDomainConditioning

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets
open V8Smz9HiddenLeafQrom
open V8Smz9RuntimeDistribution

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output : Type*}

/-- The selected role and every unrecognized raw input stay live.  In
particular, malformed frames, out-of-profile inputs, and the VC hash domains
are not turned into advice. -/
def RoleActive (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (key : Key) : Prop :=
  match parseStageQuery (keyBytes key) with
  | none => True
  | some query => query.role = selected ∨ ¬ query.counter < blockCap query.role

/-- Exactly the bounded, consumed blocks of the other three recognized
challenge roles. -/
def FixedOtherRole (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (key : Key) : Prop :=
  ¬ RoleActive selected blockCap keyBytes key

abbrev ActiveKey (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) :=
  { key : Key // RoleActive selected blockCap keyBytes key }

abbrev FixedOtherKey (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) :=
  { key : Key // FixedOtherRole selected blockCap keyBytes key }

theorem unrecognized_is_active (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (key : Key)
    (unrecognized : parseStageQuery (keyBytes key) = none) :
    RoleActive selected blockCap keyBytes key := by
  simp [RoleActive, unrecognized]

theorem selected_role_is_active (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (key : Key)
    (query : StageQuery) (parsed : parseStageQuery (keyBytes key) = some query)
    (same : query.role = selected) :
    RoleActive selected blockCap keyBytes key := by
  simp [RoleActive, parsed, same]

theorem out_of_cap_is_active (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (key : Key)
    (query : StageQuery) (parsed : parseStageQuery (keyBytes key) = some query)
    (outside : ¬ query.counter < blockCap query.role) :
    RoleActive selected blockCap keyBytes key := by
  simp [RoleActive, parsed, outside]

theorem different_bounded_role_is_fixed (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (key : Key)
    (query : StageQuery) (parsed : parseStageQuery (keyBytes key) = some query)
    (different : query.role ≠ selected)
    (bounded : query.counter < blockCap query.role) :
    FixedOtherRole selected blockCap keyBytes key := by
  simp [FixedOtherRole, RoleActive, parsed, different, bounded]

/-- The exact selected-plus-complement/other-roles partition of finite keys. -/
def roleKeySumEquiv (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) :
    Key ≃ ActiveKey selected blockCap keyBytes ⊕
      FixedOtherKey selected blockCap keyBytes where
  toFun key :=
    if active : RoleActive selected blockCap keyBytes key then
      Sum.inl ⟨key, active⟩
    else
      Sum.inr ⟨key, active⟩
  invFun value := Sum.elim Subtype.val Subtype.val value
  left_inv key := by
    by_cases active : RoleActive selected blockCap keyBytes key <;>
      simp [active]
  right_inv value := by
    cases value with
    | inl key =>
        have active : RoleActive selected blockCap keyBytes key.val := key.property
        simp [active]
    | inr key =>
        have inactive : ¬ RoleActive selected blockCap keyBytes key.val := by
          simpa only [FixedOtherRole] using key.property
        simp [inactive]

/-- Reindex a complete finite table along an input equivalence. -/
def reindexTable {Left Right Value : Type*} (equivalence : Left ≃ Right) :
    (Left → Value) ≃ (Right → Value) where
  toFun table input := table (equivalence.symm input)
  invFun table input := table (equivalence input)
  left_inv table := by
    funext input
    simp
  right_inv table := by
    funext input
    simp

/-- Whole-table equivalence used for role-specific conditioning.  Its second
component contains only recognized roles different from `selected`. -/
def roleTableSplit (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) :
    (Key → Output) ≃
      (ActiveKey selected blockCap keyBytes → Output) ×
        (FixedOtherKey selected blockCap keyBytes → Output) :=
  (reindexTable (roleKeySumEquiv selected blockCap keyBytes)).trans
    (oracleDomainSplit (ActiveKey selected blockCap keyBytes)
      (FixedOtherKey selected blockCap keyBytes) Output)

@[simp] theorem role_table_split_active (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (table : Key → Output)
    (key : ActiveKey selected blockCap keyBytes) :
    (roleTableSplit selected blockCap keyBytes table).1 key = table key.val := rfl

@[simp] theorem role_table_split_fixed (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (table : Key → Output)
    (key : FixedOtherKey selected blockCap keyBytes) :
    (roleTableSplit selected blockCap keyBytes table).2 key = table key.val := rfl

/-- A uniform whole table remains a uniform product after the exact role
partition. -/
theorem uniform_role_table_split
    [Fintype Key] [Fintype Output] [Nonempty Output]
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) :
    pmfMap (uniformFintypePMF (Key → Output))
        (roleTableSplit selected blockCap keyBytes) =
      uniformFintypePMF
        ((ActiveKey selected blockCap keyBytes → Output) ×
          (FixedOtherKey selected blockCap keyBytes → Output)) := by
  exact V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv
    (roleTableSplit selected blockCap keyBytes)

/-- Point masses factor into the active table and the fixed-other-role table.
This is the finite identity behind averaging a pointwise fixed-advice bound. -/
theorem split_uniform_role_table_point_mass_factors
    [Fintype Key] [Fintype Output] [Nonempty Output]
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output) :
    uniformFintypePMF
        ((ActiveKey selected blockCap keyBytes → Output) ×
          (FixedOtherKey selected blockCap keyBytes → Output)) (active, fixed) =
      uniformFintypePMF (ActiveKey selected blockCap keyBytes → Output) active *
        uniformFintypePMF (FixedOtherKey selected blockCap keyBytes → Output) fixed := by
  simp only [uniformFintypePMF_apply, Fintype.card_prod, Nat.cast_mul]
  exact ENNReal.mul_inv (Or.inr (by simp)) (Or.inl (by simp))

/-! ## Exact finite conditioning -/

theorem output_event_probability_equiv
    {Left Right : Type*} [Fintype Left] [Fintype Right]
    (equivalence : Left ≃ Right) (event : Right → Prop) :
    outputEventProbability (fun input => event (equivalence input)) =
      outputEventProbability event := by
  classical
  let eventSet := Finset.univ.filter event
  have count := V8Smz9CoherentVectorMerkle.equiv_event_card equivalence eventSet
  have denominator := Fintype.card_congr equivalence
  unfold outputEventProbability
  rw [show (Finset.univ.filter fun input : Left => event (equivalence input)).card =
      eventSet.card by simpa [eventSet] using count]
  rw [denominator]

/-- Uniform probability on a product is the exact average of the probabilities
after fixing its second component. -/
theorem output_event_probability_product_eq_average
    {Active Fixed : Type*} [Fintype Active] [Fintype Fixed]
    [Nonempty Active] [Nonempty Fixed]
    (event : Active → Fixed → Prop) :
    outputEventProbability (fun pair : Active × Fixed => event pair.1 pair.2) =
      (∑ fixed : Fixed, outputEventProbability (fun active => event active fixed)) /
        Fintype.card Fixed := by
  classical
  have count :
      (Finset.univ.filter fun pair : Active × Fixed => event pair.1 pair.2).card =
        ∑ fixed : Fixed,
          (Finset.univ.filter fun active : Active => event active fixed).card := by
    simp only [Finset.card_eq_sum_ones, Finset.sum_filter]
    rw [Fintype.sum_prod_type, Finset.sum_comm]
  unfold outputEventProbability
  rw [count, Fintype.card_prod, Nat.cast_mul, Nat.cast_sum]
  rw [← Finset.sum_div, div_div]

/-- Exact disintegration of a whole-table event.  The event on the right is
still the event on the original table, reconstructed from the active table
and one fixed other-role table. -/
theorem role_table_event_probability_eq_fixed_average
    [Fintype Key] [Fintype Output] [Nonempty Output]
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (event : (Key → Output) → Prop) :
    outputEventProbability event =
      (∑ fixed : FixedOtherKey selected blockCap keyBytes → Output,
        outputEventProbability fun active : ActiveKey selected blockCap keyBytes → Output =>
          event ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))) /
        Fintype.card (FixedOtherKey selected blockCap keyBytes → Output) := by
  let split := roleTableSplit (Output := Output) selected blockCap keyBytes
  calc
    outputEventProbability event =
        outputEventProbability
          (fun pair : (ActiveKey selected blockCap keyBytes → Output) ×
              (FixedOtherKey selected blockCap keyBytes → Output) =>
            event (split.symm pair)) := by
      simpa only [split, Equiv.symm_apply_apply] using
        (output_event_probability_equiv split
          (fun pair => event (split.symm pair)))
    _ = _ := output_event_probability_product_eq_average
      (fun active fixed => event (split.symm (active, fixed)))

/-- A pointwise bound for every fixed table averages to the same bound on the
original whole-table event. -/
theorem role_table_event_probability_le_of_fixed
    [Fintype Key] [Fintype Output] [Nonempty Output]
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (event : (Key → Output) → Prop) (bound : Rat)
    (pointwise : ∀ fixed : FixedOtherKey selected blockCap keyBytes → Output,
      outputEventProbability
        (fun active : ActiveKey selected blockCap keyBytes → Output =>
          event ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))) ≤ bound) :
    outputEventProbability event ≤ bound := by
  rw [role_table_event_probability_eq_fixed_average selected blockCap keyBytes event]
  have positive :
      (0 : Rat) < Fintype.card
        (FixedOtherKey selected blockCap keyBytes → Output) := by
    exact_mod_cast Fintype.card_pos
  apply (div_le_iff₀ positive).2
  calc
    (∑ fixed : FixedOtherKey selected blockCap keyBytes → Output,
        outputEventProbability
          (fun active : ActiveKey selected blockCap keyBytes → Output =>
            event ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)))) ≤
        ∑ _fixed : FixedOtherKey selected blockCap keyBytes → Output, bound :=
      Finset.sum_le_sum fun fixed _ => pointwise fixed
    _ = bound * Fintype.card
        (FixedOtherKey selected blockCap keyBytes → Output) := by
      simp [mul_comm]

/-! ## Same-physical-execution unions -/

def eventProjection {Basis : Type*} (event : Basis → Prop)
    (state : Basis → ℂ) : Basis → ℂ :=
  fun basis => if event basis then state basis else 0

def finiteNormSquared {Coordinate : Type*} [Fintype Coordinate]
    (state : Coordinate → ℂ) : ℝ :=
  ∑ coordinate, Complex.normSq (state coordinate)

/-- Union bound for diagonal events on one unchanged finite state.  No event
is evaluated on a role-conditioned surrogate state. -/
theorem same_execution_event_union_bound
    {Index Coordinate : Type*} [Fintype Index] [Fintype Coordinate]
    (events : Index → Coordinate → Prop) (state : Coordinate → ℂ) :
    finiteNormSquared
        (eventProjection (fun basis => ∃ index, events index basis) state) ≤
      ∑ index : Index,
        finiteNormSquared (eventProjection (events index) state) := by
  classical
  unfold finiteNormSquared eventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  by_cases present : ∃ index, events index basis
  · obtain ⟨index, selected⟩ := present
    rw [if_pos ⟨index, selected⟩]
    calc
      Complex.normSq (state basis) =
          Complex.normSq (if events index basis then state basis else 0) := by
        rw [if_pos selected]
      _ ≤ ∑ other : Index,
          Complex.normSq (if events other basis then state basis else 0) :=
        Finset.single_le_sum
          (fun other _ => Complex.normSq_nonneg
            (if events other basis then state basis else 0))
          (Finset.mem_univ index)
  · rw [if_neg present]
    simpa using
      (Finset.sum_nonneg fun other _ => Complex.normSq_nonneg
        (if events other basis then state basis else 0))

/-- The corresponding union bound for final workspace/database predicates in
the initialized CMS state.  All four role events can therefore be defined on
the same final execution before applying their separately conditioned bounds. -/
theorem same_execution_workspace_event_union_bound
    {Index Input Phase Workspace : Type*}
    [Fintype Index] [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (events : Index → Workspace → Database Input Output → Prop)
    (state : State Input Output Phase Workspace) :
    normSquared
        (workspaceEventProjection
          (fun workspace database => ∃ index, events index workspace database) state) ≤
      ∑ index : Index,
        normSquared (workspaceEventProjection (events index) state) := by
  simpa only [workspaceEventProjection, eventProjection,
    finiteNormSquared, normSquared] using
    (same_execution_event_union_bound
      (events := fun index basis => events index basis.workspace basis.database)
      state)

end
end HegemonCrypto.SmallWood.SmzaRoleDomainConditioning
