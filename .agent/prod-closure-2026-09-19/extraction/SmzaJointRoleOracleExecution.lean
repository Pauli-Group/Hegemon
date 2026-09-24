import SmzaDynamicStageLabels

/-!
# All four challenge roles on one oracle execution

The label is the tuple of the four actual extraction prefixes.  Both creating
and losing its bad-cell event are covered by the dynamic database lemma.  This
avoids composing four unrelated quantum readout distributions or supplying
four stage-security conclusions as hypotheses.  Only the individual classical
output densities and deterministic accepted-claim inclusion remain to apply.
-/
namespace HegemonCrypto.SmallWood.SmzaJointRoleOracleExecution

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentVectorMerkle
open SmzaChallengeStageTargets SmzaFixedAdvicePrefix SmzaDynamicDatabaseSoundness
open SmzaDynamicOracleExecution SmzaDynamicStageLabels

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option exponentiation.threshold 1024
set_option backward.isDefEq.respectTransparency false

theorem output_event_exists_le_sum {Index Output : Type*}
    [Fintype Index] [Fintype Output] (events : Index → Output → Prop) :
    outputEventProbability (fun output => ∃ index, events index output) ≤
      ∑ index, outputEventProbability (events index) := by
  classical
  have union : (Finset.univ.filter fun output => ∃ index, events index output) =
      Finset.univ.biUnion (fun index => Finset.univ.filter (events index)) := by
    ext output
    simp
  have count : (Finset.univ.filter fun output => ∃ index, events index output).card ≤
      ∑ index, (Finset.univ.filter (events index)).card := by
    rw [union]
    exact Finset.card_biUnion_le
  unfold outputEventProbability
  calc
    _ ≤ (∑ index, ((Finset.univ.filter (events index)).card : Rat)) /
        Fintype.card Output :=
      div_le_div_of_nonneg_right (by
        rw [← Nat.cast_sum, Nat.cast_le]
        convert count using 1
        apply congrArg Finset.card
        ext output
        simp only [Finset.mem_filter, Finset.mem_univ, true_and]) (Nat.cast_nonneg _)
    _ = _ := by rw [Finset.sum_div]

variable {Key Counter Label Advice Workspace : Type*}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]

def allRoleLabel (next : Next) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Role → Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (database : Database Key (VectorOutput Counter))
    (input : Key) : Role → Label :=
  fun role => actualRoleLabel next role fuel keyBytes counter (code role) advice database input

def anyRoleBad (bad : Role → Label → Key → VectorOutput Counter → Prop)
    (labels : Role → Label) (input : Key) (output : VectorOutput Counter) : Prop :=
  ∃ role, bad role (labels role) input output

theorem all_role_label_change_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (fuel : Nat) (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Role → Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability
      (TrackedLabelChange (allRoleLabel next fuel keyBytes counter code advice) database queried)
      database queried ≤ (12*cap : Rat)/(2^512 : Rat) := by
  let events := fun role output => TrackedLabelChange
    (actualRoleLabel next role fuel keyBytes counter (code role) advice)
      database queried (query database queried output)
  have included : ∀ output,
      TrackedLabelChange (allRoleLabel next fuel keyBytes counter code advice)
        database queried (query database queried output) → ∃ role, events role output := by
    intro output changed
    obtain ⟨input, tracked, different⟩ := changed
    have someRole : ∃ role,
        actualRoleLabel next role fuel keyBytes counter (code role) advice
          (query database queried output) input ≠
        actualRoleLabel next role fuel keyBytes counter (code role) advice database input := by
      by_contra none
      push Not at none
      exact different (funext none)
    obtain ⟨role, changedRole⟩ := someRole
    exact ⟨role, input, tracked, changedRole⟩
  have perRole : ∀ role, outputEventProbability (events role) ≤
      (3*cap : Rat)/(2^512 : Rat) := by
    intro role
    exact actual_role_tracked_label_changes next children role fuel keyBytes counter
      (code role) advice cap database bounded queried
  calc
    _ ≤ outputEventProbability (fun output => ∃ role, events role output) :=
      step_probability_le_output_event _ database queried _ included
    _ ≤ ∑ role, outputEventProbability (events role) := output_event_exists_le_sum events
    _ ≤ ∑ _role : Role, (3*cap : Rat)/(2^512 : Rat) :=
      Finset.sum_le_sum (fun role _ => perRole role)
    _ = _ := by
      have roleCard : Fintype.card Role = 4 := by decide
      simp only [Finset.sum_const, Finset.card_univ, roleCard, nsmul_eq_mul]
      ring

variable [Fintype Workspace] [DecidableEq Workspace]

theorem actual_joint_role_oracle_failure_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (fuel : Nat) (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Role → Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (bad : Role → Label → Key → VectorOutput Counter → Prop)
    (epsilon : Role → Rat) (nonnegative : ∀ role, 0 ≤ epsilon role)
    (perLabel : ∀ role label input,
      outputEventProbability (bad role label input) ≤ epsilon role)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (enabled : Workspace → Prop) (claims : Workspace → List (Key × VectorOutput Counter))
    (distinct : ∀ workspace, ((claims workspace).map Prod.fst).Nodup)
    (maxClaims : Nat) (claimBound : ∀ workspace, (claims workspace).length ≤ maxClaims)
    (included : ∀ workspace database,
      AdaptiveClaimsEvent enabled claims workspace database →
        DynamicBad (allRoleLabel next fuel keyBytes counter code advice)
          (anyRoleBad bad) database) :
    normSquared (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
      (totalOracleFamilyState
        (oracleFamilyRun vectorPhaseSystem steps (fun _ => registers)))) ≤
      oracleLoss (databaseLoss steps.length
        (((12*steps.length : Rat)/(2^512 : Rat) + ∑ role, epsilon role : Rat) : ℝ))
        ((maxClaims : ℝ)^2 / (Fintype.card (VectorOutput Counter) : ℝ)) := by
  apply actual_dynamic_oracle_failure_bound vectorCompletePhaseSystem
    (allRoleLabel next fuel keyBytes counter code advice) (anyRoleBad bad)
    (∑ role, epsilon role) ((12*steps.length : Rat)/(2^512 : Rat))
    (Finset.sum_nonneg (fun role _ => nonnegative role)) (by positivity)
    _ steps
    (all_role_label_change_bound next children fuel keyBytes counter code advice steps.length)
    registers normalized enabled claims distinct maxClaims claimBound included
  intro labels input
  exact (output_event_exists_le_sum (fun role => bad role (labels role) input)).trans
    (Finset.sum_le_sum (fun role _ => perLabel role (labels role) input))

end
end HegemonCrypto.SmallWood.SmzaJointRoleOracleExecution
