import SmzaRp05CurrentOrdinarySoundnessComposition
import SmzaRp05CurrentPhysicalNonchallengeClaims
import SmzaRp05CurrentPhysicalBranchClaims
import SmzaRp05ProgramPhysicalMass
import SmzaRp05CurrentKnownClaimsFailureMass

/-! # Readout-loss budget on the ordinary physical Born measure

This packages the two concrete missing-answer losses on the same unnormalized
ordinary-prefix / physical-verifier execution.  Nonchallenge failures are
charged directly on the original physical branch states.  Recognized
challenge failures are charged after the exact active fixed-fiber transport;
the sum of those selected fibers is bounded by the original incoming norm.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinaryReadoutBudget

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05OrdinarySoundnessStandardTotal
open SmzaRp05CurrentOrdinarySoundnessComposition
open SmzaRp05CurrentPhysicalNonchallengeClaims
open SmzaRp05CurrentSelectedChallengeClaims
open SmzaRp05CurrentNonchallengeSelectorTransport
open SmzaRp05CurrentNonchallengeSelectorFiberMass
open SmzaRp05CurrentPhysicalBranchClaims
open SmzaRp05CurrentKnownClaimsFailureMass
open SmzaRp05AdaptiveRetainedAdviceTransport
open SmzaRp05AdaptivePhysicalReadBound
  (ReadsAtMost ReadsWithinKeys physicalBranchesFintype)
open SmzaRp05ConditionedExecution (other_role_transform_norm_squared)
open SmzaRp05PhysicalAcceptedReplayLite (branchKeys branchClaims physicalRun)
open SmzaRp05CurrentMixedBranchClaimReadback (mixedBranchClaims)
open SmzaRp05PartialReadout (claimFailureProjection)
open SmzaRp05RoleReadTotality (StandardOn)
open SmzaRp05ProgramPhysicalMass (adaptive_program_branch_mass_eq_initial)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

private theorem branch_keys_length_le
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (depth : Nat) (program : Program Result)
    (branch : Branches decode program)
    (readBound : ReadsAtMost decode depth program) :
    (branchKeys encode decode program branch).length ≤ depth := by
  induction depth generalizing program with
  | zero =>
      cases program with
      | done result => simp [branchKeys]
      | read raw next => cases readBound
  | succ depth inductionHypothesis =>
      cases program with
      | done result => simp [branchKeys]
      | read raw next =>
          rcases branch with ⟨answer, tail⟩
          have tailBound := inductionHypothesis (next (decode raw answer)) tail
            (readBound answer)
          simp only [branchKeys, List.length_cons]
          omega

private theorem mixed_branch_claims_length_le_keys
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program) :
    (mixedBranchClaims ctx blockCap encode decode program branch).length ≤
      (branchKeys encode decode program branch).length := by
  induction program with
  | done result => rfl
  | read raw next inductionHypothesis =>
      rcases branch with ⟨answer, tail⟩
      by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
      · simp only [mixedBranchClaims, branchKeys, live, List.length_cons]
        exact Nat.succ_le_succ (inductionHypothesis (decode raw answer) tail)
      · simp only [mixedBranchClaims, branchKeys, live, List.length_cons]
        exact Nat.le_succ_of_le (inductionHypothesis (decode raw answer) tail)

private theorem selected_challenge_claim_card_le_depth
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (depth : Nat) (program : Program Result)
    (branch : Branches decode program)
    (readBound : ReadsAtMost decode depth program) :
    (recognizedActiveChallengeClaims ctx blockCap encode decode program branch).toFinset.card
      ≤ depth := by
  calc
    (recognizedActiveChallengeClaims ctx blockCap encode decode program branch).toFinset.card ≤
        (recognizedActiveChallengeClaims ctx blockCap encode decode program branch).length :=
      List.toFinset_card_le _
    _ ≤ (mixedBranchClaims ctx blockCap encode decode program branch).length :=
      List.length_filter_le _ _
    _ ≤ (branchKeys encode decode program branch).length :=
      mixed_branch_claims_length_le_keys ctx blockCap encode decode program branch
    _ ≤ depth := branch_keys_length_le encode decode depth program branch readBound

private def selectedRoleView
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (select : (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop :=
  branchXRoleSelector ctx blockCap encode decode program branch
    (nonchallengeRawKeySet ctx)
    (by
      intro claim member
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        of_decide_eq_true (List.mem_filter.mp member).2⟩)
    select

private def selectedRoleState
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (fixed : FixedTable ctx blockCap)
    (initial : ActiveState ctx blockCap)
    (select : (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    ActiveState ctx blockCap :=
  workspaceEventProjection
    (fun work database => selectedRoleView ctx blockCap encode decode program branch select
      (activeXView ctx blockCap (nonchallengeRawKeySet ctx)
        (nonchallenge_raw_key_set_unrecognized ctx) database)
      work.original.2.2)
    (mixedRun ctx blockCap fixed encode decode program branch initial)

/-- The sum of all parser-none answer failures, over the four role contexts
and every actual physical verifier branch, is charged against the exact
post-prefix incoming norm. -/
theorem ordinary_four_role_nonchallenge_failure_mass_le
    {cap finish queries : Nat}
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program) :
    letI := physicalBranchesFintype decode program
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
    (∑ role : Role, ∑ branch : Branches decode program,
      normSquared (claimFailureProjection
        (branchNonchallengeClaims (contexts role).keyBytes encode decode program branch)
        (physicalRun encode decode program branch initial))) ≤
      (4 * ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
        normSquared (ordinaryRun ordinaryProgram
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
  classical
  letI := physicalBranchesFintype decode program
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  have standard := initialized_ordinary_run_standard_total ordinaryProgram registers
  have total : StandardOn keys initial := by
    intro key _
    exact standard key
  have perRole (role : Role) :
      (∑ branch : Branches decode program,
        normSquared (claimFailureProjection
          (branchNonchallengeClaims (contexts role).keyBytes encode decode program branch)
          (physicalRun encode decode program branch initial))) ≤
        ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter) *
          normSquared initial := by
    have bound := selected_nonchallenge_claim_failure_mass_le
      (contexts role).keyBytes encode decode program initial keys keysWithin total
      depth readBound (fun _ => True)
    simpa [initial] using bound
  calc
    (∑ role : Role, ∑ branch : Branches decode program,
      normSquared (claimFailureProjection
        (branchNonchallengeClaims (contexts role).keyBytes encode decode program branch)
        (physicalRun encode decode program branch initial))) ≤
      ∑ role : Role,
        (((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter) *
          normSquared initial) := by
        apply Finset.sum_le_sum
        intro role _
        exact perRole role
    _ = (4 * ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
        normSquared initial := by
      have roleCard : Fintype.card Role = 4 := by decide
      simp only [Finset.sum_const, Finset.card_univ, roleCard, nsmul_eq_mul]
      ring

/-- The selected challenge-claim failure mass, summed over all four
role-dependent X views, is bounded on the original incoming Born measure.
The state sum first disintegrates the literal physical branches through
fixed-table fibers, then uses total ordinary physical branch mass. -/
theorem ordinary_four_role_challenge_failure_mass_le
    {cap finish queries : Nat}
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (readBound : ReadsAtMost decode depth program)
    (blockCap : Role → Nat)
    (dummy : ∀ role : Role, ActiveKey (contexts role).role blockCap
      (contexts role).keyBytes)
    (select : ∀ role : Role, Branches decode program →
      (XKey (nonchallengeRawKeySet (contexts role)) → Option (VectorOutput Counter)) →
        SmzaRp05CurrentAdaptiveExecution.Work
          (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    letI := physicalBranchesFintype decode program
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
    (∑ role : Role, ∑ branch : Branches decode program,
      ∑ fixed : FixedTable (contexts role) blockCap,
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (recognizedActiveChallengeClaims (contexts role) blockCap encode decode program branch)
            database)
          (selectedRoleState (contexts role) blockCap encode decode program branch fixed
            (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
              (otherRoleTransform (contexts role) blockCap initial))
            (select role branch)))) ≤
      (4 * ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
        normSquared (ordinaryRun ordinaryProgram
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
  classical
  letI := physicalBranchesFintype decode program
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  have standard := initialized_ordinary_run_standard_total ordinaryProgram registers
  have originalMass :
      (∑ branch : Branches decode program,
        normSquared (physicalRun encode decode program branch initial)) =
        normSquared initial := by
    simpa [initial] using adaptive_program_branch_mass_eq_initial
      encode decode program initial standard
  have selectedMassBound (role : Role) :
      (∑ branch : Branches decode program,
        ∑ fixed : FixedTable (contexts role) blockCap,
          normSquared (selectedRoleState (contexts role) blockCap encode decode program
            branch fixed
            (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
              (otherRoleTransform (contexts role) blockCap initial))
            (select role branch))) ≤ normSquared initial := by
    have fiberIdentity (branch : Branches decode program) :
        normSquared (nonchallengeSelectorProjection
          (nonchallengeRawKeySet (contexts role))
          (selectedRoleView (contexts role) blockCap encode decode program branch
            (select role branch))
          (otherRoleTransform (contexts role) blockCap
            (physicalRun encode decode program branch initial))) =
        ∑ fixed : FixedTable (contexts role) blockCap,
          normSquared (workspaceEventProjection
            (activeNonchallengeSelectorEvent (contexts role) blockCap
              (nonchallengeRawKeySet (contexts role))
              (nonchallenge_raw_key_set_unrecognized (contexts role))
              (selectedRoleView (contexts role) blockCap encode decode program branch
                (select role branch)))
            (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
              (otherRoleTransform (contexts role) blockCap
                (physicalRun encode decode program branch initial)))) := by
      exact ordinary_physical_branch_selector_mass_eq_active_fiber_sum
        ordinaryProgram registers encode decode program branch (contexts role)
        blockCap (dummy role) (nonchallengeRawKeySet (contexts role))
        (nonchallenge_raw_key_set_unrecognized (contexts role))
        (selectedRoleView (contexts role) blockCap encode decode program branch
          (select role branch))
    have selectorContract (branch : Branches decode program) :
        normSquared (nonchallengeSelectorProjection
          (nonchallengeRawKeySet (contexts role))
          (selectedRoleView (contexts role) blockCap encode decode program branch
            (select role branch))
          (otherRoleTransform (contexts role) blockCap
            (physicalRun encode decode program branch initial))) ≤
          normSquared (physicalRun encode decode program branch initial) := by
      have eventLe := workspace_event_mass_le_of_inclusion
        (fun work database =>
          selectedRoleView (contexts role) blockCap encode decode program branch
            (select role branch) (xView (nonchallengeRawKeySet (contexts role)) database)
            work)
        (fun _ _ => True)
        (otherRoleTransform (contexts role) blockCap
          (physicalRun encode decode program branch initial))
        (by intro work database _; trivial)
      calc
        _ ≤ normSquared (workspaceEventProjection (fun _ _ => True)
            (otherRoleTransform (contexts role) blockCap
              (physicalRun encode decode program branch initial))) := by
          simpa [nonchallengeSelectorProjection, selectedRoleView,
            branchXRoleSelector] using eventLe
        _ = normSquared (physicalRun encode decode program branch initial) := by
          have trueProjection (state : SmzaRp05CurrentAdaptiveExecution.CmsState
              (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
              workspaceEventProjection (fun _ _ => True) state = state := by
            funext basis
            simp [workspaceEventProjection]
          rw [trueProjection]
          exact other_role_transform_norm_squared (contexts role) blockCap _
    have selectedStateEq (branch : Branches decode program)
        (fixed : FixedTable (contexts role) blockCap) :
        selectedRoleState (contexts role) blockCap encode decode program branch fixed
          (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
            (otherRoleTransform (contexts role) blockCap initial))
          (select role branch) =
        workspaceEventProjection
          (activeNonchallengeSelectorEvent (contexts role) blockCap
            (nonchallengeRawKeySet (contexts role))
            (nonchallenge_raw_key_set_unrecognized (contexts role))
            (selectedRoleView (contexts role) blockCap encode decode program branch
              (select role branch)))
          (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
            (otherRoleTransform (contexts role) blockCap
              (physicalRun encode decode program branch initial))) := by
      unfold selectedRoleState selectedRoleView
      rw [← physical_run_to_mixed_same_fiber (contexts role) blockCap (dummy role)
        _ encode decode program branch initial]
      rfl
    calc
      (∑ branch : Branches decode program,
        ∑ fixed : FixedTable (contexts role) blockCap,
          normSquared (selectedRoleState (contexts role) blockCap encode decode program
            branch fixed
            (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
              (otherRoleTransform (contexts role) blockCap initial))
            (select role branch))) =
        ∑ branch : Branches decode program,
          ∑ fixed : FixedTable (contexts role) blockCap,
            normSquared
              (workspaceEventProjection
                (activeNonchallengeSelectorEvent (contexts role) blockCap
                  (nonchallengeRawKeySet (contexts role))
                  (nonchallenge_raw_key_set_unrecognized (contexts role))
                  (selectedRoleView (contexts role) blockCap encode decode program branch
                    (select role branch)))
                (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
                  (otherRoleTransform (contexts role) blockCap
                    (physicalRun encode decode program branch initial)))) := by
          apply Finset.sum_congr rfl
          intro branch _
          apply Finset.sum_congr rfl
          intro fixed _
          exact congrArg (fun state => normSquared state)
            (selectedStateEq branch fixed)
      _ = ∑ branch : Branches decode program,
          normSquared (nonchallengeSelectorProjection
            (nonchallengeRawKeySet (contexts role))
            (selectedRoleView (contexts role) blockCap encode decode program branch
              (select role branch))
          (otherRoleTransform (contexts role) blockCap
              (physicalRun encode decode program branch initial))) := by
          apply Finset.sum_congr rfl
          intro branch _
          simpa only [selectedRoleView] using (fiberIdentity branch).symm
      _ ≤ ∑ branch : Branches decode program,
          normSquared (physicalRun encode decode program branch initial) := by
        apply Finset.sum_le_sum
        intro branch _
        exact selectorContract branch
      _ = normSquared initial := originalMass
  have perRole (role : Role) :
      (∑ branch : Branches decode program,
        ∑ fixed : FixedTable (contexts role) blockCap,
          normSquared (databaseEventProjection
            (fun database => ¬ ClaimsDatabaseEvent
              (recognizedActiveChallengeClaims (contexts role) blockCap encode decode program branch)
              database)
            (selectedRoleState (contexts role) blockCap encode decode program branch fixed
              (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
                (otherRoleTransform (contexts role) blockCap initial))
              (select role branch)))) ≤
        ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter) *
          normSquared initial := by
    calc
      _ ≤ ∑ branch : Branches decode program,
          ∑ fixed : FixedTable (contexts role) blockCap,
            (((2 * (recognizedActiveChallengeClaims (contexts role) blockCap
                encode decode program branch).toFinset.card : Nat) : ℝ) /
              Fintype.card (VectorOutput Counter)) *
              normSquared (selectedRoleState (contexts role) blockCap encode decode program
                branch fixed
                (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
                  (otherRoleTransform (contexts role) blockCap initial))
                (select role branch)) := by
          apply Finset.sum_le_sum
          intro branch _
          apply Finset.sum_le_sum
          intro fixed _
          let fixedCtx := contexts role
          have selectedLower := actual_selected_challenge_claim_event_mass_lower_on_all_x_keys
            fixedCtx blockCap fixed encode decode program branch
            (fixedFiberToActive fixedCtx blockCap (dummy role) fixed
              (otherRoleTransform fixedCtx blockCap initial))
            (select role branch)
          have split := database_event_complement_mass_split
            (ClaimsDatabaseEvent (recognizedActiveChallengeClaims fixedCtx blockCap
              encode decode program branch))
            (selectedRoleState fixedCtx blockCap encode decode program branch fixed
              (fixedFiberToActive fixedCtx blockCap (dummy role) fixed
                (otherRoleTransform fixedCtx blockCap initial)) (select role branch))
          have failureBound :
              normSquared (databaseEventProjection
                (fun database => ¬ ClaimsDatabaseEvent
                  (recognizedActiveChallengeClaims fixedCtx blockCap encode decode
                    program branch) database)
                (selectedRoleState fixedCtx blockCap encode decode program branch fixed
                  (fixedFiberToActive fixedCtx blockCap (dummy role) fixed
                    (otherRoleTransform fixedCtx blockCap initial)) (select role branch))) ≤
              ((2 * (recognizedActiveChallengeClaims fixedCtx blockCap encode decode
                program branch).toFinset.card : Nat) : ℝ) /
                Fintype.card (VectorOutput Counter) *
                  normSquared (selectedRoleState fixedCtx blockCap encode decode program
                    branch fixed
                    (fixedFiberToActive fixedCtx blockCap (dummy role) fixed
                      (otherRoleTransform fixedCtx blockCap initial)) (select role branch)) := by
            have selectedLower' :
                normSquared (databaseEventProjection
                  (ClaimsDatabaseEvent (recognizedActiveChallengeClaims fixedCtx
                    blockCap encode decode program branch))
                  (selectedRoleState fixedCtx blockCap encode decode program branch fixed
                    (fixedFiberToActive fixedCtx blockCap (dummy role) fixed
                      (otherRoleTransform fixedCtx blockCap initial)) (select role branch))) +
                ((2 * (recognizedActiveChallengeClaims fixedCtx blockCap encode decode
                    program branch).toFinset.card : Nat) : ℝ) /
                  Fintype.card (VectorOutput Counter) *
                    normSquared (selectedRoleState fixedCtx blockCap encode decode program
                      branch fixed
                      (fixedFiberToActive fixedCtx blockCap (dummy role) fixed
                        (otherRoleTransform fixedCtx blockCap initial)) (select role branch)) ≥
              normSquared (selectedRoleState fixedCtx blockCap encode decode program branch
                fixed (fixedFiberToActive fixedCtx blockCap (dummy role) fixed
                  (otherRoleTransform fixedCtx blockCap initial)) (select role branch)) := by
              simpa [selectedRoleState, selectedRoleView] using selectedLower
            nlinarith [selectedLower', split]
          simpa only [fixedCtx] using failureBound
      _ ≤ ∑ branch : Branches decode program,
          ∑ fixed : FixedTable (contexts role) blockCap,
            (((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
              normSquared (selectedRoleState (contexts role) blockCap encode decode program
                branch fixed
                (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
                  (otherRoleTransform (contexts role) blockCap initial))
                (select role branch)) := by
          apply Finset.sum_le_sum
          intro branch _
          apply Finset.sum_le_sum
          intro fixed _
          have cardBound := selected_challenge_claim_card_le_depth
            (contexts role) blockCap encode decode depth program branch readBound
          have denomPositive :
              0 < (Fintype.card (VectorOutput Counter) : ℝ) := by
            exact_mod_cast Fintype.card_pos
          have coefficientBound :
              ((2 * (recognizedActiveChallengeClaims (contexts role) blockCap
                encode decode program branch).toFinset.card : Nat) : ℝ) /
                Fintype.card (VectorOutput Counter) ≤
              ((2 * depth : Nat) : ℝ) /
                Fintype.card (VectorOutput Counter) := by
            apply div_le_div_of_nonneg_right
            · exact_mod_cast Nat.mul_le_mul_left 2 cardBound
            · exact le_of_lt denomPositive
          exact mul_le_mul_of_nonneg_right coefficientBound (by
            unfold normSquared
            exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _)
      _ = ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter) *
          (∑ branch : Branches decode program,
            ∑ fixed : FixedTable (contexts role) blockCap,
              normSquared (selectedRoleState (contexts role) blockCap encode decode program
                branch fixed
                (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
                  (otherRoleTransform (contexts role) blockCap initial))
                (select role branch))) := by
          simp_rw [Finset.mul_sum]
      _ ≤ ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter) *
          normSquared initial := by
          apply mul_le_mul_of_nonneg_left (selectedMassBound role)
          positivity
  calc
    (∑ role : Role, ∑ branch : Branches decode program,
      ∑ fixed : FixedTable (contexts role) blockCap,
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (recognizedActiveChallengeClaims (contexts role) blockCap encode decode program branch)
            database)
          (selectedRoleState (contexts role) blockCap encode decode program branch fixed
            (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
              (otherRoleTransform (contexts role) blockCap initial))
            (select role branch)))) ≤
      ∑ role : Role,
        (((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter) *
          normSquared initial) := by
        apply Finset.sum_le_sum
        intro role _
        exact perRole role
    _ = (4 * ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
        normSquared initial := by
      have roleCard : Fintype.card Role = 4 := by decide
      simp only [Finset.sum_const, Finset.card_univ, roleCard, nsmul_eq_mul]
      ring_nf

/-- Both finite readout charges live on the same original Born measure; their
sum is therefore an additive `16*depth/M` loss, before the deterministic
current-role/collision coverage is applied. -/
theorem ordinary_four_role_total_readout_loss_le
    {cap finish queries : Nat}
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program)
    (blockCap : Role → Nat)
    (dummy : ∀ role : Role, ActiveKey (contexts role).role blockCap
      (contexts role).keyBytes)
    (select : ∀ role : Role, Branches decode program →
      (XKey (nonchallengeRawKeySet (contexts role)) → Option (VectorOutput Counter)) →
        SmzaRp05CurrentAdaptiveExecution.Work
          (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    letI := physicalBranchesFintype decode program
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
    (∑ role : Role, ∑ branch : Branches decode program,
      normSquared (claimFailureProjection
        (branchNonchallengeClaims (contexts role).keyBytes encode decode program branch)
        (physicalRun encode decode program branch initial))) +
    (∑ role : Role, ∑ branch : Branches decode program,
      ∑ fixed : FixedTable (contexts role) blockCap,
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent
            (recognizedActiveChallengeClaims (contexts role) blockCap encode decode program branch)
            database)
          (selectedRoleState (contexts role) blockCap encode decode program branch fixed
            (fixedFiberToActive (contexts role) blockCap (dummy role) fixed
              (otherRoleTransform (contexts role) blockCap initial))
            (select role branch)))) ≤
      (16 * ((depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
        normSquared (ordinaryRun ordinaryProgram
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
  classical
  dsimp only
  have nonchallenge := ordinary_four_role_nonchallenge_failure_mass_le
    contexts ordinaryProgram registers depth encode decode program readBound keys keysWithin
  have challenge := ordinary_four_role_challenge_failure_mass_le
    contexts ordinaryProgram registers depth encode decode program readBound blockCap dummy select
  have initialNonnegative :
      0 ≤ normSquared (ordinaryRun ordinaryProgram
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
    unfold normSquared
    exact Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _
  calc
    _ ≤ (4 * ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
          normSquared (ordinaryRun ordinaryProgram
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) +
        (4 * ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
          normSquared (ordinaryRun ordinaryProgram
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :=
      add_le_add nonchallenge challenge
    _ = (16 * ((depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)) *
          normSquared (ordinaryRun ordinaryProgram
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
      push_cast
      ring

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinaryReadoutBudget
