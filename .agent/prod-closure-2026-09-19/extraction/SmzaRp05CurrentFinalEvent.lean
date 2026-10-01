import SmzaRp05FinalSoundness
import SmzaRp05PhysicalTerminalRead
import SmzaRp05TerminalEventTransport
import SmzaRp05SequentialReadCharge
import SmzaRp05SecurityLedger
import SmzaRp05VectorRetention

/-!
# Accepted failure on the physical selected terminal view

This is the semantic event inclusion at the final selected readout, not at
the pre-decompression state. Every recorded vector claim is established by
an honest physical answer branch. It avoids the invalid assumption that an
arbitrary compressed database already contains those answers. The separate
same-execution probability bound for the final role event remains open.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFinalEvent

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsQuerySequence
open SmzaChallengeStageTargets SmzaRp04CompleteRawRoleCells
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05AcceptedRoleLabels SmzaRp05AcceptedExtraction
open SmzaRp05TerminalExtraction SmzaRp05TracePrefixes SmzaRp05PartialReadout
open SmzaRp05FinalSoundness SmzaRp05PhysicalTerminalRead
open SmzaRp05TerminalEventTransport
open SmzaRp05SequentialReadCharge
open SmzaRp05SecurityLedger SmzaRp05VectorRetention
open SmzaRp04FourRoleLedger
open SmzaRp05SuffixReadout SmzaRp05AdaptiveFilteredCollision
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Output := VectorOutput Counter
abbrev CmsState {Key Counter BaseWork : Type} :=
  SmzaRp05CurrentAdaptiveExecution.CmsState
    (Key := Key) (Counter := Counter) (BaseWork := BaseWork)
abbrev Work {Counter BaseWork : Type} :=
  SmzaRp05CurrentAdaptiveExecution.Work
    (Counter := Counter) (BaseWork := BaseWork)

/-- The accepted semantic failure is measured on the final selected physical
read state. The witness's database is this state, not the earlier compressed
database. -/
def acceptedPhysicalSelectedFailureMass
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)) (keys : List Key) : ℝ :=
  ∑ answers : ReadAnswers (Input := Key) (Output (Counter := Counter)) keys,
    normSquared
      (adaptiveProject
        (acceptedFailureEvent model refinement ns keyBytes counter
          routes allAdvice outerFuel innerFuel authorizedOf
          (branchClaims keys answers)) cap
        (decompressList keys (physicalReadTrace keys answers state)))

/-- Pointwise accepted-failure classification on the actual selected read
branch. Claim failure vanishes because those exact keys and vectors were
physically measured; neither their compressed initial presence nor a
postselected normalization is a premise. -/
theorem accepted_physical_branch_failure_le_final_role
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) (Output (Counter := Counter)) keys) :
    normSquared
      (adaptiveProject
        (acceptedFailureEvent model refinement ns keyBytes counter
          routes allAdvice outerFuel innerFuel authorizedOf
          (branchClaims keys answers)) cap
        (decompressList keys (physicalReadTrace keys answers state))) ≤
    normSquared
      (adaptiveProject
        (CertifiedFor.anyContextRoleEvent
          (CertifiedFor.roleContexts model ns keyBytes counter routes
            allAdvice outerFuel innerFuel authorizedOf)) cap
        (decompressList keys (physicalReadTrace keys answers state))) := by
  let finalState := decompressList keys (physicalReadTrace keys answers state)
  have known : ∀ claim ∈ branchClaims keys answers,
      KnownAt claim.1 claim.2 finalState := by
    intro claim member
    exact selected_physical_branch_claim_known keys nodup answers state
      claim member
  have claimZero := adaptive_claim_failure_eq_zero_of_known
    (BaseWork := BaseWork) (branchClaims keys answers) cap finalState known
  have classified := accepted_failure_event_mass_le_role_or_claim
    model refinement ns keyBytes counter routes allAdvice outerFuel
    innerFuel cap authorizedOf (branchClaims keys answers) finalState
  rw [claimZero] at classified
  simpa [finalState, normSquared] using classified

/-- The complete physical answer instrument inherits the pointwise final
event inclusion, with every answer branch retained at its original mass. -/
theorem accepted_physical_selected_failure_mass_le_final_roles
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)) (keys : List Key) (nodup : keys.Nodup) :
    acceptedPhysicalSelectedFailureMass model refinement ns keyBytes
      counter routes allAdvice outerFuel innerFuel cap authorizedOf state keys ≤
    ∑ answers : ReadAnswers (Input := Key) (Output (Counter := Counter)) keys,
      normSquared
        (adaptiveProject
          (CertifiedFor.anyContextRoleEvent
            (CertifiedFor.roleContexts model ns keyBytes counter routes
              allAdvice outerFuel innerFuel authorizedOf)) cap
          (decompressList keys (physicalReadTrace keys answers state))) := by
  unfold acceptedPhysicalSelectedFailureMass
  apply Finset.sum_le_sum
  intro answers _
  exact accepted_physical_branch_failure_le_final_role model refinement
    ns keyBytes counter routes allAdvice outerFuel innerFuel cap
    authorizedOf state keys nodup answers

private theorem adaptive_event_mass_le_uncapped
    (event : Work (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (Output (Counter := Counter)) → Prop)
    (cap : Nat)
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)) :
    normSquared (adaptiveProject event cap state) ≤
      normSquared (workspaceEventProjection event state) := by
  unfold normSquared adaptiveProject workspaceEventProjection
  apply Finset.sum_le_sum
  intro basis _
  by_cases within : size basis.database ≤ cap <;>
    by_cases selected : event basis.workspace basis.database <;>
    simp [within, selected, Complex.normSq_nonneg]

/-- The final accepted event, evaluated after physical read and selected
decompression, is bounded by the same-branch pre-decompression role event
plus the explicit vector-output event transport charge. The first term still
needs a certified bound on the actual physical read execution; this theorem
does not supply one by assumption or re-label a legacy read schedule. -/
theorem accepted_physical_selected_failure_mass_transport
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (keys : List Key) (nodup : keys.Nodup)
    (total : TotalOn keys (globalDecompress state)) :
    acceptedPhysicalSelectedFailureMass model refinement ns keyBytes
        counter routes allAdvice outerFuel innerFuel cap authorizedOf state keys ≤
      2 * (∑ answers : ReadAnswers (Input := Key)
          (Output (Counter := Counter)) keys,
        normSquared (workspaceEventProjection
          (CertifiedFor.anyContextRoleEvent
            (CertifiedFor.roleContexts model ns keyBytes counter routes
              allAdvice outerFuel innerFuel authorizedOf))
          (physicalReadTrace keys answers state))) +
      ((2 * (keys.length : ℝ)^2 + 2 * keys.length) /
        Fintype.card (Output (Counter := Counter))) * normSquared state := by
  let roleEvent := CertifiedFor.anyContextRoleEvent
    (CertifiedFor.roleContexts model ns keyBytes counter routes
      allAdvice outerFuel innerFuel authorizedOf)
  have included := accepted_physical_selected_failure_mass_le_final_roles
    model refinement ns keyBytes counter routes allAdvice outerFuel
    innerFuel cap authorizedOf state keys nodup
  have uncapped :
      (∑ answers : ReadAnswers (Input := Key)
          (Output (Counter := Counter)) keys,
        normSquared (adaptiveProject roleEvent cap
          (decompressList keys (physicalReadTrace keys answers state)))) ≤
      ∑ answers : ReadAnswers (Input := Key)
          (Output (Counter := Counter)) keys,
        normSquared (workspaceEventProjection roleEvent
          (decompressList keys (physicalReadTrace keys answers state))) := by
    apply Finset.sum_le_sum
    intro answers _
    exact adaptive_event_mass_le_uncapped roleEvent cap _
  have transported := sum_final_role_event_mass_le_physical_pre_event
    keys nodup state total roleEvent
  exact included.trans (uncapped.trans (by simpa [roleEvent] using transported))

/-- The remaining role term is represented by the exact one-charge-per-read
CMS circuit. This is a circuit identity, not yet a certification that the
larger verifier-plus-read circuit satisfies the four role contexts. -/
theorem accepted_physical_selected_failure_mass_charged
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap support : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (keys : List Key) (nodup : keys.Nodup)
    (bounded : BoundedState support state)
    (total : TotalOn keys (globalDecompress state)) :
    acceptedPhysicalSelectedFailureMass model refinement ns keyBytes
        counter routes allAdvice outerFuel innerFuel cap authorizedOf state keys ≤
      2 * (∑ answers : ReadAnswers (Input := Key)
          (Output (Counter := Counter)) keys,
        normSquared (workspaceEventProjection
          (CertifiedFor.anyContextRoleEvent
            (CertifiedFor.roleContexts model ns keyBytes counter routes
              allAdvice outerFuel innerFuel authorizedOf))
          (chargedReadTrace keys answers support state))) +
      ((2 * (keys.length : ℝ)^2 + 2 * keys.length) /
        Fintype.card (Output (Counter := Counter))) * normSquared state := by
  have bound := accepted_physical_selected_failure_mass_transport
    model refinement ns keyBytes counter routes allAdvice outerFuel
    innerFuel cap authorizedOf state keys nodup total
  rw [← sum_charged_read_trace_event_norm_eq
    keys support state bounded total
    (CertifiedFor.anyContextRoleEvent
      (CertifiedFor.roleContexts model ns keyBytes counter routes
        allAdvice outerFuel innerFuel authorizedOf))] at bound
  exact bound

/-- Homogeneous final-readout transport from a certified role budget. Both
charges use the same pre-terminal branch mass, which may exceed terminal mass
after contractive gates. This is the form that can be summed over branches;
it does not manufacture the role-budget premise for the actual execution. -/
theorem accepted_physical_selected_failure_le_readout_budget
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap queries : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (keys : List Key) (nodup : keys.Nodup)
    (total : TotalOn keys (globalDecompress state))
    (within : keys.length ≤ queries)
    (sourceMass : ℝ)
    (sourceDominates : normSquared state ≤ sourceMass)
    (roleBudget :
      (∑ answers : ReadAnswers (Input := Key)
          (Output (Counter := Counter)) keys,
        normSquared (workspaceEventProjection
          (CertifiedFor.anyContextRoleEvent
            (CertifiedFor.roleContexts model ns keyBytes counter routes
              allAdvice outerFuel innerFuel authorizedOf))
          (physicalReadTrace keys answers state))) ≤
        (terminalExtractionLoss queries : ℝ) * sourceMass) :
    acceptedPhysicalSelectedFailureMass model refinement ns keyBytes
      counter routes allAdvice outerFuel innerFuel cap authorizedOf state keys ≤
        (readoutTransportLoss queries : ℝ) * sourceMass := by
  let roleMass := ∑ answers : ReadAnswers (Input := Key)
      (Output (Counter := Counter)) keys,
    normSquared (workspaceEventProjection
      (CertifiedFor.anyContextRoleEvent
        (CertifiedFor.roleContexts model ns keyBytes counter routes
          allAdvice outerFuel innerFuel authorizedOf))
      (physicalReadTrace keys answers state))
  let coefficient : ℝ :=
    (2 * (keys.length : ℝ)^2 + 2 * keys.length) /
      Fintype.card (Output (Counter := Counter))
  have denominator : (2 : ℝ)^512 ≤
      (Fintype.card (Output (Counter := Counter)) : ℝ) := by
    exact_mod_cast vector_output_cardinality_ge_digest counter
  have numeratorBound :
      2 * (keys.length : ℝ)^2 + 2 * keys.length ≤
        4 * (queries : ℝ)^2 := by
    exact_mod_cast physical_readout_coefficient_le keys.length queries within
  have coefficientBound : coefficient ≤
      4 * (queries : ℝ)^2 / (2 : ℝ)^512 := by
    dsimp [coefficient]
    calc
      _ ≤ (2 * (keys.length : ℝ)^2 + 2 * keys.length) /
          (2 : ℝ)^512 :=
        div_le_div_of_nonneg_left (by positivity) (by positivity) denominator
      _ ≤ 4 * (queries : ℝ)^2 / (2 : ℝ)^512 :=
        div_le_div_of_nonneg_right numeratorBound (by positivity)
  have massNonnegative : 0 ≤ normSquared state := by
    unfold normSquared
    exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)
  have sourceNonnegative : 0 ≤ sourceMass :=
    le_trans massNonnegative sourceDominates
  have coefficientNonnegative : 0 ≤ coefficient := by
    dsimp [coefficient]
    positivity
  have charged : coefficient * normSquared state ≤
      (4 * (queries : ℝ)^2 / (2 : ℝ)^512) * sourceMass := by
    calc
      _ ≤ coefficient * sourceMass :=
        mul_le_mul_of_nonneg_left sourceDominates coefficientNonnegative
      _ ≤ (4 * (queries : ℝ)^2 / (2 : ℝ)^512) * sourceMass :=
        mul_le_mul_of_nonneg_right coefficientBound sourceNonnegative
  have transported := accepted_physical_selected_failure_mass_transport
    model refinement ns keyBytes counter routes allAdvice outerFuel
    innerFuel cap authorizedOf state keys nodup total
  change roleMass ≤ (terminalExtractionLoss queries : ℝ) *
    sourceMass at roleBudget
  change acceptedPhysicalSelectedFailureMass model refinement ns
      keyBytes counter routes allAdvice outerFuel innerFuel cap authorizedOf
      state keys ≤ 2 * roleMass + coefficient * normSquared state
    at transported
  have aggregate :
      acceptedPhysicalSelectedFailureMass model refinement ns keyBytes
          counter routes allAdvice outerFuel innerFuel cap authorizedOf state keys ≤
        (2 * (terminalExtractionLoss queries : ℝ) +
          4 * (queries : ℝ)^2 / (2 : ℝ)^512) * sourceMass := by
    calc
      _ ≤ 2 * roleMass + coefficient * normSquared state := transported
      _ ≤ (2 * (terminalExtractionLoss queries : ℝ) +
          4 * (queries : ℝ)^2 / (2 : ℝ)^512) * sourceMass := by
        nlinarith [roleBudget, charged]
  simpa [readoutTransportLoss] using aggregate

/-- The numerical `<2^-130` endpoint for at most unit source mass. A loose
pre-read bound of `<2^-130` would lose a bit under the factor of two; the
homogeneous terminal-extraction premise above is required. -/
theorem accepted_physical_selected_failure_below_130_bits_of_role_budget
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap queries : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (keys : List Key) (nodup : keys.Nodup)
    (total : TotalOn keys (globalDecompress state))
    (within : keys.length ≤ queries)
    (queriesLe : queries ≤ 3 * 2^64)
    (sourceMass : ℝ)
    (sourceDominates : normSquared state ≤ sourceMass)
    (sourceSubnormalized : sourceMass ≤ 1)
    (roleBudget :
      (∑ answers : ReadAnswers (Input := Key)
          (Output (Counter := Counter)) keys,
        normSquared (workspaceEventProjection
          (CertifiedFor.anyContextRoleEvent
            (CertifiedFor.roleContexts model ns keyBytes counter routes
              allAdvice outerFuel innerFuel authorizedOf))
          (physicalReadTrace keys answers state))) ≤
        (terminalExtractionLoss queries : ℝ) * sourceMass) :
    acceptedPhysicalSelectedFailureMass model refinement ns keyBytes
      counter routes allAdvice outerFuel innerFuel cap authorizedOf state keys <
        1 / (2 : ℝ)^130 := by
  have aggregate := accepted_physical_selected_failure_le_readout_budget
    model refinement ns keyBytes counter routes allAdvice outerFuel
    innerFuel cap queries authorizedOf state keys nodup total within
    sourceMass sourceDominates roleBudget
  have localNonnegative : (0 : Rat) ≤ fourRoleLocalLoss := by
    unfold fourRoleLocalLoss
    exact add_nonneg
      (add_nonneg
        (add_nonneg (source_only_role_loss_nonnegative .decsMatrix)
          (source_only_role_loss_nonnegative .piopMatrix))
        (source_only_role_loss_nonnegative .piopOpening))
      (source_only_role_loss_nonnegative .decsSample)
  have terminalNonnegative : (0 : ℝ) ≤
      (terminalExtractionLoss queries : ℝ) := by
    have localReal : (0 : ℝ) ≤ (fourRoleLocalLoss : ℝ) := by
      exact_mod_cast localNonnegative
    unfold terminalExtractionLoss
    push_cast
    positivity
  have budgetNonnegative : 0 ≤
      (readoutTransportLoss queries : ℝ) := by
    unfold readoutTransportLoss
    push_cast
    positivity
  have capped : (readoutTransportLoss queries : ℝ) * sourceMass ≤
      (readoutTransportLoss queries : ℝ) := by
    nlinarith [mul_le_mul_of_nonneg_left sourceSubnormalized budgetNonnegative]
  have numericalBudget : (readoutTransportLoss queries : ℝ) <
      1 / (2 : ℝ)^130 := by
    have budgetRat := readout_transport_loss_below_130_bits queries queriesLe
    have castBudget : ((readoutTransportLoss queries : Rat) : ℝ) <
        (((1 / (2 : Rat)^130) : Rat) : ℝ) :=
      (Rat.cast_lt (K := ℝ)).2 budgetRat
    simpa only [Rat.cast_div, Rat.cast_one, Rat.cast_pow, Rat.cast_ofNat] using
      castBudget
  exact lt_of_le_of_lt
    (le_trans aggregate capped) numericalBudget

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFinalEvent
