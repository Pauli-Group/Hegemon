import SmzaDynamicOracleExecution
import SmzaStageVectorInstability

/-! Instantiate the dynamic bad-database route with actual VC extraction
traces and the full vector oracle.  Labels are tracked at the existing recorded
keys PLUS the queried key, so the new selected output is not silently assumed
independent of a label computed after that output.  Their number is at most T.
The existing raw parser/child theorem supplies the 3T/2^512 insertion bound. -/
namespace HegemonCrypto.SmallWood.SmzaDynamicStageLabels

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting
open HegemonCrypto.CmsFinitePhaseSystem
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentVectorMerkle
open SmzaChallengeStageTargets SmzaFixedAdvicePrefix SmzaStageVectorInstability
open SmzaDynamicDatabaseSoundness SmzaDynamicOracleExecution

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option exponentiation.threshold 1024

variable {Key Counter Label Advice Workspace : Type*}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]

def trackedQueries (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (database : Database Key (VectorOutput Counter)) (queried : Key) :=
  (queried :: (support database).toList).map keyBytes

theorem tracked_queries_length_le (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (database : Database Key (VectorOutput Counter)) (queried : Key) (cap : Nat)
    (bounded : size database < cap) :
    (trackedQueries keyBytes database queried).length ≤ cap := by
  simpa only [trackedQueries, List.length_map, List.length_cons,
    Finset.length_toList, size] using Nat.succ_le_of_lt bounded

theorem tracked_queries_mem (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (database : Database Key (VectorOutput Counter)) (queried input : Key)
    (tracked : input = queried ∨ database input ≠ none) :
    keyBytes input ∈ trackedQueries keyBytes database queried := by
  apply List.mem_map.mpr
  refine ⟨input, ?_, rfl⟩
  rcases tracked with same | present
  · exact List.mem_cons.mpr (Or.inl same)
  · apply List.mem_cons.mpr
    right
    apply Finset.mem_toList.mpr
    exact (mem_support_iff database input).mpr (Option.ne_none_iff_exists'.mp present)

def actualRoleLabel (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (database : Database Key (VectorOutput Counter)) (input : Key) : Label :=
  enrichedLabel next role fuel code advice
    (rawRecords keyBytes (vectorOutputBytes counter) database) (keyBytes input)

theorem actual_role_tracked_label_changes
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability
      (TrackedLabelChange (actualRoleLabel next role fuel keyBytes counter code advice)
        database queried) database queried ≤ (3*cap : Rat)/(2^512 : Rat) := by
  apply stage_vector_step_change_bound next children role fuel keyBytes counter
    (trackedQueries keyBytes database queried) cap
    (tracked_queries_length_le keyBytes database queried cap bounded)
    database bounded queried
  intro output changed sameTrace
  obtain ⟨input, tracked, different⟩ := changed
  apply different
  exact fixed_advice_postprocessing_preserves_prefix_equality next role fuel code advice
    (rawRecords keyBytes (vectorOutputBytes counter) (query database queried output))
    (rawRecords keyBytes (vectorOutputBytes counter) database)
    (trackedQueries keyBytes database queried) sameTrace (keyBytes input)
    (tracked_queries_mem keyBytes database queried input tracked)

variable [Fintype Workspace] [DecidableEq Workspace]

/-- A role's accepted bad claims are bounded on the same full-vector oracle
execution.  The local label-change loss is now derived from actual source trace
geometry, not supplied as a coupling/readout/stage probability premise. -/
theorem actual_role_oracle_failure_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (bad : Label → Key → VectorOutput Counter → Prop)
    (epsilon : Rat) (nonnegative : 0 ≤ epsilon)
    (perLabel : ∀ value input, outputEventProbability (bad value input) ≤ epsilon)
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
        DynamicBad (actualRoleLabel next role fuel keyBytes counter code advice) bad database) :
    normSquared (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
      (totalOracleFamilyState
        (oracleFamilyRun vectorPhaseSystem steps (fun _ => registers)))) ≤
      oracleLoss
        (databaseLoss steps.length
          (((3*steps.length : Rat)/(2^512 : Rat) + epsilon : Rat) : ℝ))
        ((maxClaims : ℝ)^2 / (Fintype.card (VectorOutput Counter) : ℝ)) := by
  exact actual_dynamic_oracle_failure_bound vectorCompletePhaseSystem
    (actualRoleLabel next role fuel keyBytes counter code advice) bad epsilon
    ((3*steps.length : Rat)/(2^512 : Rat)) nonnegative (by positivity) perLabel steps
    (actual_role_tracked_label_changes next children role fuel keyBytes counter code advice
      steps.length) registers normalized enabled claims distinct maxClaims claimBound included

end
end HegemonCrypto.SmallWood.SmzaDynamicStageLabels
