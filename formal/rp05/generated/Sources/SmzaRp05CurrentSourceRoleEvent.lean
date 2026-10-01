import SmzaRp05CurrentTracePrefixes406
import SmzaRp05CurrentMaxAgreementSelectedStage
import SmzaRp05CurrentBornRoleTransport
import SmzaRp05CurrentRoleLabels
import SmzaRp05CurrentMatrixRoleEvent
import SmzaRp05AdaptiveDynamicBad

/-!
# Current-map source extraction event on the physical DECS-sample role

This event connects the exact current 406-map maximum-agreement decoder
failure predicate to the dynamic CMS role compiler.  Its fixed-prefix
density is charged only after the earlier matrix label has established the
complement of the current universal matrix event.  The exceptional matrix
mass remains the separate `.decsMatrix` role event.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceRoleEvent

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05CurrentTracePrefixes406
open SmzaRp05CurrentQ38DetectionProbability
open SmzaRp05CurrentMaxAgreementSelectedStage
open SmzaRp05CurrentQ38RawSamplerDensity
open SmzaRp05CurrentBornRoleTransport
open SmzaRp05CurrentRoleLabels
open SmzaRp05CurrentMatrixRoleEvent
open SmzaRp05CurrentUniversalMatrixLoss
open SmzaQ38OracleExtraction
open SmzaRp05AdaptiveDynamicBad
open SmzaRp05TracePrefixes
open SmzaRp05LeafNamespace
open SmzaRp05FilteredReadback SmzaRp05FilteredDecoderInstability
open SmzaRp04McaRoleCells SmzaRp04RoleBadCells
open SmzaRp04RawRoleSampling SmzaRp04RawMcaSampling
open V8Smz9CappedRawSampler V8Smz9RawCounterCompiler
open V8Smz9CoherentVectorMerkle
open SmzaChallengeStageTargets
open SmzaRp04FourRoleLedger

local notation "Statement" => SmzaRp05StatementNamespace.Statement

private theorem output_event_probability_false_local {Output : Type*}
    [Fintype Output] :
    outputEventProbability (fun _ : Output => False) = 0 := by
  classical
  unfold outputEventProbability
  simp

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 16000
set_option maxHeartbeats 1000000

@[reducible] def currentSourceRawInputDecidableEq :
    DecidableEq V8SmzaOracleParser.RawInput :=
  (inferInstance : LinearOrder V8SmzaOracleParser.RawInput).toDecidableEq

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  currentSourceRawInputDecidableEq

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest

inductive TypedCurrentSourceLabel406 (width : Statement → Nat) where
  | unavailable
  | decoded (statement : Statement) (sourceLabel : CurrentSourcePrefix406)

def currentSourceRoleLabelsFromBytes406 (model : RelationModel)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (advice : AllEarlierTables model .decsSample)
    (statementBytes : List HegemonCrypto.CanonicalBytes.Byte)
    (trace : SmzaRp05TracePrefixes.Trace) :
    TypedCurrentSourceLabel406 model.width :=
  match statementOfBytes? statementBytes with
  | none => .unavailable
  | some statement =>
      match currentSourcePrefixFromTrace406 model ns statement
          (advice statement) trace with
      | none => .unavailable
      | some sourceLabel => .decoded statement sourceLabel

def currentSourceRoleBad406 {Counter : Type*} (model : RelationModel)
    (routes : TypedRoutes model Counter) (label : TypedCurrentSourceLabel406 model.width)
    (vector : VectorOutput Counter) : Prop :=
  match label with
  | .unavailable => False
  | .decoded statement sourceLabel =>
      ∃ query, actualDecsSampleOutput (routes statement).decsSample vector = some query ∧
        currentSourceBad406 sourceLabel query

private def prefixAsCurrentLvcsKey406 (label : CurrentDecodedLvcsLabel406) :
    DecsSamplePrefixKey :=
  ⟨label.rows, label.points, label.claimedCoefficients⟩

theorem current_source_role_bad_density406
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (routes : TypedRoutes model Counter)
    (label : TypedCurrentSourceLabel406 model.width) :
    outputEventProbability (currentSourceRoleBad406 model routes label) ≤
      smallSupportLoss + roleLoss .decsSample := by
  cases label with
  | unavailable =>
      change outputEventProbability (fun _ : VectorOutput Counter => False) ≤ _
      rw [output_event_probability_false_local]
      change 0 ≤ sourceOnlyRoleLoss .decsSample
      exact source_only_role_loss_nonnegative .decsSample
  | decoded statement sourceLabel =>
      let route := (routes statement).decsSample
      let failure := fun vector : VectorOutput Counter =>
        ∃ query, actualDecsSampleOutput route vector = some query ∧
          currentFailureAt406 sourceLabel query
      let lvcs := fun vector : VectorOutput Counter =>
        ∃ decoded, sourceLabel.decodedLvcs = some decoded ∧
          ∃ query, actualDecsSampleOutput route vector = some query ∧
            currentDecodedLvcsBad406 decoded query
      have badEq : currentSourceRoleBad406 model routes (.decoded statement sourceLabel) =
          fun vector => failure vector ∨ lvcs vector := by
        funext vector
        apply propext
        constructor
        · rintro ⟨query, outputEq, failureOrLvcs⟩
          rcases failureOrLvcs with failed | ⟨decoded, decodedEq, bad⟩
          · exact Or.inl ⟨query, outputEq, failed⟩
          · exact Or.inr ⟨decoded, decodedEq, query, outputEq, bad⟩
        · rintro (⟨query, outputEq, failed⟩ |
            ⟨decoded, decodedEq, query, outputEq, bad⟩)
          · exact ⟨query, outputEq, Or.inl failed⟩
          · exact ⟨query, outputEq, Or.inr ⟨decoded, decodedEq, bad⟩⟩
      rw [badEq]
      apply (HegemonCrypto.SmallWood.SmzaRp04CompleteRawRoleCells.output_event_union_le
        failure lvcs).trans
      apply add_le_add
      · have failureEq : failure = fun vector : VectorOutput Counter =>
            ∃ query, actualDecsSampleOutput route vector = some query ∧
              query ∈ currentGoodMatrixFailureQueries
                (SmzaQ38McaSourceBinding.oracleData sourceLabel.oracle)
                (SmzaQ38McaSourceBinding.oracleMasks sourceLabel.oracle)
                sourceLabel.response sourceLabel.coefficients := by
          funext vector
          simp [failure, currentFailureAt406, currentAcceptedFailure406,
            currentGoodMatrixFailureQueries, sourceLabel.matrixGood]
        rw [failureEq]
        simpa only [smallSupportLoss,
          SmzaRp05CurrentMaxAgreementRecovery.currentAgreementThreshold,
          SmzaRp05CurrentMaxAgreementSelectedStage.CurrentPosition,
          SmzaRp05CurrentMaxAgreementRecovery.Position,
          SmzaQ38McaSourceBinding.Position,
          SmzaQ38OracleExtraction.decsDomainSize,
          V8Smz9LogicalOracle.decsDomainSize, Fintype.card_fin] using
          (actual_current_good_matrix_decoder_failure_le route
            (SmzaQ38McaSourceBinding.oracleData sourceLabel.oracle)
            (SmzaQ38McaSourceBinding.oracleMasks sourceLabel.oracle)
            sourceLabel.response sourceLabel.coefficients sourceLabel.matrixGood)
      · cases decoded : sourceLabel.decodedLvcs with
        | none =>
            have empty : lvcs = fun _ => False := by
              funext vector
              simp [lvcs, decoded]
            rw [empty, output_event_probability_false_local]
            have q38LossNonnegative :
                0 ≤ SmzaRp04ChronologicalAlgebra.q38SingleRootLoss := by
              unfold SmzaRp04ChronologicalAlgebra.q38SingleRootLoss
              exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
            change 0 ≤ 12 * SmzaRp04ChronologicalAlgebra.q38SingleRootLoss
            exact mul_nonneg (by norm_num) q38LossNonnegative
        | some lvcsLabel =>
            have lvcsEventEq : lvcs = fun vector : VectorOutput Counter =>
                ∃ query, actualDecsSampleOutput route vector = some query ∧
                  query ∈ SmzaRp05CurrentQ38DetectionProbability.currentLvcsBadQueryEvent
                    lvcsLabel.rows lvcsLabel.points
                    (SmzaRp04ChronologicalAlgebra.claimedPolynomials
                      lvcsLabel.claimedCoefficients) := by
              funext vector
              simp [lvcs, decoded, currentDecodedLvcsBad406, lvcsLabel.rowsDegree]
            rw [lvcsEventEq]
            exact SmzaRp05CurrentQ38RawSamplerDensity.current_decs_sample_bad_and_success_le route
              (prefixAsCurrentLvcsKey406 lvcsLabel).rows
              (prefixAsCurrentLvcsKey406 lvcsLabel).points
              (SmzaRp04ChronologicalAlgebra.claimedPolynomials
                (prefixAsCurrentLvcsKey406 lvcsLabel).claimedCoefficients)
              lvcsLabel.rowsDegree
              (SmzaRp04ChronologicalAlgebra.claimed_polynomials_degree405
                (prefixAsCurrentLvcsKey406 lvcsLabel).claimedCoefficients)

def currentSourceRoleEvent406 {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsSample) (outerFuel innerFuel : Nat)
    (authorized : Finset (List HegemonCrypto.CanonicalBytes.Byte)) :
    Database Key (VectorOutput Counter) → Prop :=
  roleEvent keyBytes (vectorOutputBytes counter) (globalLeafStatement ns)
    (rawTraceDecoder (globalOnlineNext ns)
      (fun key => targetOfRaw .decsSample (keyBytes key))
      (fun _ trace => preambleFromTrace ns .decsSample trace) outerFuel)
    (statementTraceDecoder (globalOnlineNext ns)
      (fun _ key => targetOfRaw .decsSample (keyBytes key))
      (fun statement _ trace => currentSourceRoleLabelsFromBytes406 model ns advice
        statement trace) innerFuel)
    (fun key => InRoleDomain .decsSample (keyBytes key))
    (fun _ label vector => currentSourceRoleBad406 model routes label vector) authorized

/-- The exceptional matrix mass is a sibling event compiled on the same
physical trace, using current-map matrix labels and the raw sampler bound.
The source event above is defined only on the good-matrix prefix branch.
-/
def currentSourceMatrixRoleEvent406 {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsMatrix) (outerFuel innerFuel : Nat)
    (authorized : Finset (List HegemonCrypto.CanonicalBytes.Byte)) :
    Database Key (VectorOutput Counter) → Prop :=
  currentMatrixRoleEvent406 model ns keyBytes counter routes advice
    outerFuel innerFuel authorized

theorem current_source_matrix_role_instability_406
    {Key Counter : Type*} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel cap : Nat)
    (authorized : Finset (List HegemonCrypto.CanonicalBytes.Byte)) :
    InstabilityBound
      (currentSourceMatrixRoleEvent406 model ns keyBytes counter routes advice
        outerFuel innerFuel authorized)
      cap ((6 * cap : Rat) / (2^512 : Rat) + currentMatrixLoss) := by
  simpa [currentSourceMatrixRoleEvent406] using
    current_matrix_role_event_instability_406 model ns keyBytes counter routes
      advice outerFuel innerFuel cap authorized

theorem current_source_role_instability_406
    {Key Counter : Type*} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsSample)
    (outerFuel innerFuel cap : Nat)
    (authorized : Finset (List HegemonCrypto.CanonicalBytes.Byte)) :
    InstabilityBound
      (currentSourceRoleEvent406 model ns keyBytes counter routes advice
        outerFuel innerFuel authorized)
      cap ((6 * cap : Rat) / (2^512 : Rat) + smallSupportLoss + roleLoss .decsSample) := by
  unfold currentSourceRoleEvent406
  have bound := rp05_role_instability ns keyBytes counter
    (fun key => targetOfRaw .decsSample (keyBytes key))
    (fun _ trace => preambleFromTrace ns .decsSample trace)
    (fun _ key => targetOfRaw .decsSample (keyBytes key))
    (fun statement _ trace => currentSourceRoleLabelsFromBytes406 model ns advice
      statement trace)
    outerFuel innerFuel authorized cap
    (fun key => InRoleDomain .decsSample (keyBytes key))
    (fun _statement label vector => currentSourceRoleBad406 model routes label vector)
    (smallSupportLoss + roleLoss .decsSample)
    (source_only_role_loss_nonnegative .decsSample)
    (fun _ label => current_source_role_bad_density406 model routes label)
  simpa only [add_assoc] using bound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceRoleEvent
