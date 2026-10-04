import SmzaRp05CurrentDecsMatrixSampling
import SmzaRp05CurrentUniversalMatrixLoss
import SmzaRp05CurrentBornRoleTransport
import SmzaRp05AdaptiveDynamicBad

/-!
# Current-map DECS-matrix event on the physical role trace

This is a parallel current-map role event.  It leaves the historical event
untouched and uses the same trace-derived committed-oracle label and selected
raw DECS-matrix route as the physical role compiler. The current decoder
uses the verifier's five contiguous 140-coefficient rows, not the historical
140-by-five flattening. Its explicit coordinate equivalence preserves the
successful-fiber count and all stated density bounds.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentMatrixRoleEvent

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.FiniteFieldSampling
open SmzaRp05CurrentUniversalMatrixLoss
open SmzaRp05CurrentBornRoleTransport
open SmzaRp05AdaptiveDynamicBad
open SmzaRp05CurrentDecsMatrixSampling SmzaRp04RawRoleSampling
open SmzaRp04CompleteRawRoleCells SmzaRp04McaRoleCells
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction
open SmzaRp05TracePrefixes SmzaRp05CurrentRoleLabels
open SmzaRp05FilteredDecoderInstability SmzaRp05FilteredReadback
open SmzaRp05LeafNamespace
open SmzaChallengeStageTargets
open V8Smz9RawCounterCompiler V8Smz9CappedRawSampler
open V8Smz9RobustQueryMismatch V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 20000

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

private theorem output_event_probability_false_local {Output : Type*}
    [Fintype Output] :
    outputEventProbability (fun _ : Output => False) = 0 := by
  classical
  unfold outputEventProbability
  simp

def currentRawMatrixBad (oracle : CommittedOracle)
    (coefficients : SmzaRp05CurrentUniversalMatrixLoss.Coefficients) : Prop :=
  currentMatrixBad (oracleData oracle) (oracleMasks oracle) coefficients

theorem raw_current_matrix_bad_and_success_le (oracle : CommittedOracle) :
    outputEventProbability
      (fun raw : Fin (digestCallCap (5 * 140)) → RawByteBlock =>
        ∃ output, currentRawDecsMatrixOutput raw = some output ∧
          currentRawMatrixBad oracle output) ≤ currentMatrixLoss := by
  let bad : Finset SmzaRp05CurrentUniversalMatrixLoss.Coefficients :=
    Finset.univ.filter (currentRawMatrixBad oracle)
  have decoderFiberEqual : ∀ left right : SmzaRp05CurrentUniversalMatrixLoss.Coefficients,
      Fintype.card (SuccessfulFiber (totalEquivDecoder currentDecsMatrixFieldEquiv) left) =
        Fintype.card (SuccessfulFiber (totalEquivDecoder currentDecsMatrixFieldEquiv) right) := by
    intro left right
    exact total_equiv_decoder_fibers_equal currentDecsMatrixFieldEquiv left right
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap (5 * 140)) (5 * 140)
    (totalEquivDecoder currentDecsMatrixFieldEquiv) decoderFiberEqual bad
  have event :
      (fun raw : Fin (digestCallCap (5 * 140)) → RawByteBlock =>
        ∃ output, currentRawDecsMatrixOutput raw = some output ∧ output ∈ bad) =
      (fun raw => ∃ output, currentRawDecsMatrixOutput raw = some output ∧
        currentRawMatrixBad oracle output) := by
    funext raw
    simp only [bad, Finset.mem_filter, Finset.mem_univ, true_and]
  calc
    _ ≤ FiniteEvents.probability bad := by
      rw [← event]
      exact sampled
    _ = outputEventProbability (currentRawMatrixBad oracle) := by
      calc
        _ = outputEventProbability (fun output => output ∈ bad) :=
          (SmzaRp04RoleBadCells.output_event_probability_membership bad).symm
        _ = outputEventProbability (currentRawMatrixBad oracle) := by
          apply congrArg outputEventProbability
          funext output
          apply propext
          simp [bad]
    _ ≤ currentMatrixLoss := by
      exact current_matrix_bad_output_density (oracleData oracle) (oracleMasks oracle)

theorem actual_current_matrix_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap (5 * 140)) ↪ Counter)
    (oracle : CommittedOracle) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ output, currentActualDecsMatrixOutput select vector = some output ∧
        currentRawMatrixBad oracle output) ≤ currentMatrixLoss := by
  change outputEventProbability (fun vector =>
    (fun raw => ∃ output, currentRawDecsMatrixOutput raw = some output ∧
      currentRawMatrixBad oracle output) (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ output, currentRawDecsMatrixOutput raw = some output ∧
      currentRawMatrixBad oracle output)]
  exact raw_current_matrix_bad_and_success_le oracle

def currentMatrixRouteBad {Counter : Type*}
    (route : Fin (digestCallCap (5 * 140)) ↪ Counter)
    (label : Option CommittedOracle) (vector : VectorOutput Counter) : Prop :=
  optionalEvent
    (fun oracle vector => ∃ coefficients,
      currentActualDecsMatrixOutput route vector = some coefficients ∧
        currentRawMatrixBad oracle coefficients) label vector

theorem current_matrix_route_bad_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {width : Nat} (routes : Routes Counter width)
    (label : Option CommittedOracle) :
    outputEventProbability (currentMatrixRouteBad routes.decsMatrix label) ≤
      currentMatrixLoss := by
  exact optional_event_probability_le
    (fun oracle vector => ∃ coefficients,
      currentActualDecsMatrixOutput routes.decsMatrix vector = some coefficients ∧
        currentRawMatrixBad oracle coefficients)
    currentMatrixLoss (by unfold currentMatrixLoss; positivity)
    (fun oracle => actual_current_matrix_bad_and_success_le routes.decsMatrix oracle)
    label

def typedCurrentMatrixRouteBad {Counter : Type*} (model : RelationModel)
    (routes : TypedRoutes model Counter) (label : TypedPrefixLabel model.width)
    (vector : VectorOutput Counter) : Prop :=
  match label with
  | .unavailable => False
  | .decoded statement labels =>
      currentMatrixRouteBad (routes statement).decsMatrix labels.decsMatrix vector

theorem typed_current_matrix_route_bad_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (routes : TypedRoutes model Counter)
    (label : TypedPrefixLabel model.width) :
    outputEventProbability (typedCurrentMatrixRouteBad model routes label) ≤
      currentMatrixLoss := by
  cases label with
  | unavailable =>
      change outputEventProbability (fun _ : VectorOutput Counter => False) ≤
        currentMatrixLoss
      rw [output_event_probability_false_local]
      unfold currentMatrixLoss
      positivity
  | decoded statement labels =>
      exact current_matrix_route_bad_density (routes statement) labels.decsMatrix

def currentMatrixRoleBad {Counter : Type*} (model : RelationModel)
    (routes : TypedRoutes model Counter) :
    List HegemonCrypto.CanonicalBytes.Byte → TypedPrefixLabel model.width →
      VectorOutput Counter → Prop :=
  fun _ label vector => typedCurrentMatrixRouteBad model routes label vector

def currentMatrixRoleEvent406 {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel : Nat)
    (authorized : Finset (List HegemonCrypto.CanonicalBytes.Byte)) :
    Database Key (VectorOutput Counter) → Prop :=
  roleEvent keyBytes (vectorOutputBytes counter) (globalLeafStatement ns)
    (rawTraceDecoder (globalOnlineNext ns)
      (fun key => targetOfRaw .decsMatrix (keyBytes key))
      (fun _ trace => preambleFromTrace ns .decsMatrix trace) outerFuel)
    (statementTraceDecoder (globalOnlineNext ns)
      (fun _ key => targetOfRaw .decsMatrix (keyBytes key))
      (fun statement _ trace => roleLabelsFromBytes model ns .decsMatrix advice statement trace)
      innerFuel)
    (fun key => InRoleDomain .decsMatrix (keyBytes key))
    (currentMatrixRoleBad model routes) authorized

theorem current_matrix_role_event_instability_406
    {Key Counter : Type*} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel cap : Nat)
    (authorized : Finset (List HegemonCrypto.CanonicalBytes.Byte)) :
    InstabilityBound
      (currentMatrixRoleEvent406 model ns keyBytes counter routes advice
        outerFuel innerFuel authorized)
      cap ((6 * cap : Rat) / (2^512 : Rat) + currentMatrixLoss) := by
  unfold currentMatrixRoleEvent406
  exact rp05_role_instability ns keyBytes counter
    (fun key => targetOfRaw .decsMatrix (keyBytes key))
    (fun _ trace => preambleFromTrace ns .decsMatrix trace)
    (fun _ key => targetOfRaw .decsMatrix (keyBytes key))
    (fun statement _ trace => roleLabelsFromBytes model ns .decsMatrix advice statement trace)
    outerFuel innerFuel authorized cap
    (fun key => InRoleDomain .decsMatrix (keyBytes key))
    (currentMatrixRoleBad model routes) currentMatrixLoss
    (by unfold currentMatrixLoss; positivity)
    (by intro statement label; exact typed_current_matrix_route_bad_density model routes label)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentMatrixRoleEvent
