import HegemonCrypto.NativePrivateSpendQ58CurrentDecsSampleDensity
import HegemonCrypto.NativePrivateSpendQ58CurrentSourceCandidate
import HegemonCrypto.NativePrivateSpendQ58CurrentPointGeometry

/-! Current parsed DECS trace density. The finite13173-value polynomial is
computed from each literal current DECS row:8 digest words then12 rows,
head13115 followed by tail58, rotated13115 before consecutive interpolation.
Its degree and calculated source degree are DERIVED, not supplied in the
trace endpoint. Labels and opening are fixed before the selected DECS sample;
actual same-fiber binding/readback is a separate inclusion theorem.
SOURCE ONLY, no kernel or G3 qualification. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsTraceDensity
open Polynomial V8Smz9McaRecovery V8Smz9McaDecoder
open SmzaRp05LvcsWireProjection (rotateLeft)
open SmzaRp05ExecutablePcsClosureLvcsAlgebra (consecutivePolynomial)
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentVectorMerkle
open V8Smz9RawCounterCompiler V8Smz9RuntimeRandomness
open SmzaRp04RawRoleSampling
open HegemonCrypto.CmsClassicalDatabase
open V8Smz9RobustQueryMismatch
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement (goldilocksModulus fieldValue)
open SmzaRecordedTracePath (readPath)
open scoped Classical BigOperators
namespace N
export NativePrivateSpendQ58CurrentDecsSampleDensity
  (Position Discrepancies sampleEvent loss current_decs_sample_event_card
   current_sample_event_probability current_raw_decs_success_and_bad_probability
   current_vector_decs_success_and_bad_probability)
end N
namespace U
export NativePrivateSpendQ58CurrentSuccessfulFiber (Query rawDecoder)
end U
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate
  (SourceLabel calculatedCandidate calculatedSupport labelView)
end S
namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport (currentPoint)
end L
namespace V
export NativePrivateSpendQ58CurrentLvcsEventJoin (Combination combinationPolynomial)
end V
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (Trace RawInput rawPayload)
end F
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Opening points)
end E
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Read the actual payload, with missing/malformed source represented by
its total zero/default readback, never an assumed available source. -/
def traceBytes (trace : F.Trace) : List HegemonCrypto.CanonicalBytes.Byte :=
  (((readPath [] trace).bind F.rawPayload).map V8SmzaOracleParser.Payload.bytes).getD []

def traceRowValues (trace : F.Trace) (combination : V.Combination) : List Goldilocks :=
  List.ofFn fun index : Fin 13173 =>
    (V8SmzaOracleParser.wordAt (traceBytes trace)
      (8 + 13173 * (2 * combination.1.val + combination.2.val) + index.val) : Goldilocks)

def tracePolynomial (trace : F.Trace) (combination : V.Combination) : Goldilocks[X] :=
  consecutivePolynomial (rotateLeft (traceRowValues trace combination) 13115)

private theorem current_consecutive_nodes_injective :
    Function.Injective (fun index : Fin 13173 => (index.val : Goldilocks)) := by
  intro left right same
  apply Fin.ext
  have leftBound : left.val < goldilocksModulus := left.isLt.trans (by decide)
  have rightBound : right.val < goldilocksModulus := right.isLt.trans (by decide)
  have values := congrArg fromGoldilocks same
  change fromGoldilocks (toGoldilocks left.val) = fromGoldilocks (toGoldilocks right.val) at values
  simpa only [fromGoldilocks_toGoldilocks, fieldValue,
    Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] using values

theorem trace_row_values_length (trace : F.Trace) (combination : V.Combination) :
    (traceRowValues trace combination).length = 13173 := List.length_ofFn

theorem trace_rotated_values_length (trace : F.Trace) (combination : V.Combination) :
    (rotateLeft (traceRowValues trace combination) 13115).length = 13173 := by
  unfold rotateLeft
  rw [trace_row_values_length, Nat.mod_eq_of_lt (by decide : 13115 < 13173)]
  simp only [List.length_append, List.length_drop, List.length_take, trace_row_values_length]
  omega

/-- Degree follows the finite literal constructor even on a malformed trace. -/
theorem trace_polynomial_degree (trace : F.Trace) (combination : V.Combination) :
    (tracePolynomial trace combination).natDegree ≤ 13172 := by
  let values := rotateLeft (traceRowValues trace combination) 13115
  have len : values.length = 13173 := trace_rotated_values_length trace combination
  have injective : Function.Injective (fun index : Fin values.length => (index.val : Goldilocks)) := by
    rw [len]
    exact current_consecutive_nodes_injective
  apply natDegree_le_of_degree_le
  have bounded := Lagrange.degree_interpolate_le (fun index : Fin values.length => values.getD index.val 0)
    injective.injOn (s := (Finset.univ : Finset (Fin values.length)))
  change (consecutivePolynomial values).degree ≤ (13172 : WithBot Nat)
  have degreeBound : (consecutivePolynomial values).degree ≤
      ((values.length - 1 : Nat) : WithBot Nat) := by
    simpa only [consecutivePolynomial, Finset.card_univ, Fintype.card_fin] using bounded
  have numerical : ((values.length - 1 : Nat) : WithBot Nat) ≤ (13172 : WithBot Nat) := by
    rw [len]
    norm_num
  exact degreeBound.trans numerical

/-- A successful calculated source supplies its data degree by the checked
interpolation decoder; no source-validity or satisfying relation is assumed. -/
theorem calculated_source_data_degree (label : S.SourceLabel)
    (injective : Function.Injective L.currentPoint)
    (source : DecodedSource Goldilocks (Fin 5) 140)
    (calculated : S.calculatedCandidate label = some source) :
    ∀ column, (source.data column).natDegree ≤ 13172 := by
  have actual : responseDecoder L.currentPoint 13172 (S.labelView label).data
      (S.labelView label).masks (S.labelView label).response (S.labelView label).coefficients = some source := calculated
  have recovered := decoded_source_agrees_and_has_bounded_degree L.currentPoint injective
    13172 (S.calculatedSupport label) (S.labelView label).data (S.labelView label).masks source actual
  exact recovered.2.2.2

theorem source_combination_degree (source : DecodedSource Goldilocks (Fin 5) 140)
    (degree : ∀ column, (source.data column).natDegree ≤ 13172)
    (opening : E.Opening) (combination : V.Combination) :
    (V.combinationPolynomial source opening combination).natDegree ≤ 13172 := by
  unfold V.combinationPolynomial
  refine natDegree_sum_le_of_forall_le _ _ ?_
  intro coefficient _
  exact (natDegree_C_mul_le _ _).trans
    (degree (NativePrivateSpendQ58CurrentLvcsEventJoin.blockRow combination.2 coefficient))

private def discrepanciesFromCandidate
    (candidate : Option (DecodedSource Goldilocks (Fin 5) 140))
    (value : DecodedSource Goldilocks (Fin 5) 140 → V.Combination → Goldilocks[X]) : N.Discrepancies :=
  match candidate with
  | none => fun _ => 0
  | some source => value source

private theorem discrepanciesFromCandidate_none
    (value : DecodedSource Goldilocks (Fin 5) 140 → V.Combination → Goldilocks[X])
    (combination : V.Combination) :
    discrepanciesFromCandidate none value combination = (0 : Goldilocks[X]) := rfl

private theorem discrepanciesFromCandidate_some
    (source : DecodedSource Goldilocks (Fin 5) 140)
    (value : DecodedSource Goldilocks (Fin 5) 140 → V.Combination → Goldilocks[X])
    (combination : V.Combination) :
    discrepanciesFromCandidate (some source) value combination = value source combination := rfl

private theorem discrepancies_from_candidate_degree
    (candidate : Option (DecodedSource Goldilocks (Fin 5) 140))
    (value : DecodedSource Goldilocks (Fin 5) 140 → V.Combination → Goldilocks[X])
    (valueDegree : ∀ source, candidate = some source →
      ∀ combination, (value source combination).natDegree ≤ 13172) :
    ∀ combination, (discrepanciesFromCandidate candidate value combination).natDegree ≤ 13172 := by
  cases candidate with
  | none =>
      intro combination
      rw [discrepanciesFromCandidate_none, natDegree_zero]
      exact Nat.zero_le 13172
  | some source =>
      intro combination
      rw [discrepanciesFromCandidate_some]
      exact valueDegree source rfl combination

private theorem polynomial_sub_degree_le (left right : Goldilocks[X]) (bound : Nat)
    (leftDegree : left.natDegree ≤ bound) (rightDegree : right.natDegree ≤ bound) :
    (left - right).natDegree ≤ bound :=
  (natDegree_sub_le left right).trans (max_le leftDegree rightDegree)

/-- No candidate is supplied: failed calculation uses zero discrepancies,
while its computed small support remains counted independently. -/
def discrepancies (label : S.SourceLabel) (opening : E.Opening) (trace : F.Trace) : N.Discrepancies :=
  discrepanciesFromCandidate (S.calculatedCandidate label)
    (fun source combination => tracePolynomial trace combination - V.combinationPolynomial source opening combination)

theorem trace_discrepancies_degree (label : S.SourceLabel) (opening : E.Opening) (trace : F.Trace)
    (injective : Function.Injective L.currentPoint) :
    ∀ combination, (discrepancies label opening trace combination).natDegree ≤ 13172 := by
  unfold discrepancies
  with_reducible
    exact discrepancies_from_candidate_degree (S.calculatedCandidate label)
      (fun source combination => tracePolynomial trace combination - V.combinationPolynomial source opening combination)
      (fun source calculated combination =>
        polynomial_sub_degree_le (tracePolynomial trace combination)
          (V.combinationPolynomial source opening combination) 13172
          (trace_polynomial_degree trace combination)
          (source_combination_degree source
            (calculated_source_data_degree label injective source calculated) opening combination))

def traceEvent (label : S.SourceLabel) (opening : E.Opening) (trace : F.Trace) : Finset U.Query :=
  N.sampleEvent L.currentPoint (S.calculatedSupport label) (discrepancies label opening trace)

/-- Fixed current source/response label plus current DECS trace; no support
membership, sample-root certificate or degree bound is a premise. -/
theorem current_decs_sample_trace_event_probability
    (label : S.SourceLabel) (opening : E.Opening) (trace : F.Trace)
    (injective : Function.Injective L.currentPoint) :
    FiniteEvents.probability (traceEvent label opening trace) ≤ N.loss :=
  N.current_sample_event_probability L.currentPoint injective _ _
    (trace_discrepancies_degree label opening trace injective)

/-- The point map is derived from ONE actual successful source lookup. -/
theorem current_decs_sample_trace_event_density
    (label : S.SourceLabel) (opening : E.Opening) (trace : F.Trace)
    (sample : N.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) :
    outputEventProbability (fun raw : Fin (digestCallCap 80) → V8Smz9CappedRawSampler.RawByteBlock =>
      ∃ query, U.rawDecoder raw = some query ∧ query ∈ traceEvent label opening trace) ≤ N.loss := by
  have injective : Function.Injective L.currentPoint :=
    NativePrivateSpendQ58CurrentPointGeometry.field_point_getter_injective_from_one_success sample point lookup
  exact N.current_raw_decs_success_and_bad_probability L.currentPoint injective _ _
    (trace_discrepancies_degree label opening trace injective)

/-- Whole-vector form of the same current14-block statement. -/
theorem current_decs_sample_trace_vector_density {Counter : Type}
    [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap 80) ↪ Counter)
    (label : S.SourceLabel) (opening : E.Opening) (trace : F.Trace)
    (sample : N.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ query, U.rawDecoder (selectedRawBlocks select vector) = some query ∧
        query ∈ traceEvent label opening trace) ≤ N.loss := by
  have injective : Function.Injective L.currentPoint :=
    NativePrivateSpendQ58CurrentPointGeometry.field_point_getter_injective_from_one_success sample point lookup
  exact N.current_vector_decs_success_and_bad_probability select L.currentPoint injective _ _
    (trace_discrepancies_degree label opening trace injective)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsTraceDensity
