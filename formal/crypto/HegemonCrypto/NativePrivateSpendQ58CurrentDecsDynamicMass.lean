import HegemonCrypto.NativePrivateSpendQ58CurrentFixedOpeningReplay
import HegemonCrypto.NativePrivateSpendQ58CurrentDecsLiteralInclusion
import HegemonCrypto.NativePrivateSpendQ58CurrentFiberMassTransport
import HegemonCrypto.NativePrivateSpendQ58CurrentDecsTraceDensity

/-! Literal current DECS58 sample event on the same selected-role fiber.
The source label is calculated from DECS28 -> PIOP27 -> FPP26 -> root25.
The Opening is calculated by the actual first-valid sixteen-nonce Program on
this SAME fixed other-role table, including its selected repeat. Neither the
source, its support, the Opening nor a degree/probability certificate is a
supplied callback. Missing/malformed trace defaults are preserved. The sole
field lookup witness proves injectivity of the deterministic current getter;
actual accepted PCS supplies that witness in the inclusion endpoint.
SOURCE ONLY; literal accepted-branch inclusion and kernel validation pending.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsDynamicMass
open scoped Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting HegemonCrypto.CmsFinitePhaseSystem
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes vectorPhaseSystem)
open V8Smz9RawCounterCompiler (digestCallCap)
open SmzaRp04RawRoleSampling (selectedRawBlocks)
open SmzaDynamicDatabaseSoundness SmzaDynamicOracleExecution
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaChallengeStageTargets (Role)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Counter Key RawInput RawDigest keyBytes decode zero)
end G
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims (live)
end AC
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end GF
namespace A
export NativePrivateSpendQ58ActiveEventProjection (FixedTable ActiveKey)
end A
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (parseCurrentStageQuery)
end C
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (Trace)
end F
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel current_tracked_label_changes)
end P
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass (fppLabel child childDigest)
end T
namespace O
export NativePrivateSpendQ58CurrentFixedOpeningReplay (fixedOpening)
end O
namespace N
export NativePrivateSpendQ58CurrentDecsTraceDensity (traceEvent current_decs_sample_trace_vector_density)
end N
namespace D
export NativePrivateSpendQ58CurrentDecsSampleDensity (loss Position)
end D
namespace U
export NativePrivateSpendQ58CurrentSuccessfulFiber (rawDecoder)
end U
namespace R
export NativePrivateSpendQ58CurrentFiberMassTransport
  (Active FixedVectors actualFixed activeBytes OriginalSteps OriginalRegisters fiberSteps fiberRegisters
   current_fiber_steps_preserve_actual_query_count current_fiber_empty_initialization_is_subnormalized)
end R
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
variable {Result Work : Type}

/-- Literal current 80-field sample uses fourteen digest calls. -/
def sampleSelect : Fin (digestCallCap 80) ↪ G.Counter where
  toFun index := ⟨index.val, index.isLt.trans_le (by decide)⟩
  inj' := by intro left right same; exact Fin.ext (congrArg (fun counter : G.Counter => counter.val) same)

/-- One fixed-trace event. All twelve discrepancy polynomials and the
support are computed by the retained current trace density module. -/
def decsSampleBad (program : Program Result)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live program .decsSample GF.currentRoleCaps))
    (fallback : G.RawDigest) (nonce : Fin (2^32))
    (trace : F.Trace) (key : G.Key program) (vector : VectorOutput G.Counter) : Prop :=
  match O.fixedOpening program .decsSample GF.currentRoleCaps fixed fallback nonce (T.childDigest trace) with
  | none => False
  | some opening =>
      (∃ query, C.parseCurrentStageQuery (G.keyBytes program key) = some query ∧
        query.role = .decsSample ∧ query.nonce = 0 ∧ query.counter = 0) ∧
      ∃ query, U.rawDecoder (selectedRawBlocks sampleSelect vector) = some query ∧
        query ∈ N.traceEvent
          (T.fppLabel .decsSample (G.keyBytes program) fixed G.decode (T.child (T.child trace 0) 0))
          opening trace

private theorem nat_ratio_nonneg (a b : Nat) :
    (0 : Rat) ≤ (a : Rat) / (b : Rat) :=
  div_nonneg (Nat.cast_nonneg a) (Nat.cast_nonneg b)

private theorem decs_loss_nonneg : (0 : Rat) ≤ D.loss :=
  nat_ratio_nonneg NativePrivateSpendQ58CurrentDecsSampleDensity.numerator
    (Nat.choose 8388608 58)

private theorem false_output_event_probability {Output : Type} [Fintype Output] :
    outputEventProbability (fun _ : Output => False) = 0 := by
  simp [outputEventProbability]

private theorem probability_mono {Output : Type} [Fintype Output]
    (left right : Output → Prop) (included : ∀ output, left output → right output) :
    outputEventProbability left ≤ outputEventProbability right := by
  unfold outputEventProbability
  apply div_le_div_of_nonneg_right
  · exact_mod_cast Finset.card_le_card (show Finset.univ.filter left ⊆ Finset.univ.filter right from
      fun output member => Finset.mem_filter.mpr
        ⟨Finset.mem_univ _, included output (Finset.mem_filter.mp member).2⟩)
  · exact Nat.cast_nonneg _

-- Finite binder types time out in the constructor-name style linter; proof checking is unchanged.
set_option linter.constructorNameAsVariable false in
/-- Exact current choose-bound; no historical sample/Opening relabeling. -/
theorem current_decs_sample_per_calculated_trace
    (program : Program Result)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live program .decsSample GF.currentRoleCaps))
    (fallback : G.RawDigest) (nonce : Fin (2^32)) (trace : F.Trace) (key : G.Key program)
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) :
    outputEventProbability (decsSampleBad program fixed fallback nonce trace key) ≤ D.loss := by
  cases openingEq : O.fixedOpening program .decsSample GF.currentRoleCaps fixed fallback nonce
      (T.childDigest trace) with
  | none =>
      have empty : decsSampleBad program fixed fallback nonce trace key =
          (fun _ : VectorOutput G.Counter => False) := by
        funext vector
        simp only [decsSampleBad, openingEq]
      rw [empty, false_output_event_probability]
      exact decs_loss_nonneg
  | some opening =>
      apply (probability_mono _ _ (by
        intro vector event
        simp only [decsSampleBad, openingEq] at event
        exact event.2)).trans
      exact N.current_decs_sample_trace_vector_density sampleSelect
        (T.fppLabel .decsSample (G.keyBytes program) fixed G.decode (T.child (T.child trace 0) 0))
        opening trace sample point lookup

/-- Literal current source hashes are live even when the DECS sample role
is selected. Every late source insertion is charged by its actual trace
change; no final transcript or Opening is declared pre-query by fiat. -/
def fiberBad (program : Program Result)
    (fixed : R.FixedVectors (Counter := G.Counter) .decsSample (G.keyBytes program))
    (fallback : G.RawDigest) (nonce : Fin (2^32))
    (trace : F.Trace) (key : R.Active .decsSample (G.keyBytes program))
    (vector : VectorOutput G.Counter) : Prop :=
  decsSampleBad program (R.actualFixed .decsSample (G.keyBytes program) fixed)
    fallback nonce trace key.val vector

theorem current_decs_sample_fiber_instability
    (program : Program Result)
    (fixed : R.FixedVectors (Counter := G.Counter) .decsSample (G.keyBytes program))
    (fallback : G.RawDigest) (nonce : Fin (2^32)) (cap : Nat)
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) :
    InstabilityBound
      (DynamicBad (P.currentLabel (R.activeBytes .decsSample (G.keyBytes program)) G.zero 28)
        (fiberBad program fixed fallback nonce)) cap
      (((3*cap : Rat)/(2^512 : Rat)) + D.loss) := by
  apply dynamic_bad_instability _ _ cap D.loss ((3*cap : Rat)/(2^512 : Rat))
    decs_loss_nonneg (by positivity)
  · intro trace key
    exact current_decs_sample_per_calculated_trace program
      (R.actualFixed .decsSample (G.keyBytes program) fixed) fallback nonce trace key.val sample point lookup
  · exact P.current_tracked_label_changes (R.activeBytes .decsSample (G.keyBytes program)) G.zero 28 cap

/-- Actual initial empty CMS and unchanged Q private contractions, with the
same fixed-phase table and register embedding retained from PR205. No later
cut receives a fabricated zero event projection. -/
theorem current_initialized_decs_sample_fiber_event_mass
    [Fintype Work] [DecidableEq Work]
    (program : Program Result)
    (dummy : R.Active .decsSample (G.keyBytes program))
    (fixed : R.FixedVectors (Counter := G.Counter) .decsSample (G.keyBytes program))
    (fallback : G.RawDigest) (nonce : Fin (2^32))
    (steps : R.OriginalSteps (Key := G.Key program) (Counter := G.Counter) (Work := Work))
    (registers : R.OriginalRegisters (Key := G.Key program) (Counter := G.Counter) (Work := Work))
    (normalized : Subnormalized (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers))
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) :
    normSquared (project
      (DynamicBad (P.currentLabel (R.activeBytes .decsSample (G.keyBytes program)) G.zero 28)
        (fiberBad program fixed fallback nonce)) steps.length
      (rawRun vectorPhaseSystem steps.length
        ((R.fiberSteps .decsSample (G.keyBytes program) dummy fixed steps).map
          DatabaseIndependentContraction.toDatabaseBlindContraction)
        (partialRandomOracleState (Output := VectorOutput G.Counter) ∅
          (R.fiberRegisters .decsSample (G.keyBytes program) dummy registers)))) ≤
      databaseLoss steps.length
        ((((3*steps.length : Rat)/(2^512 : Rat)) + D.loss : Rat) : ℝ) := by
  let label := P.currentLabel (R.activeBytes .decsSample (G.keyBytes program)) G.zero 28
  let bad := fiberBad program fixed fallback nonce
  let blind := (R.fiberSteps .decsSample (G.keyBytes program) dummy fixed steps).map
    DatabaseIndependentContraction.toDatabaseBlindContraction
  let initial := partialRandomOracleState (Output := VectorOutput G.Counter) ∅
    (R.fiberRegisters .decsSample (G.keyBytes program) dummy registers)
  have length : blind.length = steps.length := by
    simp only [blind, List.length_map, R.current_fiber_steps_preserve_actual_query_count]
  have bound := implemented_raw_database_game_le_database_loss vectorPhaseSystem
    (DynamicBad label bad) steps.length blind initial
    (current_decs_sample_fiber_instability program fixed fallback nonce steps.length sample point lookup).toReal
    (by omega) (partial_random_oracle_empty_bounded _)
    (R.current_fiber_empty_initialization_is_subnormalized .decsSample (G.keyBytes program)
      dummy registers normalized)
    (initialized_dynamic_bad_zero label bad steps.length _)
  simpa only [label, bad, blind, initial, length] using bound

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsDynamicMass
