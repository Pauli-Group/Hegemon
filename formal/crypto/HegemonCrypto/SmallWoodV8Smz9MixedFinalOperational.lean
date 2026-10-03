import HegemonCrypto.SmallWoodV8Smz9MixedFinalStage

namespace HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9DynamicRequest
open V8Smz9HonestHybrid V8Smz9HonestOpeningSchedule
open V8Smz9DynamicTransport V8Smz9DynamicPhysicalTransport V8Smz9PostFinalProgram
open V8Smz9CurrentPublicContext V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical ENNReal

noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

variable {Work : Type} [Fintype Work] {bound : Nat}

/-- The full T is sampled at the selected event, after the source prefix.
Its continuation retains T and all pre-final values, then performs literal
current leaf writes and the source post-final byte program in both games. -/
def selectedFinal (context : RequestContext bound) (labels : LeafIndex → DigestRegister)
    (stage : PrefinalResult) (response : DecsFullCoefficients Goldilocks)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work) : MixedProgram (FullRawInput bound) Work :=
  .freshInput (sourceFinalSampler bound (by have := context.largeEnough; omega) (sourceDigestPrefix stage.hashFpp))
    fun transcript digest => afterFinal context labels stage response transcript digest next

/-- Constructed before any oracle is chosen. The pre-final nonleaf source
schedule runs first; no address recovered from T is queried before its event. -/
def operationalRequest (context : RequestContext bound)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work) : MixedProgram (FullRawInput bound) Work :=
  randomPair (LeafIndex → DigestRegister) (DecsFullCoefficients Goldilocks) fun labels response =>
      nonleafCompile (sourcePrefinal bound (by have := context.largeEnough; omega)
        context.statementBinding context.bindingFits context.salt labels response context.retainedRows context.rowBound)
        (fun stage => selectedFinal context labels stage response next)

attribute [local irreducible] sourcePrefinal sourceFinalKey afterFinal nonleafCompile
  V8Smz9MixedMaskCompiler.run V8Smz9HonestWholeViewGames.run NonleafProgram.compile

theorem selected_final_honest_execution (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run false (selectedFinal context labels stage response next) oracle state =
    uniformAverage (fun transcript : PiopCoefficients Goldilocks =>
      V8Smz9MixedMaskCompiler.run false
        (afterFinal context labels stage response transcript
          (oracle (sourceFinalKey bound (by have := context.largeEnough; omega)
            (sourceDigestPrefix stage.hashFpp) transcript)) next) oracle state) := by
  simp only [selectedFinal, V8Smz9MixedMaskCompiler.run, Bool.false_eq_true, if_false,
    sourceFinalSampler, uniform_average_const]

theorem selected_final_randomized_execution (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true (selectedFinal context labels stage response next) oracle state =
    uniformAverage (fun transcript : PiopCoefficients Goldilocks =>
      uniformAverage (fun digest : DigestRegister =>
        V8Smz9MixedMaskCompiler.run true
          (afterFinal context labels stage response transcript digest next)
          (Function.update oracle (sourceFinalKey bound (by have := context.largeEnough; omega)
            (sourceDigestPrefix stage.hashFpp) transcript) digest) state)) := by
  simp only [selectedFinal, V8Smz9MixedMaskCompiler.run, if_true,
    sourceFinalSampler, Function.update_self]

theorem operational_request_executes_prefix (randomized : Bool) (context : RequestContext bound)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run randomized (operationalRequest context next) oracle state =
    uniformAverage (fun labels : LeafIndex → DigestRegister =>
      uniformAverage (fun response : DecsFullCoefficients Goldilocks =>
        V8Smz9MixedMaskCompiler.run randomized
          (selectedFinal context labels
            (sourcePublicPrefinal bound (by have := context.largeEnough; omega)
              context.statementBinding context.bindingFits context.salt context.retainedRows context.rowBound
              (fun input => oracle (Sum.inr input)) labels response) response next) oracle state)) := by
  rw [operationalRequest, random_pair_execution]
  simp only [nonleaf_compile_executes, sourcePublicPrefinal]

/-- Actual fixed-bit execution equals the physical source observation after
the joint source Q/M transport. No game equality is an input to this theorem.
The complete oracle and quantum state, including all prior history, continue. -/
theorem honest_request_is_transported_physical_observation (context : RequestContext bound)
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run false
      (operationalRequest context (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) oracle state =
    uniformAverage (fun labels : LeafIndex → DigestRegister =>
      uniformAverage (fun output : JointMaskOutputs Goldilocks =>
        uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
          physicalOutputObservation bound (by have := context.largeEnough; omega)
            context.statementBinding context.bindingFits context.values context.salt context.retainedRows context.rowBound
            (oldByteContinuation context base next) oracle state base labels
            (transportedMasks context (fun input => oracle (Sum.inr input)) labels base output) output))) := by
  rw [operational_request_executes_prefix]
  apply congrArg uniformAverage
  funext labels
  rw [V8Smz9HonestLeafBatch.uniform_average_product
    (fun (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks) =>
      uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
        physicalOutputObservation bound (by have := context.largeEnough; omega)
          context.statementBinding context.bindingFits context.values context.salt context.retainedRows context.rowBound
          (oldByteContinuation context base next) oracle state base labels
          (transportedMasks context (fun input => oracle (Sum.inr input)) labels base (response, transcript))
          (response, transcript)))]
  apply congrArg uniformAverage
  funext response
  rw [selected_final_honest_execution]
  apply congrArg uniformAverage
  funext transcript
  rw [after_final_fixed_executes]
  apply congrArg uniformAverage
  funext base
  rw [recovered_masks_are_transport context (fun input => oracle (Sum.inr input)) labels base
    (response, transcript)]
  simp only [physicalOutputObservation, retainedPending]

theorem operational_request_mass (context : RequestContext bound)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.InputMassAtMost
      ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹ (next bytes)) :
    V8Smz9MixedMaskCompiler.InputMassAtMost ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹
      (operationalRequest context next) := by
  unfold operationalRequest
  apply random_pair_mass
  intro labels response
  apply nonleaf_compile_mass
  intro stage
  unfold selectedFinal
  refine ⟨source_final_sampler_mass bound _ _, ?_⟩
  intro transcript digest
  exact after_final_mass _ context labels stage response transcript digest next remaining

theorem operational_request_program_bound (context : RequestContext bound)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work) (programs : Nat)
    (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.programmingCount (next bytes) ≤ programs) :
    V8Smz9MixedMaskCompiler.programmingCount (operationalRequest context next) ≤ programs + 1 := by
  unfold operationalRequest
  apply random_pair_program_bound
  intro labels response
  apply nonleaf_compile_program_bound
  intro stage
  simp only [selectedFinal, V8Smz9MixedMaskCompiler.programmingCount]
  apply Nat.add_le_add_right
  apply Finset.sup_le
  intro transcript _
  apply Finset.sup_le
  intro digest _
  exact after_final_program_bound context labels stage response transcript digest next programs remaining

/-- The only analytic premise is the pre-existing physical external theorem;
all selected-event mass and program accounting is derived from this program. -/
theorem measured_operational_request_bound (context : RequestContext bound)
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := FullRawInput bound) (Work := Work))
    (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (queries programs : Nat) (normalized : ‖initial‖ = 1)
    (queryBound : V8Smz9MixedMaskCompiler.queryCount (operationalRequest context next) ≤ queries)
    (futurePrograms : ∀ bytes, V8Smz9MixedMaskCompiler.programmingCount (next bytes) ≤ programs)
    (futureMass : ∀ bytes, V8Smz9MixedMaskCompiler.InputMassAtMost
      ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹ (next bytes)) :
    |V8Smz9MixedMaskCompiler.acceptance true (operationalRequest context next) initial -
      V8Smz9MixedMaskCompiler.acceptance false (operationalRequest context next) initial| ≤
      ((programs + 1 : Nat) : ℝ) *
        (Real.sqrt ((queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹) +
          (queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹ / 2) := by
  apply V8Smz9MixedMaskCompiler.mixed_adaptive_reprogramming_bound ghhm _ initial queries (programs + 1) _
    normalized queryBound (operational_request_program_bound context next programs futurePrograms) (by positivity)
  simpa only [ENNReal.ofReal_inv_of_pos (by norm_num [goldilocksModulus] :
      (0 : ℝ) < (goldilocksModulus : ℝ) ^ 3105),
    ENNReal.ofReal_pow (Nat.cast_nonneg goldilocksModulus), ENNReal.ofReal_natCast] using
      operational_request_mass context next futureMass


theorem measured_fixed_future_request_bound (context : RequestContext bound)
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := FullRawInput bound) (Work := Work))
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (queries : Nat) (normalized : ‖initial‖ = 1)
    (queryBound : V8Smz9MixedMaskCompiler.queryCount
      (operationalRequest context (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) ≤ queries) :
    |V8Smz9MixedMaskCompiler.acceptance true
        (operationalRequest context (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) initial -
      V8Smz9MixedMaskCompiler.acceptance false
        (operationalRequest context (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) initial| ≤
      Real.sqrt ((queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹) +
        (queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹ / 2 := by
  have result := measured_operational_request_bound context ghhm
    (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes)) initial queries 0 normalized queryBound
    (fun bytes => Nat.le_of_eq (fixed_program_has_no_selected_events true (next bytes)))
    (fun bytes => fixed_program_has_input_mass _ true (next bytes))
  simpa only [Nat.zero_add, Nat.cast_one, one_mul] using result


end
end HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational
