import Q38StateValuedCoinTransport
import SmzaRp04PublicContext
import HegemonCrypto.SmallWoodV8Smz9CurrentProgramOpeningBinding

/-! State-valued chronological changes of variables for the actual current
DECS and PIOP response formulas.  The two translations are deliberately
separate: an arbitrary finite public/instrument outcome is retained between
them, so no random-oracle table is fixed to define one joint permutation.
-/
namespace HegemonCrypto.SmallWood.V8SmzaChronologicalStateAlgebra
open HegemonCrypto.SmallWood.V8SmzaStateValuedCoinTransport
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy
open HegemonCrypto.SmallWood.V8Smz9HonestHybrid
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9PiopOpeningRecovery
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding
open HegemonCrypto.SmallWood.SmzaRp04ProgramPiop
open HegemonCrypto.SmallWood.SmzaRp04PublicContext
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Polynomial
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Coin Value : Type*}
variable [Fintype Coin] [AddCommGroup Coin] [AddCommMonoid Value]

/-- Translation by a public offset as an explicit finite equivalence. -/
def addTranslation (offset : Coin) : Coin ≃ Coin where
  toFun coin := offset + coin
  invFun output := output - offset
  left_inv coin := by
    change offset + coin - offset = coin
    rw [add_sub_cancel_left]
  right_inv output := by
    change offset + (output - offset) = output
    rw [add_comm, sub_add_cancel]

/-- Reindex a state-valued kernel while retaining both the old coin and the
new public coordinate. -/
theorem translated_state_kernel_sum (offset : Coin)
    (kernel : Coin → Coin → Value) :
    (∑ coin, kernel coin (offset + coin)) =
      ∑ output, kernel (output - offset) output := by
  have transported := bijective_state_kernel_sum (addTranslation offset)
    (fun output => kernel (output - offset) output)
  simpa only [addTranslation, Equiv.coe_fn_mk, add_sub_cancel_left]
    using transported

variable {First Second Challenge : Type*}
variable [Fintype First] [AddCommGroup First]
variable [Fintype Second] [AddCommGroup Second]
variable [Fintype Challenge]

/-- Exact chronological two-stage transport.  `Second` is first translated
to the public response.  Only then is the finite instrument outcome exposed,
and `First` is translated to the later public transcript.  The kernel retains
both original coins and all three public coordinates. -/
theorem two_stage_translation_state_kernel_sum
    (firstOffset : First → Second)
    (laterOffset : Second → Challenge → First)
    (kernel : Second → Challenge → First → Second → First → Value) :
    (∑ first, ∑ second, ∑ challenge,
      kernel (firstOffset first + second) challenge first second
        (laterOffset (firstOffset first + second) challenge + first)) =
    ∑ response, ∑ challenge, ∑ transcript,
      kernel response challenge
        (transcript - laterOffset response challenge)
        (response - firstOffset (transcript - laterOffset response challenge))
        transcript := by
  have firstStage (first : First) :
      (∑ second, ∑ challenge,
        kernel (firstOffset first + second) challenge first second
          (laterOffset (firstOffset first + second) challenge + first)) =
      ∑ response, ∑ challenge,
        kernel response challenge first (response - firstOffset first)
          (laterOffset response challenge + first) := by
    exact translated_state_kernel_sum (Coin := Second) (Value := Value)
      (firstOffset first)
      (fun second response => ∑ challenge,
        kernel response challenge first second
          (laterOffset response challenge + first))
  calc
    _ = ∑ first, ∑ response, ∑ challenge,
        kernel response challenge first (response - firstOffset first)
          (laterOffset response challenge + first) := by
      apply Finset.sum_congr rfl
      intro first _
      exact firstStage first
    _ = ∑ response, ∑ first, ∑ challenge,
        kernel response challenge first (response - firstOffset first)
          (laterOffset response challenge + first) := Finset.sum_comm
    _ = ∑ response, ∑ challenge, ∑ first,
        kernel response challenge first (response - firstOffset first)
          (laterOffset response challenge + first) := by
      apply Finset.sum_congr rfl
      intro response _
      exact Finset.sum_comm
    _ = _ := by
      apply Finset.sum_congr rfl
      intro response _
      apply Finset.sum_congr rfl
      intro challenge _
      exact translated_state_kernel_sum (Coin := First) (Value := Value)
        (laterOffset response challenge)
        (fun first transcript =>
          kernel response challenge first (response - firstOffset first) transcript)

section ActualQ38Responses

/-- The q38 PIOP mask coordinate is unchanged, while the DECS response now
contains the literal 406 coefficients for each of the five polynomials. -/
abbrev Q := PiopCoefficients Goldilocks
abbrev D := HegemonCrypto.SmallWood.V8SmzaMathPrivacy.Decs Goldilocks

variable {PublicBranch : Type*} [Fintype PublicBranch]

/-- Correct q38 chronological mask transport.  `base.2.2` is the full
`140 × 38 = 5,320` tail tape.  The arbitrary finite `PublicBranch` remains
strictly between the D and T translations, and the kernel retains both
inverse masks. -/
theorem q38_response_state_kernel_sum
    (gamma : Gamma Goldilocks)
    (base : RemainingCoins Goldilocks)
    (heads : WitnessInterpolationCoins Goldilocks →
      SourcePcsCoins Goldilocks → Q → Heads Goldilocks)
    (piopUnmasked : WitnessInterpolationCoins Goldilocks →
      D → PublicBranch → Q)
    (kernel : D → PublicBranch → Q → D → Q → Value) :
    (∑ q, ∑ m, ∑ branch,
      let reply := V8SmzaMathPrivacy.response gamma
        (heads base.1 base.2.1 q) base.2.2 m
      kernel reply branch q m
        (piopUnmasked base.1 reply branch + q)) =
    ∑ reply, ∑ branch, ∑ transcript,
      let q := transcript - piopUnmasked base.1 reply branch
      let m := reply - V8SmzaMathPrivacy.unmasked gamma
        (heads base.1 base.2.1 q) base.2.2
      kernel reply branch q m transcript := by
  let firstOffset : Q → D := fun q =>
    V8SmzaMathPrivacy.unmasked gamma
      (heads base.1 base.2.1 q) base.2.2
  let laterOffset : D → PublicBranch → Q := fun reply branch =>
    piopUnmasked base.1 reply branch
  have transported := two_stage_translation_state_kernel_sum
    (Value := Value) firstOffset laterOffset kernel
  simpa only [V8SmzaMathPrivacy.response, firstOffset, laterOffset]
    using transported

/-! The repaired RP04 application is kept below the generic q38 transport.
It imports the actual 773-root constraint program and public context, but does
not make the generic coin algebra depend on extraction or degree closure. -/

/-- Actual RP04 nonlinear batch over the source-owned 773 constraint roots. -/
def rp04NonlinearBatch
    (parameters : SmzaRp04ProgramPiop.CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) (polynomial : Fin 5) : Goldilocks[X] :=
  V8Smz9PiopOpeningRecovery.nonlinearBatch
    (parameters.nonlinearGamma polynomial)
    (SmzaRp04ProgramPiop.currentConstraints parameters witness)

/-- The witness-dependent, mask-zero RP04 PIOP response.  The nonlinear
coordinate is the exact quotient of the actual 773-root batch; the linear
coordinate uses the actual public retained-row weights. -/
def rp04UnmaskedResponseCoefficients
    (parameters : SmzaRp04ProgramPiop.CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) : Q :=
  (fun polynomial coefficient =>
      (V8Smz9PiopOpeningRecovery.sourceNonlinearQuotient canonicalPacking
        (rp04NonlinearBatch parameters witness polynomial)).coeff coefficient.val,
    fun polynomial coefficient =>
      (V8Smz9PiopOpeningRecovery.sourceLinearUnmasked
        (parameters.linearWeights polynomial)
        (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking)
        witness).coeff (coefficient.val + 1))

/-- Actual RP04 response formula in coefficient coordinates.  The 489
nonlinear and 132 nonconstant linear mask coefficients are added exactly once
to the source-program response. -/
def rp04ResponseCoefficients
    (parameters : SmzaRp04ProgramPiop.CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) (masks : Q) : Q :=
  rp04UnmaskedResponseCoefficients parameters witness + masks

theorem rp04_response_is_affine_mask_map
    (parameters : SmzaRp04ProgramPiop.CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) (masks : Q) :
    rp04ResponseCoefficients parameters witness masks =
      rp04UnmaskedResponseCoefficients parameters witness + masks := rfl

/-- RP04 committed heads use only the witness polynomials, PIOP masks and PCS
coins.  In particular the old q20 tail type is not an argument; the q38 tails
enter only through `V8SmzaMathPrivacy.response`. -/
def rp04PhysicalHeads (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q) : Heads Goldilocks :=
  V8Smz9CurrentProgramOpeningBinding.physicalHeads
    (sourceWitnessPolynomials values base.1) masks base.2.1

/-- Actual repaired-program specialization.  `parameters` may depend on D and
on the complete intermediate instrument branch, exactly matching the protocol
chronology.  No distribution identity is assumed. -/
theorem rp04_response_state_kernel_sum
    (gamma : Gamma Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks)
    (parameters : D → PublicBranch →
      SmzaRp04ProgramPiop.CurrentPublicParameters)
    (kernel : D → PublicBranch → Q → D → Q → Value) :
    (∑ q, ∑ m, ∑ branch,
      let reply := V8SmzaMathPrivacy.response gamma
        (rp04PhysicalHeads values base q) base.2.2 m
      kernel reply branch q m
        (rp04ResponseCoefficients (parameters reply branch)
          (sourceWitnessPolynomials values base.1) q)) =
    ∑ reply, ∑ branch, ∑ transcript,
      let q := transcript - rp04UnmaskedResponseCoefficients
        (parameters reply branch) (sourceWitnessPolynomials values base.1)
      let m := reply - V8SmzaMathPrivacy.unmasked gamma
        (rp04PhysicalHeads values base q) base.2.2
      kernel reply branch q m transcript := by
  let heads : WitnessInterpolationCoins Goldilocks →
      SourcePcsCoins Goldilocks → Q → Heads Goldilocks :=
    fun witnessCoins pcsCoins q =>
      V8Smz9CurrentProgramOpeningBinding.physicalHeads
        (sourceWitnessPolynomials values witnessCoins) q pcsCoins
  let piopUnmasked : WitnessInterpolationCoins Goldilocks →
      D → PublicBranch → Q :=
    fun witnessCoins reply branch =>
      rp04UnmaskedResponseCoefficients (parameters reply branch)
        (sourceWitnessPolynomials values witnessCoins)
  simpa only [rp04PhysicalHeads, rp04ResponseCoefficients, heads,
    piopUnmasked] using
      (q38_response_state_kernel_sum (Value := Value)
        gamma base heads piopUnmasked kernel)

end ActualQ38Responses

section RemainingCoins

variable {F : Type*} [Field F] [Fintype F]

/-- Strong q38 form: the inverse witness, PCS and all 5,320 tail coins remain
available to the state kernel on the public side.  Both late-sampler abort
branches are retained by `abortProjection`. -/
theorem remaining_partial_state_kernel_sum_retaining_coins
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → Heads F)
    (fallback : Targets points)
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F →
      Option (Targets points))
    (kernel : RemainingCoins F → PartialView F → Value) :
    (∑ coins : RemainingCoins F,
      kernel coins
        (partialChronologicalView values points pcsBase heads choose coins)) =
    ∑ view : RemainingView F,
      let transport := remainingEquiv values points witnessAdmissible
        pointsNonzero pcsBase heads
          (fun witnessView pcsView early =>
            (choose witnessView pcsView early).getD fallback)
      kernel (transport.symm view) (abortProjection choose view) := by
  let totalChoose := fun witnessView pcsView early =>
    (choose witnessView pcsView early).getD fallback
  let transport := remainingEquiv values points witnessAdmissible pointsNonzero
    pcsBase heads totalChoose
  have pointwise (coins : RemainingCoins F) :
      abortProjection choose (transport coins) =
        partialChronologicalView values points pcsBase heads choose coins := by
    have transportEq :
        transport coins =
          chronologicalView values points pcsBase heads totalChoose coins :=
      remaining_equiv_is_chronological values points witnessAdmissible
        pointsNonzero pcsBase heads totalChoose coins
    calc
      abortProjection choose (transport coins) =
          abortProjection choose
            (chronologicalView values points pcsBase heads totalChoose coins) :=
        congrArg (abortProjection choose) transportEq
      _ = partialChronologicalView values points pcsBase heads choose coins := by
        cases selected : choose (sourceWitnessOpenings values points coins.1)
            (sourcePcsFullView points (pcsBase coins.1) coins.2.1)
            (earlier points coins.2.2) with
        | none =>
            simp [abortProjection, chronologicalView, partialChronologicalView,
              HegemonCrypto.SmallWood.V8SmzaMathPrivacy.exactLvcsPartialFeedbackOutput,
              totalChoose, selected]
        | some targets =>
            simp [abortProjection, chronologicalView, partialChronologicalView,
              HegemonCrypto.SmallWood.V8SmzaMathPrivacy.exactLvcsPartialFeedbackOutput,
              totalChoose, selected]
  have reindexed := bijective_state_kernel_sum transport
    (fun view => kernel (transport.symm view) (abortProjection choose view))
  simpa only [Equiv.symm_apply_apply, pointwise] using reindexed

/-- State-valued q38 projection when the continuation does not need the
inverse coins explicitly. -/
theorem remaining_partial_state_kernel_sum
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → Heads F)
    (fallback : Targets points)
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F →
      Option (Targets points))
    (kernel : PartialView F → Value) :
    (∑ coins : RemainingCoins F,
      kernel (partialChronologicalView values points pcsBase heads choose coins)) =
    ∑ view : RemainingView F, kernel (abortProjection choose view) := by
  simpa only using
    (remaining_partial_state_kernel_sum_retaining_coins
      (Value := Value) values points witnessAdmissible pointsNonzero pcsBase
      heads fallback choose (fun _ view => kernel view))

end RemainingCoins

end
end HegemonCrypto.SmallWood.V8SmzaChronologicalStateAlgebra
