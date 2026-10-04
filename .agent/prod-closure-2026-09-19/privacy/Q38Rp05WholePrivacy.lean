import Q38Rp05ExecutionBridge
import Q38CompleteAlgebraR2

/-!
# RP05 two-witness and adaptive-round algebraic privacy

The simulator below is public-only.  It is not given a witness-dependent
continuation or a desired probability.  The current RP05 relation enters
through `unmaskedResponse`; the q38 opening transport then removes all
remaining witness, PCS and LVCS coins while retaining both sampler aborts.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05WholePrivacy

open Polynomial
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9WholeViewObservation
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaCompleteAlgebra
open HegemonCrypto.SmallWood.V8SmzaMaskFeedback
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.V8Smz9RunHomogeneity
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

/-- PCS base columns corresponding to the actual PIOP mask coordinate.  The
DECS reply is retained in the type because the chronology publishes it first;
the base-column formula itself uses only Q, as in the source program. -/
def pcsBase (points : Fin 6 → Goldilocks)
    (q : Q) (_reply : D) : SourcePcsView Goldilocks :=
  (fun polynomial opening column =>
      (sourceNonlinearBaseColumns (q.1 polynomial) column.succ).eval
        (points opening),
    fun polynomial opening =>
      (sourceLinearBaseColumns
        (sourceLinearMaskFullCoefficients (q.2 polynomial)) 1).eval
          (points opening))

/-- Concrete current-relation model consumed by the proven q38 joint opening
transport.  `plan` is public-response indexed.  No witness occurs in it. -/
def model (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (gamma : Gamma Goldilocks)
    (points : MaskOutputs Goldilocks → Fin 6 → Goldilocks)
    (parameters : D → Parameters dsl statement)
    (plan : MaskOutputs Goldilocks → Option (OpeningPlan Goldilocks)) :
    Model Goldilocks where
  values := values
  gamma := gamma
  piopUnmasked witness reply :=
    unmaskedResponse dsl statement (parameters reply)
      (sourceWitnessPolynomials values witness)
  heads witness pcs q :=
    physicalHeads (sourceWitnessPolynomials values witness) q pcs
  pcsBase witness q reply :=
    let transcript :=
      unmaskedResponse dsl statement (parameters reply)
        (sourceWitnessPolynomials values witness) + q
    pcsBase (points (reply, transcript)) q reply
  plan := plan

abbrev View := PublicView Goldilocks

def real (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (gamma : Gamma Goldilocks)
    (points : MaskOutputs Goldilocks → Fin 6 → Goldilocks)
    (parameters : D → Parameters dsl statement)
    (plan : MaskOutputs Goldilocks → Option (OpeningPlan Goldilocks)) : PMF View :=
  source (model dsl statement values gamma points parameters plan)

def simulator
    (plan : MaskOutputs Goldilocks → Option (OpeningPlan Goldilocks)) : PMF View :=
  simulate plan

/-- Exact current-RP05 response/opening law.  This invokes the complete joint
transport, so D, T, witness openings, PCS openings, LVCS openings and both
modeled aborts all remain in the view. -/
theorem real_eq_public_simulator (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (gamma : Gamma Goldilocks)
    (points : MaskOutputs Goldilocks → Fin 6 → Goldilocks)
    (parameters : D → Parameters dsl statement)
    (plan : MaskOutputs Goldilocks → Option (OpeningPlan Goldilocks)) :
    real dsl statement values gamma points parameters plan = simulator plan := by
  exact q38_complete_joint_algebraic_simulator
    (model dsl statement values gamma points parameters plan)

/-- Two valid source witnesses induce the identical full public/opening law.
The common middle distribution is executable `simulate plan` and contains no
witness or witness search. -/
theorem two_witness_request_view (dsl : RelationDsl) (statement : Statement)
    (left right : WitnessPackingValues Goldilocks)
    (gamma : Gamma Goldilocks)
    (points : MaskOutputs Goldilocks → Fin 6 → Goldilocks)
    (parameters : D → Parameters dsl statement)
    (plan : MaskOutputs Goldilocks → Option (OpeningPlan Goldilocks)) :
    real dsl statement left gamma points parameters plan =
      real dsl statement right gamma points parameters plan := by
  calc
    real dsl statement left gamma points parameters plan = simulator plan :=
      real_eq_public_simulator dsl statement left gamma points parameters plan
    _ = real dsl statement right gamma points parameters plan :=
      (real_eq_public_simulator dsl statement right gamma points parameters plan).symm

/-- State-valued chronological identity for the same current response formulas
used by `model`.  A measured public branch may depend on D before the PIOP
parameters are decoded; the branch remains inside `kernel`. -/
theorem request_response_state_transport
    {PublicBranch Value : Type*} [Fintype PublicBranch] [AddCommMonoid Value]
    (dsl : RelationDsl) (statement : Statement)
    (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
    (base : V8SmzaRemainingAlgebra.RemainingCoins Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (kernel : D → PublicBranch → Q → D → Q → Value) :
    (∑ q, ∑ m, ∑ branch,
      let reply := V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m
      kernel reply branch q m
        (Q38Rp05ChronologicalAlgebra.response dsl statement
          (parameters reply branch) (sourceWitnessPolynomials values base.1) q)) =
    ∑ reply, ∑ branch, ∑ publicTranscript,
      let q := publicTranscript - unmaskedResponse dsl statement
        (parameters reply branch) (sourceWitnessPolynomials values base.1)
      let m := reply - V8SmzaMathPrivacy.unmasked gamma
        (currentHeads values base q) base.2.2
      kernel reply branch q m publicTranscript := by
  exact response_state_kernel_sum dsl statement gamma values base parameters kernel

/-- Measured-trace form of the current response transport.  Unlike the
`PiopSample` projection below, the complete answer-conditioned trace remains
inside `kernel`, so a CMS/GameState continuation is not detached from the
oracle answers which produced the RP05 batching parameters. -/
theorem request_response_measured_trace_sum
    {Other : Type} {Value : Type*} [AddCommMonoid Value]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks)
    (kernel : D → PublicTrace DigestRegister fuel → Q → D → Q → Value) :
    (∑ q, ∑ m, ∑ trace : PublicTrace DigestRegister fuel,
      let reply := V8SmzaMathPrivacy.response
        (decodedQ38DecsGamma stage.decsGamma)
        (currentHeads values base q) base.2.2 m
      kernel reply trace q m
        (Q38Rp05ChronologicalAlgebra.response dsl statement
          (decodedParameters dsl statement
            (tracedPiopSample fuel shape stage reply trace))
          (sourceWitnessPolynomials values base.1) q)) =
    ∑ reply, ∑ trace : PublicTrace DigestRegister fuel, ∑ publicTranscript,
      let q := publicTranscript - unmaskedResponse dsl statement
        (decodedParameters dsl statement
          (tracedPiopSample fuel shape stage reply trace))
        (sourceWitnessPolynomials values base.1)
      let m := reply - V8SmzaMathPrivacy.unmasked
        (decodedQ38DecsGamma stage.decsGamma)
        (currentHeads values base q) base.2.2
      kernel reply trace q m publicTranscript := by
  exact request_response_state_transport dsl statement
    (decodedQ38DecsGamma stage.decsGamma) values base
    (fun reply trace => decodedParameters dsl statement
      (tracedPiopSample fuel shape stage reply trace)) kernel

/-- Complete state-valued RP05 request transport in the real chronological
order `D -> measured branch -> T -> openings`.  The right side sums only over
public response/branch/transcript/opening coordinates.  `kernel` can itself be
an unnormalised quantum/adversary state in any additive space. -/
theorem request_public_opening_state_kernel_sum
    {PublicBranch Value : Type*} [Fintype PublicBranch] [AddCommMonoid Value]
    (dsl : RelationDsl) (statement : Statement)
    (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (admissible : ∀ reply branch transcript,
      Smz9WitnessInterpolationAdmissible (points reply branch transcript))
    (pointsNonzero : ∀ reply branch transcript opening,
      points reply branch transcript opening ≠ 0)
    (fallback : ∀ reply branch transcript,
      Targets (points reply branch transcript))
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
        Earlier Goldilocks → Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → Value) :
    (∑ base : RemainingCoins Goldilocks, ∑ q, ∑ m, ∑ branch,
      let reply := V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m
      let publicTranscript := Q38Rp05ChronologicalAlgebra.response dsl statement
        (parameters reply branch) (sourceWitnessPolynomials values base.1) q
      kernel reply branch publicTranscript
        (partialChronologicalView values (points reply branch publicTranscript)
          (fun _witness => pcsBase (points reply branch publicTranscript) q reply)
          (fun witness pcs =>
            physicalHeads (sourceWitnessPolynomials values witness) q pcs)
          (choose reply branch publicTranscript) base)) =
    ∑ reply, ∑ branch, ∑ publicTranscript,
      ∑ view : RemainingView Goldilocks,
        kernel reply branch publicTranscript
          (abortProjection (choose reply branch publicTranscript) view) := by
  calc
    _ = ∑ base : RemainingCoins Goldilocks, ∑ reply, ∑ branch, ∑ publicTranscript,
        let q := publicTranscript - unmaskedResponse dsl statement
          (parameters reply branch) (sourceWitnessPolynomials values base.1)
        kernel reply branch publicTranscript
          (partialChronologicalView values (points reply branch publicTranscript)
            (fun _witness => pcsBase (points reply branch publicTranscript) q reply)
            (fun witness pcs =>
              physicalHeads (sourceWitnessPolynomials values witness) q pcs)
            (choose reply branch publicTranscript) base) := by
      apply Finset.sum_congr rfl
      intro base _
      exact request_response_state_transport
        (Value := Value) dsl statement gamma values base parameters
          (fun reply branch q _m publicTranscript =>
            kernel reply branch publicTranscript
              (partialChronologicalView values (points reply branch publicTranscript)
                (fun _witness => pcsBase (points reply branch publicTranscript) q reply)
                (fun witness pcs =>
                  physicalHeads (sourceWitnessPolynomials values witness) q pcs)
                (choose reply branch publicTranscript) base))
    _ = ∑ reply, ∑ branch, ∑ publicTranscript,
        ∑ base : RemainingCoins Goldilocks,
          let q := publicTranscript - unmaskedResponse dsl statement
            (parameters reply branch) (sourceWitnessPolynomials values base.1)
          kernel reply branch publicTranscript
            (partialChronologicalView values (points reply branch publicTranscript)
              (fun witness => pcsBase (points reply branch publicTranscript)
                (publicTranscript - unmaskedResponse dsl statement
                  (parameters reply branch) (sourceWitnessPolynomials values witness)) reply)
              (fun witness pcs => physicalHeads
                (sourceWitnessPolynomials values witness)
                (publicTranscript - unmaskedResponse dsl statement
                  (parameters reply branch) (sourceWitnessPolynomials values witness)) pcs)
              (choose reply branch publicTranscript) base) := by
      rw [Finset.sum_comm]
      apply Finset.sum_congr rfl
      intro reply _
      rw [Finset.sum_comm]
      apply Finset.sum_congr rfl
      intro branch _
      rw [Finset.sum_comm]
      simp only [partialChronologicalView]
    _ = _ := by
      apply Finset.sum_congr rfl
      intro reply _
      apply Finset.sum_congr rfl
      intro branch _
      apply Finset.sum_congr rfl
      intro publicTranscript _
      exact HegemonCrypto.SmallWood.V8SmzaChronologicalStateAlgebra.remaining_partial_state_kernel_sum values
        (points reply branch publicTranscript)
        (admissible reply branch publicTranscript)
        (pointsNonzero reply branch publicTranscript)
        (fun witness => pcsBase (points reply branch publicTranscript)
          (publicTranscript - unmaskedResponse dsl statement
            (parameters reply branch) (sourceWitnessPolynomials values witness)) reply)
        (fun witness pcs => physicalHeads
          (sourceWitnessPolynomials values witness)
          (publicTranscript - unmaskedResponse dsl statement
            (parameters reply branch) (sourceWitnessPolynomials values witness)) pcs)
        (fallback reply branch publicTranscript)
        (choose reply branch publicTranscript)
        (kernel reply branch publicTranscript)

def sourceRequestKernelSum
    {PublicBranch Value : Type*} [Fintype PublicBranch] [AddCommMonoid Value]
    (dsl : RelationDsl) (statement : Statement)
    (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
        Earlier Goldilocks → Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → Value) : Value :=
  ∑ base : RemainingCoins Goldilocks, ∑ q, ∑ m, ∑ branch,
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    let publicTranscript := Q38Rp05ChronologicalAlgebra.response dsl statement
      (parameters reply branch) (sourceWitnessPolynomials values base.1) q
    kernel reply branch publicTranscript
      (partialChronologicalView values (points reply branch publicTranscript)
        (fun _witness => pcsBase (points reply branch publicTranscript) q reply)
        (fun witness pcs =>
          physicalHeads (sourceWitnessPolynomials values witness) q pcs)
        (choose reply branch publicTranscript) base)

def publicRequestKernelSum
    {PublicBranch Value : Type*} [Fintype PublicBranch] [AddCommMonoid Value]
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
        Earlier Goldilocks → Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → Value) : Value :=
  ∑ reply, ∑ branch, ∑ publicTranscript,
    ∑ view : RemainingView Goldilocks,
      kernel reply branch publicTranscript
        (abortProjection (choose reply branch publicTranscript) view)

theorem source_request_eq_public_request
    {PublicBranch Value : Type*} [Fintype PublicBranch] [AddCommMonoid Value]
    (dsl : RelationDsl) (statement : Statement)
    (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (admissible : ∀ reply branch transcript,
      Smz9WitnessInterpolationAdmissible (points reply branch transcript))
    (pointsNonzero : ∀ reply branch transcript opening,
      points reply branch transcript opening ≠ 0)
    (fallback : ∀ reply branch transcript,
      Targets (points reply branch transcript))
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
        Earlier Goldilocks → Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → Value) :
    sourceRequestKernelSum dsl statement gamma values parameters points choose kernel =
      publicRequestKernelSum points choose kernel := by
  exact request_public_opening_state_kernel_sum dsl statement gamma values
    parameters points admissible pointsNonzero fallback choose kernel

abbrev PiopSample (dsl : RelationDsl) (statement : Statement) :=
  Option (Fin (5 * dsl.width statement) → V8Smz9WholeViewObservation.FieldWord)

def PiopSample.toList {dsl : RelationDsl} {statement : Statement} :
    PiopSample dsl statement →
      Option (List V8Smz9WholeViewObservation.FieldWord)
  | none => none
  | some sample => some (List.ofFn sample)

/-- Literal compiler specialization: the early sample is decoded by the
700-word source rule and the measured PIOP branch by exactly
`decodedParameters`, including `none` poison outputs. -/
theorem literal_request_eq_public_request
    {Value : Type*} [AddCommMonoid Value]
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (decsSample : Option (List V8Smz9WholeViewObservation.FieldWord))
    (points : D → PiopSample dsl statement → Q → Fin 6 → Goldilocks)
    (admissible : ∀ reply branch transcript,
      Smz9WitnessInterpolationAdmissible (points reply branch transcript))
    (pointsNonzero : ∀ reply branch transcript opening,
      points reply branch transcript opening ≠ 0)
    (fallback : ∀ reply branch transcript,
      Targets (points reply branch transcript))
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
        Earlier Goldilocks → Option (Targets (points reply branch transcript)))
    (kernel : D → PiopSample dsl statement → Q →
      PartialView Goldilocks → Value) :
    sourceRequestKernelSum dsl statement (decodedQ38DecsGamma decsSample) values
        (fun _reply branch => decodedParameters dsl statement branch.toList)
        points choose kernel =
      publicRequestKernelSum points choose kernel := by
  exact source_request_eq_public_request
    (PublicBranch := PiopSample dsl statement) (Value := Value) dsl statement
    (decodedQ38DecsGamma decsSample) values
    (fun _reply branch => decodedParameters dsl statement branch.toList)
    points admissible pointsNonzero fallback choose kernel

/-- Actual two-witness state-valued endpoint.  Both witnesses meet the same
public statement and execute the same public branch/opening kernel; neither
appears in the common middle experiment. -/
theorem two_witness_request_state
    {PublicBranch Value : Type*} [Fintype PublicBranch] [AddCommMonoid Value]
    (dsl : RelationDsl) (statement : Statement)
    (gamma : Gamma Goldilocks)
    (left right : WitnessPackingValues Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (admissible : ∀ reply branch transcript,
      Smz9WitnessInterpolationAdmissible (points reply branch transcript))
    (pointsNonzero : ∀ reply branch transcript opening,
      points reply branch transcript opening ≠ 0)
    (fallback : ∀ reply branch transcript,
      Targets (points reply branch transcript))
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
        Earlier Goldilocks → Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → Value) :
    sourceRequestKernelSum dsl statement gamma left parameters points choose kernel =
      sourceRequestKernelSum dsl statement gamma right parameters points choose kernel := by
  calc
    _ = publicRequestKernelSum points choose kernel :=
      source_request_eq_public_request dsl statement gamma left parameters points
        admissible pointsNonzero fallback choose kernel
    _ = _ := (source_request_eq_public_request dsl statement gamma right parameters
      points admissible pointsNonzero fallback choose kernel).symm

def sourceRequestAverage {PublicBranch : Type*} [Fintype PublicBranch]
    (dsl : RelationDsl) (statement : Statement) (gamma : Gamma Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → Earlier Goldilocks →
        Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → ℝ) : ℝ :=
  sourceRequestKernelSum dsl statement gamma values parameters points choose kernel /
    ((Fintype.card (RemainingCoins Goldilocks) : ℝ) *
      Fintype.card Q * Fintype.card D)

def publicRequestAverage {PublicBranch : Type*} [Fintype PublicBranch]
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → Earlier Goldilocks →
        Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → ℝ) : ℝ :=
  publicRequestKernelSum points choose kernel /
    ((Fintype.card D : ℝ) * Fintype.card Q *
      Fintype.card (RemainingView Goldilocks))

/-- Normalized form of the state transport.  Both uniform-coin denominators
are displayed and their equality is derived from the actual remaining-coin
equivalence.  `PublicBranch` is an instrument sum, not a uniform coin, so its
cardinality correctly does not occur in either denominator. -/
theorem source_request_average_eq_public_request_average
    {PublicBranch : Type*} [Fintype PublicBranch] [Inhabited PublicBranch]
    (dsl : RelationDsl) (statement : Statement) (gamma : Gamma Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (admissible : ∀ reply branch transcript,
      Smz9WitnessInterpolationAdmissible (points reply branch transcript))
    (pointsNonzero : ∀ reply branch transcript opening,
      points reply branch transcript opening ≠ 0)
    (fallback : ∀ reply branch transcript, Targets (points reply branch transcript))
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → Earlier Goldilocks →
        Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → ℝ) :
    sourceRequestAverage dsl statement gamma values parameters points choose kernel =
      publicRequestAverage points choose kernel := by
  have cards : Fintype.card (RemainingCoins Goldilocks) =
      Fintype.card (RemainingView Goldilocks) := by
    let reply : D := default
    let branch : PublicBranch := default
    let transcript : Q := default
    let totalChoose := fun witness pcs early =>
      (choose reply branch transcript witness pcs early).getD
        (fallback reply branch transcript)
    exact Fintype.card_congr (remainingEquiv values (points reply branch transcript)
      (admissible reply branch transcript) (pointsNonzero reply branch transcript)
      (fun witness => pcsBase (points reply branch transcript)
        (transcript - unmaskedResponse dsl statement (parameters reply branch)
          (sourceWitnessPolynomials values witness)) reply)
      (fun witness pcs => physicalHeads (sourceWitnessPolynomials values witness)
        (transcript - unmaskedResponse dsl statement (parameters reply branch)
          (sourceWitnessPolynomials values witness)) pcs) totalChoose)
  unfold sourceRequestAverage publicRequestAverage
  rw [source_request_eq_public_request dsl statement gamma values parameters points
    admissible pointsNonzero fallback choose kernel, cards]
  ring

theorem two_witness_request_average
    {PublicBranch : Type*} [Fintype PublicBranch] [Inhabited PublicBranch]
    (dsl : RelationDsl) (statement : Statement) (gamma : Gamma Goldilocks)
    (left right : WitnessPackingValues Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
    (admissible : ∀ reply branch transcript,
      Smz9WitnessInterpolationAdmissible (points reply branch transcript))
    (pointsNonzero : ∀ reply branch transcript opening,
      points reply branch transcript opening ≠ 0)
    (fallback : ∀ reply branch transcript, Targets (points reply branch transcript))
    (choose : ∀ reply branch transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → Earlier Goldilocks →
        Option (Targets (points reply branch transcript)))
    (kernel : D → PublicBranch → Q → PartialView Goldilocks → ℝ) :
    sourceRequestAverage dsl statement gamma left parameters points choose kernel =
      sourceRequestAverage dsl statement gamma right parameters points choose kernel := by
  calc
    _ = publicRequestAverage points choose kernel :=
      source_request_average_eq_public_request_average dsl statement gamma left
        parameters points admissible pointsNonzero fallback choose kernel
    _ = _ := (source_request_average_eq_public_request_average dsl statement gamma right
      parameters points admissible pointsNonzero fallback choose kernel).symm

/-- A finite adaptive request schedule.  `Work` may contain the complete
public history and adversary-private workspace.  Consequently the statement,
both candidate witnesses, challenges and opening plan can change after every
public branch, while the transition itself receives no hidden coins. -/
structure AdaptiveSchedule (Work PublicBranch : Type*) [Fintype PublicBranch] where
  dsl : Work → RelationDsl
  statement : Work → Statement
  gamma : Work → Gamma Goldilocks
  leftWitness : Work → WitnessPackingValues Goldilocks
  rightWitness : Work → WitnessPackingValues Goldilocks
  parameters : (work : Work) → D → PublicBranch →
    Parameters (dsl work) (statement work)
  points : Work → D → PublicBranch → Q → Fin 6 → Goldilocks
  admissible : ∀ work reply branch transcript,
    Smz9WitnessInterpolationAdmissible (points work reply branch transcript)
  pointsNonzero : ∀ work reply branch transcript opening,
    points work reply branch transcript opening ≠ 0
  fallback : ∀ work reply branch transcript,
    Targets (points work reply branch transcript)
  choose : ∀ work reply branch transcript,
    WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      Earlier Goldilocks → Option (Targets (points work reply branch transcript))
  advance : Work → D → PublicBranch → Q → PartialView Goldilocks → Work
  failed : Work → Bool
  branchFailed : PublicBranch → Bool
  failureLatched : ∀ work reply branch transcript opening,
    failed (advance work reply branch transcript opening) =
      latchFailure (failed work) (branchFailed branch)

def runLeft {Work PublicBranch Value : Type*} [Fintype PublicBranch]
    [AddCommMonoid Value] (schedule : AdaptiveSchedule Work PublicBranch)
    (finish : Work → Value) : Nat → Work → Value
  | 0, work => finish work
  | rounds + 1, work =>
      sourceRequestKernelSum (schedule.dsl work) (schedule.statement work)
        (schedule.gamma work) (schedule.leftWitness work)
        (schedule.parameters work) (schedule.points work) (schedule.choose work)
        fun reply branch transcript opening =>
          runLeft schedule finish rounds
            (schedule.advance work reply branch transcript opening)

def runRight {Work PublicBranch Value : Type*} [Fintype PublicBranch]
    [AddCommMonoid Value] (schedule : AdaptiveSchedule Work PublicBranch)
    (finish : Work → Value) : Nat → Work → Value
  | 0, work => finish work
  | rounds + 1, work =>
      sourceRequestKernelSum (schedule.dsl work) (schedule.statement work)
        (schedule.gamma work) (schedule.rightWitness work)
        (schedule.parameters work) (schedule.points work) (schedule.choose work)
        fun reply branch transcript opening =>
          runRight schedule finish rounds
            (schedule.advance work reply branch transcript opening)

/-- Finite adaptive two-witness telescope in an arbitrary additive state
space.  Each induction step invokes the derived state-valued request theorem;
there is no assumed per-request privacy inequality. -/
theorem adaptive_two_witness_state
    {Work PublicBranch Value : Type*} [Fintype PublicBranch]
    [AddCommMonoid Value] (schedule : AdaptiveSchedule Work PublicBranch)
    (finish : Work → Value) (rounds : Nat) (work : Work) :
    runLeft schedule finish rounds work = runRight schedule finish rounds work := by
  induction rounds generalizing work with
  | zero => rfl
  | succ rounds ih =>
      simp only [runLeft, runRight]
      have continuation :
          (fun reply branch transcript opening =>
              runLeft schedule finish rounds
                (schedule.advance work reply branch transcript opening)) =
            (fun reply branch transcript opening =>
              runRight schedule finish rounds
                (schedule.advance work reply branch transcript opening)) := by
        funext reply branch transcript opening
        exact ih (schedule.advance work reply branch transcript opening)
      rw [continuation]
      exact two_witness_request_state
        (schedule.dsl work) (schedule.statement work) (schedule.gamma work)
        (schedule.leftWitness work) (schedule.rightWitness work)
        (schedule.parameters work) (schedule.points work)
        (schedule.admissible work) (schedule.pointsNonzero work)
        (schedule.fallback work) (schedule.choose work)
        (fun reply branch transcript opening =>
          runRight schedule finish rounds
            (schedule.advance work reply branch transcript opening))

def runLeftNormalized {Work PublicBranch : Type*} [Fintype PublicBranch]
    [Inhabited PublicBranch] (schedule : AdaptiveSchedule Work PublicBranch)
    (finish : Work → ℝ) : Nat → Work → ℝ
  | 0, work => finish work
  | rounds + 1, work =>
      sourceRequestAverage (schedule.dsl work) (schedule.statement work)
        (schedule.gamma work) (schedule.leftWitness work)
        (schedule.parameters work) (schedule.points work) (schedule.choose work)
        fun reply branch transcript opening =>
          runLeftNormalized schedule finish rounds
            (schedule.advance work reply branch transcript opening)

def runRightNormalized {Work PublicBranch : Type*} [Fintype PublicBranch]
    [Inhabited PublicBranch] (schedule : AdaptiveSchedule Work PublicBranch)
    (finish : Work → ℝ) : Nat → Work → ℝ
  | 0, work => finish work
  | rounds + 1, work =>
      sourceRequestAverage (schedule.dsl work) (schedule.statement work)
        (schedule.gamma work) (schedule.rightWitness work)
        (schedule.parameters work) (schedule.points work) (schedule.choose work)
        fun reply branch transcript opening =>
          runRightNormalized schedule finish rounds
            (schedule.advance work reply branch transcript opening)

/-- Normalized finite adaptive request telescope.  Every uniform source is
divided out at its own request; measured branches remain weighted sums. -/
theorem adaptive_two_witness_normalized
    {Work PublicBranch : Type*} [Fintype PublicBranch] [Inhabited PublicBranch]
    (schedule : AdaptiveSchedule Work PublicBranch)
    (finish : Work → ℝ) (rounds : Nat) (work : Work) :
    runLeftNormalized schedule finish rounds work =
      runRightNormalized schedule finish rounds work := by
  induction rounds generalizing work with
  | zero => rfl
  | succ rounds ih =>
      simp only [runLeftNormalized, runRightNormalized]
      have continuation :
          (fun reply branch transcript opening =>
              runLeftNormalized schedule finish rounds
                (schedule.advance work reply branch transcript opening)) =
            (fun reply branch transcript opening =>
              runRightNormalized schedule finish rounds
                (schedule.advance work reply branch transcript opening)) := by
        funext reply branch transcript opening
        exact ih (schedule.advance work reply branch transcript opening)
      rw [continuation]
      exact two_witness_request_average
        (schedule.dsl work) (schedule.statement work) (schedule.gamma work)
        (schedule.leftWitness work) (schedule.rightWitness work)
        (schedule.parameters work) (schedule.points work)
        (schedule.admissible work) (schedule.pointsNonzero work)
        (schedule.fallback work) (schedule.choose work)
        (fun reply branch transcript opening =>
          runRightNormalized schedule finish rounds
            (schedule.advance work reply branch transcript opening))

/-- The literal compiled continuation satisfies the environment-blind premise
needed by the CMS bridge.  Retained overwritten labels are traced out as
orthogonal fibers; the request program cannot inspect that register. -/
theorem request_continuation_label_blind
    {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool) (largeEnough : 25029 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : PublicResult → Program (Input bound) Work)
    (oracle : Input bound → DigestRegister)
    (state : GameState (Input := Input bound)
      (Work := (LeafIndex → DigestRegister) × Work)) :
    V8Smz9HonestWholeViewGames.run randomized
        (liftEnvironmentProgram (Environment := LeafIndex → DigestRegister)
          (requestContinuation largeEnough dsl statement values base masks salt
            labels widthBound next)) oracle state =
      ∑ environment : LeafIndex → DigestRegister,
        V8Smz9HonestWholeViewGames.run randomized
          (requestContinuation largeEnough dsl statement values base masks salt
            labels widthBound next) oracle (environmentFiber environment state) := by
  exact run_lift_environment_program randomized _ oracle state

/-- Every request constructor is selected from the already-public history.
In particular, neither challenge decoder nor opening plan can inspect the
private witness. -/
structure Schedule (dsl : RelationDsl) (statement : Statement) where
  gamma : List View → Gamma Goldilocks
  points : List View → MaskOutputs Goldilocks → Fin 6 → Goldilocks
  parameters : (history : List View) → D → Parameters dsl statement
  plan : List View → MaskOutputs Goldilocks → Option (OpeningPlan Goldilocks)
  planPoints : ∀ history output opening,
    plan history output = some opening → opening.points = points history output

def aborted (view : View) : Bool :=
  match view.2 with
  | none => true
  | some partialView => partialView.2.2.2.isNone

def runReal (dsl : RelationDsl) (statement : Statement)
    (schedule : Schedule dsl statement)
    (values : WitnessPackingValues Goldilocks) :
    Nat → List View → PMF (List View)
  | 0, history => PMF.pure history
  | rounds + 1, history =>
      (real dsl statement values (schedule.gamma history)
        (schedule.points history) (schedule.parameters history)
        (schedule.plan history)).bind fun view =>
          if aborted view then PMF.pure (history ++ [view])
          else runReal dsl statement schedule values rounds (history ++ [view])

def runSimulator (dsl : RelationDsl) (statement : Statement)
    (schedule : Schedule dsl statement) :
    Nat → List View → PMF (List View)
  | 0, history => PMF.pure history
  | rounds + 1, history =>
      (simulator (schedule.plan history)).bind fun view =>
        if aborted view then PMF.pure (history ++ [view])
        else runSimulator dsl statement schedule rounds (history ++ [view])

/-- Adaptive request-round composition on persistent chronological history.
The induction rewrites each actual request with its derived public simulator;
there is no per-round security premise. -/
theorem adaptive_history_eq_simulator (dsl : RelationDsl)
    (statement : Statement) (schedule : Schedule dsl statement)
    (values : WitnessPackingValues Goldilocks)
    (rounds : Nat) (history : List View) :
    runReal dsl statement schedule values rounds history =
      runSimulator dsl statement schedule rounds history := by
  induction rounds generalizing history with
  | zero => rfl
  | succ rounds ih =>
      simp only [runReal, runSimulator,
        real_eq_public_simulator dsl statement values
          (schedule.gamma history) (schedule.points history)
          (schedule.parameters history) (schedule.plan history)]
      apply congrArg (PMF.bind _)
      funext view
      split
      · rfl
      · exact ih (history ++ [view])

/-- Full two-witness adaptive transcript equality for every finite number of
requests.  The simulator is the same on both sides and stores the complete
chronological public/opening history. -/
theorem two_witness_adaptive_history (dsl : RelationDsl)
    (statement : Statement) (schedule : Schedule dsl statement)
    (left right : WitnessPackingValues Goldilocks)
    (rounds : Nat) (history : List View) :
    runReal dsl statement schedule left rounds history =
      runReal dsl statement schedule right rounds history := by
  calc
    runReal dsl statement schedule left rounds history =
        runSimulator dsl statement schedule rounds history :=
      adaptive_history_eq_simulator dsl statement schedule left rounds history
    _ = runReal dsl statement schedule right rounds history :=
      (adaptive_history_eq_simulator dsl statement schedule right rounds history).symm

end
end HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
