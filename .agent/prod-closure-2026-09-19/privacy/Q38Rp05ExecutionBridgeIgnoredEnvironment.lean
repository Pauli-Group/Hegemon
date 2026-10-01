import Q38Rp05RequestCompiler
import HegemonCrypto.SmallWoodV8Smz9RunHomogeneity

/-!
# RP05 initialized-CMS execution bridge

This file records two distinct exact identities.  First, after controlled
swaps we can decode the complete persistent database, reconstruct its
canonical total-oracle family, and execute the same seven-constructor
`Program` on every named oracle branch.  That family remains tape-dependent,
so this identity alone is deliberately *not* advertised as the common-state
input to the adaptive-opening theorem.  Second, the literal RP05
`Program.freshInput` batch is reduced to the finite old-oracle/full-overlay
law while retaining the old-oracle-indexed prior state.

The terminal reads below are explicitly CURRENT reads.  On each canonical
branch they return `oracle (key i)`; reinstalling those answers with the RP05
batch-update function leaves that complete oracle unchanged.  Thus the saved
fresh-label registers are never substituted for current database answers.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RunHomogeneity
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Other Branch BaseWork : Type}
variable [Fintype Other] [DecidableEq Other]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype BaseWork] [DecidableEq BaseWork]

local notation "FullInput" => Rp05LeafInput ⊕ Other
local notation "FullWork" =>
  (LeafIndex → DigestRegister) × (Branch × BaseWork)
local notation "FullCore" =>
  Core FullInput Branch
    (FullInput × DigestRegister × BaseWork) DigestRegister
section IgnoredEnvironment

variable {Input Work Environment : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [Fintype Environment]

/-- Reassociate a whole-view basis so the retained environment is an outer
orthogonal coordinate. -/
def environmentBasisEquiv :
    QueryBasis Input DigestRegister (Environment × Work) ≃
      Environment × QueryBasis Input DigestRegister Work where
  toFun basis := (basis.2.2.1, basis.1, basis.2.1, basis.2.2.2)
  invFun pair := (pair.2.1, pair.2.2.1, pair.1, pair.2.2.2)
  left_inv basis := by cases basis; rfl
  right_inv pair := by cases pair; rfl

/-- One computational-basis environment fiber.  Summing the probabilities
of these fibers is the partial trace needed here; no amplitude sum erases the
retained overwritten answers. -/
def environmentFiber (environment : Environment)
    (state : GameState (Input := Input) (Work := Environment × Work)) :
    GameState (Input := Input) (Work := Work) :=
  WithLp.toLp 2 (fun basis =>
    state (basis.1, basis.2.1, environment, basis.2.2))

omit [DecidableEq Input] in
theorem environment_fiber_norm_squared
    (state : GameState (Input := Input) (Work := Environment × Work)) :
    (∑ environment : Environment, ‖environmentFiber environment state‖ ^ 2) =
      ‖state‖ ^ 2 := by
  simp_rw [EuclideanSpace.norm_sq_eq]
  calc
    (∑ environment : Environment,
        ∑ basis : QueryBasis Input DigestRegister Work,
          ‖environmentFiber environment state basis‖ ^ 2) =
      ∑ pair : Environment × QueryBasis Input DigestRegister Work,
        Complex.normSq (state ((environmentBasisEquiv
          (Input := Input) (Work := Work) (Environment := Environment)).symm pair)) := by
        rw [Fintype.sum_prod_type]
        apply Finset.sum_congr rfl
        intro pair _
        apply Finset.sum_congr rfl
        intro basis _
        exact Complex.sq_norm _
    _ = ∑ basis : QueryBasis Input DigestRegister (Environment × Work),
        Complex.normSq (state basis) :=
      (environmentBasisEquiv
        (Input := Input) (Work := Work) (Environment := Environment)).symm.sum_comp
          (fun basis => Complex.normSq (state basis))
    _ = ∑ basis : QueryBasis Input DigestRegister (Environment × Work),
        ‖state basis‖ ^ 2 := by
      apply Finset.sum_congr rfl
      intro basis _
      exact (Complex.sq_norm _).symm

/-- Lift a linear branch independently on every environment fiber. -/
def liftEnvironmentLinear
    (operation : GameState (Input := Input) (Work := Work) →ₗ[ℂ]
      GameState (Input := Input) (Work := Work)) :
    GameState (Input := Input) (Work := Environment × Work) →ₗ[ℂ]
      GameState (Input := Input) (Work := Environment × Work) where
  toFun state := WithLp.toLp 2 (fun basis =>
    operation (environmentFiber basis.2.2.1 state)
      (basis.1, basis.2.1, basis.2.2.2))
  map_add' left right := by
    ext basis
    change operation (environmentFiber basis.2.2.1 (left + right)) _ = _
    rw [show environmentFiber basis.2.2.1 (left + right) =
        environmentFiber basis.2.2.1 left +
          environmentFiber basis.2.2.1 right by rfl,
      map_add]
    rfl
  map_smul' scalar state := by
    ext basis
    change operation (environmentFiber basis.2.2.1 (scalar • state)) _ = _
    rw [show environmentFiber basis.2.2.1 (scalar • state) =
        scalar • environmentFiber basis.2.2.1 state by rfl,
      map_smul]
    rfl

omit [Fintype Input] [DecidableEq Input] [Fintype Work] [Fintype Environment] in
@[simp]
theorem environment_fiber_lift_linear
    (operation : GameState (Input := Input) (Work := Work) →ₗ[ℂ]
      GameState (Input := Input) (Work := Work))
    (environment : Environment)
    (state : GameState (Input := Input) (Work := Environment × Work)) :
    environmentFiber environment (liftEnvironmentLinear operation state) =
      operation (environmentFiber environment state) := by
  ext basis
  rfl

/-- Tensor a whole-view gate with identity on the saved environment. -/
def liftEnvironmentGate
    (operation : GameGate (Input := Input) (Work := Work)) :
    GameGate (Input := Input) (Work := Environment × Work) :=
  let split := LinearIsometryEquiv.piLpCongrLeft 2 ℂ ℂ
    ((environmentBasisEquiv
      (Input := Input) (Work := Work) (Environment := Environment)).trans
      (Equiv.sigmaEquivProd Environment (QueryBasis Input DigestRegister Work)).symm)
  let curry := LinearIsometryEquiv.piLpCurry ℂ 2
    (fun (_ : Environment) (_ : QueryBasis Input DigestRegister Work) => ℂ)
  split.trans (curry.trans ((LinearIsometryEquiv.piLpCongrRight 2
    (fun _ : Environment => operation)).trans (curry.symm.trans split.symm)))

omit [DecidableEq Input] in
@[simp]
theorem environment_fiber_lift_gate
    (operation : GameGate (Input := Input) (Work := Work))
    (environment : Environment)
    (state : GameState (Input := Input) (Work := Environment × Work)) :
    environmentFiber environment (liftEnvironmentGate operation state) =
      operation (environmentFiber environment state) := by
  ext basis
  rfl

/-- Tensor a complete instrument with identity on the saved environment. -/
def liftEnvironmentInstrument {count : Nat}
    (operation : Instrument Input Work count) :
    Instrument Input (Environment × Work) count where
  branch outcome := liftEnvironmentLinear (operation.branch outcome)
  complete state := by
    calc
      (∑ outcome, ‖liftEnvironmentLinear (Environment := Environment)
          (operation.branch outcome) state‖ ^ 2) =
          ∑ outcome, ∑ environment : Environment,
            ‖operation.branch outcome
              (environmentFiber environment state)‖ ^ 2 := by
        apply Finset.sum_congr rfl
        intro outcome _
        rw [← environment_fiber_norm_squared
          (liftEnvironmentLinear (Environment := Environment)
            (operation.branch outcome) state)]
        simp only [environment_fiber_lift_linear]
      _ = ∑ environment : Environment, ∑ outcome,
          ‖operation.branch outcome
            (environmentFiber environment state)‖ ^ 2 := Finset.sum_comm
      _ = ∑ environment : Environment,
          ‖environmentFiber environment state‖ ^ 2 := by
        apply Finset.sum_congr rfl
        intro environment _
        exact operation.complete (environmentFiber environment state)
      _ = ‖state‖ ^ 2 := environment_fiber_norm_squared state

def liftEnvironmentEvent
    (event : Finset (QueryBasis Input DigestRegister Work)) :
    Finset (QueryBasis Input DigestRegister (Environment × Work)) :=
  Finset.univ.filter (fun basis =>
    (basis.1, basis.2.1, basis.2.2.2) ∈ event)

/-- Event projection does not depend on the equality decider used for
membership in its finite event. -/
theorem eventProjection_decidableEq_irrel {Basis : Type*} [Fintype Basis]
    (event : Finset Basis) (state : EuclideanSpace ℂ Basis)
    (left right : DecidableEq Basis) :
    @eventProjection Basis left event state =
      @eventProjection Basis right event state := by
  ext basis
  by_cases member : basis ∈ event <;> simp [eventProjection, member]

omit [Fintype Other] [DecidableEq Other] in
theorem environment_fiber_event_projection
    (event : Finset (QueryBasis Input DigestRegister Work))
    (environment : Environment)
    (state : GameState (Input := Input) (Work := Environment × Work)) :
    environmentFiber environment
        (eventProjection (liftEnvironmentEvent
          (Environment := Environment) event) state) =
      eventProjection event (environmentFiber environment state) := by
  ext basis
  by_cases member : basis ∈ event <;>
    simp [environmentFiber, liftEnvironmentEvent, eventProjection, member]

omit [Fintype Other] [DecidableEq Other] in
theorem born_lift_environment_event
    (event : Finset (QueryBasis Input DigestRegister Work))
    (state : GameState (Input := Input) (Work := Environment × Work)) :
    born (liftEnvironmentEvent (Environment := Environment) event) state =
      ∑ environment : Environment,
        born event (environmentFiber environment state) := by
  unfold born
  rw [← environment_fiber_norm_squared
    (eventProjection (liftEnvironmentEvent
      (Environment := Environment) event) state)]
  apply Finset.sum_congr rfl
  intro environment _
  rw [environment_fiber_event_projection]

omit [Fintype Other] [DecidableEq Other] [DecidableEq Input] in
@[simp]
theorem environment_fiber_query
    (oracle : Input → DigestRegister) (environment : Environment)
    (state : GameState (Input := Input) (Work := Environment × Work)) :
    environmentFiber environment (query oracle state) =
      query oracle (environmentFiber environment state) := by
  ext basis
  rfl

/-- Syntactic certificate that a continuation ignores the retained label
environment.  Every one of the seven constructors is lifted; gates and
instruments act fiberwise and the final event contains every environment
basis value. -/
def liftEnvironmentProgram : Program Input Work →
    Program Input (Environment × Work)
  | .finish event => .finish (liftEnvironmentEvent event)
  | .gate operation next =>
      .gate (liftEnvironmentGate operation) (liftEnvironmentProgram next)
  | .quantumQuery next => .quantumQuery (liftEnvironmentProgram next)
  | .honestRead input next =>
      .honestRead input (fun answer => liftEnvironmentProgram (next answer))
  | .instrument operation next =>
      .instrument (liftEnvironmentInstrument operation)
        (fun outcome => liftEnvironmentProgram (next outcome))
  | .random source next =>
      .random source (fun coins => liftEnvironmentProgram (next coins))
  | .freshInput sampler next =>
      .freshInput sampler (fun coins output =>
        liftEnvironmentProgram (next coins output))

/-- Exact probability-level partial trace for the lifted program.  This is a
constructor induction, not a generic continuation-bound premise. -/
theorem run_lift_environment_program (randomized : Bool)
    (program : Program Input Work) (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Environment × Work)) :
    V8Smz9HonestWholeViewGames.run randomized
        (liftEnvironmentProgram (Environment := Environment) program)
        oracle state =
      ∑ environment : Environment,
        V8Smz9HonestWholeViewGames.run randomized program oracle
          (environmentFiber environment state) := by
  induction program generalizing oracle state with
  | finish event =>
      simp only [liftEnvironmentProgram, V8Smz9HonestWholeViewGames.run]
      unfold born
      let totalTailClassicalDecEq : DecidableEq
          (DigestRegister × (Environment × Work)) := fun left right =>
        @instDecidableEqProd DigestRegister (Environment × Work)
          (fun a b => Fintype.decidablePiFintype a b)
          (fun x y => Classical.propDecidable (x = y)) left right
      let totalClassicalDecEq : DecidableEq
          (Input × DigestRegister × (Environment × Work)) := fun left right =>
        @instDecidableEqProd Input (DigestRegister × (Environment × Work))
          (inferInstance : DecidableEq Input) totalTailClassicalDecEq left right
      let baseTailClassicalDecEq : DecidableEq (DigestRegister × Work) :=
        fun left right =>
          @instDecidableEqProd DigestRegister Work
            (fun a b => Fintype.decidablePiFintype a b)
            (fun x y => Classical.propDecidable (x = y)) left right
      let baseClassicalDecEq : DecidableEq (Input × DigestRegister × Work) :=
        fun left right =>
          @instDecidableEqProd Input (DigestRegister × Work)
            (inferInstance : DecidableEq Input) baseTailClassicalDecEq left right
      have totalProjectionEq :
          @eventProjection _ (inferInstance : DecidableEq
            (QueryBasis Input DigestRegister (Environment × Work)))
              (liftEnvironmentEvent (Environment := Environment) event) state =
            @eventProjection _ totalClassicalDecEq
              (liftEnvironmentEvent (Environment := Environment) event) state :=
        eventProjection_decidableEq_irrel _ _ _ _
      have baseProjectionEq (environment : Environment) :
          @eventProjection _ (inferInstance : DecidableEq
            (QueryBasis Input DigestRegister Work)) event
              (environmentFiber environment state) =
            @eventProjection _ baseClassicalDecEq event
              (environmentFiber environment state) :=
        eventProjection_decidableEq_irrel _ _ _ _
      calc
        ‖@eventProjection _ totalClassicalDecEq
            (liftEnvironmentEvent (Environment := Environment) event) state‖ ^ 2 =
          ‖eventProjection (liftEnvironmentEvent
            (Environment := Environment) event) state‖ ^ 2 :=
          congrArg (fun vector : GameState (Input := Input)
            (Work := Environment × Work) => ‖vector‖ ^ 2) totalProjectionEq.symm
        _ =
          ∑ environment : Environment,
            ‖environmentFiber environment
              (eventProjection (liftEnvironmentEvent
                (Environment := Environment) event) state)‖ ^ 2 :=
          (environment_fiber_norm_squared
            (eventProjection (liftEnvironmentEvent
              (Environment := Environment) event) state)).symm
        _ = ∑ environment : Environment,
            ‖@eventProjection _ baseClassicalDecEq event
              (environmentFiber environment state)‖ ^ 2 := by
          apply Finset.sum_congr rfl
          intro environment _
          have fiberProjection :
              environmentFiber environment
                (eventProjection (liftEnvironmentEvent
                  (Environment := Environment) event) state) =
              eventProjection event (environmentFiber environment state) := by
            ext basis
            by_cases member : basis ∈ event <;>
              simp [environmentFiber, liftEnvironmentEvent, eventProjection, member]
          exact congrArg (fun vector : GameState (Input := Input) (Work := Work) =>
            ‖vector‖ ^ 2) (fiberProjection.trans (baseProjectionEq environment))
  | gate operation next ih =>
      simp only [liftEnvironmentProgram, V8Smz9HonestWholeViewGames.run]
      rw [ih]
      simp only [environment_fiber_lift_gate]
  | quantumQuery next ih =>
      simp only [liftEnvironmentProgram, V8Smz9HonestWholeViewGames.run]
      rw [ih]
      simp only [environment_fiber_query]
  | honestRead input next ih =>
      simp only [liftEnvironmentProgram, V8Smz9HonestWholeViewGames.run]
      exact ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [liftEnvironmentProgram, V8Smz9HonestWholeViewGames.run]
      calc
        _ = ∑ outcome, ∑ environment : Environment,
            V8Smz9HonestWholeViewGames.run randomized (next outcome) oracle
              (operation.branch outcome (environmentFiber environment state)) := by
          apply Finset.sum_congr rfl
          intro outcome _
          rw [ih]
          apply Finset.sum_congr rfl
          intro environment _
          exact congrArg
            (V8Smz9HonestWholeViewGames.run randomized (next outcome) oracle)
            (environment_fiber_lift_linear
              (operation.branch outcome) environment state)
        _ = ∑ environment : Environment, ∑ outcome,
            V8Smz9HonestWholeViewGames.run randomized (next outcome) oracle
              (operation.branch outcome (environmentFiber environment state)) :=
          Finset.sum_comm
  | random source next ih =>
      simp only [liftEnvironmentProgram, V8Smz9HonestWholeViewGames.run]
      simp_rw [ih]
      exact V8Smz9MeasuredRunContinuity.average_sum _
  | freshInput sampler next ih =>
      simp only [liftEnvironmentProgram, V8Smz9HonestWholeViewGames.run]
      simp_rw [ih]
      calc
        uniformAverage (fun coins : sampler.Coins =>
            uniformAverage (fun output : DigestRegister =>
              let current := if randomized then
                Function.update oracle (sampler.input coins) output
              else oracle
              ∑ environment : Environment,
                V8Smz9HonestWholeViewGames.run randomized
                  (next coins (current (sampler.input coins))) current
                  (environmentFiber environment state))) =
          uniformAverage (fun coins : sampler.Coins =>
            ∑ environment : Environment,
              uniformAverage (fun output : DigestRegister =>
                let current := if randomized then
                  Function.update oracle (sampler.input coins) output
                else oracle
                V8Smz9HonestWholeViewGames.run randomized
                  (next coins (current (sampler.input coins))) current
                  (environmentFiber environment state))) := by
            apply congrArg uniformAverage
            funext coins
            exact V8Smz9MeasuredRunContinuity.average_sum _
        _ = ∑ environment : Environment,
            uniformAverage (fun coins : sampler.Coins =>
              uniformAverage (fun output : DigestRegister =>
                let current := if randomized then
                  Function.update oracle (sampler.input coins) output
                else oracle
                V8Smz9HonestWholeViewGames.run randomized
                  (next coins (current (sampler.input coins))) current
                  (environmentFiber environment state))) :=
          V8Smz9MeasuredRunContinuity.average_sum _

end IgnoredEnvironment
end
end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
