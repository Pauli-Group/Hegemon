import Q38Rp05InitializedEndpoint
import Q38Rp05CanonicalAbortPadding
import Q38Rp05PrivacyNumerics
import SmzaRp05GeneratedCertificates

/-! Two witnesses share a structural public adaptive strategy. Equality of
the common simulator is derived from that syntax, not assumed as a game law. -/
namespace HegemonCrypto.SmallWood.Q38Rp05TwoWitnessEndpoint

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.Q38Rp05ActualPivot
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveEndpoint
open HegemonCrypto.SmallWood.Q38Rp05InitializedEndpoint
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
variable {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
local notation "OracleInput" => Rp05FullRawInput bound
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement

/-- Public source data only. The witness is absent. Bound proofs are fields
only because the current compiler is dependently typed; proof irrelevance
prevents them from being observable data. -/
structure PublicRequestData (bound : Nat) where
  largeEnough : 39162 ≤ bound
  dsl : RelationDsl
  statement : Statement
  salt : SaltBytes
  widthBound : 5 * dsl.width statement ≤ 2 ^ 24

def publicData (data : Request bound) : PublicRequestData bound :=
  ⟨data.largeEnough, data.dsl, data.statement, data.salt, data.widthBound⟩

def publicCode (data : PublicRequestData bound) (next : Bytes → MixedProgram OracleInput Work) :
    MixedProgram OracleInput Work :=
  publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound next

/-- Same operations, actual random/measurement outcomes, stop events, and
public requests. The two witness fields may differ at EVERY request, including
requests selected adaptively after arbitrary byte/error responses. -/
inductive SamePublicStrategy : {requests : Nat} →
    Schedule bound Work requests → Schedule bound Work requests → Prop where
  | finish {requests : Nat} (event : Finset (QueryBasis OracleInput DigestRegister Work)) :
      SamePublicStrategy (Schedule.finish (requests := requests) event) (Schedule.finish event)
  | gate {requests : Nat} (operation : GameGate (Input := OracleInput) (Work := Work))
      {left right : Schedule bound Work requests} (next : SamePublicStrategy left right) :
      SamePublicStrategy (.gate operation left) (.gate operation right)
  | quantumQuery {requests : Nat} {left right : Schedule bound Work requests}
      (next : SamePublicStrategy left right) : SamePublicStrategy (.quantumQuery left) (.quantumQuery right)
  | honestRead {requests : Nat} (input : OracleInput)
      {left right : DigestRegister → Schedule bound Work requests}
      (next : ∀ answer, SamePublicStrategy (left answer) (right answer)) :
      SamePublicStrategy (.honestRead input left) (.honestRead input right)
  | instrument {requests count : Nat} (operation : Instrument OracleInput Work count)
      {left right : Fin count → Schedule bound Work requests}
      (next : ∀ outcome, SamePublicStrategy (left outcome) (right outcome)) :
      SamePublicStrategy (.instrument operation left) (.instrument operation right)
  | random {requests : Nat} (source : RandomSource)
      {left right : source.Coins → Schedule bound Work requests}
      (next : ∀ coins, SamePublicStrategy (left coins) (right coins)) :
      SamePublicStrategy (.random source left) (.random source right)
  | request {requests : Nat} (leftData rightData : Request bound)
      (sameData : publicData leftData = publicData rightData)
      {left right : Bytes → Schedule bound Work requests}
      (next : ∀ bytes, SamePublicStrategy (left bytes) (right bytes)) :
      SamePublicStrategy (.request leftData left) (.request rightData right)

omit [DecidableEq Work] in
theorem same_strategy_same_public_code {requests : Nat}
    {left right : Schedule bound Work requests} (same : SamePublicStrategy left right) :
    hybrid 0 left = hybrid 0 right := by
  induction same with
  | finish event => rfl
  | gate operation next ih => exact congrArg (MixedProgram.gate operation) ih
  | quantumQuery next ih => exact congrArg MixedProgram.quantumQuery ih
  | honestRead input next ih => exact congrArg (MixedProgram.honestRead input) (funext ih)
  | instrument operation next ih => exact congrArg (MixedProgram.instrument operation) (funext ih)
  | random source next ih => exact congrArg (MixedProgram.random source) (funext ih)
  | request leftData rightData sameData next ih =>
      change publicCode (publicData leftData) _ = publicCode (publicData rightData) _
      rw [sameData]
      exact congrArg (publicCode (publicData rightData)) (funext ih)

omit [DecidableEq Work] in
theorem same_strategy_same_compiled_public {requests : Nat}
    {left right : Schedule bound Work requests} (same : SamePublicStrategy left right) :
    compiledHybrid 0 left = compiledHybrid 0 right :=
  congrArg (fun program => V8Smz9MixedMaskCompiler.compile program [])
    (same_strategy_same_public_code same)

section Endpoint
local notation "W" => Unit × Work

/-- Initialized two-witness bound. Both complete source games use the same
adversary and public adaptive strategy; only accepted witnesses may differ.
There is no assumed common-simulator probability equality. -/
theorem initialized_two_witness_bound
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0) (abortTargets : Targets abortPoints)
    {requests : Nat} (left right : Schedule bound W requests)
    (same : SamePublicStrategy left right)
    (leftEligible : Eligible components nonlinearRoot nodeDegree left)
    (rightEligible : Eligible components nonlinearRoot nodeDegree right)
    (total : Nat) (leftBudget : WithinBudget left total) (rightBudget : WithinBudget right total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ) :
    |acceptance true (compiledHybrid requests left) (WithLp.toLp 2 registers) -
      acceptance true (compiledHybrid requests right) (WithLp.toLp 2 registers)| ≤
      2 * (Q38Rp05ReachableBudget.effectiveRequests requests total : ℝ) * loss total *
        ‖WithLp.toLp 2 registers‖ ^ 2 := by
  have leftBound := initialized_adaptive_acceptance_bound components nonlinearRoot nodeDegree
    certificates abortPoints abortAdmissible abortNonzero abortTargets left leftEligible
    total leftBudget registers
  have rightBound := initialized_adaptive_acceptance_bound components nonlinearRoot nodeDegree
    certificates abortPoints abortAdmissible abortNonzero abortTargets right rightEligible
    total rightBudget registers
  rw [same_strategy_same_compiled_public same] at leftBound
  calc
    _ ≤ |acceptance true (compiledHybrid requests left) (WithLp.toLp 2 registers) -
          acceptance true (compiledHybrid 0 right) (WithLp.toLp 2 registers)| +
        |acceptance true (compiledHybrid 0 right) (WithLp.toLp 2 registers) -
          acceptance true (compiledHybrid requests right) (WithLp.toLp 2 registers)| := abs_sub_le _ _ _
    _ ≤ _ := add_le_add leftBound (by simpa only [abs_sub_comm] using rightBound)
    _ = _ := by ring

/-- The same two-witness theorem stated on the literal zero-entry initialized
CMS state.  The multiplicative term is its original unnormalized Born mass;
the equality to the response-basis register mass is proved by
`initialized_cms_mass`, not assumed or reweighted branch by branch. -/
theorem initialized_cms_two_witness_bound
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat)
    (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0) (abortTargets : Targets abortPoints)
    {requests : Nat} (left right : Schedule bound W requests)
    (same : SamePublicStrategy left right)
    (leftEligible : Eligible components nonlinearRoot nodeDegree left)
    (rightEligible : Eligible components nonlinearRoot nodeDegree right)
    (total : Nat) (leftBudget : WithinBudget left total)
    (rightBudget : WithinBudget right total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister)
      (Workspace := W) → ℂ) :
    |phaseRun true (compiledHybrid requests left) (initializedCms registers) -
      phaseRun true (compiledHybrid requests right) (initializedCms registers)| ≤
      2 * (Q38Rp05ReachableBudget.effectiveRequests requests total : ℝ) *
        loss total * normSquared (initializedCms registers) := by
  simpa only [initialized_phase_is_acceptance, initialized_cms_mass] using
    initialized_two_witness_bound components nonlinearRoot nodeDegree certificates
      abortPoints abortAdmissible abortNonzero abortTargets left right same
      leftEligible rightEligible total leftBudget rightBudget registers

theorem normalized_two_witness_bound
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0) (abortTargets : Targets abortPoints)
    {requests : Nat} (left right : Schedule bound W requests)
    (same : SamePublicStrategy left right)
    (leftEligible : Eligible components nonlinearRoot nodeDegree left)
    (rightEligible : Eligible components nonlinearRoot nodeDegree right)
    (total : Nat) (leftBudget : WithinBudget left total) (rightBudget : WithinBudget right total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ)
    (normalized : ‖WithLp.toLp 2 registers‖ = 1) :
    |acceptance true (compiledHybrid requests left) (WithLp.toLp 2 registers) -
      acceptance true (compiledHybrid requests right) (WithLp.toLp 2 registers)| ≤
      2 * (Q38Rp05ReachableBudget.effectiveRequests requests total : ℝ) * loss total := by
  simpa only [normalized, one_pow, mul_one] using initialized_two_witness_bound components
    nonlinearRoot nodeDegree certificates abortPoints abortAdmissible abortNonzero abortTargets
    left right same leftEligible rightEligible total leftBudget rightBudget registers

/-- No initial CMS-support or abort-padding assumptions remain. The remaining
premises describe the accepted current relation, common public strategy, real
resource contract, and normalized state fixed before the oracle is sampled. -/
theorem two_witness_privacy
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    {requests : Nat} (left right : Schedule bound W requests)
    (same : SamePublicStrategy left right)
    (leftEligible : Eligible components nonlinearRoot nodeDegree left)
    (rightEligible : Eligible components nonlinearRoot nodeDegree right)
    (total : Nat)
    (leftBudget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests left) ≤ total)
    (rightBudget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests right) ≤ total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ)
    (normalized : ‖WithLp.toLp 2 registers‖ = 1) :
    |acceptance true (compiledHybrid requests left) (WithLp.toLp 2 registers) -
      acceptance true (compiledHybrid requests right) (WithLp.toLp 2 registers)| ≤
      24 * (total : ℝ)^2 / (2 : ℝ)^279 := by
  have exactBound := normalized_two_witness_bound components nonlinearRoot nodeDegree certificates
    Q38Rp05CanonicalAbortPadding.points Q38Rp05CanonicalAbortPadding.points_admissible
    Q38Rp05CanonicalAbortPadding.points_nonzero Q38Rp05CanonicalAbortPadding.targets
    left right same leftEligible rightEligible total
    (Q38Rp05PrefinalBudget.within_budget_of_all_real left total leftBudget)
    (Q38Rp05PrefinalBudget.within_budget_of_all_real right total rightBudget) registers normalized
  exact exactBound.trans (Q38Rp05PrivacyNumerics.effective_two_witness_spec_ledger total requests)

/-- Concrete current-RP05 form before normalization. It states the bound on
the actual zero-entry CMS run and retains its exact initial Born mass. -/
theorem current_rp05_initialized_two_witness_born_bound
    {requests : Nat} (left right : Schedule bound W requests)
    (same : SamePublicStrategy left right)
    (leftEligible : Eligible SmzaRp05Components.program
      SmzaRp05DegreeCertificateData.nonlinearRoot
      SmzaRp05DegreeCertificateData.nodeDegree left)
    (rightEligible : Eligible SmzaRp05Components.program
      SmzaRp05DegreeCertificateData.nonlinearRoot
      SmzaRp05DegreeCertificateData.nodeDegree right)
    (total : Nat)
    (leftBudget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests left) ≤ total)
    (rightBudget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests right) ≤ total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister)
      (Workspace := W) → ℂ) :
    |phaseRun true (compiledHybrid requests left) (initializedCms registers) -
      phaseRun true (compiledHybrid requests right) (initializedCms registers)| ≤
      2 * (Q38Rp05ReachableBudget.effectiveRequests requests total : ℝ) *
        loss total * normSquared (initializedCms registers) := by
  exact initialized_cms_two_witness_bound
    SmzaRp05Components.program
    SmzaRp05DegreeCertificateData.nonlinearRoot
    SmzaRp05DegreeCertificateData.nodeDegree
    SmzaRp05GeneratedCertificates.certificates
    Q38Rp05CanonicalAbortPadding.points
    Q38Rp05CanonicalAbortPadding.points_admissible
    Q38Rp05CanonicalAbortPadding.points_nonzero
    Q38Rp05CanonicalAbortPadding.targets
    left right same leftEligible rightEligible total
    (Q38Rp05PrefinalBudget.within_budget_of_all_real left total leftBudget)
    (Q38Rp05PrefinalBudget.within_budget_of_all_real right total rightBudget)
    registers

/-- Concrete current-RP05 two-witness endpoint on the actual initialized
CMS run. The generated relation certificates are instantiated from the
checked RP05 relation modules, rather than supplied as a caller assumption.
The only protocol-side premises are the common public strategy, eligibility
of both accepted witnesses, the actual request-count budgets, and a
normalized initial response-basis state. -/
theorem current_rp05_initialized_two_witness_privacy
    {requests : Nat} (left right : Schedule bound W requests)
    (same : SamePublicStrategy left right)
    (leftEligible : Eligible SmzaRp05Components.program
      SmzaRp05DegreeCertificateData.nonlinearRoot
      SmzaRp05DegreeCertificateData.nodeDegree left)
    (rightEligible : Eligible SmzaRp05Components.program
      SmzaRp05DegreeCertificateData.nonlinearRoot
      SmzaRp05DegreeCertificateData.nodeDegree right)
    (total : Nat)
    (leftBudget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests left) ≤ total)
    (rightBudget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests right) ≤ total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister)
      (Workspace := W) → ℂ)
    (normalized : ‖WithLp.toLp 2 registers‖ = 1) :
    |phaseRun true (compiledHybrid requests left) (initializedCms registers) -
      phaseRun true (compiledHybrid requests right) (initializedCms registers)| ≤
      24 * (total : ℝ)^2 / (2 : ℝ)^279 := by
  rw [initialized_phase_is_acceptance, initialized_phase_is_acceptance]
  exact two_witness_privacy
    SmzaRp05Components.program
    SmzaRp05DegreeCertificateData.nonlinearRoot
    SmzaRp05DegreeCertificateData.nodeDegree
    SmzaRp05GeneratedCertificates.certificates
    left right same leftEligible rightEligible total leftBudget rightBudget
    registers normalized

end Endpoint
end
end HegemonCrypto.SmallWood.Q38Rp05TwoWitnessEndpoint
