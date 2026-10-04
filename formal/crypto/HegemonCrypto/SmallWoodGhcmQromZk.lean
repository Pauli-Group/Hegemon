import Mathlib.Tactic.NormNum

set_option maxRecDepth 100000
set_option exponentiation.threshold 1024

/-!
# SmallWood direct-GHCM QROM-ZK arithmetic and obligation boundary

This module mechanizes only exact dyadic arithmetic for the proposed
heterogeneous GHCM21 adaptive-reprogramming route. It does not formalize or
instantiate GHCM21 Proposition 2. Every theorem, simulator, entropy,
soundness, concrete-hash, and implementation premise needed to turn the
arithmetic into a production claim remains an explicitly missing external
obligation below.
-/

namespace HegemonCrypto.SmallWood.GhcmQromZk

/-! ## Fixed dyadic parameters -/

def decsDomainSize : Nat := 2 ^ 20
def leafReprogramPoints : Nat := 2 * decsDomainSize
def chainReprogramPoints : Nat := 8
def totalReprogramPointCap : Nat :=
  leafReprogramPoints + chainReprogramPoints

def quantumQueryBits : Nat := 64
def historyProofBits : Nat := 64
def quantumQueryCap : Nat := 2 ^ quantumQueryBits
def historyProofCap : Nat := 2 ^ historyProofBits

def leafConditionalEntropyBits : Nat := 576
def chainConditionalEntropyBits : Nat := 512
def currentFirstProgramEntropyBits : Nat := 256
def strictTargetBits : Nat := 128

theorem fixed_program_counts :
    leafReprogramPoints = 2 * 2 ^ 20 ∧
      chainReprogramPoints = 8 ∧
      totalReprogramPointCap = 2 * 2 ^ 20 + 8 := by
  norm_num [leafReprogramPoints, chainReprogramPoints,
    totalReprogramPointCap, decsDomainSize]

theorem total_program_count_factorization :
    totalReprogramPointCap = 2 ^ 3 * 262145 := by
  norm_num [totalReprogramPointCap, leafReprogramPoints,
    chainReprogramPoints, decsDomainSize]

theorem fixed_query_and_history_caps :
    quantumQueryCap = 2 ^ 64 ∧ historyProofCap = 2 ^ 64 := by
  exact ⟨rfl, rfl⟩

/-!
`DyadicAdvantage n e` denotes the exact rational `n / 2^e`. Keeping the
admission comparison in integer form avoids floating-point or logarithmic
rounding in the strict-security decision.
-/
structure DyadicAdvantage where
  numerator : Nat
  denominatorExponent : Nat
deriving DecidableEq, Repr

/--
Exact dyadic specialization of `(3*R/2)*sqrt(q_H*2^-h)*U` when
`R = oddReprogramFactor * 2^reprogramFactorBits`, `q_H=2^queryBits`, and
`U=2^proofHistoryBits`. The well-formedness predicate below prevents every
subtraction and halving ambiguity. Applicability of GHCM21 is external.
-/
def ghcmFactoredDyadicHistoryTerm
    (oddReprogramFactor reprogramFactorBits queryBits
      conditionalEntropyBits proofHistoryBits : Nat) : DyadicAdvantage :=
  { numerator := 3 * oddReprogramFactor
    denominatorExponent :=
      1 + (conditionalEntropyBits - queryBits) / 2 -
        reprogramFactorBits - proofHistoryBits }

def FactoredDyadicParametersWellFormed
    (oddReprogramFactor reprogramFactorBits queryBits
      conditionalEntropyBits proofHistoryBits : Nat) : Prop :=
  0 < oddReprogramFactor ∧
    oddReprogramFactor % 2 = 1 ∧
    queryBits < conditionalEntropyBits ∧
    (conditionalEntropyBits - queryBits) % 2 = 0 ∧
    reprogramFactorBits + proofHistoryBits <
      1 + (conditionalEntropyBits - queryBits) / 2

def leafHistoryLoss : DyadicAdvantage :=
  ghcmFactoredDyadicHistoryTerm 1 21 quantumQueryBits
    leafConditionalEntropyBits historyProofBits

def chainHistoryLoss : DyadicAdvantage :=
  ghcmFactoredDyadicHistoryTerm 1 3 quantumQueryBits
    chainConditionalEntropyBits historyProofBits

def currentFirstProgramLoss : DyadicAdvantage :=
  ghcmFactoredDyadicHistoryTerm 1 0 quantumQueryBits
    currentFirstProgramEntropyBits 0

def currentFirstProgramHistoryLoss : DyadicAdvantage :=
  ghcmFactoredDyadicHistoryTerm 1 0 quantumQueryBits
    currentFirstProgramEntropyBits historyProofBits

/-- Counterfactual sensitivity: every one of `2*N+8` programs has 576 bits. -/
def homogeneous576HistorySensitivity : DyadicAdvantage :=
  ghcmFactoredDyadicHistoryTerm 262145 3 quantumQueryBits
    leafConditionalEntropyBits historyProofBits

/-- The homogeneous screen is retained for comparison and can never authorize this route. -/
def Homogeneous576SensitivityHasAuthority : Prop := False

theorem homogeneous_576_sensitivity_has_no_authority :
    ¬ Homogeneous576SensitivityHasAuthority := by
  intro impossible
  exact impossible

theorem fixed_factored_parameters_well_formed :
    FactoredDyadicParametersWellFormed 1 21 quantumQueryBits
        leafConditionalEntropyBits historyProofBits ∧
      FactoredDyadicParametersWellFormed 1 3 quantumQueryBits
        chainConditionalEntropyBits historyProofBits ∧
      FactoredDyadicParametersWellFormed 1 0 quantumQueryBits
        currentFirstProgramEntropyBits 0 ∧
      FactoredDyadicParametersWellFormed 1 0 quantumQueryBits
        currentFirstProgramEntropyBits historyProofBits ∧
      FactoredDyadicParametersWellFormed 262145 3 quantumQueryBits
        leafConditionalEntropyBits historyProofBits := by
  norm_num [FactoredDyadicParametersWellFormed, quantumQueryBits,
    leafConditionalEntropyBits, chainConditionalEntropyBits,
    currentFirstProgramEntropyBits, historyProofBits]

theorem leaf_history_loss_exact :
    leafHistoryLoss = ⟨3, 172⟩ := by
  norm_num [leafHistoryLoss, ghcmFactoredDyadicHistoryTerm, quantumQueryBits,
    leafConditionalEntropyBits, historyProofBits]

theorem chain_history_loss_exact :
    chainHistoryLoss = ⟨3, 158⟩ := by
  norm_num [chainHistoryLoss, ghcmFactoredDyadicHistoryTerm, quantumQueryBits,
    chainConditionalEntropyBits, historyProofBits]

theorem current_first_program_loss_exact :
    currentFirstProgramLoss = ⟨3, 97⟩ := by
  norm_num [currentFirstProgramLoss, ghcmFactoredDyadicHistoryTerm,
    quantumQueryBits, currentFirstProgramEntropyBits]

theorem current_first_program_history_loss_exact :
    currentFirstProgramHistoryLoss = ⟨3, 33⟩ := by
  norm_num [currentFirstProgramHistoryLoss, ghcmFactoredDyadicHistoryTerm,
    quantumQueryBits, currentFirstProgramEntropyBits, historyProofBits]

theorem homogeneous_576_history_sensitivity_exact :
    homogeneous576HistorySensitivity = ⟨786435, 190⟩ := by
  norm_num [homogeneous576HistorySensitivity, ghcmFactoredDyadicHistoryTerm,
    quantumQueryBits, leafConditionalEntropyBits, historyProofBits]

/-- Add exact dyadics by aligning both numerators to the larger exponent. -/
def addDyadic (left right : DyadicAdvantage) : DyadicAdvantage :=
  if left.denominatorExponent < right.denominatorExponent then
    { numerator :=
        left.numerator * 2 ^
            (right.denominatorExponent - left.denominatorExponent) +
          right.numerator
      denominatorExponent := right.denominatorExponent }
  else
    { numerator :=
        left.numerator + right.numerator * 2 ^
          (left.denominatorExponent - right.denominatorExponent)
      denominatorExponent := left.denominatorExponent }

def heterogeneousHistoryLoss : DyadicAdvantage :=
  addDyadic leafHistoryLoss chainHistoryLoss

theorem heterogeneous_history_loss_exact :
    heterogeneousHistoryLoss = ⟨49155, 172⟩ := by
  norm_num [heterogeneousHistoryLoss, addDyadic, leafHistoryLoss,
    chainHistoryLoss, ghcmFactoredDyadicHistoryTerm, quantumQueryBits,
    leafConditionalEntropyBits, chainConditionalEntropyBits, historyProofBits]

/-- Exact predicate for `advantage < 2^-bits`. -/
def StrictlyBelowBits (advantage : DyadicAdvantage) (bits : Nat) : Prop :=
  advantage.numerator * 2 ^ bits < 2 ^ advantage.denominatorExponent

/-- Exact predicate for `2^-bits < advantage`. -/
def StrictlyAboveBits (advantage : DyadicAdvantage) (bits : Nat) : Prop :=
  2 ^ advantage.denominatorExponent < advantage.numerator * 2 ^ bits

theorem heterogeneous_history_loss_strictly_below_target :
    StrictlyBelowBits heterogeneousHistoryLoss strictTargetBits := by
  norm_num [StrictlyBelowBits, strictTargetBits, heterogeneousHistoryLoss,
    addDyadic, leafHistoryLoss, chainHistoryLoss,
    ghcmFactoredDyadicHistoryTerm, quantumQueryBits,
    leafConditionalEntropyBits, chainConditionalEntropyBits, historyProofBits]

/-- The live heterogeneous loss is strictly between `2^-157` and `2^-156`. -/
theorem heterogeneous_history_loss_exact_security_bracket :
    StrictlyAboveBits heterogeneousHistoryLoss 157 ∧
      StrictlyBelowBits heterogeneousHistoryLoss 156 := by
  norm_num [StrictlyAboveBits, StrictlyBelowBits, heterogeneousHistoryLoss,
    addDyadic, leafHistoryLoss, chainHistoryLoss,
    ghcmFactoredDyadicHistoryTerm, quantumQueryBits,
    leafConditionalEntropyBits, chainConditionalEntropyBits, historyProofBits]

theorem current_first_program_fails_strict_target :
    ¬ StrictlyBelowBits currentFirstProgramLoss strictTargetBits := by
  norm_num [StrictlyBelowBits, strictTargetBits, currentFirstProgramLoss,
    ghcmFactoredDyadicHistoryTerm, quantumQueryBits,
    currentFirstProgramEntropyBits]

structure ArithmeticCertificate : Prop where
  leafExact : leafHistoryLoss = ⟨3, 172⟩
  chainExact : chainHistoryLoss = ⟨3, 158⟩
  heterogeneousExact : heterogeneousHistoryLoss = ⟨49155, 172⟩
  heterogeneousStrict :
    StrictlyBelowBits heterogeneousHistoryLoss strictTargetBits
  currentFirstProgramExact : currentFirstProgramLoss = ⟨3, 97⟩
  currentFirstProgramFails :
    ¬ StrictlyBelowBits currentFirstProgramLoss strictTargetBits

theorem checkedArithmetic : ArithmeticCertificate :=
  { leafExact := leaf_history_loss_exact
    chainExact := chain_history_loss_exact
    heterogeneousExact := heterogeneous_history_loss_exact
    heterogeneousStrict := heterogeneous_history_loss_strictly_below_target
    currentFirstProgramExact := current_first_program_loss_exact
    currentFirstProgramFails := current_first_program_fails_strict_target }

/-! ## Explicit, atomic, undischarged external obligations -/

inductive ExternalObligation where
  | ghcmProposition2Applicability
  | adaptiveProgrammingTiming
  | wholeViewHybridBound
  | leafTapeConditionalIndependence
  | conditionalEntropyAtEveryProgram
  | chainFreshnessAfterSaltReveal
  | injectiveDomainEncoding
  | rngFailureAccounting
  | abortRetryGrindingAccounting
  | fullViewSimulatorAndNizkCompletion
  | pcsBindingProximityAndHiding
  | iopSoundness
  | completeHvzk
  | cmsBcsTransformRefinement
  | cmsRbrSoundnessAndKnowledge
  | cmsQueryExpansionConstants
  | sha512QroInstantiation
  | shake256QroInstantiation
  | globalHistoryCapConsensusEnforcement
  | compiledRelationRefinement
  | parserWireRefinement
  | verifierConsensusRefinement
  | lifecycleRestartReorgRefinement
  | releaseArtifactClosure
  | independentCryptographicReview
deriving DecidableEq, Repr

def allExternalObligations : List ExternalObligation :=
  [ .ghcmProposition2Applicability,
    .adaptiveProgrammingTiming,
    .wholeViewHybridBound,
    .leafTapeConditionalIndependence,
    .conditionalEntropyAtEveryProgram,
    .chainFreshnessAfterSaltReveal,
    .injectiveDomainEncoding,
    .rngFailureAccounting,
    .abortRetryGrindingAccounting,
    .fullViewSimulatorAndNizkCompletion,
    .pcsBindingProximityAndHiding,
    .iopSoundness,
    .completeHvzk,
    .cmsBcsTransformRefinement,
    .cmsRbrSoundnessAndKnowledge,
    .cmsQueryExpansionConstants,
    .sha512QroInstantiation,
    .shake256QroInstantiation,
    .globalHistoryCapConsensusEnforcement,
    .compiledRelationRefinement,
    .parserWireRefinement,
    .verifierConsensusRefinement,
    .lifecycleRestartReorgRefinement,
    .releaseArtifactClosure,
    .independentCryptographicReview ]

theorem external_obligation_report_exhaustive
    (obligation : ExternalObligation) :
    obligation ∈ allExternalObligations := by
  cases obligation <;> norm_num [allExternalObligations]

theorem external_obligation_report_duplicate_free :
    allExternalObligations.Nodup := by
  unfold allExternalObligations
  decide

/-!
This constructor-free indexed proposition is the evidence-bearing interface.
There is currently no inhabitant for any obligation: no Boolean or enum tag can
be relabeled as a discharge. A future source change must replace this boundary
with theorem-backed evidence for every constructor.
-/
inductive ExternalObligationEvidence : ExternalObligation → Prop

structure CompleteExternalEvidence : Type where
  evidence : ∀ obligation, ExternalObligationEvidence obligation

structure EvidenceRecord where
  arithmetic : ArithmeticCertificate
  external : Option CompleteExternalEvidence

def incompleteEvidence : EvidenceRecord :=
  { arithmetic := checkedArithmetic
    external := none }

/-- This is a fail-closed gate, not a deployed security-authority constructor. -/
def ProductionPrerequisites (evidence : EvidenceRecord) : Prop :=
  ∃ externalEvidence : CompleteExternalEvidence,
    evidence.external = some externalEvidence

theorem no_external_obligation_is_currently_discharged
    (obligation : ExternalObligation) :
    ¬ ExternalObligationEvidence obligation := by
  intro impossible
  cases impossible

theorem production_cannot_be_derived_from_incomplete_evidence :
    ¬ ProductionPrerequisites incompleteEvidence := by
  intro prerequisites
  obtain ⟨externalEvidence, retained⟩ := prerequisites
  simp [incompleteEvidence] at retained

end HegemonCrypto.SmallWood.GhcmQromZk
