import HegemonCrypto.SmallWoodRom
import HegemonCrypto.SmallWoodProofWire
import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import Mathlib.Data.Fintype.Card
import Mathlib.Tactic.Abel
import Mathlib.Tactic.NormNum

/-!
# SmallWood zero-knowledge and leakage boundary

This module separates four claims that must not be conflated:

* canonical field sampling for prover masks;
* information-theoretic masking of algebraic views;
* simulation of the complete SmallWood proof in the classical random-oracle model; and
* network-level unlinkability.

The deployed prover previously mapped one uniform 64-bit word to Goldilocks by one conditional
subtraction.  Since `2^64 = p + (2^32 - 1)`, every residue below `2^32 - 1` had two source words
while the remaining residues had one.  The checked source classification below records that defect.
The repaired rejection sampler accepts exactly the words below `p`; its acceptance space is
explicitly equivalent to `Fin p`.

Uniform additive masks perfectly hide an unconstrained field view.  Uniform zero-sum masks
perfectly hide a vector within its public-sum affine space.  Both statements are proved by explicit
random-coin equivalences, which provide exact couplings rather than an informal entropy claim.

These algebraic results do not prove complete SmallWood zero knowledge.  The published simulator
also requires DECS hiding and random-oracle programming.  Its exact classical-ROM failure bound is
mechanized here and already misses a 128-bit floor at one simulated proof and one oracle query.
-/

namespace HegemonCrypto.SmallWood.ZeroKnowledge

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open HegemonCrypto.SmallWoodProofWire
open HegemonCrypto.CanonicalBytes
open scoped BigOperators

def machineWordCardinality : Nat := 2 ^ 64

def wrappedWordCount : Nat := 2 ^ 32 - 1

theorem machine_word_cardinality_decomposition :
    machineWordCardinality = goldilocksModulus + wrappedWordCount := by
  decide

theorem goldilocks_modulus_lt_machine_word_cardinality :
    goldilocksModulus < machineWordCardinality := by
  decide

theorem wrapped_word_count_lt_goldilocks_modulus :
    wrappedWordCount < goldilocksModulus := by
  decide

/-- The pre-repair runtime map from one machine word to a canonical Goldilocks residue. -/
def singleSubtractionResidue (word : Nat) : Nat :=
  if word < goldilocksModulus then word else word - goldilocksModulus

theorem single_subtraction_low_source
    {residue : Nat}
    (residueBound : residue < goldilocksModulus) :
    singleSubtractionResidue residue = residue := by
  simp [singleSubtractionResidue, residueBound]

theorem single_subtraction_wrapped_source
    {residue : Nat} :
    singleSubtractionResidue (goldilocksModulus + residue) = residue := by
  have modulusBound : ¬goldilocksModulus + residue < goldilocksModulus := by omega
  simp [singleSubtractionResidue, modulusBound]

/-- Every low residue had two distinct in-range source words. -/
theorem low_residue_has_two_distinct_machine_word_sources
    {residue : Nat}
    (residueBound : residue < wrappedWordCount) :
    residue < machineWordCardinality
      ∧ goldilocksModulus + residue < machineWordCardinality
      ∧ residue ≠ goldilocksModulus + residue
      ∧ singleSubtractionResidue residue = residue
      ∧ singleSubtractionResidue (goldilocksModulus + residue) = residue := by
  have residueFieldBound : residue < goldilocksModulus := by
    exact residueBound.trans wrapped_word_count_lt_goldilocks_modulus
  constructor
  · exact residueFieldBound.trans goldilocks_modulus_lt_machine_word_cardinality
  constructor
  · rw [machine_word_cardinality_decomposition]
    exact Nat.add_lt_add_left residueBound goldilocksModulus
  constructor
  · have modulusPositive : 0 < goldilocksModulus := by decide
    omega
  exact ⟨single_subtraction_low_source residueFieldBound,
    single_subtraction_wrapped_source⟩

/-- Every in-range source of a canonical residue is either its direct or wrapped source. -/
theorem single_subtraction_source_classification
    {word residue : Nat}
    (mapsTo : singleSubtractionResidue word = residue) :
    word = residue ∨ word = goldilocksModulus + residue := by
  by_cases low : word < goldilocksModulus
  · left
    simpa [singleSubtractionResidue, low] using mapsTo
  · right
    simp only [singleSubtractionResidue, if_neg low] at mapsTo
    omega

/-- High residues had no in-range wrapped source, hence only one source word. -/
theorem high_residue_has_only_direct_machine_word_source
    {word residue : Nat}
    (wordBound : word < machineWordCardinality)
    (residueLowerBound : wrappedWordCount ≤ residue)
    (mapsTo : singleSubtractionResidue word = residue) :
    word = residue := by
  rcases single_subtraction_source_classification mapsTo with
    direct | wrapped
  · exact direct
  · rw [wrapped] at wordBound
    rw [machine_word_cardinality_decomposition] at wordBound
    omega

abbrev MachineWord := Fin machineWordCardinality
abbrev CanonicalFieldWord := Fin goldilocksModulus

/-- Words accepted by canonical rejection sampling. -/
abbrev AcceptedMachineWord := { word : MachineWord // word.val < goldilocksModulus }

/-- Accepted 64-bit words and canonical Goldilocks representatives are exactly the same finite set. -/
def acceptedMachineWordEquiv : AcceptedMachineWord ≃ CanonicalFieldWord where
  toFun word := ⟨word.val.val, word.property⟩
  invFun residue :=
    ⟨⟨residue.val,
      residue.isLt.trans goldilocks_modulus_lt_machine_word_cardinality⟩,
      residue.isLt⟩
  left_inv word := by
    apply Subtype.ext
    apply Fin.ext
    rfl
  right_inv residue := by
    apply Fin.ext
    rfl

theorem accepted_machine_word_count_is_exactly_field_order :
    Fintype.card AcceptedMachineWord = goldilocksModulus := by
  rw [Fintype.card_congr acceptedMachineWordEquiv]
  simp

section AdditiveMasking

variable {F : Type*} [AddCommGroup F]

def realMaskedView (secret mask : F) : F := secret + mask

def simulatedMaskedView (simulatorCoins : F) : F := simulatorCoins

/-- Translation by a secret is a permutation of the entire mask space. -/
def additiveMaskCoinsEquiv (secret : F) : F ≃ F where
  toFun mask := secret + mask
  invFun view := view - secret
  left_inv mask := by simp
  right_inv view := by simp

/-- Explicit perfect-simulation coupling for one uniformly masked field value. -/
theorem additive_masking_has_perfect_simulation_coupling
    (secret mask : F) :
    simulatedMaskedView (additiveMaskCoinsEquiv secret mask) =
      realMaskedView secret mask := by
  rfl

/-- Random coins can be transported between any two secrets without changing the masked view. -/
def additiveMaskTransport (leftSecret rightSecret : F) : F ≃ F where
  toFun mask := leftSecret + mask - rightSecret
  invFun mask := rightSecret + mask - leftSecret
  left_inv mask := by
    simp only [sub_eq_add_neg]
    abel
  right_inv mask := by
    simp only [sub_eq_add_neg]
    abel

theorem additive_masked_views_are_exactly_coupled
    (leftSecret rightSecret mask : F) :
    realMaskedView rightSecret (additiveMaskTransport leftSecret rightSecret mask) =
      realMaskedView leftSecret mask := by
  change rightSecret + (leftSecret + mask - rightSecret) = leftSecret + mask
  abel

end AdditiveMasking

section ZeroSumMasking

variable {F Index : Type*}
variable [AddCommGroup F] [Fintype Index]

def vectorSum (values : Index → F) : F := ∑ index, values index

abbrev ZeroSumMask := { mask : Index → F // vectorSum mask = 0 }

def maskedVectorView (secret : Index → F) (mask : ZeroSumMask (F := F) (Index := Index)) :
    Index → F :=
  fun index => secret index + mask.val index

/-- Translate zero-sum mask coins between two secrets with the same public sum. -/
def zeroSumMaskTransport
    (leftSecret rightSecret : Index → F)
    (samePublicSum : vectorSum leftSecret = vectorSum rightSecret) :
    ZeroSumMask (F := F) (Index := Index) ≃
      ZeroSumMask (F := F) (Index := Index) where
  toFun mask :=
    ⟨fun index => leftSecret index + mask.val index - rightSecret index, by
      unfold vectorSum
      rw [Finset.sum_sub_distrib, Finset.sum_add_distrib]
      change vectorSum leftSecret + vectorSum mask.val - vectorSum rightSecret = 0
      rw [mask.property, add_zero, samePublicSum, sub_self]⟩
  invFun mask :=
    ⟨fun index => rightSecret index + mask.val index - leftSecret index, by
      unfold vectorSum
      rw [Finset.sum_sub_distrib, Finset.sum_add_distrib]
      change vectorSum rightSecret + vectorSum mask.val - vectorSum leftSecret = 0
      rw [mask.property, add_zero, samePublicSum, sub_self]⟩
  left_inv mask := by
    apply Subtype.ext
    funext index
    simp only [sub_eq_add_neg]
    abel
  right_inv mask := by
    apply Subtype.ext
    funext index
    simp only [sub_eq_add_neg]
    abel

/-- A zero-sum uniform mask perfectly hides every vector except its public sum. -/
theorem zero_sum_masked_views_are_exactly_coupled
    (leftSecret rightSecret : Index → F)
    (samePublicSum : vectorSum leftSecret = vectorSum rightSecret)
    (mask : ZeroSumMask (F := F) (Index := Index)) :
    maskedVectorView rightSecret
        (zeroSumMaskTransport leftSecret rightSecret samePublicSum mask) =
      maskedVectorView leftSecret mask := by
  funext index
  change
    rightSecret index + (leftSecret index + mask.val index - rightSecret index) =
      leftSecret index + mask.val index
  abel

end ZeroSumMasking

/-- Public proof-shape leakage carried by the canonical SmallWood grammar. -/
structure ProofShape where
  encodedLength : Nat
  matrixDimensions : List (Nat × Nat)
  authenticationPathLengths : List Nat
  openedWitnessMode : Nat
  auxiliaryWordCount : Nat
  auxiliaryLimbCount : Nat
deriving DecidableEq, Repr

def matrixDimensions (matrix : MatrixWire) : Nat × Nat :=
  (matrix.rowCount, matrix.columnCount)

def proofShape (proof : ProofWire) : ProofShape :=
  let opened := match proof.openedWitness with
    | .none => (0, 0, 0, none)
    | .rowScalars matrix wordCountBytes limbCountBytes _ =>
        (1, decodeLE wordCountBytes, decodeLE limbCountBytes, some matrix)
  { encodedLength := proof.encode.length
    matrixDimensions :=
      [ matrixDimensions proof.piop.polynomialHighs,
        matrixDimensions proof.piop.linearHighs,
        matrixDimensions proof.pcs.randomCombinationTails,
        matrixDimensions proof.pcs.subsetEvaluations,
        matrixDimensions proof.pcs.partialEvaluations,
        matrixDimensions proof.pcs.decs.maskingEvaluations,
        matrixDimensions proof.pcs.decs.highCoefficients ] ++
        match opened.2.2.2 with
        | none => []
        | some matrix => [matrixDimensions matrix]
    authenticationPathLengths := proof.pcs.decs.authPaths.pathLengthBytes.map Fin.val
    openedWitnessMode := opened.1
    auxiliaryWordCount := opened.2.1
    auxiliaryLimbCount := opened.2.2.1 }

/-- The proof-system view excludes peer identity and timing; those require separate privacy models. -/
structure NetworkObservation where
  proof : ProofWire
  remotePeerTag : Nat
  receivedAtMillis : Nat
deriving DecidableEq, Repr

def proofSystemProjection (observation : NetworkObservation) : ProofWire := observation.proof

def allowedProofLeakage (observation : NetworkObservation) : ProofShape :=
  proofShape observation.proof

/-- Identical proof transcripts and leakage can coexist with distinguishable network observations. -/
theorem proof_zero_knowledge_cannot_by_itself_establish_network_unlinkability
    (proof : ProofWire) :
    ∃ left right : NetworkObservation,
      proofSystemProjection left = proofSystemProjection right
        ∧ allowedProofLeakage left = allowedProofLeakage right
        ∧ left ≠ right := by
  refine ⟨{ proof, remotePeerTag := 0, receivedAtMillis := 0 },
    { proof, remotePeerTag := 1, receivedAtMillis := 0 }, rfl, rfl, ?_⟩
  intro equal
  have peerEqual := congrArg NetworkObservation.remotePeerTag equal
  simp at peerEqual

section ClassicalRomSimulationLoss

def activeSecurityBits : Nat := 128
def activeSaltBits : Nat := 2 * activeSecurityBits

inductive SimulatorFailure where
  | saltCollision
  | decsHiding
  | fiatShamirProgramming
deriving DecidableEq, Repr

def allSimulatorFailures : List SimulatorFailure :=
  [.saltCollision, .decsHiding, .fiatShamirProgramming]

theorem active_salt_bits_are_256 : activeSaltBits = 256 := by
  rfl

theorem simulator_failure_inventory_is_complete : allSimulatorFailures.length = 3 := by
  rfl

/-- Published classical-ROM SmallWood simulation failure bound at `lambda = 128`. -/
def activeClassicalRomSimulationLoss (proofs hashQueries : Nat) : ℚ :=
  ((proofs ^ 2 : Nat) : ℚ) / ((2 ^ activeSaltBits : Nat) : ℚ)
    + (hashQueries : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ)
    + ((proofs * hashQueries : Nat) : ℚ) / ((2 ^ activeSaltBits : Nat) : ℚ)

def supportsActiveClassicalRomZkBits (bits proofs hashQueries : Nat) : Prop :=
  activeClassicalRomSimulationLoss proofs hashQueries ≤
    (1 : ℚ) / ((2 ^ bits : Nat) : ℚ)

theorem one_proof_one_query_supports_127_zk_bits :
    supportsActiveClassicalRomZkBits 127 1 1 := by
  norm_num [supportsActiveClassicalRomZkBits, activeClassicalRomSimulationLoss,
    activeSaltBits, activeSecurityBits]

theorem one_proof_one_query_does_not_support_128_zk_bits :
    ¬supportsActiveClassicalRomZkBits 128 1 1 := by
  norm_num [supportsActiveClassicalRomZkBits, activeClassicalRomSimulationLoss,
    activeSaltBits, activeSecurityBits]

/-- Any positive proof and hash-query budget misses 128 bits through the published simulation bound. -/
theorem positive_proof_and_query_budgets_do_not_support_128_zk_bits
    {proofs hashQueries : Nat}
    (positiveProofs : 1 ≤ proofs)
    (positiveHashQueries : 1 ≤ hashQueries) :
    ¬supportsActiveClassicalRomZkBits 128 proofs hashQueries := by
  intro claimed
  unfold supportsActiveClassicalRomZkBits activeClassicalRomSimulationLoss at claimed
  have hashTermAtLeast :
      (1 : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ) ≤
        (hashQueries : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ) := by
    gcongr
    exact_mod_cast positiveHashQueries
  have saltTermPositive :
      (0 : ℚ) < ((proofs ^ 2 : Nat) : ℚ) / ((2 ^ activeSaltBits : Nat) : ℚ) := by
    apply div_pos
    · exact_mod_cast (pow_pos (Nat.zero_lt_of_lt positiveProofs) 2)
    · positivity
  have strictLower :
      (1 : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ) <
        ((proofs ^ 2 : Nat) : ℚ) / ((2 ^ activeSaltBits : Nat) : ℚ)
          + (hashQueries : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ)
          + ((proofs * hashQueries : Nat) : ℚ) /
              ((2 ^ activeSaltBits : Nat) : ℚ) := by
    calc
      (1 : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ) ≤
          (hashQueries : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ) :=
        hashTermAtLeast
      _ < ((proofs ^ 2 : Nat) : ℚ) / ((2 ^ activeSaltBits : Nat) : ℚ)
            + (hashQueries : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ) := by linarith
      _ ≤ ((proofs ^ 2 : Nat) : ℚ) / ((2 ^ activeSaltBits : Nat) : ℚ)
            + (hashQueries : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ)
            + ((proofs * hashQueries : Nat) : ℚ) /
                ((2 ^ activeSaltBits : Nat) : ℚ) := by
        apply le_add_of_nonneg_right
        apply div_nonneg
        · exact_mod_cast Nat.zero_le (proofs * hashQueries)
        · positivity
  have targetMatches :
      (1 : ℚ) / ((2 ^ activeSecurityBits : Nat) : ℚ) =
        (1 : ℚ) / ((2 ^ 128 : Nat) : ℚ) := by rfl
  rw [targetMatches] at strictLower
  exact (not_lt_of_ge claimed) strictLower

end ClassicalRomSimulationLoss

end HegemonCrypto.SmallWood.ZeroKnowledge
