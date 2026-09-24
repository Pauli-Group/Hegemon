import HegemonCrypto.SmallWoodRom
import HegemonCrypto.SmallWoodProofWire
import HegemonCrypto.SmallWoodSmz8ProofWire
import HegemonCrypto.SecurityAuthority
import Hegemon.Transaction.Poseidon2V8ConstraintRefinement
import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import Mathlib.Data.Fintype.Card
import Mathlib.Tactic.Abel
import Mathlib.Tactic.NormNum

/-!
# SmallWood zero-knowledge and leakage boundary

This module separates four claims that must not be conflated:

* canonical field sampling for prover masks;
* information-theoretic masking of algebraic views;
* simulation of the complete SmallWood proof in the classical random-oracle model;
* the exact receipt boundary for an SMZ8 whole-view adaptive-QROM theorem; and
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

The final section does not promote that classical bound to the QROM.  It instead binds a
witness-free whole-view simulator to the exact SMZ8 decoder, a nonempty compiled-relation identity,
the 120-word semantic target, the seven binding limbs, and Rust/Lean verifier replay.  Its
adaptive-QROM theorem is conditional on separately supplied SHA-512 transcript, QROM
instantiation, whole-view hybrid, relation-refinement, and independent-review receipts.  No such
release receipt is constructed in this module.
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

section Smz8AdaptiveQromWholeView

/-!
The executable Rust harness records the canonical proof bytes, every lazily programmed Merkle
node, the programmed final PIOP input and output, the raw-witness consumption count, and the
concrete SHA-512 verifier result.  The structures below are the exact Lean-facing refinement and
probability boundary for that complete view.  They do not infer an adaptive-QROM theorem from the
classical-ROM arithmetic above.
-/

def smz8SemanticTargetId : String :=
  "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2"

def smz8PublicStatementWordCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.publicStatementWordCount
def smz8BindingLimbCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationBindingLimbCount
def smz8RelationRowCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationRowCount
def smz8ProofGeometryColumnCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.proofGeometryColumnCount
def smz8HashCallCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.liveHashCallCount
def smz8HashRowCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.hashRowCount
def smz8HashConstraintCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.hashConstraintCount
def smz8NonlinearIdentityCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.nonlinearIdentityCount
/-! These four counts belong to the historical HGV8RP02/SMZ8 rehearsal.  They
must not follow the active HGV8RP03 constants: the repair added one linear
identity and one family without changing the proof geometry. -/
def smz8MinimumStatementLinearConstraintCount : Nat := 19898
def smz8MaximumStatementLinearConstraintCount : Nat := 20472
def smz8EnginePiopGammaWidth : Nat := 20472
def smz8MaximumSummedIdentityUnionCount : Nat := 21302
def smz8TranscriptDigestBytes : Nat := 64
def smz8MaximumCompactAuthenticationNodes : Nat := 355
def smz8MaximumAuthenticationPathSectionBytes : Nat :=
  2 + SmallWoodSmz8ProofWire.openedLeafCount +
    smz8MaximumCompactAuthenticationNodes * smz8TranscriptDigestBytes
def smz8MaximumAuthenticationAndTapeBytes : Nat :=
  smz8MaximumAuthenticationPathSectionBytes +
    SmallWoodSmz8ProofWire.openedLeafTapesBytes
def smz8QuantumTargetBits : Nat := 128

def smz8AdaptiveQromTarget : ℚ :=
  (1 : ℚ) / ((2 ^ smz8QuantumTargetBits : Nat) : ℚ)

theorem smz8_whole_view_profile_is_exact :
    smz8PublicStatementWordCount = 120
      ∧ smz8BindingLimbCount = 7
      ∧ SmallWoodSmz8ProofWire.openedLeafCount = 19
      ∧ SmallWoodSmz8ProofWire.openedLeafTapeBytes = 64
      ∧ SmallWoodSmz8ProofWire.openedLeafTapesBytes = 1216
      ∧ SmallWoodSmz8ProofWire.maximumAuthPathDepth = 23
      ∧ smz8RelationRowCount = 686
      ∧ smz8ProofGeometryColumnCount = 368
      ∧ smz8HashCallCount = 125
      ∧ smz8HashRowCount = 364
      ∧ smz8HashConstraintCount = 332
      ∧ smz8NonlinearIdentityCount = 830
      ∧ smz8MinimumStatementLinearConstraintCount = 19898
      ∧ smz8MaximumStatementLinearConstraintCount = 20472
      ∧ smz8EnginePiopGammaWidth = 20472
      ∧ smz8MaximumSummedIdentityUnionCount = 21302
      ∧ smz8MaximumCompactAuthenticationNodes = 355
      ∧ smz8MaximumAuthenticationPathSectionBytes = 22741
      ∧ smz8MaximumAuthenticationAndTapeBytes = 23957
      ∧ SmallWoodSmz8ProofWire.maximumInnerProofBytes = 131072
      ∧ SmallWoodSmz8ProofWire.proofMagic = [83, 77, 90, 56] := by
  decide

/--
Exact compiled-relation-to-semantic-target receipt required by the SMZ8 theorem.  The relation id
is deliberately data, not a caller-selected profile tag.  The embedded V8 compiler receipt binds
the exact width-16 kernel, 120-word projection, program bytes, program SHA-512, and universal
compiled acceptance equivalence.  The executable compiler alone does not inhabit that receipt:
the checked-in artifact/refinement status remains unbound.
-/
structure CompiledSmz8RelationBinding (Statement Witness : Type*) where
  v8CompilerRefinement :
    Hegemon.Transaction.Poseidon2V8ConstraintRefinement.FullRelationCompilerRefinementReceipt
      Statement Witness
  relationId : List Byte
  relationIdExactLength : relationId.length = 48
  relationIdExact :
    relationId.map Fin.val = v8CompilerRefinement.programSha512.take 48
  semanticTargetId : String
  semanticTargetIdExact : semanticTargetId = smz8SemanticTargetId
  publicStatementWords : Statement → List CanonicalFieldWord
  publicStatementWordsExact :
    ∀ statement,
      (publicStatementWords statement).length = smz8PublicStatementWordCount
  bindingLimbs : Statement → List CanonicalFieldWord
  bindingLimbsExact :
    ∀ statement, (bindingLimbs statement).length = smz8BindingLimbCount
  v8PublicStatementProjectionExact :
    ∀ statement,
      v8CompilerRefinement.publicStatementWords statement =
        (publicStatementWords statement).map Fin.val
  v8BindingProjectionExact :
    ∀ statement,
      v8CompilerRefinement.bindingLimbs statement =
        (bindingLimbs statement).map Fin.val
  semanticTarget : Statement → Witness → Prop
  compiledAccepts : Statement → Witness → Bool
  v8SemanticTargetExact :
    ∀ statement witness,
      v8CompilerRefinement.semanticTarget statement witness ↔
        semanticTarget statement witness
  v8CompiledAcceptanceExact :
    ∀ statement witness,
      v8CompilerRefinement.compiledAccepts statement witness =
        compiledAccepts statement witness
  compiledAcceptsIffSemanticTarget :
    ∀ statement witness,
      compiledAccepts statement witness = true ↔
        semanticTarget statement witness

theorem compiled_smz8_relation_binding_is_unavailable_from_checked_in_v8_status
    (Statement Witness : Type*) :
    ¬ Nonempty (CompiledSmz8RelationBinding Statement Witness) := by
  intro evidence
  rcases evidence with ⟨relation⟩
  exact
    (Hegemon.Transaction.Poseidon2V8ConstraintRefinement.full_relation_compiler_receipt_is_unavailable_from_checked_in_status
        Statement Witness) ⟨relation.v8CompilerRefinement⟩

/-- One programmed sibling subtree in the Rust whole-view simulator trace. -/
structure Smz8ProgrammedMerkleNode where
  level : Nat
  nodeIndex : Nat
  digestBytes : List Byte
deriving DecidableEq, Repr

def Smz8ProgrammedMerkleNode.Canonical
    (node : Smz8ProgrammedMerkleNode) : Prop :=
  node.digestBytes.length = smz8TranscriptDigestBytes

/-- Lean model of every verifier-visible field recorded by the Rust whole-view harness. -/
structure Smz8WholeView (VerifierTrace : Type*) where
  proofBytes : List Byte
  verifierTrace : VerifierTrace
  programmedMerkleNodes : List Smz8ProgrammedMerkleNode
  programmedFinalPiopInputWords : List CanonicalFieldWord
  programmedFinalPiopOutputBytes : List Byte
  rawWitnessWordsConsumed : Nat
  concreteSha512Accepts : Bool
deriving DecidableEq, Repr

/-- Exact SMZ8 decoding, canonical encoding, digest widths, and witness-free execution. -/
def Smz8WholeView.Canonical
    {VerifierTrace : Type*} (view : Smz8WholeView VerifierTrace) : Prop :=
  (∃ proof : SmallWoodSmz8ProofWire.ProofWire,
      SmallWoodSmz8ProofWire.decodeProofExact view.proofBytes = some proof
        ∧ proof.encode = view.proofBytes)
    ∧ view.programmedMerkleNodes.Forall
        Smz8ProgrammedMerkleNode.Canonical
    ∧ view.programmedFinalPiopOutputBytes.length =
        smz8TranscriptDigestBytes
    ∧ view.rawWitnessWordsConsumed = 0

/-- Serialized authentication nodes carried by one decoded SMZ8 proof. -/
def smz8AuthenticationNodeCount
    (proof : SmallWoodSmz8ProofWire.ProofWire) : Nat :=
  proof.pcs.decs.authPaths.nodeCount

/--
Universal Rust/Lean refinement statement for the executable SMZ8 whole-view simulator.  The
simulator takes a statement and simulator coins but no witness.  The final two fields bind the
recorded oracle program and concrete acceptance result to an independently modeled verifier
replay; a finite conformance vector cannot replace these universal equalities.
-/
structure RustLeanSmz8WholeViewRefinement
    (Statement Witness SimulatorCoins VerifierTrace : Type*)
    (relation : CompiledSmz8RelationBinding Statement Witness) where
  simulator : Statement → SimulatorCoins → Smz8WholeView VerifierTrace
  leanVerifierAccepts :
    Statement → SmallWoodSmz8ProofWire.ProofWire → Bool
  rustVerifierAccepts : Statement → List Byte → Bool
  rebuildVerifierTrace : Statement → List Byte → VerifierTrace
  programmingMatchesVerifierReplay :
    Statement → Smz8WholeView VerifierTrace → Prop
  simulatorCanonical :
    ∀ statement coins, (simulator statement coins).Canonical
  rustLeanVerifierReplayExact :
    ∀ statement coins proof,
      SmallWoodSmz8ProofWire.decodeProofExact
          (simulator statement coins).proofBytes = some proof →
        rustVerifierAccepts statement
            (simulator statement coins).proofBytes =
          leanVerifierAccepts statement proof
  recordedVerifierTraceExact :
    ∀ statement coins,
      (simulator statement coins).verifierTrace =
        rebuildVerifierTrace statement
          (simulator statement coins).proofBytes
  recordedConcreteAcceptanceExact :
    ∀ statement coins,
      (simulator statement coins).concreteSha512Accepts =
        rustVerifierAccepts statement
          (simulator statement coins).proofBytes
  verifierAcceptanceEnforcesCompactAuthenticationBound :
    ∀ statement proof,
      leanVerifierAccepts statement proof = true →
        smz8AuthenticationNodeCount proof ≤
          smz8MaximumCompactAuthenticationNodes
  oracleProgrammingReplayExact :
    ∀ statement coins,
      programmingMatchesVerifierReplay statement
        (simulator statement coins)
  relatedStatementsUseExactCompiledTarget :
    ∀ statement witness,
      relation.semanticTarget statement witness →
        relation.compiledAccepts statement witness = true

/-- The two oracle models are distinct in the theorem type. -/
inductive WholeViewOracleModel where
  | classicalRom
  | adaptiveQrom
deriving DecidableEq, Repr

/--
Exact real/simulated whole-view experiment for one related SMZ8 statement.  Probability evaluation
is supplied by the selected formal QROM model; range proofs prevent an arbitrary signed quantity
from being relabeled as a probability.
-/
structure Smz8WholeViewExperiment
    (Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*)
    (relation : CompiledSmz8RelationBinding Statement Witness)
    (refinement :
      RustLeanSmz8WholeViewRefinement Statement Witness SimulatorCoins
        VerifierTrace relation) where
  statement : Statement
  witness : Witness
  relationHolds : relation.semanticTarget statement witness
  realAcceptanceProbability : Distinguisher → ℚ
  simulatedAcceptanceProbability : Distinguisher → ℚ
  realProbabilityInRange :
    ∀ distinguisher,
      0 ≤ realAcceptanceProbability distinguisher
        ∧ realAcceptanceProbability distinguisher ≤ 1
  simulatedProbabilityInRange :
    ∀ distinguisher,
      0 ≤ simulatedAcceptanceProbability distinguisher
        ∧ simulatedAcceptanceProbability distinguisher ≤ 1

/--
Adaptive-QROM reduction receipt for the entire verifier-visible view.  Field rejection, canonical
nonce/opening selection, DECS sampling, lazy Merkle programming, final PIOP programming, SHA-512
instantiation, and residual-view losses are explicit and nonnegative.  None can be silently
replaced by `activeClassicalRomSimulationLoss`.  The whole-view hybrid is indexed by the exact
compiler receipt's nonlinear-identity, maximum statement-specialized linear-constraint, and
maximum summed-identity-union counts.  The engine PIOP/gamma width is the maximum of the first two,
whereas union terms use their sum; the compact 368-column proof geometry cannot be substituted for
any of those inputs.
-/
structure Smz8AdaptiveQromWholeViewReduction
    {Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*}
    {relation : CompiledSmz8RelationBinding Statement Witness}
    {refinement :
      RustLeanSmz8WholeViewRefinement Statement Witness SimulatorCoins
        VerifierTrace relation}
    (experiment :
      Smz8WholeViewExperiment Statement Witness SimulatorCoins VerifierTrace
        Distinguisher relation refinement)
    (HonestAffineViewRefinement Sha512TranscriptRefinement
      Sha512QromInstantiation : Prop)
    (AdaptiveWholeViewHybrid : Nat → Nat → Nat → Prop) where
  oracleModel : WholeViewOracleModel
  oracleModelExact : oracleModel = .adaptiveQrom
  globalQuantumHashQueries : Nat
  globalPriorProofInteractions : Nat
  fieldSamplingAbortLoss : ℚ
  canonicalNonceAndOpeningAbortLoss : ℚ
  decsSamplingAbortLoss : ℚ
  adaptiveMerkleProgrammingLoss : ℚ
  adaptiveFinalPiopProgrammingLoss : ℚ
  sha512InstantiationLoss : ℚ
  residualWholeViewLoss : ℚ
  totalLoss : ℚ
  fieldSamplingAbortLossNonnegative : 0 ≤ fieldSamplingAbortLoss
  canonicalNonceAndOpeningAbortLossNonnegative :
    0 ≤ canonicalNonceAndOpeningAbortLoss
  decsSamplingAbortLossNonnegative : 0 ≤ decsSamplingAbortLoss
  adaptiveMerkleProgrammingLossNonnegative :
    0 ≤ adaptiveMerkleProgrammingLoss
  adaptiveFinalPiopProgrammingLossNonnegative :
    0 ≤ adaptiveFinalPiopProgrammingLoss
  sha512InstantiationLossNonnegative : 0 ≤ sha512InstantiationLoss
  residualWholeViewLossNonnegative : 0 ≤ residualWholeViewLoss
  totalLossExact :
    totalLoss =
      fieldSamplingAbortLoss + canonicalNonceAndOpeningAbortLoss +
        decsSamplingAbortLoss + adaptiveMerkleProgrammingLoss +
        adaptiveFinalPiopProgrammingLoss + sha512InstantiationLoss +
        residualWholeViewLoss
  honestAffineViewRefinement : HonestAffineViewRefinement
  sha512TranscriptRefinement : Sha512TranscriptRefinement
  sha512QromInstantiation : Sha512QromInstantiation
  adaptiveWholeViewHybrid :
    AdaptiveWholeViewHybrid
      relation.v8CompilerRefinement.exactNonlinearIdentityCount
      relation.v8CompilerRefinement.maximumStatementLinearConstraintCount
      relation.v8CompilerRefinement.maximumSummedIdentityUnionCount
  completeViewBound :
    ∀ distinguisher,
      |experiment.realAcceptanceProbability distinguisher -
          experiment.simulatedAcceptanceProbability distinguisher| ≤
        totalLoss

/--
Release receipt required in addition to executable refinement.  `IndependentReview` is a proof
parameter, so merely naming a JSON field does not inhabit it.
-/
structure Smz8AdaptiveQromWholeViewReleaseReceipt
    {Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*}
    {relation : CompiledSmz8RelationBinding Statement Witness}
    {refinement :
      RustLeanSmz8WholeViewRefinement Statement Witness SimulatorCoins
        VerifierTrace relation}
    (experiment :
      Smz8WholeViewExperiment Statement Witness SimulatorCoins VerifierTrace
        Distinguisher relation refinement)
    (HonestAffineViewRefinement Sha512TranscriptRefinement
      Sha512QromInstantiation : Prop)
    (AdaptiveWholeViewHybrid : Nat → Nat → Nat → Prop)
    (IndependentReview : Prop) where
  reduction :
    Smz8AdaptiveQromWholeViewReduction experiment
      HonestAffineViewRefinement Sha512TranscriptRefinement
      Sha512QromInstantiation AdaptiveWholeViewHybrid
  lossWithinTarget :
    reduction.totalLoss ≤ smz8AdaptiveQromTarget
  independentReview : IndependentReview

/--
Exact conditional adaptive-QROM whole-view theorem for SMZ8.  The conclusion is deliberately
tagged `conditionalSupply`; this theorem cannot construct deployed end-to-end authority.
-/
theorem smz8_adaptive_qrom_whole_view_indistinguishability_given_release_receipt
    {Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*}
    {relation : CompiledSmz8RelationBinding Statement Witness}
    {refinement :
      RustLeanSmz8WholeViewRefinement Statement Witness SimulatorCoins
        VerifierTrace relation}
    (experiment :
      Smz8WholeViewExperiment Statement Witness SimulatorCoins VerifierTrace
        Distinguisher relation refinement)
    {HonestAffineViewRefinement Sha512TranscriptRefinement
      Sha512QromInstantiation : Prop}
    {AdaptiveWholeViewHybrid : Nat → Nat → Nat → Prop}
    {IndependentReview : Prop}
    (receipt :
      Smz8AdaptiveQromWholeViewReleaseReceipt experiment
        HonestAffineViewRefinement Sha512TranscriptRefinement
        Sha512QromInstantiation AdaptiveWholeViewHybrid
        IndependentReview) :
    SecurityAuthority.ScopedSecurityClaim .conditionalSupply
      (∀ distinguisher,
        |experiment.realAcceptanceProbability distinguisher -
            experiment.simulatedAcceptanceProbability distinguisher| ≤
          smz8AdaptiveQromTarget) := by
  apply SecurityAuthority.ScopedSecurityClaim.ofConditionalSupply
  intro distinguisher
  exact (receipt.reduction.completeViewBound distinguisher).trans
    receipt.lossWithinTarget

end Smz8AdaptiveQromWholeView

end HegemonCrypto.SmallWood.ZeroKnowledge
