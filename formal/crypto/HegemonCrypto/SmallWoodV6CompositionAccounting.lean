import Init.Data.Rat

/-!
# SmallWood V6 composition-accounting identities

This isolated core-only module proves finite bookkeeping and rejection
identities used by the V6 PQ/QROM certificate. It constructs no production
security authority, deployed-hash reduction, extractor, or zero-knowledge
simulator.

The currently encoded `HGF6HR02` relation has 79 hash invocations and 145
Keccak-f[1600] permutations. Its algorithm tag 2 is a nonstandard rate-72,
capacity-1024 XOF, not FIPS SHAKE. The numerical screens below therefore record
only a rejected candidate boundary.
-/

namespace HegemonCrypto.SmallWood.V6CompositionAccounting

def statementBytes : Nat := 893
def publicFieldCount : Nat := 128
def statementLimbBytes : Nat := 7
def statementPaddingZeroBytes : Nat := 3
def consensusBindingBytes : Nat := 56
def circuitVersion : Nat := 6
def cryptoSuite : Nat := 5
def proofProfile : Nat := 3
def domainSet : Nat := 2

theorem statement_projection_exact :
    publicFieldCount * statementLimbBytes =
      statementBytes + statementPaddingZeroBytes := by
  decide

theorem three_consensus_bindings_are_168_bytes :
    3 * consensusBindingBytes = 168 := by
  decide

theorem successor_route_is_profile3_domain2 :
    circuitVersion = 6 ∧ cryptoSuite = 5 ∧
      proofProfile = 3 ∧ domainSet = 2 := by
  decide

/-! ## Exact HGF6HR02 schedule -/

def noteInvocations : Nat := 4
def nullifierInvocations : Nat := 2
def merkleInvocations : Nat := 64
def spendInvocations : Nat := 2
def policyInvocations : Nat := 1
def authorizationInvocations : Nat := 2
def intentInvocations : Nat := 1
def balanceInvocations : Nat := 1
def ciphertextInvocations : Nat := 2
def semanticInvocations : Nat := 79

def notePermutations : Nat := 16
def nullifierPermutations : Nat := 4
def merklePermutations : Nat := 64
def spendPermutations : Nat := 6
def policyPermutations : Nat := 6
def authorizationPermutations : Nat := 8
def intentPermutations : Nat := 6
def balancePermutations : Nat := 1
def ciphertextPermutations : Nat := 34
def semanticPermutations : Nat := 145

def privateInvocations : Nat := 75
def privatePermutations : Nat := 104
def collisionOnlyShake256Permutations : Nat := 105

theorem semantic_invocation_schedule_exact :
    noteInvocations + nullifierInvocations + merkleInvocations +
        spendInvocations + policyInvocations + authorizationInvocations +
        intentInvocations + balanceInvocations + ciphertextInvocations =
      semanticInvocations := by
  decide

theorem semantic_permutation_schedule_exact :
    notePermutations + nullifierPermutations + merklePermutations +
        spendPermutations + policyPermutations + authorizationPermutations +
        intentPermutations + balancePermutations + ciphertextPermutations =
      semanticPermutations := by
  decide

theorem private_schedule_exact :
    privateInvocations = 75 ∧ privatePermutations = 104 := by
  decide

def intentPayloadBytes : Nat := 725
def intentFrameBytes : Nat := 744
def ciphertextBytes : Nat := 2_147
def ciphertextFrameBytes : Nat := 2_182
def shake256RateBytes : Nat := 136

theorem intent_frame_overhead_exact :
    intentFrameBytes - intentPayloadBytes = 19 := by
  decide

theorem ciphertext_frame_overhead_exact :
    ciphertextFrameBytes - ciphertextBytes = 35 := by
  decide

theorem ciphertext_frame_uses_seventeen_permutations :
    ciphertextFrameBytes / shake256RateBytes + 1 = 17 := by
  decide

/-! ## Primitive authority and strict role margin -/

inductive PrimitiveProfile where
  | fipsShake256
  | fipsSha3_512
  | rfc7693Blake2b
  | nonstandardKeccakCapacity1024Xof
  deriving DecidableEq

def ConventionalPrimitive : PrimitiveProfile → Prop
  | .fipsShake256 => True
  | .fipsSha3_512 => True
  | .rfc7693Blake2b => True
  | .nonstandardKeccakCapacity1024Xof => False

theorem hgf6hr02_wide_xof_is_not_conventional :
    ¬ ConventionalPrimitive .nonstandardKeccakCapacity1024Xof := by
  intro impossible
  exact impossible

def strictRoleTargetBits : Nat := 128
def strictRoleMargin (bits : Nat) : Bool := strictRoleTargetBits < bits

theorem exactly_128_bits_never_has_strict_margin :
    strictRoleMargin 128 = false := by
  decide

theorem collision_149_has_strict_margin : strictRoleMargin 149 = true := by
  decide

theorem preimage_224_has_strict_margin : strictRoleMargin 224 = true := by
  decide

theorem spend_seed_192_has_strict_margin : strictRoleMargin 192 = true := by
  decide

/-! ## One term per primitive/property, never per call/permutation -/

def globalPrimitiveLoss (loss : Rat) : Rat := loss
def rejectedPerPermutationUnion (loss : Rat) : Rat :=
  semanticPermutations * loss

theorem global_primitive_loss_has_unit_multiplier (loss : Rat) :
    globalPrimitiveLoss loss = loss := by
  rfl

theorem rejected_permutation_union_has_multiplier_145 (loss : Rat) :
    rejectedPerPermutationUnion loss = 145 * loss := by
  rfl

/-! ## Global query, CMS, hash, and history terms -/

def lowAdvantageQueries : Nat := 2 ^ 64
def workFactorQueries : Nat := 2 ^ 128
def securityEpochProofBudget : Nat := 2 ^ 32
def maxProofsPerBlock : Nat := 10_000

def interactiveError (epsilon1 epsilon2 epsilon3 epsilon4 : Rat) : Rat :=
  epsilon1 + epsilon2 + epsilon3 + epsilon4

def idealCmsEnvelope
    (queries baseGameArity : Nat) (epsilonInteractive : Rat) : Rat :=
  12 * queries ^ 2 * epsilonInteractive +
    48 * queries ^ 3 / (2 ^ 512 : Nat) +
    2 * baseGameArity ^ 2 / (2 ^ 512 : Nat)

theorem ideal_cms_term_inventory
    (queries baseGameArity : Nat)
    (epsilon1 epsilon2 epsilon3 epsilon4 : Rat) :
    idealCmsEnvelope queries baseGameArity
        (interactiveError epsilon1 epsilon2 epsilon3 epsilon4) =
      12 * queries ^ 2 * (epsilon1 + epsilon2 + epsilon3 + epsilon4) +
        48 * queries ^ 3 / (2 ^ 512 : Nat) +
        2 * baseGameArity ^ 2 / (2 ^ 512 : Nat) := by
  rfl

def shake256CollisionScreen (queries : Nat) : Rat :=
  4 * queries ^ 3 / (2 ^ 448 : Nat)

def rejectedWideXofCollisionScreen (queries : Nat) : Rat :=
  4 * queries ^ 3 / (2 ^ 448 : Nat)

def rejectedWideXofPreimagePrfScreen (queries : Nat) : Rat :=
  queries ^ 2 / (2 ^ 448 : Nat)

def uniformShake256PreimageCounterfactual (queries : Nat) : Rat :=
  queries ^ 2 / (2 ^ 256 : Nat)

def leafTapeGuessingScreen (queries : Nat) : Rat :=
  queries ^ 2 / (2 ^ 512 : Nat)

theorem three_semantic_screens_are_global (queries : Nat) :
    shake256CollisionScreen queries = 4 * queries ^ 3 / (2 ^ 448 : Nat) ∧
    rejectedWideXofCollisionScreen queries = 4 * queries ^ 3 / (2 ^ 448 : Nat) ∧
    rejectedWideXofPreimagePrfScreen queries = queries ^ 2 / (2 ^ 448 : Nat) := by
  exact ⟨rfl, rfl, rfl⟩

def sharedHistoryIdealLoss (oneGlobalRunLoss : Rat) : Rat := oneGlobalRunLoss
def rejectedPerProofUnion (historyProofs : Nat) (oneProofLoss : Rat) : Rat :=
  historyProofs * oneProofLoss

theorem shared_history_has_unit_multiplier (loss : Rat) :
    sharedHistoryIdealLoss loss = loss := by
  rfl

theorem counterfactual_epoch_union_has_2pow32_multiplier (loss : Rat) :
    rejectedPerProofUnion securityEpochProofBudget loss = (2 ^ 32 : Nat) * loss := by
  rfl

/-! ## Conventional successor tournament -/

def splitSha3SecretPermutations : Nat := 46
def splitSha3TotalPermutations : Nat := 151
def hmacSha3TotalPermutationLowerBound : Nat := 173
def blake2bSecretCompressionLowerBound : Nat := 28

theorem split_sha3_schedule_is_151 :
    collisionOnlyShake256Permutations + splitSha3SecretPermutations =
      splitSha3TotalPermutations := by
  decide

structure SuccessorEvidence where
  keyedRoleConstructionSelected : Prop
  authorizationKeyEntropyBound : Prop
  exactFixedShapeGeometryMeasured : Prop
  qromPrfReduction : Prop

def SuccessorReady (evidence : SuccessorEvidence) : Prop :=
  evidence.keyedRoleConstructionSelected ∧
    evidence.authorizationKeyEntropyBound ∧
    evidence.exactFixedShapeGeometryMeasured ∧
    evidence.qromPrfReduction

/-! ## Strict DECS identity -/

def openedLeafRandomTapeBytes : Nat := 64
def decsOpenedLeaves : Nat := 23

theorem opened_leaf_tape_payload_is_1472_bytes :
    decsOpenedLeaves * openedLeafRandomTapeBytes = 1_472 := by
  decide

inductive DecsEvaluationDomain where
  | radix2Subgroup
  | disjointCoset
  deriving DecidableEq

structure DecsIdentity where
  evaluationDomain : DecsEvaluationDomain
  openedLeafRandomTapeBound : Bool
  openedLeafIndexBound : Bool
  openedLeafRandomTapeBytes : Nat

def StrictDecsIdentity (identity : DecsIdentity) : Prop :=
  identity.evaluationDomain = .disjointCoset ∧
    identity.openedLeafRandomTapeBound = true ∧
    identity.openedLeafIndexBound = true ∧
    identity.openedLeafRandomTapeBytes = 64

theorem radix2_subgroup_never_has_strict_identity
    (randomTapeBound indexBound : Bool) :
    ¬ StrictDecsIdentity
      { evaluationDomain := .radix2Subgroup
        openedLeafRandomTapeBound := randomTapeBound
        openedLeafIndexBound := indexBound
        openedLeafRandomTapeBytes := openedLeafRandomTapeBytes } := by
  intro strict
  cases strict.1

/-! ## Unavoidable external assumptions -/

structure ExternalAssumptions where
  lppcLvcsDecsPcsBinding : Prop
  lppcPiopKnowledgeSoundness : Prop
  fiatShamirQromTransform : Prop
  sha512StandardToTaggedProductOracle : Prop
  sha512MerklePcsBinding : Prop
  sha512XofSamplingAndRejection : Prop
  shake256CollisionBinding : Prop
  conventionalSecretRoleConstruction : Prop
  secretRolePreimagePrfSecurity : Prop
  decsLeafTapeQromHiding : Prop
  noninteractiveProofOfKnowledgeExtraction : Prop
  globalHistoryProductOracleTransfer : Prop
  grindingRetryAbortComposition : Prop
  compiledRelationRefinement : Prop
  compiledVerifierRefinement : Prop
  parserAndWireRefinement : Prop
  physicalSha512CallCapEnforced : Prop
  historyBudgetConsensusEnforced : Prop
  completeZeroKnowledge : Prop
  independentCryptographicReview : Prop

def ProductionAuthority (_assumptions : ExternalAssumptions) : Prop := False

theorem this_module_never_authorizes_production
    (assumptions : ExternalAssumptions) :
    ¬ ProductionAuthority assumptions := by
  intro impossible
  exact impossible

end HegemonCrypto.SmallWood.V6CompositionAccounting
