import Hegemon.Bytes
import Hegemon.Transaction.Poseidon2Width16Kernel

namespace Hegemon
namespace Transaction
namespace Poseidon2V8SemanticSpecification

/-!
Exact semantic target and non-circular refinement boundary for `HGV8RP03`.

The executable relation program is not itself the transaction specification.  This file fixes a
separate typed 2-input/2-output V8 target covering every activity mask, every V8 authorization
mode, note commitments, nullifiers, the depth-32 note tree, action intent, per-asset balance,
stablecoin transition, and the separately carried ciphertext bytes.  A refinement receipt may
provide decoders and universal proofs, but it may not choose or redefine the semantic target.

The cryptographic primitive record is an explicit assumption seam.  In particular, the relation
adequacy theorem does not manufacture a Poseidon2 or BLAKE2b security claim.  Consensus context
and inline ciphertext bytes are separate conjuncts because neither is an arbitrary private
packed-witness coordinate.
-/

def semanticTargetId : String :=
  "hegemon.smallwood.poseidon2-v8.exact-transaction-semantics.v1"
def refinementReceiptSchema : String :=
  "hegemon.poseidon2-v8.semantic-adequacy-refinement-v1"

def fieldModulus : Nat := 18446744069414584321
def publicWordCount : Nat := 120
def typedWitnessWordCount : Nat := 721
def packedWitnessWordCount : Nat := 43904
def inputCount : Nat := 2
def outputCount : Nat := 2
def balanceSlotCount : Nat := 4
def merkleDepth : Nat := 32
def digestWords : Nat := 7
def ciphertextCommitmentWords : Nat := 6
def inlineCiphertextBytes : Nat := 2147
def signerCountMaximum : Nat := 6
def signerTagWords : Nat := 5
def valueBound : Nat := 2 ^ 61
def stablecoinValueBound : Nat := 2 ^ 56
def stablecoinScalarBound : Nat := 2 ^ 63
def nativeAssetId : Nat := 0
/-- The external `u64::MAX` sentinel reduced into Goldilocks, matching transaction-core. -/
def balancePaddingAssetId : Nat := (2 ^ 64 - 1) % fieldModulus

theorem balance_padding_asset_id_eq : balancePaddingAssetId = 4294967294 := by decide

theorem balance_padding_asset_id_is_canonical : balancePaddingAssetId < fieldModulus := by decide

theorem balance_padding_asset_id_is_not_field_minus_one :
    balancePaddingAssetId ≠ fieldModulus - 1 := by decide
def circuitVersion : Nat := 8
def cryptoSuiteEta : Nat := 7

abbrev Digest := List Nat
abbrev CiphertextCommitment := List Nat
abbrev CiphertextBytes := List Nat

def ExactWords (count : Nat) (words : List Nat) : Prop :=
  words.length = count ∧ ∀ word, word ∈ words → word < fieldModulus

def ZeroWords (words : List Nat) : Prop :=
  ∀ word, word ∈ words → word = 0

def NonzeroWords (words : List Nat) : Prop :=
  ∃ word, word ∈ words ∧ word ≠ 0

def BooleanWord (word : Nat) : Prop := word = 0 ∨ word = 1

def flagAt (flags : List Nat) (slot : Nat) : Nat := flags.getD slot 0
def digestAt (digests : List Digest) (slot : Nat) : Digest := digests.getD slot []
def wordAt (words : List Nat) (slot : Nat) : Nat := words.getD slot 0

inductive StableDirection where
  | disabled
  | mint
  | burn
deriving DecidableEq, Repr, Inhabited

def StableDirection.word : StableDirection → Nat
  | .disabled => 0
  | .mint => 1
  | .burn => 2

structure V8StablecoinCompatibility where
  enabled : Nat
  assetId : Nat
  policyVersion : Nat
  issuanceSign : Nat
  issuanceMagnitude : Nat
  reservedLegacyCommitments : List CiphertextCommitment
deriving DecidableEq, Repr, Inhabited

structure V8StablecoinCounters where
  epochId : Nat
  mintedInEpoch : Nat
  totalDebt : Nat
  sequence : Nat
deriving DecidableEq, Repr, Inhabited

structure V8StablecoinPublic where
  direction : StableDirection
  assetId : Nat
  policyVersion : Nat
  magnitude : Nat
  actionIntent : Digest
  parentHeight : Nat
  beforeRoot : Digest
  afterRoot : Digest
  after : V8StablecoinCounters
  issuerAuthorization : Digest
deriving DecidableEq, Repr, Inhabited

/-- The exact stable witness is 94 canonical words.  Its internal config layout is owned by the
    stablecoin semantic primitive, rather than duplicated as a second hash implementation here. -/
structure V8StablecoinWitness where
  words : List Nat
deriving DecidableEq, Repr, Inhabited

structure V8PublicStatement where
  inputFlags : List Nat
  outputFlags : List Nat
  nullifiers : List Digest
  commitments : List Digest
  ciphertextCommitments : List CiphertextCommitment
  fee : Nat
  valueBalanceSign : Nat
  valueBalanceMagnitude : Nat
  merkleRoot : Digest
  balanceAssets : List Nat
  compatibility : V8StablecoinCompatibility
  version : Nat
  cryptoSuite : Nat
  stablecoin : V8StablecoinPublic
deriving DecidableEq, Repr, Inhabited

structure V8NoteOpening where
  value : Nat
  assetId : Nat
  recipientKey : List Nat
  authorizationKey : List Nat
  rho : List Nat
  randomness : List Nat
deriving DecidableEq, Repr, Inhabited

structure V8InputWitness where
  active : Nat
  spendKey : List Nat
  note : V8NoteOpening
  position : Nat
  siblings : List Digest
  balanceSelectors : List Nat
deriving DecidableEq, Repr, Inhabited

structure V8OutputWitness where
  active : Nat
  note : V8NoteOpening
  balanceSelectors : List Nat
deriving DecidableEq, Repr, Inhabited

structure V8AccumulatorOpening where
  policyRoot : Digest
  intentDigest : Digest
  threshold : Nat
  signerCount : Nat
  approvalCount : Nat
  approvedSlots : List Nat
deriving DecidableEq, Repr, Inhabited

inductive V8AuthorizationMode where
  | singleKey
  | approvalStep
  | finalThresholdSpend
deriving DecidableEq, Repr, Inhabited

structure V8AuthorizationWitness where
  mode : V8AuthorizationMode
  current : V8AccumulatorOpening
  next : V8AccumulatorOpening
  policySignerTags : List (List Nat)
deriving DecidableEq, Repr, Inhabited

structure V8Witness where
  inputs : List V8InputWitness
  outputs : List V8OutputWitness
  authorization : V8AuthorizationWitness
  stablecoin : V8StablecoinWitness
deriving DecidableEq, Repr, Inhabited

structure V8StablecoinContext where
  currentRoot : Digest
  parentHeight : Nat
  expectedActionIntent : Digest
deriving DecidableEq, Repr, Inhabited

structure V8InlineCiphertexts where
  slots : List (Option CiphertextBytes)
deriving DecidableEq, Repr, Inhabited

def encodeCompatibility (compatibility : V8StablecoinCompatibility) : List Nat :=
  [ compatibility.enabled, compatibility.assetId, compatibility.policyVersion,
    compatibility.issuanceSign, compatibility.issuanceMagnitude ] ++
    compatibility.reservedLegacyCommitments.flatten

def encodeStablecoinPublic (stable : V8StablecoinPublic) : List Nat :=
  [ stable.direction.word, stable.assetId, stable.policyVersion, stable.magnitude ] ++
    stable.actionIntent ++ [stable.parentHeight] ++ stable.beforeRoot ++ stable.afterRoot ++
    [ stable.after.epochId, stable.after.mintedInEpoch, stable.after.totalDebt,
      stable.after.sequence ] ++ stable.issuerAuthorization

/-- Exact public layout used by `SmallwoodPoseidon2V8PublicStatement::to_public_words`. -/
def encodePublicStatement (statement : V8PublicStatement) : List Nat :=
  statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten ++
    statement.commitments.flatten ++ statement.ciphertextCommitments.flatten ++
    [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
    statement.merkleRoot ++ statement.balanceAssets ++
    encodeCompatibility statement.compatibility ++
    [statement.version, statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin

def ZeroNoteOpening (note : V8NoteOpening) : Prop :=
  note.value = 0 ∧ note.assetId = 0 ∧
    ExactWords 4 note.recipientKey ∧ ZeroWords note.recipientKey ∧
    ExactWords 4 note.authorizationKey ∧ ZeroWords note.authorizationKey ∧
    ExactWords 4 note.rho ∧ ZeroWords note.rho ∧
    ExactWords 4 note.randomness ∧ ZeroWords note.randomness

def CanonicalNoteOpening (note : V8NoteOpening) : Prop :=
  note.value < valueBound ∧ note.assetId < fieldModulus ∧
    note.assetId ≠ balancePaddingAssetId ∧
    ExactWords 4 note.recipientKey ∧ ExactWords 4 note.authorizationKey ∧
    ExactWords 4 note.rho ∧ ExactWords 4 note.randomness

def ZeroAccumulator (opening : V8AccumulatorOpening) : Prop :=
  ExactWords digestWords opening.policyRoot ∧ ZeroWords opening.policyRoot ∧
    ExactWords digestWords opening.intentDigest ∧ ZeroWords opening.intentDigest ∧
    opening.threshold = 0 ∧ opening.signerCount = 0 ∧ opening.approvalCount = 0 ∧
    opening.approvedSlots.length = signerCountMaximum ∧ ZeroWords opening.approvedSlots

def ZeroSignerTags (tags : List (List Nat)) : Prop :=
  tags.length = signerCountMaximum ∧
    ∀ tag, tag ∈ tags → ExactWords signerTagWords tag ∧ ZeroWords tag

def CanonicalAccumulator (opening : V8AccumulatorOpening) : Prop :=
  ExactWords digestWords opening.policyRoot ∧ NonzeroWords opening.policyRoot ∧
    ExactWords digestWords opening.intentDigest ∧ NonzeroWords opening.intentDigest ∧
    0 < opening.threshold ∧ opening.threshold ≤ opening.signerCount ∧
    opening.signerCount ≤ signerCountMaximum ∧
    opening.approvalCount ≤ opening.signerCount ∧
    opening.approvedSlots.length = signerCountMaximum ∧
    (∀ slot, slot < signerCountMaximum → BooleanWord (wordAt opening.approvedSlots slot)) ∧
    opening.approvalCount = opening.approvedSlots.sum ∧
    ∀ slot, opening.signerCount ≤ slot → slot < signerCountMaximum →
      wordAt opening.approvedSlots slot = 0

def CanonicalSignerTags (authorization : V8AuthorizationWitness) : Prop :=
  authorization.policySignerTags.length = signerCountMaximum ∧
    (∀ slot, slot < signerCountMaximum →
      ExactWords signerTagWords (authorization.policySignerTags.getD slot [])) ∧
    (∀ slot, slot < authorization.current.signerCount →
      NonzeroWords (authorization.policySignerTags.getD slot [])) ∧
    (∀ left right, left < right → right < authorization.current.signerCount →
      wordAt (authorization.policySignerTags.getD left []) 0 ≠
        wordAt (authorization.policySignerTags.getD right []) 0) ∧
    ∀ slot, authorization.current.signerCount ≤ slot → slot < signerCountMaximum →
      ZeroWords (authorization.policySignerTags.getD slot [])

def CanonicalBalanceAssets (assets : List Nat) : Prop :=
  assets.length = balanceSlotCount ∧ wordAt assets 0 = nativeAssetId ∧
    (∀ slot, slot < balanceSlotCount → wordAt assets slot < fieldModulus) ∧
    (∀ left right, left < right → right < balanceSlotCount →
      wordAt assets left ≠ balancePaddingAssetId →
      wordAt assets right ≠ balancePaddingAssetId →
      wordAt assets left < wordAt assets right) ∧
    ∀ left right, left < right → right < balanceSlotCount →
      wordAt assets left = balancePaddingAssetId → wordAt assets right = balancePaddingAssetId

/-- The native-only asset layout produced by Rust is admitted by the independent specification. -/
theorem canonical_native_only_balance_assets :
    CanonicalBalanceAssets
      [nativeAssetId, balancePaddingAssetId, balancePaddingAssetId, balancePaddingAssetId] := by
  refine ⟨rfl, rfl, ?_, ?_, ?_⟩
  · intro slot bounded
    have finite : ∀ index : Fin 4,
        wordAt [nativeAssetId, balancePaddingAssetId, balancePaddingAssetId,
          balancePaddingAssetId] index.val < fieldModulus := by decide
    exact finite ⟨slot, bounded⟩
  · intro left right ordered bounded leftReal rightReal
    have finite : ∀ first second : Fin 4, first.val < second.val →
        wordAt [nativeAssetId, balancePaddingAssetId, balancePaddingAssetId,
          balancePaddingAssetId] first.val ≠ balancePaddingAssetId →
        wordAt [nativeAssetId, balancePaddingAssetId, balancePaddingAssetId,
          balancePaddingAssetId] second.val ≠ balancePaddingAssetId →
        wordAt [nativeAssetId, balancePaddingAssetId, balancePaddingAssetId,
          balancePaddingAssetId] first.val <
        wordAt [nativeAssetId, balancePaddingAssetId, balancePaddingAssetId,
          balancePaddingAssetId] second.val := by decide
    exact finite ⟨left, Nat.lt_trans ordered bounded⟩ ⟨right, bounded⟩ ordered leftReal rightReal
  · intro left right ordered bounded leftPadding
    have finite : ∀ first second : Fin 4, first.val < second.val →
        wordAt [nativeAssetId, balancePaddingAssetId, balancePaddingAssetId,
          balancePaddingAssetId] first.val = balancePaddingAssetId →
        wordAt [nativeAssetId, balancePaddingAssetId, balancePaddingAssetId,
          balancePaddingAssetId] second.val = balancePaddingAssetId := by decide
    exact finite ⟨left, Nat.lt_trans ordered bounded⟩ ⟨right, bounded⟩ ordered leftPadding

/-- Repeating the old, incorrect field-minus-one sentinel is not canonical asset padding. -/
theorem field_minus_one_is_not_native_only_padding :
    ¬ CanonicalBalanceAssets
      [nativeAssetId, fieldModulus - 1, fieldModulus - 1, fieldModulus - 1] := by
  intro canonical
  have impossible := canonical.2.2.2.1 1 2 (by decide) (by decide) (by decide) (by decide)
  exact (Nat.lt_irrefl (fieldModulus - 1)) impossible

def CanonicalCompatibility
    (compatibility : V8StablecoinCompatibility) (stable : V8StablecoinPublic) : Prop :=
  BooleanWord compatibility.enabled ∧ BooleanWord compatibility.issuanceSign ∧
    compatibility.issuanceMagnitude < stablecoinValueBound ∧
    compatibility.reservedLegacyCommitments.length = 3 ∧
    (∀ digest, digest ∈ compatibility.reservedLegacyCommitments →
      ExactWords ciphertextCommitmentWords digest ∧ ZeroWords digest) ∧
    match stable.direction with
    | .disabled =>
        compatibility.enabled = 0 ∧ compatibility.assetId = 0 ∧
          compatibility.policyVersion = 0 ∧ compatibility.issuanceSign = 0 ∧
          compatibility.issuanceMagnitude = 0 ∧ stable.assetId = 0 ∧
          stable.policyVersion = 0 ∧ stable.magnitude = 0 ∧
          ZeroWords stable.actionIntent ∧ stable.beforeRoot = stable.afterRoot ∧
          stable.after.epochId = 0 ∧ stable.after.mintedInEpoch = 0 ∧
          stable.after.totalDebt = 0 ∧ stable.after.sequence = 0 ∧
          ZeroWords stable.issuerAuthorization
    | .mint =>
        compatibility.enabled = 1 ∧ compatibility.assetId = stable.assetId ∧
          compatibility.policyVersion = stable.policyVersion ∧
          compatibility.issuanceSign = 1 ∧
          compatibility.issuanceMagnitude = stable.magnitude ∧
          compatibility.assetId ≠ nativeAssetId ∧
          compatibility.assetId ≠ balancePaddingAssetId ∧
          stable.assetId < 2 ^ 32 ∧ stable.policyVersion < 2 ^ 32
    | .burn =>
        compatibility.enabled = 1 ∧ compatibility.assetId = stable.assetId ∧
          compatibility.policyVersion = stable.policyVersion ∧
          compatibility.issuanceSign = 0 ∧
          compatibility.issuanceMagnitude = stable.magnitude ∧
          compatibility.assetId ≠ nativeAssetId ∧
          compatibility.assetId ≠ balancePaddingAssetId ∧
          stable.assetId < 2 ^ 32 ∧ stable.policyVersion < 2 ^ 32 ∧
          ZeroWords stable.issuerAuthorization

def PublicSlotShapeValid (statement : V8PublicStatement) : Prop :=
  ∀ slot, slot < 2 →
    ((flagAt statement.inputFlags slot = 0 ∧ ZeroWords (digestAt statement.nullifiers slot)) ∨
      (flagAt statement.inputFlags slot = 1 ∧ NonzeroWords (digestAt statement.nullifiers slot))) ∧
    ((flagAt statement.outputFlags slot = 0 ∧
        ZeroWords (digestAt statement.commitments slot) ∧
        ZeroWords (statement.ciphertextCommitments.getD slot [])) ∨
      (flagAt statement.outputFlags slot = 1 ∧
        NonzeroWords (digestAt statement.commitments slot) ∧
        NonzeroWords (statement.ciphertextCommitments.getD slot [])))

structure V8SemanticPrimitives where
  noteCommitment : V8NoteOpening → Digest
  transactionPrf : List Nat → Digest
  /-- Input slot, mode-selected authorization PRF scalar, note position, and four rho words. -/
  nullifier : Nat → Nat → Nat → List Nat → Digest
  merkleRoot : Digest → Nat → List Digest → Digest
  actionIntent : V8PublicStatement → Digest
  policyRoot : List (List Nat) → Nat → Nat → Digest
  accumulatorDigest : V8AccumulatorOpening → Digest
  valueLockDigest : V8AccumulatorOpening → Digest
  stableTransition : V8StablecoinContext → V8StablecoinPublic → V8StablecoinWitness → Prop
  ciphertextCommitment : CiphertextBytes → CiphertextCommitment

/-!
Fixed primitive symbols for the semantic target.  These declarations prevent a compiler receipt
from choosing witness-dependent hash functions to make the theorem vacuous.  Their equations are
not asserted here: refinement to the width-16 Poseidon2 source frames, the stablecoin transition,
and RFC 7693 BLAKE2b-384 remains an explicit, separately reviewable proof obligation.
-/

def poseidon2V8PrimitiveSpecificationId : String :=
  "hegemon-p2w16-v1-114a4e7eb2684d29"
def stablecoinV8PrimitiveSpecificationId : String :=
  "hegemon.stablecoin.poseidon2-v8.transition.v1"
def ciphertextV8PrimitiveSpecificationId : String :=
  "hegemon.rfc7693.blake2b-384.inline-ciphertext.v1"

def poseidon2V8SpongeModeMarker : Nat := 0x5350_4f4e_4745_5631
def poseidon2V8SuiteMarker : Nat := 0x4845_475f_5032_3136
def poseidon2V8NoteDomain : Nat := 1
def poseidon2V8NullifierDomain : Nat := 2
def poseidon2V8MerkleDomain : Nat := 4
def poseidon2V8AccumulatorDomain : Nat := 6
def poseidon2V8PolicyDomain : Nat := 7
def poseidon2V8ValueLockDomain : Nat := 8
def poseidon2V8ActionIntentDomain : Nat := 0x4854_5838_494e_5400

def poseidon2V8InitialState : List Nat := List.replicate Poseidon2Width16Kernel.width 0

def poseidon2V8SeedFirstBlock (domain inputLength : Nat) (state : List Nat) : List Nat :=
  (((state.set Poseidon2Width16Kernel.rate domain).set
      (Poseidon2Width16Kernel.rate + 1) inputLength).set
      (Poseidon2Width16Kernel.rate + 2) poseidon2V8SpongeModeMarker).set
      (Poseidon2Width16Kernel.width - 1) poseidon2V8SuiteMarker

def poseidon2V8AbsorbBlock
    (domain : Nat) (inputs : List Nat) (blockCount : Nat)
    (state : List Nat) (block : Nat) : List Nat :=
  let seeded := if block = 0 then poseidon2V8SeedFirstBlock domain inputs.length state else state
  let absorbed := (List.range Poseidon2Width16Kernel.rate).foldl (fun current lane =>
    let inputIndex := block * Poseidon2Width16Kernel.rate + lane
    if inputIndex < inputs.length then
      current.set lane (Poseidon2Width16Kernel.fieldAdd
        (current.getD lane 0) (inputs.getD inputIndex 0))
    else current) seeded
  let padded := if block + 1 = blockCount then
    absorbed.set (Poseidon2Width16Kernel.rate + 3)
      (Poseidon2Width16Kernel.fieldAdd
        (absorbed.getD (Poseidon2Width16Kernel.rate + 3) 0) 1)
    else absorbed
  Poseidon2Width16Kernel.permutation padded

/-- Exact width-16, rate-8 V8 source sponge, including length, mode, suite, and final markers. -/
def poseidon2V8Sponge (domain : Nat) (inputs : List Nat) : Digest :=
  let blockCount := Nat.max 1 ((inputs.length + Poseidon2Width16Kernel.rate - 1) /
    Poseidon2Width16Kernel.rate)
  let finalState := (List.range blockCount).foldl
    (poseidon2V8AbsorbBlock domain inputs blockCount) poseidon2V8InitialState
  finalState.take digestWords

/-- Exact width-16 V8 two-digest compression frame. -/
def poseidon2V8Compress14 (domain : Nat) (left right : Digest) : Digest :=
  let initial := (List.range Poseidon2Width16Kernel.width).map fun lane =>
    if lane < digestWords then left.getD lane 0
    else if lane < 2 * digestWords then right.getD (lane - digestWords) 0
    else if lane = 2 * digestWords then domain
    else poseidon2V8SuiteMarker
  (Poseidon2Width16Kernel.permutation initial).take digestWords

def exactV8NoteWords (note : V8NoteOpening) : List Nat :=
  [note.value, note.assetId] ++ note.recipientKey ++ note.rho ++ note.randomness ++
    note.authorizationKey

def exactV8NoteCommitment (note : V8NoteOpening) : Digest :=
  poseidon2V8Sponge poseidon2V8NoteDomain (exactV8NoteWords note)

def exactV8TransactionPrf (spendKey : List Nat) : Digest :=
  poseidon2V8Sponge poseidon2V8NullifierDomain spendKey

def exactV8Nullifier (_slot authorizationPrf position : Nat) (rho : List Nat) : Digest :=
  poseidon2V8Sponge poseidon2V8NullifierDomain ([authorizationPrf, position] ++ rho)

def exactV8MerkleRoot (leaf : Digest) (position : Nat) (siblings : List Digest) : Digest :=
  (List.range merkleDepth).foldl (fun current level =>
    let sibling := siblings.getD level []
    if (position / (2 ^ level)) % 2 = 0 then
      poseidon2V8Compress14 poseidon2V8MerkleDomain current sibling
    else poseidon2V8Compress14 poseidon2V8MerkleDomain sibling current) leaf

def exactV8ActionIntentProjection (statement : V8PublicStatement) : List Nat :=
  let words := encodePublicStatement statement
  (List.range publicWordCount).map fun index =>
    if (4 ≤ index ∧ index < 18) ∨ (47 ≤ index ∧ index < 54) ∨
        (87 ≤ index ∧ index < 94) ∨ (113 ≤ index ∧ index < 120) then 0
    else words.getD index 0

def exactV8ActionIntent (statement : V8PublicStatement) : Digest :=
  poseidon2V8Sponge poseidon2V8ActionIntentDomain (exactV8ActionIntentProjection statement)

def exactV8PolicyRoot
    (signerTags : List (List Nat)) (threshold signerCount : Nat) : Digest :=
  poseidon2V8Sponge poseidon2V8PolicyDomain
    ([threshold, signerCount] ++ signerTags.flatten)

def exactV8AccumulatorWords (opening : V8AccumulatorOpening) : List Nat :=
  opening.policyRoot ++ opening.intentDigest ++
    [opening.threshold, opening.signerCount, opening.approvalCount] ++ opening.approvedSlots

def exactV8AccumulatorDigest (opening : V8AccumulatorOpening) : Digest :=
  poseidon2V8Sponge poseidon2V8AccumulatorDomain (exactV8AccumulatorWords opening)

def exactV8ValueLockDigest (opening : V8AccumulatorOpening) : Digest :=
  poseidon2V8Sponge poseidon2V8ValueLockDomain (opening.policyRoot ++ opening.intentDigest)

/-!
Exact typed stablecoin transition.

The 94 witness words below are decoded in precisely the order used by
`SmallwoodPoseidon2V8Witness::try_from_witness_words`: 55 static config words, four before-state
counters, four seven-word siblings, and one seven-word issuer secret.  All hashes use the same
width-16 compression primitive defined above.  Arithmetic is over `Nat`; the explicit source
bounds make each checked Rust `u64`/`u128` operation inject into these equations.
-/

def stablecoinV8Depth : Nat := 4
def stablecoinV8EpochHeightShift : Nat := 12
def stablecoinV8RatioScalePpm : Nat := 1000000

def stablecoinV8DomainConfigChunk0 : Nat := 0x4853_4338_4346_3000
def stablecoinV8DomainConfigChunk1 : Nat := 0x4853_4338_4346_3100
def stablecoinV8DomainConfigChunk2 : Nat := 0x4853_4338_4346_3200
def stablecoinV8DomainConfigChunk3 : Nat := 0x4853_4338_4346_3300
def stablecoinV8DomainConfigNode0 : Nat := 0x4853_4338_434e_3000
def stablecoinV8DomainConfigNode1 : Nat := 0x4853_4338_434e_3100
def stablecoinV8DomainConfigRoot : Nat := 0x4853_4338_4346_5200
def stablecoinV8DomainStateLeaf : Nat := 0x4853_4338_4c45_4146
def stablecoinV8DomainStateNode0 : Nat := 0x4853_4338_4e4f_4400
def stablecoinV8DomainIssuerCommitment : Nat := 0x4853_4338_4953_434d
def stablecoinV8DomainIssuerAuthorization : Nat := 0x4853_4338_4953_4155

structure V8StablecoinConfigOpening where
  assetId : Nat
  policyVersion : Nat
  active : Nat
  enabledAt : Nat
  retiredPresent : Nat
  retiredAt : Nat
  issuerCommitment : Digest
  minCollateralRatioPpm : Nat
  maxMintPerEpoch : Nat
  oracleSubmittedAt : Nat
  oracleMaxAge : Nat
  oraclePriceNumerator : Nat
  oraclePriceDenominator : Nat
  collateralAmount : Nat
  attestationCreatedAt : Nat
  attestationDisputed : Nat
  attestationPresent : Nat
  attestationMaxAge : Nat
  policyAdminCommitment : Digest
  oracleAuthorityCommitment : Digest
  attestationAuthorityCommitment : Digest
  collateralAssetId : Nat
  collateralDecimals : Nat
  collateralScale : Nat
  lockedCollateralCommitment : Digest
deriving DecidableEq, Repr, Inhabited

def stableWitnessWord (witness : V8StablecoinWitness) (index : Nat) : Nat :=
  witness.words.getD index 0

def stableWitnessSlice (witness : V8StablecoinWitness) (start count : Nat) : List Nat :=
  (List.range count).map fun offset => stableWitnessWord witness (start + offset)

def decodeV8StablecoinConfig (witness : V8StablecoinWitness) : V8StablecoinConfigOpening :=
  { assetId := stableWitnessWord witness 0
    policyVersion := stableWitnessWord witness 1
    active := stableWitnessWord witness 2
    enabledAt := stableWitnessWord witness 3
    retiredPresent := stableWitnessWord witness 4
    retiredAt := stableWitnessWord witness 5
    issuerCommitment := stableWitnessSlice witness 6 7
    minCollateralRatioPpm := stableWitnessWord witness 13
    maxMintPerEpoch := stableWitnessWord witness 14
    oracleSubmittedAt := stableWitnessWord witness 15
    oracleMaxAge := stableWitnessWord witness 16
    oraclePriceNumerator := stableWitnessWord witness 17
    oraclePriceDenominator := stableWitnessWord witness 18
    collateralAmount := stableWitnessWord witness 19
    attestationCreatedAt := stableWitnessWord witness 20
    attestationDisputed := stableWitnessWord witness 21
    attestationPresent := stableWitnessWord witness 22
    attestationMaxAge := stableWitnessWord witness 23
    policyAdminCommitment := stableWitnessSlice witness 24 7
    oracleAuthorityCommitment := stableWitnessSlice witness 31 7
    attestationAuthorityCommitment := stableWitnessSlice witness 38 7
    collateralAssetId := stableWitnessWord witness 45
    collateralDecimals := stableWitnessWord witness 46
    collateralScale := stableWitnessWord witness 47
    lockedCollateralCommitment := stableWitnessSlice witness 48 7 }

def decodeV8StablecoinBefore (witness : V8StablecoinWitness) : V8StablecoinCounters :=
  { epochId := stableWitnessWord witness 55
    mintedInEpoch := stableWitnessWord witness 56
    totalDebt := stableWitnessWord witness 57
    sequence := stableWitnessWord witness 58 }

def decodeV8StablecoinSiblings (witness : V8StablecoinWitness) : List Digest :=
  (List.range stablecoinV8Depth).map fun level =>
    stableWitnessSlice witness (59 + level * digestWords) digestWords

def decodeV8StablecoinIssuerSecret (witness : V8StablecoinWitness) : Digest :=
  stableWitnessSlice witness 87 digestWords

def encodeV8StablecoinConfig (config : V8StablecoinConfigOpening) : List Nat :=
  [ config.assetId, config.policyVersion, config.active, config.enabledAt,
    config.retiredPresent, config.retiredAt ] ++ config.issuerCommitment ++
  [ config.minCollateralRatioPpm, config.maxMintPerEpoch, config.oracleSubmittedAt,
    config.oracleMaxAge, config.oraclePriceNumerator, config.oraclePriceDenominator,
    config.collateralAmount, config.attestationCreatedAt, config.attestationDisputed,
    config.attestationPresent, config.attestationMaxAge ] ++
  config.policyAdminCommitment ++ config.oracleAuthorityCommitment ++
  config.attestationAuthorityCommitment ++
  [config.collateralAssetId, config.collateralDecimals, config.collateralScale] ++
  config.lockedCollateralCommitment

def stablecoinV8ConfigChunkDomains : List Nat :=
  [ stablecoinV8DomainConfigChunk0, stablecoinV8DomainConfigChunk1,
    stablecoinV8DomainConfigChunk2, stablecoinV8DomainConfigChunk3 ]

def exactV8StablecoinConfigDigest (config : V8StablecoinConfigOpening) : Digest :=
  let fields := encodeV8StablecoinConfig config
  let chunks := (List.range 4).map fun chunk =>
    (List.range 14).map fun lane => fields.getD (chunk * 14 + lane) 0
  let digests := (List.range 4).map fun chunk =>
    let words := chunks.getD chunk []
    poseidon2V8Compress14 (stablecoinV8ConfigChunkDomains.getD chunk 0)
      (words.take 7) ((words.drop 7).take 7)
  let left := poseidon2V8Compress14 stablecoinV8DomainConfigNode0
    (digests.getD 0 []) (digests.getD 1 [])
  let right := poseidon2V8Compress14 stablecoinV8DomainConfigNode1
    (digests.getD 2 []) (digests.getD 3 [])
  poseidon2V8Compress14 stablecoinV8DomainConfigRoot left right

def exactV8StablecoinLeaf
    (index : Nat) (configDigest : Digest) (counters : V8StablecoinCounters) : Digest :=
  poseidon2V8Compress14 stablecoinV8DomainStateLeaf configDigest
    [counters.epochId, counters.mintedInEpoch, counters.totalDebt, counters.sequence, index, 0, 0]

def exactV8StablecoinRoot
    (assetId : Nat) (configDigest : Digest) (counters : V8StablecoinCounters)
    (siblings : List Digest) : Digest :=
  let index := assetId % (2 ^ stablecoinV8Depth)
  let leaf := exactV8StablecoinLeaf index configDigest counters
  (List.range stablecoinV8Depth).foldl (fun current level =>
    let sibling := siblings.getD level []
    if (index / (2 ^ level)) % 2 = 0 then
      poseidon2V8Compress14 (stablecoinV8DomainStateNode0 + level) current sibling
    else
      poseidon2V8Compress14 (stablecoinV8DomainStateNode0 + level) sibling current) leaf

def exactV8StablecoinIssuerCommitment
    (assetId policyVersion : Nat) (issuerSecret : Digest) : Digest :=
  poseidon2V8Compress14 stablecoinV8DomainIssuerCommitment issuerSecret
    [assetId, policyVersion, 0, 0, 0, 0, 0]

def exactV8StablecoinIssuerAuthorization
    (actionIntent issuerSecret : Digest) : Digest :=
  poseidon2V8Compress14 stablecoinV8DomainIssuerAuthorization issuerSecret actionIntent

def StableCanonicalWords (count : Nat) (words : List Nat) : Prop :=
  words.length = count ∧ words.all (fun word => decide (word < fieldModulus)) = true

def StableZeroWords (words : List Nat) : Prop :=
  words.all (fun word => decide (word = 0)) = true

def StableNonzeroWords (words : List Nat) : Prop :=
  words.any (fun word => decide (word ≠ 0)) = true

def CanonicalV8StablecoinWitnessEncoding (witness : V8StablecoinWitness) : Prop :=
  StableCanonicalWords 94 witness.words ∧
    stableWitnessWord witness 0 < 2 ^ 32 ∧ stableWitnessWord witness 1 < 2 ^ 32 ∧
    BooleanWord (stableWitnessWord witness 2) ∧ BooleanWord (stableWitnessWord witness 4) ∧
    stableWitnessWord witness 13 < 2 ^ 32 ∧ stableWitnessWord witness 17 < 2 ^ 32 ∧
    stableWitnessWord witness 18 < 2 ^ 32 ∧ BooleanWord (stableWitnessWord witness 21) ∧
    BooleanWord (stableWitnessWord witness 22) ∧ stableWitnessWord witness 45 < 2 ^ 32 ∧
    stableWitnessWord witness 46 < 2 ^ 8 ∧
    (stableWitnessWord witness 4 = 0 → stableWitnessWord witness 5 = 0)

def DigestListPairwiseDistinct (digests : List Digest) : Prop :=
  digests.zipIdx.all (fun left =>
    digests.zipIdx.all (fun right =>
      if left.2 < right.2 then decide (left.1 ≠ right.1) else true)) = true

def exactV8StablecoinCommonValid
    (config : V8StablecoinConfigOpening) (before : V8StablecoinCounters) : Prop :=
  config.assetId ≠ 0 ∧
    config.maxMintPerEpoch < stablecoinValueBound ∧
    config.collateralAmount < stablecoinValueBound ∧
    before.mintedInEpoch < stablecoinValueBound ∧ before.totalDebt < stablecoinValueBound ∧
    config.enabledAt < stablecoinScalarBound ∧ config.retiredAt < stablecoinScalarBound ∧
    config.oracleSubmittedAt < stablecoinScalarBound ∧
    config.oracleMaxAge < stablecoinScalarBound ∧
    config.attestationCreatedAt < stablecoinScalarBound ∧
    config.attestationMaxAge < stablecoinScalarBound ∧
    config.collateralScale < stablecoinScalarBound ∧
    before.epochId < stablecoinScalarBound ∧ before.sequence < stablecoinScalarBound ∧
    before.mintedInEpoch ≤ config.maxMintPerEpoch ∧
    let commitments := [ config.issuerCommitment, config.policyAdminCommitment,
      config.oracleAuthorityCommitment, config.attestationAuthorityCommitment,
      config.lockedCollateralCommitment ]
    commitments.all (fun digest => digest.any (fun word => decide (word ≠ 0))) = true ∧
      DigestListPairwiseDistinct commitments ∧
      config.collateralDecimals ≤ 18 ∧ config.collateralScale = 10 ^ config.collateralDecimals

def exactV8StablecoinMintPolicyValid
    (config : V8StablecoinConfigOpening) (parentHeight : Nat) : Prop :=
  config.active = 1 ∧ config.enabledAt ≤ parentHeight ∧
    (config.retiredPresent = 1 →
      config.enabledAt < config.retiredAt ∧ parentHeight < config.retiredAt) ∧
    stablecoinV8RatioScalePpm ≤ config.minCollateralRatioPpm ∧
    config.oraclePriceNumerator ≠ 0 ∧ config.oraclePriceDenominator ≠ 0 ∧
    config.oracleSubmittedAt ≤ parentHeight ∧
    parentHeight - config.oracleSubmittedAt ≤ config.oracleMaxAge ∧
    config.attestationCreatedAt ≤ parentHeight ∧ config.attestationPresent = 1 ∧
    parentHeight - config.attestationCreatedAt ≤ config.attestationMaxAge ∧
    config.attestationDisputed = 0

def exactV8StablecoinDisabledValid
    (context : V8StablecoinContext) (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) : Prop :=
  stablePublic.parentHeight = context.parentHeight ∧
    stablePublic.parentHeight < stablecoinScalarBound ∧
    stablePublic.assetId = 0 ∧ stablePublic.policyVersion = 0 ∧ stablePublic.magnitude = 0 ∧
    StableZeroWords stablePublic.actionIntent ∧ stablePublic.beforeRoot = context.currentRoot ∧
    stablePublic.afterRoot = context.currentRoot ∧ stablePublic.after.epochId = 0 ∧
    stablePublic.after.mintedInEpoch = 0 ∧ stablePublic.after.totalDebt = 0 ∧
    stablePublic.after.sequence = 0 ∧ StableZeroWords stablePublic.issuerAuthorization ∧
    StableCanonicalWords 94 witness.words ∧ StableZeroWords witness.words

def exactV8StablecoinEnabledValid
    (context : V8StablecoinContext) (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) : Prop :=
  let config := decodeV8StablecoinConfig witness
  let before := decodeV8StablecoinBefore witness
  let siblings := decodeV8StablecoinSiblings witness
  let issuerSecret := decodeV8StablecoinIssuerSecret witness
  let configDigest := exactV8StablecoinConfigDigest config
  let currentEpoch := stablePublic.parentHeight / (2 ^ stablecoinV8EpochHeightShift)
  let mintBase := if before.epochId = currentEpoch then before.mintedInEpoch else 0
  CanonicalV8StablecoinWitnessEncoding witness ∧
    stablePublic.parentHeight = context.parentHeight ∧
    stablePublic.parentHeight < stablecoinScalarBound ∧
    stablePublic.after.epochId < stablecoinScalarBound ∧
    stablePublic.after.sequence < stablecoinScalarBound ∧
    stablePublic.beforeRoot = context.currentRoot ∧ StableNonzeroWords stablePublic.actionIntent ∧
    stablePublic.actionIntent = context.expectedActionIntent ∧
    0 < stablePublic.magnitude ∧ stablePublic.magnitude < stablecoinValueBound ∧
    stablePublic.assetId = config.assetId ∧ stablePublic.policyVersion = config.policyVersion ∧
    exactV8StablecoinCommonValid config before ∧
    exactV8StablecoinRoot stablePublic.assetId configDigest before siblings =
      stablePublic.beforeRoot ∧
    before.epochId ≤ currentEpoch ∧
    match stablePublic.direction with
    | .disabled => False
    | .mint =>
        exactV8StablecoinMintPolicyValid config stablePublic.parentHeight ∧
          StableNonzeroWords issuerSecret ∧
          exactV8StablecoinIssuerCommitment stablePublic.assetId stablePublic.policyVersion
              issuerSecret =
            config.issuerCommitment ∧
          exactV8StablecoinIssuerAuthorization stablePublic.actionIntent issuerSecret =
            stablePublic.issuerAuthorization ∧
          stablePublic.after.epochId = currentEpoch ∧
          stablePublic.after.mintedInEpoch = mintBase + stablePublic.magnitude ∧
          stablePublic.after.mintedInEpoch ≤ config.maxMintPerEpoch ∧
          stablePublic.after.totalDebt = before.totalDebt + stablePublic.magnitude ∧
          stablePublic.after.totalDebt < stablecoinValueBound ∧
          stablePublic.after.sequence = before.sequence + 1 ∧
          stablePublic.after.totalDebt * config.oraclePriceDenominator *
              config.minCollateralRatioPpm ≤
            config.collateralAmount * config.oraclePriceNumerator * stablecoinV8RatioScalePpm ∧
          exactV8StablecoinRoot stablePublic.assetId configDigest stablePublic.after siblings =
            stablePublic.afterRoot
    | .burn =>
        StableZeroWords issuerSecret ∧ StableZeroWords stablePublic.issuerAuthorization ∧
          stablePublic.after.epochId = currentEpoch ∧
          stablePublic.after.mintedInEpoch = mintBase ∧
          stablePublic.magnitude ≤ before.totalDebt ∧
          stablePublic.after.totalDebt = before.totalDebt - stablePublic.magnitude ∧
          stablePublic.after.sequence = before.sequence + 1 ∧
          exactV8StablecoinRoot stablePublic.assetId configDigest stablePublic.after siblings =
            stablePublic.afterRoot

def exactV8StableTransition
    (context : V8StablecoinContext) (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) : Prop :=
  match stablePublic.direction with
  | .disabled => exactV8StablecoinDisabledValid context stablePublic witness
  | .mint => exactV8StablecoinEnabledValid context stablePublic witness
  | .burn => exactV8StablecoinEnabledValid context stablePublic witness

/-!
The transcript framing and six-word projection below are executable.  The only remaining external
primitive interpretation is `rfc7693Blake2b384`: the native, unkeyed 48-byte digest-size instance
of RFC 7693 BLAKE2b.  No security or implementation claim is inferred from this opaque symbol.
-/

def blake2b384FrameV1Bytes : List Nat :=
  [104, 101, 103, 101, 109, 111, 110, 46, 98, 108, 97, 107, 101, 50,
    98, 45, 51, 56, 52, 46, 102, 114, 97, 109, 101, 45, 118, 49]

def ciphertextHashV2DomainBytes : List Nat :=
  [104, 101, 103, 101, 109, 111, 110, 46, 116, 114, 97, 110, 115, 97,
    99, 116, 105, 111, 110, 46, 99, 105, 112, 104, 101, 114, 116, 101,
    120, 116, 45, 104, 97, 115, 104, 46, 118, 50]

def u64LittleEndianBytes (value : Nat) : List Nat :=
  (List.range 8).map fun byte => (value / (2 ^ (8 * byte))) % 256

def exactV8CiphertextHashFrame (ciphertext : CiphertextBytes) : List Nat :=
  blake2b384FrameV1Bytes ++ u64LittleEndianBytes ciphertextHashV2DomainBytes.length ++
    ciphertextHashV2DomainBytes ++ u64LittleEndianBytes ciphertext.length ++ ciphertext

/-- Sole external cryptographic computation in the exact ciphertext commitment definition. -/
opaque rfc7693Blake2b384 : List Nat → List Nat

def bytesToNatBigEndian (bytes : List Nat) : Nat :=
  bytes.foldl (fun value byte => value * 256 + byte) 0

def blake2b384DigestToCanonicalWords (digest : List Nat) : CiphertextCommitment :=
  (List.range ciphertextCommitmentWords).map fun limb =>
    bytesToNatBigEndian ((digest.drop (limb * 8)).take 8) % fieldModulus

def exactV8CiphertextCommitment (ciphertext : CiphertextBytes) : CiphertextCommitment :=
  blake2b384DigestToCanonicalWords
    (rfc7693Blake2b384 (exactV8CiphertextHashFrame ciphertext))

def ciphertextV8KatBytes : CiphertextBytes :=
  [104, 101, 103, 101, 109, 111, 110, 32, 99, 105, 112, 104, 101, 114, 116,
    101, 120, 116, 32, 104, 97, 115, 104, 32, 118, 50, 32, 75, 65, 84]

def ciphertextV8KatExpectedDigestBytes : List Nat :=
  [ 0x03, 0xcb, 0x27, 0x8f, 0x4e, 0x6b, 0x79, 0x9a,
    0xac, 0x41, 0xa8, 0xe4, 0x4d, 0x53, 0xd4, 0xb0,
    0xc1, 0x6b, 0x44, 0xe6, 0x99, 0xf5, 0x73, 0x5b,
    0x0a, 0x1c, 0x52, 0xd9, 0xa0, 0xc1, 0x52, 0xd9,
    0xad, 0x65, 0x40, 0xf1, 0xf1, 0xcc, 0x3e, 0x87,
    0xa1, 0xc5, 0x3a, 0xe6, 0xbe, 0xd3, 0x96, 0x73 ]

def ciphertextV8KatExpectedCommitmentWords : CiphertextCommitment :=
  [ 273355698835519898, 12412387746513147056, 13937309229044298587,
    728548334385582809, 12494464149097299591, 11656787973236823667 ]

theorem ciphertext_v8_kat_frame_is_exact :
    (exactV8CiphertextHashFrame ciphertextV8KatBytes).length = 112 ∧
      (exactV8CiphertextHashFrame ciphertextV8KatBytes).take 28 = blake2b384FrameV1Bytes ∧
      ((exactV8CiphertextHashFrame ciphertextV8KatBytes).drop 36).take 38 =
        ciphertextHashV2DomainBytes := by
  native_decide

theorem ciphertext_v8_kat_projection_is_exact :
    blake2b384DigestToCanonicalWords ciphertextV8KatExpectedDigestBytes =
      ciphertextV8KatExpectedCommitmentWords := by
  native_decide

def exactV8SemanticPrimitives : V8SemanticPrimitives :=
  { noteCommitment := exactV8NoteCommitment
    transactionPrf := exactV8TransactionPrf
    nullifier := exactV8Nullifier
    merkleRoot := exactV8MerkleRoot
    actionIntent := exactV8ActionIntent
    policyRoot := exactV8PolicyRoot
    accumulatorDigest := exactV8AccumulatorDigest
    valueLockDigest := exactV8ValueLockDigest
    stableTransition := exactV8StableTransition
    ciphertextCommitment := exactV8CiphertextCommitment }

/-- The Poseidon2 primitives above are executable. -/
def checkedInExactPoseidon2PrimitiveInterpretationAvailable : Bool := true

/-- The complete typed stablecoin transition above is executable. -/
def checkedInExactStablecoinTransitionInterpretationAvailable : Bool := true

/-- Ciphertext framing, domain, length prefixes, and six-word projection are executable. -/
def checkedInExactCiphertextFramingAndProjectionAvailable : Bool := true

/-- Full primitive interpretation still relies on the external RFC 7693 BLAKE2b computation. -/
def checkedInExactPrimitiveInterpretationRefinementAvailable : Bool := false

/-! Executable stablecoin known-answer fixtures shared with the Rust refinement test. -/

def stablecoinV8KatTagged (base : Nat) : Digest :=
  (List.range digestWords).map fun limb => base + limb

def stablecoinV8KatIssuerSecret : Digest := stablecoinV8KatTagged 1
def stablecoinV8KatIntent : Digest := stablecoinV8KatTagged 11

def stablecoinV8KatConfig : V8StablecoinConfigOpening :=
  { assetId := 1001
    policyVersion := 7
    active := 1
    enabledAt := 1
    retiredPresent := 1
    retiredAt := 20000
    issuerCommitment := exactV8StablecoinIssuerCommitment 1001 7 stablecoinV8KatIssuerSecret
    minCollateralRatioPpm := 1500000
    maxMintPerEpoch := 1000000
    oracleSubmittedAt := 8900
    oracleMaxAge := 500
    oraclePriceNumerator := 2
    oraclePriceDenominator := 1
    collateralAmount := 10000
    attestationCreatedAt := 8800
    attestationDisputed := 0
    attestationPresent := 1
    attestationMaxAge := 500
    policyAdminCommitment := stablecoinV8KatTagged 101
    oracleAuthorityCommitment := stablecoinV8KatTagged 201
    attestationAuthorityCommitment := stablecoinV8KatTagged 301
    collateralAssetId := 0
    collateralDecimals := 6
    collateralScale := 1000000
    lockedCollateralCommitment := stablecoinV8KatTagged 401 }

def stablecoinV8KatBefore : V8StablecoinCounters :=
  { epochId := 2, mintedInEpoch := 100, totalDebt := 1000, sequence := 9 }

def stablecoinV8KatSiblings : List Digest :=
  [ stablecoinV8KatTagged 601, stablecoinV8KatTagged 701,
    stablecoinV8KatTagged 801, stablecoinV8KatTagged 901 ]

def stablecoinV8KatConfigDigest : Digest := exactV8StablecoinConfigDigest stablecoinV8KatConfig
def stablecoinV8KatBeforeRoot : Digest :=
  exactV8StablecoinRoot 1001 stablecoinV8KatConfigDigest stablecoinV8KatBefore
    stablecoinV8KatSiblings

def stablecoinV8KatWitness (issuerSecret : Digest) : V8StablecoinWitness :=
  { words := encodeV8StablecoinConfig stablecoinV8KatConfig ++
      [ stablecoinV8KatBefore.epochId, stablecoinV8KatBefore.mintedInEpoch,
        stablecoinV8KatBefore.totalDebt, stablecoinV8KatBefore.sequence ] ++
      stablecoinV8KatSiblings.flatten ++ issuerSecret }

def stablecoinV8KatContext : V8StablecoinContext :=
  { currentRoot := stablecoinV8KatBeforeRoot
    parentHeight := 9000
    expectedActionIntent := stablecoinV8KatIntent }

def stablecoinV8MintKatAfter : V8StablecoinCounters :=
  { epochId := 2, mintedInEpoch := 125, totalDebt := 1025, sequence := 10 }

def stablecoinV8BurnKatAfter : V8StablecoinCounters :=
  { epochId := 2, mintedInEpoch := 100, totalDebt := 975, sequence := 10 }

def stablecoinV8MintKatPublic : V8StablecoinPublic :=
  { direction := .mint
    assetId := 1001
    policyVersion := 7
    magnitude := 25
    actionIntent := stablecoinV8KatIntent
    parentHeight := 9000
    beforeRoot := stablecoinV8KatBeforeRoot
    afterRoot := exactV8StablecoinRoot 1001 stablecoinV8KatConfigDigest
      stablecoinV8MintKatAfter stablecoinV8KatSiblings
    after := stablecoinV8MintKatAfter
    issuerAuthorization := exactV8StablecoinIssuerAuthorization
      stablecoinV8KatIntent stablecoinV8KatIssuerSecret }

def stablecoinV8BurnKatPublic : V8StablecoinPublic :=
  { direction := .burn
    assetId := 1001
    policyVersion := 7
    magnitude := 25
    actionIntent := stablecoinV8KatIntent
    parentHeight := 9000
    beforeRoot := stablecoinV8KatBeforeRoot
    afterRoot := exactV8StablecoinRoot 1001 stablecoinV8KatConfigDigest
      stablecoinV8BurnKatAfter stablecoinV8KatSiblings
    after := stablecoinV8BurnKatAfter
    issuerAuthorization := List.replicate digestWords 0 }

section StablecoinKatDecidability

local instance (word : Nat) : Decidable (BooleanWord word) := by
  unfold BooleanWord
  infer_instance

local instance (count : Nat) (words : List Nat) : Decidable (StableCanonicalWords count words) := by
  unfold StableCanonicalWords
  infer_instance

local instance (words : List Nat) : Decidable (StableZeroWords words) := by
  unfold StableZeroWords
  infer_instance

local instance (words : List Nat) : Decidable (StableNonzeroWords words) := by
  unfold StableNonzeroWords
  infer_instance

local instance (digests : List Digest) : Decidable (DigestListPairwiseDistinct digests) := by
  unfold DigestListPairwiseDistinct
  infer_instance

local instance (witness : V8StablecoinWitness) :
    Decidable (CanonicalV8StablecoinWitnessEncoding witness) := by
  unfold CanonicalV8StablecoinWitnessEncoding
  infer_instance

local instance (config : V8StablecoinConfigOpening) (before : V8StablecoinCounters) :
    Decidable (exactV8StablecoinCommonValid config before) := by
  unfold exactV8StablecoinCommonValid
  infer_instance

local instance (config : V8StablecoinConfigOpening) (parentHeight : Nat) :
    Decidable (exactV8StablecoinMintPolicyValid config parentHeight) := by
  unfold exactV8StablecoinMintPolicyValid
  infer_instance

local instance (context : V8StablecoinContext) (stable : V8StablecoinPublic)
    (witness : V8StablecoinWitness) :
    Decidable (exactV8StablecoinDisabledValid context stable witness) := by
  unfold exactV8StablecoinDisabledValid
  infer_instance

local instance (context : V8StablecoinContext) (stable : V8StablecoinPublic)
    (witness : V8StablecoinWitness) :
    Decidable (exactV8StablecoinEnabledValid context stable witness) := by
  unfold exactV8StablecoinEnabledValid
  cases stable.direction <;> infer_instance

local instance (context : V8StablecoinContext) (stable : V8StablecoinPublic)
    (witness : V8StablecoinWitness) :
    Decidable (exactV8StableTransition context stable witness) := by
  unfold exactV8StableTransition
  cases stable.direction <;> infer_instance

theorem stablecoin_v8_kat_config_has_exact_word_count :
    (encodeV8StablecoinConfig stablecoinV8KatConfig).length = 55 := by
  native_decide

theorem stablecoin_v8_mint_kat_accepts :
    exactV8StableTransition stablecoinV8KatContext stablecoinV8MintKatPublic
      (stablecoinV8KatWitness stablecoinV8KatIssuerSecret) := by
  native_decide

theorem stablecoin_v8_burn_kat_accepts :
    exactV8StableTransition stablecoinV8KatContext stablecoinV8BurnKatPublic
      (stablecoinV8KatWitness (List.replicate digestWords 0)) := by
  native_decide

end StablecoinKatDecidability

def CanonicalPublicStatement
    (primitives : V8SemanticPrimitives) (statement : V8PublicStatement) : Prop :=
  statement.inputFlags.length = inputCount ∧ statement.outputFlags.length = outputCount ∧
    (∀ flag, flag ∈ statement.inputFlags → BooleanWord flag) ∧
    (∀ flag, flag ∈ statement.outputFlags → BooleanWord flag) ∧
    statement.nullifiers.length = inputCount ∧
    (∀ digest, digest ∈ statement.nullifiers → ExactWords digestWords digest) ∧
    statement.commitments.length = outputCount ∧
    (∀ digest, digest ∈ statement.commitments → ExactWords digestWords digest) ∧
    statement.ciphertextCommitments.length = outputCount ∧
    (∀ digest, digest ∈ statement.ciphertextCommitments →
      ExactWords ciphertextCommitmentWords digest) ∧
    statement.fee < valueBound ∧ statement.valueBalanceSign = 0 ∧
    statement.valueBalanceMagnitude = 0 ∧ ExactWords digestWords statement.merkleRoot ∧
    CanonicalBalanceAssets statement.balanceAssets ∧
    CanonicalCompatibility statement.compatibility statement.stablecoin ∧
    statement.version = circuitVersion ∧ statement.cryptoSuite = cryptoSuiteEta ∧
    statement.stablecoin.parentHeight < stablecoinScalarBound ∧
    ExactWords digestWords statement.stablecoin.actionIntent ∧
    ExactWords digestWords statement.stablecoin.beforeRoot ∧
    ExactWords digestWords statement.stablecoin.afterRoot ∧
    ExactWords digestWords statement.stablecoin.issuerAuthorization ∧
    PublicSlotShapeValid statement ∧
    (flagAt statement.inputFlags 0 = 1 → flagAt statement.inputFlags 1 = 1 →
      digestAt statement.nullifiers 0 ≠ digestAt statement.nullifiers 1) ∧
    (statement.stablecoin.direction ≠ .disabled →
      statement.stablecoin.actionIntent = primitives.actionIntent statement) ∧
    ExactWords publicWordCount (encodePublicStatement statement)

def OneHotSelectorForAsset
    (active : Nat) (note : V8NoteOpening) (selectors assets : List Nat) : Prop :=
  selectors.length = balanceSlotCount ∧
    (∀ selector, selector ∈ selectors → BooleanWord selector) ∧
    if active = 0 then ZeroWords selectors ∧ ZeroNoteOpening note
    else selectors.sum = 1 ∧
      ∃ slot, slot < balanceSlotCount ∧ wordAt selectors slot = 1 ∧
        wordAt assets slot = note.assetId

def ZeroInputWitness (input : V8InputWitness) : Prop :=
  input.active = 0 ∧ ExactWords 4 input.spendKey ∧ ZeroWords input.spendKey ∧
    ZeroNoteOpening input.note ∧
    input.position = 0 ∧ input.siblings.length = merkleDepth ∧
    (∀ digest, digest ∈ input.siblings → ExactWords digestWords digest ∧ ZeroWords digest) ∧
    input.balanceSelectors.length = balanceSlotCount ∧ ZeroWords input.balanceSelectors

def ZeroOutputWitness (output : V8OutputWitness) : Prop :=
  output.active = 0 ∧ ZeroNoteOpening output.note ∧
    output.balanceSelectors.length = balanceSlotCount ∧ ZeroWords output.balanceSelectors

def CanonicalWitnessShape (statement : V8PublicStatement) (witness : V8Witness) : Prop :=
  witness.inputs.length = inputCount ∧ witness.outputs.length = outputCount ∧
    (∀ slot, slot < inputCount →
      let input := witness.inputs.getD slot
        { active := 0, spendKey := [], note :=
          { value := 0, assetId := 0, recipientKey := [], authorizationKey := [], rho := [],
            randomness := [] }, position := 0, siblings := [], balanceSelectors := [] }
      input.active = flagAt statement.inputFlags slot ∧
      (if input.active = 0 then ZeroInputWitness input
       else CanonicalNoteOpening input.note ∧ ExactWords 4 input.spendKey ∧
         NonzeroWords input.spendKey ∧ input.position < 2 ^ merkleDepth ∧
         input.siblings.length = merkleDepth ∧
         (∀ digest, digest ∈ input.siblings → ExactWords digestWords digest) ∧
         OneHotSelectorForAsset input.active input.note input.balanceSelectors
           statement.balanceAssets)) ∧
    (∀ slot, slot < outputCount →
      let output := witness.outputs.getD slot
        { active := 0, note :=
          { value := 0, assetId := 0, recipientKey := [], authorizationKey := [], rho := [],
            randomness := [] }, balanceSelectors := [] }
      output.active = flagAt statement.outputFlags slot ∧
      (if output.active = 0 then ZeroOutputWitness output
       else CanonicalNoteOpening output.note ∧
         OneHotSelectorForAsset output.active output.note output.balanceSelectors
           statement.balanceAssets)) ∧
    (flagAt statement.inputFlags 0 = 1 → flagAt statement.inputFlags 1 = 1 →
      (witness.inputs.getD 0 default).spendKey = (witness.inputs.getD 1 default).spendKey) ∧
    ExactWords 94 witness.stablecoin.words

def changedApprovalSlots (current next : V8AccumulatorOpening) : Nat :=
  (List.zip current.approvedSlots next.approvedSlots).countP fun pair => pair.1 ≠ pair.2

def noApprovalCleared (current next : V8AccumulatorOpening) : Prop :=
  ∀ slot, slot < signerCountMaximum →
    wordAt current.approvedSlots slot = 1 → wordAt next.approvedSlots slot = 1

def V8AuthorizationValid
    (primitives : V8SemanticPrimitives) (statement : V8PublicStatement)
    (witness : V8Witness) : Prop :=
  let auth := witness.authorization
  let sharedSpendKey := (witness.inputs.getD 0 default).spendKey
  let legacy := primitives.transactionPrf sharedSpendKey
  match auth.mode with
  | .singleKey =>
      ZeroAccumulator auth.current ∧ ZeroAccumulator auth.next ∧
        ZeroSignerTags auth.policySignerTags ∧
        ∀ slot, slot < inputCount → flagAt statement.inputFlags slot = 1 →
          (witness.inputs.getD slot default).note.authorizationKey = (legacy.drop 1).take 4
  | .approvalStep =>
      statement.inputFlags = [1, 1] ∧ flagAt statement.outputFlags 0 = 1 ∧
        CanonicalAccumulator auth.current ∧ CanonicalAccumulator auth.next ∧
        CanonicalSignerTags auth ∧
        auth.current.policyRoot = primitives.policyRoot auth.policySignerTags
          auth.current.threshold auth.current.signerCount ∧
        auth.next.policyRoot = auth.current.policyRoot ∧
        auth.next.intentDigest = auth.current.intentDigest ∧
        auth.next.threshold = auth.current.threshold ∧
        auth.next.signerCount = auth.current.signerCount ∧
        auth.next.approvalCount = auth.current.approvalCount + 1 ∧
        changedApprovalSlots auth.current auth.next = 1 ∧ noApprovalCleared auth.current auth.next ∧
        (witness.inputs.getD 0 default).note.authorizationKey =
          (primitives.accumulatorDigest auth.current).take 4 ∧
        (witness.inputs.getD 1 default).note.authorizationKey = (legacy.drop 1).take 4 ∧
        (witness.outputs.getD 0 default).note.authorizationKey =
          (primitives.accumulatorDigest auth.next).take 4
  | .finalThresholdSpend =>
      statement.inputFlags = [1, 1] ∧ CanonicalAccumulator auth.current ∧
        ZeroAccumulator auth.next ∧ CanonicalSignerTags auth ∧
        auth.current.policyRoot = primitives.policyRoot auth.policySignerTags
          auth.current.threshold auth.current.signerCount ∧
        auth.current.approvalCount ≥ auth.current.threshold ∧
        auth.current.intentDigest = primitives.actionIntent statement ∧
        (witness.inputs.getD 0 default).note.authorizationKey =
          (primitives.valueLockDigest auth.current).take 4 ∧
        (witness.inputs.getD 1 default).note.authorizationKey =
          (primitives.accumulatorDigest auth.current).take 4

/--
Exact authorization-mode-dependent scalar absorbed by the V8 nullifier call.  The single-key
path uses limb zero of the transaction PRF.  Approval input zero uses limb four of the current
accumulator digest.  Final spend uses limb four of the value-lock digest for input zero and limb
four of the current accumulator digest for input one.  This mirrors calls 36 and 72 of
`HGV8RP03`; treating every mode as the legacy PRF is not the V8 relation.
-/
def effectiveInputAuthorizationPrf
    (primitives : V8SemanticPrimitives) (witness : V8Witness) (slot : Nat) : Nat :=
  let auth := witness.authorization
  let spendKey := (witness.inputs.getD slot default).spendKey
  match auth.mode with
  | .singleKey => wordAt (primitives.transactionPrf spendKey) 0
  | .approvalStep =>
      if slot = 0 then wordAt (primitives.accumulatorDigest auth.current) 4
      else wordAt (primitives.transactionPrf spendKey) 0
  | .finalThresholdSpend =>
      if slot = 0 then wordAt (primitives.valueLockDigest auth.current) 4
      else wordAt (primitives.accumulatorDigest auth.current) 4

def V8CryptographicLinksValid
    (primitives : V8SemanticPrimitives) (statement : V8PublicStatement)
    (witness : V8Witness) : Prop :=
  (∀ slot, slot < inputCount → flagAt statement.inputFlags slot = 1 →
    let input := witness.inputs.getD slot default
    let noteCommitment := primitives.noteCommitment input.note
    primitives.merkleRoot noteCommitment input.position input.siblings = statement.merkleRoot ∧
      primitives.nullifier slot (effectiveInputAuthorizationPrf primitives witness slot)
          input.position input.note.rho = digestAt statement.nullifiers slot) ∧
  (∀ slot, slot < outputCount → flagAt statement.outputFlags slot = 1 →
    primitives.noteCommitment (witness.outputs.getD slot default).note =
      digestAt statement.commitments slot) ∧
  V8AuthorizationValid primitives statement witness

def inputValueForAsset (witness : V8Witness) (asset : Nat) : Nat :=
  witness.inputs.foldl (fun total input =>
    if input.active = 1 ∧ input.note.assetId = asset then total + input.note.value else total) 0

def outputValueForAsset (witness : V8Witness) (asset : Nat) : Nat :=
  witness.outputs.foldl (fun total output =>
    if output.active = 1 ∧ output.note.assetId = asset then total + output.note.value else total) 0

def V8BalanceValid (statement : V8PublicStatement) (witness : V8Witness) : Prop :=
  ∀ slot, slot < balanceSlotCount →
    let asset := wordAt statement.balanceAssets slot
    asset = balancePaddingAssetId ∨
      if asset = nativeAssetId then
        inputValueForAsset witness asset = outputValueForAsset witness asset + statement.fee
      else if statement.compatibility.enabled = 1 ∧
          statement.compatibility.assetId = asset then
        if statement.compatibility.issuanceSign = 1 then
          inputValueForAsset witness asset + statement.compatibility.issuanceMagnitude =
            outputValueForAsset witness asset
        else
          inputValueForAsset witness asset =
            outputValueForAsset witness asset + statement.compatibility.issuanceMagnitude
      else inputValueForAsset witness asset = outputValueForAsset witness asset

def derivedRelationContext (statement : V8PublicStatement) : V8StablecoinContext :=
  { currentRoot := statement.stablecoin.beforeRoot
    parentHeight := statement.stablecoin.parentHeight
    expectedActionIntent :=
      if statement.stablecoin.direction = .disabled then List.replicate digestWords 0
      else statement.stablecoin.actionIntent }

/-- Fixed higher-level relation semantics.  This is not a field of any refinement receipt. -/
def V8RelationSemanticValid
    (primitives : V8SemanticPrimitives) (statement : V8PublicStatement)
    (witness : V8Witness) : Prop :=
  CanonicalPublicStatement primitives statement ∧
    CanonicalWitnessShape statement witness ∧
    V8CryptographicLinksValid primitives statement witness ∧
    V8BalanceValid statement witness ∧
    primitives.stableTransition (derivedRelationContext statement)
      statement.stablecoin witness.stablecoin

def ConsensusContextMatches
    (context : V8StablecoinContext) (statement : V8PublicStatement) : Prop :=
  context.currentRoot = statement.stablecoin.beforeRoot ∧
    context.parentHeight = statement.stablecoin.parentHeight ∧
    context.expectedActionIntent = (derivedRelationContext statement).expectedActionIntent

def InlineCiphertextsMatch
    (primitives : V8SemanticPrimitives) (statement : V8PublicStatement)
    (ciphertexts : V8InlineCiphertexts) : Prop :=
  ciphertexts.slots.length = outputCount ∧
    ∀ slot, slot < outputCount →
      match flagAt statement.outputFlags slot, ciphertexts.slots.getD slot none with
      | 0, none => True
      | 1, some bytes =>
          bytes.length = inlineCiphertextBytes ∧
            (∀ byte, byte ∈ bytes → byte < 256) ∧
            primitives.ciphertextCommitment bytes =
              statement.ciphertextCommitments.getD slot []
      | _, _ => False

def V8FullActionSemanticValid
    (primitives : V8SemanticPrimitives) (context : V8StablecoinContext)
    (ciphertexts : V8InlineCiphertexts) (statement : V8PublicStatement)
    (witness : V8Witness) : Prop :=
  V8RelationSemanticValid primitives statement witness ∧
    ConsensusContextMatches context statement ∧
    InlineCiphertextsMatch primitives statement ciphertexts

/-- Fixed private-relation semantic target used by HGV8RP03 adequacy receipts. -/
def ExactV8RelationSemanticValid
    (statement : V8PublicStatement) (witness : V8Witness) : Prop :=
  V8RelationSemanticValid exactV8SemanticPrimitives statement witness

/-- Fixed full-action target after consensus context and inline ciphertext admission. -/
def ExactV8FullActionSemanticValid
    (context : V8StablecoinContext) (ciphertexts : V8InlineCiphertexts)
    (statement : V8PublicStatement) (witness : V8Witness) : Prop :=
  V8FullActionSemanticValid exactV8SemanticPrimitives context ciphertexts statement witness

structure SemanticFamily where
  name : String
  externalToPrivateRelation : Bool
deriving DecidableEq, Repr, Inhabited

def exactSemanticFamilies : List SemanticFamily :=
  [ { name := "canonical_public_statement", externalToPrivateRelation := false },
    { name := "two_input_two_output_all_activity_masks", externalToPrivateRelation := false },
    { name := "note_commitments", externalToPrivateRelation := false },
    { name := "nullifiers_and_depth32_merkle", externalToPrivateRelation := false },
    { name := "all_authorization_modes", externalToPrivateRelation := false },
    { name := "action_intent", externalToPrivateRelation := false },
    { name := "per_asset_balance", externalToPrivateRelation := false },
    { name := "stablecoin_transition", externalToPrivateRelation := false },
    { name := "inline_blake2b384_ciphertexts", externalToPrivateRelation := true },
    { name := "consensus_stablecoin_context", externalToPrivateRelation := true } ]

theorem exact_semantic_scope_counts_are_pinned :
    inputCount = 2 ∧ outputCount = 2 ∧ 2 ^ (inputCount + outputCount) = 16 ∧
      signerCountMaximum = 6 ∧ merkleDepth = 32 ∧ publicWordCount = 120 ∧
      typedWitnessWordCount = 721 ∧ packedWitnessWordCount = 43904 ∧
      exactSemanticFamilies.length = 10 := by
  decide

end Poseidon2V8SemanticSpecification
end Transaction
end Hegemon
