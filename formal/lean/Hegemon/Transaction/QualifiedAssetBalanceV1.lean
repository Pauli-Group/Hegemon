import Std
import Hegemon.Policy.BoundedPrivateSpend

/-!
Exact-natural-number specification for the development qualified-asset slice.

The shape is one optional asset input, one native fee input, one asset recipient,
optional asset change, and optional native change. Only Transfer, Mint, and Burn
are allowed. A missing asset input is allowed only for Mint. Every asset note,
including change, needs a current credential. Native fee notes are ordinary
notes and are outside the asset administrator's credential and freeze powers.

This file proves properties of the explicit relation below. It does not prove
that a Rust compiler, field circuit, parser, Merkle hash, proof verifier, or
storage writer implements it. `ProofSoundness`, `RegistryRootBindingAt`, and
`CredentialRootBindingAt` name those cryptographic interfaces separately. They
are hypotheses to the accepted-proof theorem, not declared axioms or booleans
standing for the conclusion. All balances and collateral products are Nat;
lifting bounded field equations into this model remains a separate obligation.
Recovery, HTLC, and multisig routes have no acceptance branch in this model.
-/

namespace Hegemon.Transaction.QualifiedAssetBalanceV1

set_option autoImplicit false

abbrev Digest := Fin 7 → Nat
abbrev RecipientKey := Fin 4 → Nat
abbrev Secret := Fin 7 → Nat
abbrev MerklePath := List Digest

def zeroDigest : Digest := fun _ => 0
def nativeAsset : Nat := 0
def valueBound : Nat := 2 ^ 56
def scalarBound : Nat := 2 ^ 63
def productBound : Nat := 2 ^ 128
def ratioScale : Nat := 1000000

inductive Route where
  | transfer | mint | burn
  | htlcLock | htlcClaim | htlcRefund | recovery | approval | final
  deriving DecidableEq, Repr

def Supported : Route → Prop
  | .transfer | .mint | .burn => True
  | _ => False

structure Note where
  value : Nat
  assetId : Nat
  recipientKey : RecipientKey
  /-- Full seven-limb owner, not its four-limb authorization-key prefix. -/
  owner : Digest
  rho : Fin 4 → Nat
  /-- The fourth randomness limb; its first three limbs carry the full owner. -/
  blinding : Nat

structure CredentialLeaf where
  assetId : Nat
  policyVersion : Nat
  recipientKey : RecipientKey
  owner : Digest
  expiresAt : Nat

structure CredentialEvidence where
  leaf : CredentialLeaf
  path : MerklePath

structure Counters where
  epoch : Nat
  mintedInEpoch : Nat
  debt : Nat
  sequence : Nat
  deriving DecidableEq

structure Policy where
  assetId : Nat
  version : Nat
  frozen : Bool
  mintEnabled : Bool
  active : Bool
  enabledAt : Nat
  retiredAt : Option Nat
  issuerCommitment : Digest
  policyAdminCommitment : Digest
  oracleAuthorityCommitment : Digest
  attestationAuthorityCommitment : Digest
  collateralCustodyCommitment : Digest
  maxMintPerEpoch : Nat
  collateralAmount : Nat
  minCollateralRatio : Nat
  oracleNumerator : Nat
  oracleDenominator : Nat
  oracleSubmittedAt : Nat
  oracleMaxAge : Nat
  attestationCreatedAt : Nat
  attestationMaxAge : Nat
  attestationPresent : Bool
  attestationDisputed : Bool

structure RegistryRow where
  policy : Policy
  counters : Counters

def authorityCommitments (policy : Policy) : List Digest :=
  [policy.issuerCommitment, policy.policyAdminCommitment,
    policy.oracleAuthorityCommitment, policy.attestationAuthorityCommitment,
    policy.collateralCustodyCommitment]

/-- Common policy bounds and separation of administration, issuance, oracle,
attestation, and collateral custody. Hash security remains external. -/
def PolicyWellFormed (policy : Policy) : Prop :=
  policy.assetId < 2 ^ 32 ∧ policy.version < 2 ^ 32 ∧
  policy.maxMintPerEpoch < valueBound ∧ policy.collateralAmount < valueBound ∧
  policy.minCollateralRatio < 2 ^ 32 ∧
  policy.oracleNumerator < 2 ^ 32 ∧ policy.oracleDenominator < 2 ^ 32 ∧
  policy.enabledAt < scalarBound ∧
  (∀ retired, policy.retiredAt = some retired → retired < scalarBound) ∧
  policy.oracleSubmittedAt < scalarBound ∧ policy.oracleMaxAge < scalarBound ∧
  policy.attestationCreatedAt < scalarBound ∧ policy.attestationMaxAge < scalarBound ∧
  (authorityCommitments policy).Nodup ∧
  (∀ commitment, commitment ∈ authorityCommitments policy → commitment ≠ zeroDigest)

structure Public where
  relationIdentity : Digest
  chainId : Digest
  parentHash : Digest
  parentHeight : Nat
  noteRoot : Digest
  registryRoot : Digest
  credentialRoot : Digest
  route : Route
  assetId : Nat
  policyVersion : Nat
  magnitude : Nat
  fee : Nat
  intent : Digest
  issuerAuthorization : Digest
  assetNullifier : Digest
  nativeNullifier : Digest
  recipientCommitment : Digest
  assetChangeCommitment : Digest
  nativeChangeCommitment : Digest
  ciphertextCommitments : Fin 3 → Digest
  afterCounters : Counters

/-- Every public action component affecting the modeled transfer is in the
intent. Credential subjects are bound to its note commitments below. The
model does not assume hash injectivity or prove a collision bound. -/
structure IntentFrame where
  relationIdentity : Digest
  chainId : Digest
  parentHash : Digest
  parentHeight : Nat
  noteRoot : Digest
  registryRoot : Digest
  credentialRoot : Digest
  route : Route
  assetId : Nat
  policyVersion : Nat
  magnitude : Nat
  fee : Nat
  assetNullifier : Digest
  nativeNullifier : Digest
  recipientCommitment : Digest
  assetChangeCommitment : Digest
  nativeChangeCommitment : Digest
  ciphertextCommitments : Fin 3 → Digest
  afterCounters : Counters

def intentFrame (p : Public) : IntentFrame :=
  { relationIdentity := p.relationIdentity, chainId := p.chainId,
    parentHash := p.parentHash, parentHeight := p.parentHeight,
    noteRoot := p.noteRoot, registryRoot := p.registryRoot,
    credentialRoot := p.credentialRoot, route := p.route,
    assetId := p.assetId, policyVersion := p.policyVersion,
    magnitude := p.magnitude, fee := p.fee,
    assetNullifier := p.assetNullifier, nativeNullifier := p.nativeNullifier,
    recipientCommitment := p.recipientCommitment,
    assetChangeCommitment := p.assetChangeCommitment,
    nativeChangeCommitment := p.nativeChangeCommitment,
    ciphertextCommitments := p.ciphertextCommitments,
    afterCounters := p.afterCounters }

/-- Abstract functions stand for domain-separated cryptographic operations.
Their membership/binding security and implementation are not proved here. -/
structure Crypto where
  registryTreeRoot : List RegistryRow → Digest
  registryPathRoot : RegistryRow → MerklePath → Digest
  credentialTreeRoot : List CredentialLeaf → Digest
  credentialPathRoot : CredentialLeaf → MerklePath → Digest
  noteCommitment : Note → Digest
  notePathRoot : Note → Nat → MerklePath → Digest
  noteNullifier : Note → Nat → Secret → Digest
  ownerCommitment : Secret → Digest
  issuerCommitment : Nat → Nat → Secret → Digest
  issuerAuthorization : Digest → Secret → Digest
  intentCommitment : IntentFrame → Digest

structure Witness where
  row : RegistryRow
  registryPath : MerklePath
  assetInput : Option Note
  assetPosition : Nat
  assetPath : MerklePath
  assetSecret : Secret
  nativeInput : Note
  nativePosition : Nat
  nativePath : MerklePath
  nativeSecret : Secret
  recipient : Note
  assetChange : Option Note
  nativeChange : Option Note
  issuerSecret : Secret

structure State where
  relationIdentity : Digest
  chainId : Digest
  parentHash : Digest
  parentHeight : Nat
  noteRoot : Digest
  registry : List RegistryRow
  credentials : List CredentialLeaf
  spentNullifiers : List Digest

def optionValue (n : Option Note) : Nat :=
  match n with | none => 0 | some note => note.value

def valueAt (asset : Nat) (n : Note) : Nat :=
  if asset = n.assetId then n.value else 0

def optionValueAt (asset : Nat) (n : Option Note) : Nat :=
  match n with | none => 0 | some note => valueAt asset note

def inputTotal (asset : Nat) (w : Witness) : Nat :=
  optionValueAt asset w.assetInput + valueAt asset w.nativeInput

def outputTotal (asset : Nat) (w : Witness) : Nat :=
  valueAt asset w.recipient + optionValueAt asset w.assetChange +
    optionValueAt asset w.nativeChange

def mintAmount (p : Public) : Nat := if p.route = .mint then p.magnitude else 0
def burnAmount (p : Public) : Nat := if p.route = .burn then p.magnitude else 0
def mintAt (asset : Nat) (p : Public) : Nat :=
  if asset = p.assetId then mintAmount p else 0
def burnAt (asset : Nat) (p : Public) : Nat :=
  if asset = p.assetId then burnAmount p else 0

def AssetParticipants (w : Witness) : List Note :=
  w.assetInput.toList ++ [w.recipient] ++ w.assetChange.toList

def CredentialFor (c : Crypto) (p : Public) (note : Note)
    (e : CredentialEvidence) : Prop :=
  e.leaf.assetId = p.assetId ∧
  e.leaf.policyVersion = p.policyVersion ∧
  e.leaf.recipientKey = note.recipientKey ∧
  e.leaf.owner = note.owner ∧
  p.parentHeight ≤ e.leaf.expiresAt ∧
  c.credentialPathRoot e.leaf e.path = p.credentialRoot

def AllCredentials (c : Crypto) (p : Public) (w : Witness) : Prop :=
  ∀ note, note ∈ AssetParticipants w → ∃ e, CredentialFor c p note e

def AmountCanonical (p : Public) : Prop :=
  match p.route with
  | .transfer => p.magnitude = 0
  | .mint | .burn => 0 < p.magnitude ∧ p.magnitude < valueBound
  | _ => False

def MintPolicy (policy : Policy) (height : Nat) : Prop :=
  policy.mintEnabled = true ∧ policy.active = true ∧
  policy.enabledAt ≤ height ∧
  (∀ retired, policy.retiredAt = some retired →
    policy.enabledAt < retired ∧ height < retired) ∧
  ratioScale ≤ policy.minCollateralRatio ∧
  0 < policy.oracleNumerator ∧ 0 < policy.oracleDenominator ∧
  policy.oracleSubmittedAt ≤ height ∧
  height ≤ policy.oracleSubmittedAt + policy.oracleMaxAge ∧
  policy.attestationPresent = true ∧ policy.attestationDisputed = false ∧
  policy.attestationCreatedAt ≤ height ∧
  height ≤ policy.attestationCreatedAt + policy.attestationMaxAge

def RoutePolicy (route : Route) (policy : Policy) (height : Nat) : Prop :=
  policy.frozen = false ∧
  match route with
  | .transfer | .burn => True
  | .mint => MintPolicy policy height
  | _ => False

def mintBase (height : Nat) (before : Counters) : Nat :=
  if before.epoch = height / 4096 then before.mintedInEpoch else 0

/-- The V8 cap/debt/epoch/collateral arithmetic, over exact naturals. Burn
uses an addition equality to prohibit truncated-natural debt underflow. -/
def CounterTransition (p : Public) (row : RegistryRow) : Prop :=
  match p.route with
  | .transfer => p.afterCounters = row.counters
  | .mint =>
      row.counters.epoch ≤ p.parentHeight / 4096 ∧
      p.afterCounters.epoch = p.parentHeight / 4096 ∧
      p.afterCounters.sequence = row.counters.sequence + 1 ∧
      p.afterCounters.mintedInEpoch = mintBase p.parentHeight row.counters + p.magnitude ∧
      p.afterCounters.mintedInEpoch ≤ row.policy.maxMintPerEpoch ∧
      p.afterCounters.debt = row.counters.debt + p.magnitude ∧
      p.afterCounters.debt < valueBound ∧
      row.policy.collateralAmount * row.policy.oracleNumerator * ratioScale < productBound ∧
      p.afterCounters.debt * row.policy.oracleDenominator * row.policy.minCollateralRatio <
        productBound ∧
      p.afterCounters.debt * row.policy.oracleDenominator * row.policy.minCollateralRatio ≤
        row.policy.collateralAmount * row.policy.oracleNumerator * ratioScale
  | .burn =>
      row.counters.epoch ≤ p.parentHeight / 4096 ∧
      p.afterCounters.epoch = p.parentHeight / 4096 ∧
      p.afterCounters.sequence = row.counters.sequence + 1 ∧
      p.afterCounters.mintedInEpoch = mintBase p.parentHeight row.counters ∧
      p.afterCounters.debt + p.magnitude = row.counters.debt
  | _ => False

def IssuerAuthorization (c : Crypto) (p : Public) (w : Witness) : Prop :=
  match p.route with
  | .mint =>
      w.issuerSecret ≠ zeroDigest ∧
      c.issuerCommitment p.assetId p.policyVersion w.issuerSecret =
        w.row.policy.issuerCommitment ∧
      c.issuerAuthorization p.intent w.issuerSecret = p.issuerAuthorization
  | .transfer | .burn =>
      w.issuerSecret = zeroDigest ∧ p.issuerAuthorization = zeroDigest
  | _ => False

def OptionalCommitment (c : Crypto) (note : Option Note) (commitment : Digest) : Prop :=
  match note with
  | none => commitment = zeroDigest
  | some n => c.noteCommitment n = commitment

/-- A semantic witness relation, not an assertion about generated field rows.
In particular note authorization and issuer-secret openings are explicit. -/
structure Relation (c : Crypto) (p : Public) (w : Witness) : Prop where
  supported : Supported p.route
  nonNative : p.assetId ≠ nativeAsset
  notPadding : p.assetId ≠ 18446744073709551615 ∧ p.assetId ≠ 4294967294
  policyAsset : w.row.policy.assetId = p.assetId
  policyVersion : w.row.policy.version = p.policyVersion
  policyWellFormed : PolicyWellFormed w.row.policy
  registryOpening : c.registryPathRoot w.row w.registryPath = p.registryRoot
  intentBinding : c.intentCommitment (intentFrame p) = p.intent
  policy : RoutePolicy p.route w.row.policy p.parentHeight
  amount : AmountCanonical p
  counters : CounterTransition p w.row
  issuer : IssuerAuthorization c p w
  inputAsset : ∀ note, w.assetInput = some note → note.assetId = p.assetId
  noDummySpend : w.assetInput = none → p.route = .mint
  inputAuthorization : ∀ note, w.assetInput = some note →
    c.ownerCommitment w.assetSecret = note.owner ∧
    c.notePathRoot note w.assetPosition w.assetPath = p.noteRoot ∧
    c.noteNullifier note w.assetPosition w.assetSecret = p.assetNullifier
  nativeInputAsset : w.nativeInput.assetId = nativeAsset
  nativeAuthorization : c.ownerCommitment w.nativeSecret = w.nativeInput.owner ∧
    c.notePathRoot w.nativeInput w.nativePosition w.nativePath = p.noteRoot ∧
    c.noteNullifier w.nativeInput w.nativePosition w.nativeSecret = p.nativeNullifier
  recipientAsset : w.recipient.assetId = p.assetId
  assetChangeAsset : ∀ note, w.assetChange = some note → note.assetId = p.assetId
  nativeChangeAsset : ∀ note, w.nativeChange = some note → note.assetId = nativeAsset
  recipientBinding : c.noteCommitment w.recipient = p.recipientCommitment
  assetChangeBinding : OptionalCommitment c w.assetChange p.assetChangeCommitment
  nativeChangeBinding : OptionalCommitment c w.nativeChange p.nativeChangeCommitment
  credentials : AllCredentials c p w
  assetBalance : optionValue w.assetInput + mintAmount p =
    w.recipient.value + optionValue w.assetChange + burnAmount p
  nativeBalance : w.nativeInput.value = optionValue w.nativeChange + p.fee
  feeBound : p.fee < valueBound
  noteBounds : ∀ note, note ∈ AssetParticipants w ∨ note = w.nativeInput ∨
    w.nativeChange = some note → note.value < valueBound
  counterBounds : w.row.counters.debt < valueBound ∧
    w.row.counters.mintedInEpoch ≤ w.row.policy.maxMintPerEpoch ∧
    w.row.policy.maxMintPerEpoch < valueBound ∧
    w.row.counters.epoch < scalarBound ∧ w.row.counters.sequence < scalarBound ∧
    p.parentHeight < scalarBound ∧ p.afterCounters.epoch < scalarBound ∧
    p.afterCounters.sequence < scalarBound

/-- State checks compare exact authenticated roots and the current parent,
not caller-supplied claims that a policy or credential is current. -/
structure Fresh (c : Crypto) (s : State) (p : Public) : Prop where
  relationIdentity : p.relationIdentity = s.relationIdentity
  chainId : p.chainId = s.chainId
  parentHash : p.parentHash = s.parentHash
  parentHeight : p.parentHeight = s.parentHeight
  noteRoot : p.noteRoot = s.noteRoot
  registryRoot : p.registryRoot = c.registryTreeRoot s.registry
  credentialRoot : p.credentialRoot = c.credentialTreeRoot s.credentials
  assetNullifierFresh : p.assetNullifier ∉ s.spentNullifiers
  nativeNullifierFresh : p.nativeNullifier ∉ s.spentNullifiers
  distinctNullifiers : p.assetNullifier ≠ p.nativeNullifier

/-- Named cryptographic assumptions at this concrete state. The model does
not turn a Merkle opening or a hash equation into unconditional membership. -/
def RegistryRootBindingAt (c : Crypto) (s : State) : Prop :=
  ∀ row path, c.registryPathRoot row path = c.registryTreeRoot s.registry →
    row ∈ s.registry

def CredentialRootBindingAt (c : Crypto) (s : State) : Prop :=
  ∀ leaf path, c.credentialPathRoot leaf path = c.credentialTreeRoot s.credentials →
    leaf ∈ s.credentials

structure ProofVerifier where
  Proof : Type
  accepts : Public → Proof → Prop

/-- Knowledge soundness for this exact semantic relation is an explicit
external premise. No backend security or compiler refinement is proved here. -/
def ProofSoundness (c : Crypto) (v : ProofVerifier) : Prop :=
  ∀ p proof, v.accepts p proof → ∃ w, Relation c p w

structure Admitted (c : Crypto) (v : ProofVerifier) (s : State)
    (p : Public) (proof : v.Proof) : Prop where
  fresh : Fresh c s p
  accepted : v.accepts p proof

private theorem option_value_at_of_shape {note : Option Note} {asset target : Nat}
    (shape : ∀ n, note = some n → n.assetId = target) :
    optionValueAt asset note = if asset = target then optionValue note else 0 := by
  cases note with
  | none => simp [optionValueAt, optionValue]
  | some n => simp [optionValueAt, optionValue, valueAt, shape n rfl]

theorem relation_per_asset_conservation {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (asset : Nat) :
    inputTotal asset w + mintAt asset p =
      outputTotal asset w + burnAt asset p + (if asset = nativeAsset then p.fee else 0) := by
  have input := option_value_at_of_shape (asset := asset) valid.inputAsset
  have change := option_value_at_of_shape (asset := asset) valid.assetChangeAsset
  have nativeChange := option_value_at_of_shape (asset := asset) valid.nativeChangeAsset
  unfold inputTotal outputTotal
  rw [input, change, nativeChange]
  simp only [valueAt, valid.nativeInputAsset, valid.recipientAsset, mintAt, burnAt]
  by_cases isAsset : asset = p.assetId
  · have nonNative : asset ≠ nativeAsset := by simpa [isAsset] using valid.nonNative
    simp only [if_pos isAsset, if_neg nonNative, Nat.add_zero]
    exact valid.assetBalance
  · by_cases isNative : asset = nativeAsset
    · simp only [if_neg isAsset, if_pos isNative, Nat.add_zero, Nat.zero_add]
      exact valid.nativeBalance
    · simp [isAsset, isNative]

theorem relation_no_mint_or_burn_of_hgn {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) :
    mintAt nativeAsset p = 0 ∧ burnAt nativeAsset p = 0 := by
  have different : nativeAsset ≠ p.assetId := Ne.symm valid.nonNative
  simp [mintAt, burnAt, different]

theorem relation_native_fee_isolation {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) :
    inputTotal nativeAsset w = outputTotal nativeAsset w + p.fee := by
  have balance := relation_per_asset_conservation valid nativeAsset
  rcases relation_no_mint_or_burn_of_hgn valid with ⟨noMint, noBurn⟩
  simpa [noMint, noBurn] using balance

theorem asset_value_cannot_fund_native_fee {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (noNativeValue : w.nativeInput.value = 0) : p.fee = 0 := by
  have balance := valid.nativeBalance
  omega

theorem relation_transfer_asset_conservation {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (transfer : p.route = .transfer) :
    optionValue w.assetInput = w.recipient.value + optionValue w.assetChange := by
  simpa [mintAmount, burnAmount, transfer] using valid.assetBalance

theorem relation_mint_asset_conservation {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (mint : p.route = .mint) :
    optionValue w.assetInput + p.magnitude =
      w.recipient.value + optionValue w.assetChange := by
  simpa [mintAmount, burnAmount, mint] using valid.assetBalance

theorem relation_burn_asset_conservation {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (burn : p.route = .burn) :
    optionValue w.assetInput =
      w.recipient.value + optionValue w.assetChange + p.magnitude := by
  simpa [mintAmount, burnAmount, burn] using valid.assetBalance

theorem relation_supports_only_transfer_mint_burn {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) :
    p.route = .transfer ∨ p.route = .mint ∨ p.route = .burn := by
  have supported := valid.supported
  cases routeEq : p.route <;> simp_all [Supported]

theorem unsupported_route_has_no_bypass {c : Crypto} {p : Public} {w : Witness}
    (unsupported : ¬ Supported p.route) : ¬ Relation c p w := by
  intro valid
  exact unsupported valid.supported

theorem relation_frozen_asset_rejected {c : Crypto} {p : Public} {w : Witness}
    (frozen : w.row.policy.frozen = true) : ¬ Relation c p w := by
  intro valid
  have unfrozen := valid.policy.1
  rw [frozen] at unfrozen
  contradiction

theorem relation_mint_disabled_rejected {c : Crypto} {p : Public} {w : Witness}
    (mint : p.route = .mint) (disabled : w.row.policy.mintEnabled = false) :
    ¬ Relation c p w := by
  intro valid
  have enabled := valid.policy.2
  simp only [mint, MintPolicy] at enabled
  rw [disabled] at enabled
  exact Bool.false_ne_true enabled.1

/-- Disabling minting is not a transfer freeze. This is a policy-predicate
identity; changing a policy still requires newly authenticated state roots. -/
theorem transfer_policy_independent_of_mint_enabled (policy : Policy) (height : Nat)
    (enabled : Bool) :
    RoutePolicy .transfer { policy with mintEnabled := enabled } height ↔
      RoutePolicy .transfer policy height := by
  rfl

theorem burn_policy_independent_of_mint_enabled (policy : Policy) (height : Nat)
    (enabled : Bool) :
    RoutePolicy .burn { policy with mintEnabled := enabled } height ↔
      RoutePolicy .burn policy height := by
  rfl

theorem relation_dummy_asset_input_only_mint {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (dummy : w.assetInput = none) : p.route = .mint :=
  valid.noDummySpend dummy

theorem relation_non_mint_has_asset_input {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (notMint : p.route ≠ .mint) :
    ∃ note, w.assetInput = some note := by
  cases input : w.assetInput with
  | none => exact False.elim (notMint (valid.noDummySpend input))
  | some note => exact ⟨note, rfl⟩

/-- Burn still consumes the holder-authorized asset note. It does not grant
the issuer a recovery, seizure, or alternative-nullifier route. -/
theorem relation_burn_requires_holder_authorization {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (burn : p.route = .burn) :
    ∃ note, w.assetInput = some note ∧ note.assetId = p.assetId ∧
      c.ownerCommitment w.assetSecret = note.owner ∧
      c.noteNullifier note w.assetPosition w.assetSecret = p.assetNullifier := by
  have notMint : p.route ≠ .mint := by simp [burn]
  obtain ⟨note, input⟩ := relation_non_mint_has_asset_input valid notMint
  have authorization := valid.inputAuthorization note input
  exact ⟨note, input, valid.inputAsset note input, authorization.1, authorization.2.2⟩

theorem relation_mint_requires_issuer_opening {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (mint : p.route = .mint) :
    w.issuerSecret ≠ zeroDigest ∧
    c.issuerCommitment p.assetId p.policyVersion w.issuerSecret =
      w.row.policy.issuerCommitment ∧
    c.issuerAuthorization p.intent w.issuerSecret = p.issuerAuthorization := by
  simpa [IssuerAuthorization, mint] using valid.issuer

theorem relation_mint_policy_fresh {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (mint : p.route = .mint) :
    MintPolicy w.row.policy p.parentHeight := by
  simpa [mint] using valid.policy.2

theorem relation_recipient_credential_mandatory {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) : ∃ e, CredentialFor c p w.recipient e := by
  exact valid.credentials w.recipient (by simp [AssetParticipants])

theorem relation_asset_change_credential_mandatory {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) {note : Note} (change : w.assetChange = some note) :
    ∃ e, CredentialFor c p note e := by
  exact valid.credentials note (by simp [AssetParticipants, change])

theorem relation_asset_input_credential_mandatory {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) {note : Note} (input : w.assetInput = some note) :
    ∃ e, CredentialFor c p note e := by
  exact valid.credentials note (by simp [AssetParticipants, input])

theorem relation_uses_authenticated_current_row {c : Crypto} {s : State} {p : Public}
    {w : Witness} (valid : Relation c p w) (fresh : Fresh c s p)
    (binding : RegistryRootBindingAt c s) : w.row ∈ s.registry := by
  exact binding w.row w.registryPath (valid.registryOpening.trans fresh.registryRoot)

theorem relation_all_participants_current_nonrevoked {c : Crypto} {s : State}
    {p : Public} {w : Witness} (valid : Relation c p w) (fresh : Fresh c s p)
    (binding : CredentialRootBindingAt c s) (note : Note)
    (participant : note ∈ AssetParticipants w) :
    ∃ e : CredentialEvidence, e.leaf ∈ s.credentials ∧ e.leaf.assetId = p.assetId ∧
      e.leaf.policyVersion = p.policyVersion ∧
      e.leaf.recipientKey = note.recipientKey ∧ e.leaf.owner = note.owner ∧
      s.parentHeight ≤ e.leaf.expiresAt := by
  obtain ⟨e, asset, version, recipient, owner, expiry, root⟩ := valid.credentials note participant
  exact ⟨e, binding e.leaf e.path (root.trans fresh.credentialRoot),
    asset, version, recipient, owner, by simpa [fresh.parentHeight] using expiry⟩

theorem wrong_asset_credential_rejected {c : Crypto} {p : Public} {note : Note}
    {e : CredentialEvidence} (wrong : e.leaf.assetId ≠ p.assetId) :
    ¬ CredentialFor c p note e := by
  intro valid
  exact wrong valid.1

theorem wrong_version_credential_rejected {c : Crypto} {p : Public} {note : Note}
    {e : CredentialEvidence} (wrong : e.leaf.policyVersion ≠ p.policyVersion) :
    ¬ CredentialFor c p note e := by
  intro valid
  exact wrong valid.2.1

theorem wrong_full_owner_credential_rejected {c : Crypto} {p : Public} {note : Note}
    {e : CredentialEvidence} (wrong : e.leaf.owner ≠ note.owner) :
    ¬ CredentialFor c p note e := by
  intro valid
  exact wrong valid.2.2.2.1

theorem expired_credential_rejected {c : Crypto} {p : Public} {note : Note}
    {e : CredentialEvidence} (expired : e.leaf.expiresAt < p.parentHeight) :
    ¬ CredentialFor c p note e := by
  intro valid
  have notExpired := valid.2.2.2.2.1
  omega

theorem stale_credential_root_rejected {c : Crypto} {s : State} {p : Public}
    (stale : p.credentialRoot ≠ c.credentialTreeRoot s.credentials) : ¬ Fresh c s p := by
  intro fresh
  exact stale fresh.credentialRoot

theorem stale_registry_root_rejected {c : Crypto} {s : State} {p : Public}
    (stale : p.registryRoot ≠ c.registryTreeRoot s.registry) : ¬ Fresh c s p := by
  intro fresh
  exact stale fresh.registryRoot

theorem other_chain_replay_rejected {c : Crypto} {s : State} {p : Public}
    (different : p.chainId ≠ s.chainId) : ¬ Fresh c s p := by
  intro fresh
  exact different fresh.chainId

theorem other_relation_replay_rejected {c : Crypto} {s : State} {p : Public}
    (different : p.relationIdentity ≠ s.relationIdentity) : ¬ Fresh c s p := by
  intro fresh
  exact different fresh.relationIdentity

theorem relation_mint_cap_and_collateral {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (mint : p.route = .mint) :
    p.afterCounters.mintedInEpoch ≤ w.row.policy.maxMintPerEpoch ∧
    p.afterCounters.debt = w.row.counters.debt + p.magnitude ∧
    p.afterCounters.debt * w.row.policy.oracleDenominator * w.row.policy.minCollateralRatio ≤
      w.row.policy.collateralAmount * w.row.policy.oracleNumerator * ratioScale := by
  have counters := valid.counters
  simp only [CounterTransition, mint] at counters
  exact ⟨counters.2.2.2.2.1, counters.2.2.2.2.2.1, counters.2.2.2.2.2.2.2.2.2⟩

theorem relation_burn_debt_no_underflow {c : Crypto} {p : Public} {w : Witness}
    (valid : Relation c p w) (burn : p.route = .burn) :
    p.magnitude ≤ w.row.counters.debt ∧
    p.afterCounters.debt + p.magnitude = w.row.counters.debt := by
  have counters := valid.counters
  simp only [CounterTransition, burn] at counters
  have debt := counters.2.2.2.2
  exact ⟨by omega, debt⟩

/-- The accepted-proof lift displays all external contracts. It establishes
modeled protocol properties conditionally, not production authorization. -/
theorem admitted_protocol_properties {c : Crypto} {v : ProofVerifier} {s : State}
    {p : Public} {proof : v.Proof} (sound : ProofSoundness c v)
    (registryBinding : RegistryRootBindingAt c s)
    (credentialBinding : CredentialRootBindingAt c s)
    (admitted : Admitted c v s p proof) :
    ∃ w, Relation c p w ∧ w.row ∈ s.registry ∧
      (∀ asset, inputTotal asset w + mintAt asset p = outputTotal asset w +
        burnAt asset p + (if asset = nativeAsset then p.fee else 0)) ∧
      (inputTotal nativeAsset w = outputTotal nativeAsset w + p.fee) ∧
      (p.assetId ≠ nativeAsset) ∧ w.row.policy.frozen = false ∧
      (p.route = .transfer ∨ p.route = .mint ∨ p.route = .burn) ∧
      (∀ note, note ∈ AssetParticipants w →
        ∃ e : CredentialEvidence, e.leaf ∈ s.credentials ∧ e.leaf.assetId = p.assetId ∧
          e.leaf.policyVersion = p.policyVersion ∧
          e.leaf.recipientKey = note.recipientKey ∧ e.leaf.owner = note.owner ∧
          s.parentHeight ≤ e.leaf.expiresAt) := by
  obtain ⟨w, valid⟩ := sound p proof admitted.accepted
  exact ⟨w, valid, relation_uses_authenticated_current_row valid admitted.fresh registryBinding,
    relation_per_asset_conservation valid, relation_native_fee_isolation valid,
    valid.nonNative, valid.policy.1, relation_supports_only_transfer_mint_burn valid,
    relation_all_participants_current_nonrevoked valid admitted.fresh credentialBinding⟩

/-! Administrator controls are separate from spending-policy interpretation.
`Config` is the COMPLETE configuration object (for example the V8 config),
not a selected projection. The update preserves that object and all counters.
The history model requires authenticated snapshots to retain consumed IDs;
it does not authorize rolling back to an earlier snapshot of history. -/

structure AdminControls where
  credentialRoot : Digest
  credentialDepth : Nat
  frozen : Bool
  mintEnabled : Bool

structure AdminRow (Config : Type) where
  config : Config
  counters : Counters
  controls : AdminControls

def controlsAfter {Config : Type} (before : AdminRow Config) (controls : AdminControls) :
    AdminRow Config := { before with controls := controls }

structure AdminPublic where
  chainId : Digest
  parentHash : Digest
  parentHeight : Nat
  registryRoot : Digest
  afterRegistryRoot : Digest
  assetId : Nat
  oldPolicyVersion : Nat
  newPolicyVersion : Nat
  policyAdminCommitment : Digest
  beforeLeaf : Digest
  afterLeaf : Digest
  controls : AdminControls
  expiresAt : Nat
  actionIntent : Digest

structure AdminCrypto (Config : Type) where
  configAsset : Config → Nat
  configVersion : Config → Nat
  configAdminCommitment : Config → Digest
  treeRoot : List (AdminRow Config) → Digest
  pathRoot : AdminRow Config → MerklePath → Digest
  leaf : AdminRow Config → Digest
  adminCommitment : Nat → Nat → Secret → Digest
  /-- Hash of the canonical, domain-separated public statement only. Its
  collision resistance and exact byte encoding remain external obligations. -/
  actionId : AdminPublic → Digest

structure AdminWitness (Config : Type) where
  before : AdminRow Config
  path : MerklePath
  adminSecret : Secret

structure AdminRelation {Config : Type} (c : AdminCrypto Config)
    (p : AdminPublic) (w : AdminWitness Config) : Prop where
  nonNative : p.assetId ≠ nativeAsset
  asset : c.configAsset w.before.config = p.assetId
  version : c.configVersion w.before.config = p.oldPolicyVersion
  sameVersion : p.newPolicyVersion = p.oldPolicyVersion
  admin : c.configAdminCommitment w.before.config = p.policyAdminCommitment
  beforeRoot : c.pathRoot w.before w.path = p.registryRoot
  afterRoot : c.pathRoot (controlsAfter w.before p.controls) w.path = p.afterRegistryRoot
  beforeLeaf : c.leaf w.before = p.beforeLeaf
  afterLeaf : c.leaf (controlsAfter w.before p.controls) = p.afterLeaf
  secretNonzero : w.adminSecret ≠ zeroDigest
  secretOpening : c.adminCommitment p.assetId p.oldPolicyVersion w.adminSecret =
    p.policyAdminCommitment
  depth : p.controls.credentialDepth = 4 ∨ p.controls.credentialDepth = 8 ∨
    p.controls.credentialDepth = 16
  notExpired : p.parentHeight ≤ p.expiresAt

structure AdminLedger where
  chainId : Digest
  parentHash : Digest
  parentHeight : Nat
  registryRoot : Digest
  consumedAdminIds : List Digest

structure AdminFresh {Config : Type} (c : AdminCrypto Config)
    (s : AdminLedger) (p : AdminPublic) : Prop where
  chain : p.chainId = s.chainId
  parent : p.parentHash = s.parentHash
  height : p.parentHeight = s.parentHeight
  root : p.registryRoot = s.registryRoot
  unused : c.actionId p ∉ s.consumedAdminIds

def commitAdmin {Config : Type} (c : AdminCrypto Config) (s : AdminLedger)
    (p : AdminPublic) : AdminLedger :=
  { s with
    registryRoot := p.afterRegistryRoot
    consumedAdminIds := s.consumedAdminIds ++ [c.actionId p] }

def AdminStep {Config : Type} (c : AdminCrypto Config) (s : AdminLedger)
    (p : AdminPublic) (w : AdminWitness Config) (next : AdminLedger) : Prop :=
  AdminRelation c p w ∧ AdminFresh c s p ∧ next = commitAdmin c s p

structure AdminProofVerifier where
  Proof : Type
  accepts : AdminPublic → Proof → Prop

def AdminProofSoundness {Config : Type} (c : AdminCrypto Config)
    (v : AdminProofVerifier) : Prop :=
  ∀ p proof, v.accepts p proof → ∃ w, AdminRelation c p w

def adminEnvelopeActionId {Config : Type} (c : AdminCrypto Config)
    (v : AdminProofVerifier) (p : AdminPublic) (_proof : v.Proof) : Digest := c.actionId p

theorem randomized_admin_proofs_have_same_action_id {Config : Type}
    (c : AdminCrypto Config) (v : AdminProofVerifier) (p : AdminPublic)
    (proof1 proof2 : v.Proof) :
    adminEnvelopeActionId c v p proof1 = adminEnvelopeActionId c v p proof2 := rfl

theorem controls_preserve_complete_config_and_counters {Config : Type}
    (before : AdminRow Config) (controls : AdminControls) :
    (controlsAfter before controls).config = before.config ∧
    (controlsAfter before controls).counters = before.counters ∧
    (controlsAfter before controls).controls = controls := ⟨rfl, rfl, rfl⟩

theorem admin_hgn_excluded {Config : Type} {c : AdminCrypto Config} {p : AdminPublic}
    {w : AdminWitness Config} (native : p.assetId = nativeAsset) :
    ¬ AdminRelation c p w := fun valid => valid.nonNative native

theorem admin_current_asset_authority {Config : Type} {c : AdminCrypto Config}
    {s : AdminLedger} {p : AdminPublic} {w : AdminWitness Config}
    (valid : AdminRelation c p w) (fresh : AdminFresh c s p)
    (rows : List (AdminRow Config)) (current : s.registryRoot = c.treeRoot rows)
    (binding : ∀ row path, c.pathRoot row path = c.treeRoot rows → row ∈ rows) :
    w.before ∈ rows ∧ c.configAsset w.before.config = p.assetId ∧
      c.configAdminCommitment w.before.config = p.policyAdminCommitment ∧
      c.adminCommitment p.assetId p.oldPolicyVersion w.adminSecret =
        c.configAdminCommitment w.before.config := by
  exact ⟨binding w.before w.path (valid.beforeRoot.trans (fresh.root.trans current)),
    valid.asset, valid.admin, valid.secretOpening.trans valid.admin.symm⟩

theorem admin_step_history_grows {Config : Type} {c : AdminCrypto Config}
    {s next : AdminLedger} {p : AdminPublic} {w : AdminWitness Config}
    (step : AdminStep c s p w next) :
    next.consumedAdminIds = s.consumedAdminIds ++ [c.actionId p] ∧
      next.consumedAdminIds.length = s.consumedAdminIds.length + 1 := by
  rw [step.2.2]
  simp [commitAdmin]

theorem admin_step_replay_impossible {Config : Type} {c : AdminCrypto Config}
    {s next : AdminLedger} {p : AdminPublic} {w : AdminWitness Config}
    (step : AdminStep c s p w next) : ¬ AdminFresh c next p := by
  intro replay
  apply replay.unused
  rw [(admin_step_history_grows step).1]
  simp

inductive AdminHistory {Config : Type} (c : AdminCrypto Config) :
    AdminLedger → AdminLedger → Nat → Prop where
  | refl (s) : AdminHistory c s s 0
  | step {s middle next p w n} : AdminHistory c s middle n →
      AdminStep c middle p w next → AdminHistory c s next (n + 1)

theorem admin_history_exact_growth {Config : Type} {c : AdminCrypto Config}
    {s next : AdminLedger} {n : Nat} (history : AdminHistory c s next n) :
    next.consumedAdminIds.length = s.consumedAdminIds.length + n := by
  induction history with
  | refl => simp
  | step _ step ih => rw [(admin_step_history_grows step).2, ih]; omega

theorem admin_history_retains_ids {Config : Type} {c : AdminCrypto Config}
    {s next : AdminLedger} {n : Nat} (history : AdminHistory c s next n)
    (id : Digest) (consumed : id ∈ s.consumedAdminIds) : id ∈ next.consumedAdminIds := by
  induction history with
  | refl => exact consumed
  | step _ step ih => rw [(admin_step_history_grows step).1]; exact List.mem_append_left _ ih

/-- Root equality can recur after freeze/unfreeze; history still blocks the
old canonical statement, independent of proof randomization or root cycles. -/
theorem admin_root_cycle_cannot_replay {Config : Type} {c : AdminCrypto Config}
    {s next : AdminLedger} {p : AdminPublic} {n : Nat}
    (consumed : c.actionId p ∈ s.consumedAdminIds) (history : AdminHistory c s next n) :
    ¬ AdminFresh c next p := by
  intro replay
  exact replay.unused (admin_history_retains_ids history (c.actionId p) consumed)

abbrev AdminSnapshot := AdminLedger
def adminSnapshot (s : AdminLedger) : AdminSnapshot := s
def restoreAdminSnapshot (snapshot : AdminSnapshot) : AdminLedger := snapshot

theorem admin_snapshot_preserves_exact_history (s : AdminLedger) :
    (restoreAdminSnapshot (adminSnapshot s)).consumedAdminIds = s.consumedAdminIds := rfl

theorem admin_snapshot_cannot_erase_replay {Config : Type} {c : AdminCrypto Config}
    {s : AdminLedger} {p : AdminPublic} (consumed : c.actionId p ∈ s.consumedAdminIds) :
    ¬ AdminFresh c (restoreAdminSnapshot (adminSnapshot s)) p := by
  intro replay
  exact replay.unused consumed

theorem accepted_admin_step_requires_secret_and_consumes_identity {Config : Type}
    {c : AdminCrypto Config} {v : AdminProofVerifier} {s : AdminLedger} {p : AdminPublic}
    {proof : v.Proof} (sound : AdminProofSoundness c v) (accepted : v.accepts p proof)
    (fresh : AdminFresh c s p) :
    ∃ w, AdminStep c s p w (commitAdmin c s p) ∧ w.adminSecret ≠ zeroDigest ∧
      ¬ AdminFresh c (commitAdmin c s p) p := by
  obtain ⟨w, valid⟩ := sound p proof accepted
  have step : AdminStep c s p w (commitAdmin c s p) := ⟨valid, fresh, rfl⟩
  exact ⟨w, step, valid.secretNonzero, admin_step_replay_impossible step⟩

/-- Mandatory asset checks wrap any future spending-policy alternative. This
abstract conjunction states no interpreter or parent integration is complete. -/
def MandatoryPolicyEnvelope (mandatory : Prop) {Alternative : Type}
    (authorized : Alternative → Prop) : Prop := mandatory ∧ ∃ alternative, authorized alternative

theorem alternative_policy_cannot_bypass_mandatory {mandatory : Prop} {Alternative : Type}
    {authorized : Alternative → Prop}
    (accepted : MandatoryPolicyEnvelope mandatory authorized) : mandatory := accepted.1

/-!
Composition with the imported bounded policy semantics. These are mandatory
asset facts, not a second spending-policy interpreter. In particular ordinary
`Relation.inputAuthorization` is NOT imposed on a policy-owned input: that
note's owner-policy commitment, derived branch authority, public release fields
and shared-nullifier calls need their own exact source-role bindings. The
following theorems do not infer those bindings or knowledge soundness from a
successful Rust verifier call. Unchanged primitive/compiler assumptions receive
no new credit here. Mint authorization and accounting remain the preceding
relation's separate obligations; this composition is not a complete mint gate.
-/

structure MandatoryAssetFacts (c : Crypto) (s : State) (p : Public) (w : Witness) : Prop where
  fresh : Fresh c s p
  nonNative : p.assetId ≠ nativeAsset
  currentPolicyOpening : c.registryPathRoot w.row w.registryPath = p.registryRoot
  policyAsset : w.row.policy.assetId = p.assetId
  policyVersion : w.row.policy.version = p.policyVersion
  unfrozen : w.row.policy.frozen = false
  credentials : AllCredentials c p w
  conservation : ∀ asset, inputTotal asset w + mintAt asset p =
    outputTotal asset w + burnAt asset p + (if asset = nativeAsset then p.fee else 0)
  nativeFee : inputTotal nativeAsset w = outputTotal nativeAsset w + p.fee

def ControlledPolicySemantics (c : Crypto) (s : State) (p : Public) (w : Witness)
    (sha256 : Hegemon.Policy.BoundedPrivateSpend.Secret →
      Hegemon.Policy.BoundedPrivateSpend.HashWords)
    (policy : Hegemon.Policy.BoundedPrivateSpend.Policy) (choice : Bool)
    (spend : Hegemon.Policy.BoundedPrivateSpend.SpendWitness)
    (release : Hegemon.Policy.BoundedPrivateSpend.PublicRelease) : Prop :=
  Hegemon.Policy.BoundedPrivateSpend.Accepted (MandatoryAssetFacts c s p w)
    sha256 policy choice p.parentHeight spend release

theorem ordinary_relation_preserves_mandatory_facts {c : Crypto} {s : State}
    {p : Public} {w : Witness} (valid : Relation c p w) (fresh : Fresh c s p) :
    MandatoryAssetFacts c s p w :=
  ⟨fresh, valid.nonNative, valid.registryOpening, valid.policyAsset,
    valid.policyVersion, valid.policy.1, valid.credentials,
    relation_per_asset_conservation valid, relation_native_fee_isolation valid⟩

theorem bounded_policy_alternative_keeps_asset_conjunction {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {choice} {spend} {release}
    (accepted : ControlledPolicySemantics c s p w sha256 policy choice spend release) :
    MandatoryAssetFacts c s p w := accepted.2.2.1

theorem bounded_policy_current_authenticated_row {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {choice} {spend} {release}
    (accepted : ControlledPolicySemantics c s p w sha256 policy choice spend release)
    (binding : RegistryRootBindingAt c s) : w.row ∈ s.registry := by
  have mandatory := bounded_policy_alternative_keeps_asset_conjunction accepted
  exact binding w.row w.registryPath
    (mandatory.currentPolicyOpening.trans mandatory.fresh.registryRoot)

theorem bounded_policy_current_credential_for_every_asset_participant {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {choice} {spend} {release}
    (accepted : ControlledPolicySemantics c s p w sha256 policy choice spend release)
    (binding : CredentialRootBindingAt c s) (note : Note)
    (participant : note ∈ AssetParticipants w) :
    ∃ e : CredentialEvidence, e.leaf ∈ s.credentials ∧ e.leaf.assetId = p.assetId ∧
      e.leaf.policyVersion = p.policyVersion ∧ e.leaf.recipientKey = note.recipientKey ∧
      e.leaf.owner = note.owner ∧ s.parentHeight ≤ e.leaf.expiresAt := by
  have mandatory := bounded_policy_alternative_keeps_asset_conjunction accepted
  obtain ⟨e, asset, version, recipient, owner, expiry, root⟩ :=
    mandatory.credentials note participant
  exact ⟨e, binding e.leaf e.path (root.trans mandatory.fresh.credentialRoot),
    asset, version, recipient, owner, by simpa [mandatory.fresh.parentHeight] using expiry⟩

/-- The imported descriptor commitment is the inner policy hash. The complete
source owner additionally compresses the shared private nullifier key with
that hash. These cryptographic functions are explicit parameters, not an
injectivity assumption or a second policy evaluator. -/
def boundedPolicyOwner
    (policyHash : Hegemon.Policy.BoundedPrivateSpend.ChainWords → Nat → List Nat →
      Hegemon.Policy.BoundedPrivateSpend.Authority)
    (ownerCompress : Hegemon.Policy.BoundedPrivateSpend.NullifierKey →
      Hegemon.Policy.BoundedPrivateSpend.Authority → Digest)
    (chain : Hegemon.Policy.BoundedPrivateSpend.ChainWords) (asset : Nat)
    (policy : Hegemon.Policy.BoundedPrivateSpend.Policy) : Digest :=
  ownerCompress policy.nullifierKey
    (Hegemon.Policy.BoundedPrivateSpend.policyCommitment policyHash chain asset policy)

theorem bounded_policy_credential_binds_complete_policy_owner {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {choice} {spend} {release}
    (accepted : ControlledPolicySemantics c s p w sha256 policy choice spend release)
    (binding : CredentialRootBindingAt c s) (note : Note)
    (participant : note ∈ AssetParticipants w) (policyHash) (ownerCompress) (chain)
    (ownerBound : note.owner = boundedPolicyOwner policyHash ownerCompress chain p.assetId policy) :
    ∃ e : CredentialEvidence, e.leaf ∈ s.credentials ∧
      e.leaf.owner = boundedPolicyOwner policyHash ownerCompress chain p.assetId policy := by
  obtain ⟨e, member, _, _, _, owner, _⟩ :=
    bounded_policy_current_credential_for_every_asset_participant accepted binding note participant
  exact ⟨e, member, owner.trans ownerBound⟩

theorem bounded_policy_frozen_asset_rejects_all_alternatives {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {spend} {release}
    (frozen : w.row.policy.frozen = true) :
    ¬ ∃ choice, ControlledPolicySemantics c s p w sha256 policy choice spend release := by
  rintro ⟨choice, accepted⟩
  have unfrozen := (bounded_policy_alternative_keeps_asset_conjunction accepted).unfrozen
  rw [frozen] at unfrozen
  contradiction

theorem bounded_policy_stale_credentials_reject_all_alternatives {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {spend} {release}
    (stale : p.credentialRoot ≠ c.credentialTreeRoot s.credentials) :
    ¬ ∃ choice, ControlledPolicySemantics c s p w sha256 policy choice spend release := by
  rintro ⟨choice, accepted⟩
  exact stale (bounded_policy_alternative_keeps_asset_conjunction accepted).fresh.credentialRoot

theorem bounded_policy_height_is_current_inclusion_height {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {choice} {spend} {release}
    (accepted : ControlledPolicySemantics c s p w sha256 policy choice spend release) :
    (policy.branches (Hegemon.Policy.BoundedPrivateSpend.selected choice)).notBefore + 1 ≤
      s.parentHeight + 1 := by
  have fresh := (bounded_policy_alternative_keeps_asset_conjunction accepted).fresh
  exact Hegemon.Policy.BoundedPrivateSpend.absolute_height_no_early_spend
    (MandatoryAssetFacts c s p w) sha256 policy choice p.parentHeight s.parentHeight
    spend release accepted (Nat.le_of_eq fresh.parentHeight)

theorem bounded_policy_forced_release_and_hashlock {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {choice} {spend} {release}
    (accepted : ControlledPolicySemantics c s p w sha256 policy choice spend release)
    (required : (policy.branches
      (Hegemon.Policy.BoundedPrivateSpend.selected choice)).releaseSecret = true) :
    release.flag = true ∧ release.preimage = spend.secret ∧
      sha256 release.preimage =
        (policy.branches (Hegemon.Policy.BoundedPrivateSpend.selected choice)).hashlock := by
  have released := Hegemon.Policy.BoundedPrivateSpend.mandatory_release_no_opt_out
    (MandatoryAssetFacts c s p w) sha256 policy choice p.parentHeight spend release accepted required
  exact ⟨released.1, released.2,
    Hegemon.Policy.BoundedPrivateSpend.released_preimage_matches_hashlock
      (MandatoryAssetFacts c s p w) sha256 policy choice p.parentHeight
      spend release accepted required⟩

theorem bounded_policy_private_branch_zero_public_release {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {choice} {spend} {release}
    (accepted : ControlledPolicySemantics c s p w sha256 policy choice spend release)
    (privateBranch : (policy.branches
      (Hegemon.Policy.BoundedPrivateSpend.selected choice)).releaseSecret = false) :
    release.flag = false ∧ release.preimage = Hegemon.Policy.BoundedPrivateSpend.zeroSecret :=
  Hegemon.Policy.BoundedPrivateSpend.no_release_has_zero_public_bytes
    (MandatoryAssetFacts c s p w) sha256 policy choice p.parentHeight
    spend release accepted privateBranch

theorem bounded_policy_branch_change_cannot_evade_consumed_nullifier {c : Crypto} {s : State}
    {p : Public} {w : Witness} {sha256} {policy} {choice} {spend} {release}
    (nullify : Hegemon.Policy.BoundedPrivateSpend.NullifierKey → Nat → Nat →
      Hegemon.Policy.BoundedPrivateSpend.Authority) (value position : Nat)
    (bound : Hegemon.Policy.BoundedPrivateSpend.policyNullifier nullify policy value position choice =
      p.assetNullifier)
    (consumed : Hegemon.Policy.BoundedPrivateSpend.policyNullifier nullify policy value position
      false ∈ s.spentNullifiers) :
    ¬ ControlledPolicySemantics c s p w sha256 policy choice spend release := by
  intro accepted
  have shared := Hegemon.Policy.BoundedPrivateSpend.both_branches_share_nullifier
    nullify policy value position false choice
  have spent : p.assetNullifier ∈ s.spentNullifiers := by
    rw [← bound, ← shared]
    exact consumed
  exact (bounded_policy_alternative_keeps_asset_conjunction accepted).fresh.assetNullifierFresh spent

end Hegemon.Transaction.QualifiedAssetBalanceV1
