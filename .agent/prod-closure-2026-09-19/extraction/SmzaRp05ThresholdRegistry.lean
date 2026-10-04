import SmzaRp05ThresholdHistory
import Hegemon.Transaction.Poseidon2V8SemanticSpecification
import Mathlib.Data.List.Nodup
import Lean.Elab.Tactic.Omega

/-!
# RP05 accepted-branch threshold registry

This module is the structural, local interface between an accepted canonical
branch pass and `SmzaRp05ThresholdHistory`.  It deliberately does not take an
`ApprovalHistory` as input.  A branch entry contains the result of reducing
one zero/native accumulator input against its actual producer.  The only
successful result is an earlier, typed Approval output0; every other result
carries tagged conflicting preimages found by the pass. A `BindingBreak` alone
is not yet a collision of distinct live hash inputs: note identity and the
authorization domain tag are metadata ignored by `currentBindingDigest`.
`SmzaRp05ConcreteBindingInputs` states the additional effective-input test.

`RawOrigin.ordinary`, `.coinbase`, `.emptyNote`, and `.merkle` cover the
positive-output, coinbase, canonical-empty, and authentication-path cases.
The `.emptyAuthorization`, `.policy`, and `.intent` cases retain tagged
authorization or descriptor preimages.  In particular `.emptyAuthorization`
does not by itself establish a single-function primitive collision: the live
single-key identity is not evaluated by calls 107/108. Filtering these cases
as primitive collisions requires a separate source-correct reduction.

The seven-word tag type below is intentional.  `FullTagMatch` cannot be
constructed from the old five-word prefix.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry

open SmzaRp05ThresholdHistory
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option autoImplicit false

/-! ## Exact binding and membership witnesses -/

/-- A named hash/encoding family.  Equality of the family is retained in a
break so that a caller cannot accidentally report a cross-function pair as a
same-function collision. Family equality alone does not establish distinct
effective inputs; see `SmzaRp05ConcreteBindingInputs`. -/
inductive BindingFamily where
  | note
  | merkle
  | authorization
  | accumulator
  | policy
  | intent
deriving DecidableEq

inductive AuthorizationDomain where
  | singleKey
  | accumulator
deriving DecidableEq

/-- Two distinct concrete preimages with the same complete output. -/
structure ConflictingPreimages {Preimage Digest : Type*}
    (family : Preimage → BindingFamily) (digest : Preimage → Digest) where
  left : Preimage
  right : Preimage
  sameFamily : family left = family right
  different : left ≠ right
  sameDigest : digest left = digest right

/- The evaluator used by the accepted-branch pass.  `Preimage` is normally a
tagged sum of canonical note, Merkle-compression, authorization, policy, and
intent encodings. -/
set_option linter.checkUnivs false in
structure BindingModel where
  Preimage : Type*
  Digest : Type*
  family : Preimage → BindingFamily
  digest : Preimage → Digest

/-! ## Concrete RP05 binding evaluator

The registry below is polymorphic so that the reduction can be reused.  Its
RP05 instantiation is nevertheless fixed here: a preimage is a tagged member
of the six source families and `digest` runs the corresponding live Poseidon2
evaluator.  In particular, an intent preimage contains all 104 words; it is
not a seven-word digest relabelled as a preimage.
-/

abbrev CurrentPolicyEncoding := Fin 44 → Nat
abbrev CurrentIntentEncoding := Fin 104 → Nat
abbrev CurrentAccumulatorEncoding := Fin 23 → Nat

/-- A note binding retains both the complete note opening used by the note
commitment and the seven-word authorization identity carried by its role in
the AUTH relation.  The latter is not part of the note commitment preimage. -/
structure CurrentNotePreimage where
  opening : V8NoteOpening
  authorizationIdentity : Digest
deriving DecidableEq

structure CurrentMerklePreimage where
  left : Digest
  right : Digest
deriving DecidableEq

/-- The exact two-digest input of calls 107/108. -/
structure CurrentAuthorizationPreimage where
  domain : AuthorizationDomain
  policyKey : Digest
  accumulatorDigest : Digest
deriving DecidableEq

inductive CurrentBindingPreimage where
  | note (preimage : CurrentNotePreimage)
  | merkle (preimage : CurrentMerklePreimage)
  | authorization (preimage : CurrentAuthorizationPreimage)
  | singleKeyAuthorization (key : Fin 5 → Nat)
  | accumulator (preimage : CurrentAccumulatorEncoding)
  | policy (preimage : CurrentPolicyEncoding)
  | intent (preimage : CurrentIntentEncoding)

noncomputable instance : DecidableEq CurrentBindingPreimage := Classical.decEq _

/-- Source constant `HMBDV2\0\1`, used by the accepted call-107/108 frame. -/
def currentAuthorizationBindingDomain : Nat := 0x484d_4244_5632_0001

/-- Live RP05 intent domain.  The older semantic constant ending in `5400`
belongs to the previous program and must not be used by this registry. -/
def currentIntentBindingDomain : Nat := 0x4854_5838_494e_5401

/-- Live call-0 SingleKey source. It is a one-block seven-word sponge, not
the two-digest call-107/108 compression with a different metadata tag. -/
def currentSourceSingleKeyDomain : Nat := 0x4853_4b41_5632_0001

def currentSourceSingleKeyWords (key : Fin 5 → Nat) : List Nat :=
  List.ofFn key ++ [0, 0]

def currentBindingFamily : CurrentBindingPreimage → BindingFamily
  | .note _ => .note
  | .merkle _ => .merkle
  | .authorization _ => .authorization
  | .singleKeyAuthorization _ => .authorization
  | .accumulator _ => .accumulator
  | .policy _ => .policy
  | .intent _ => .intent

/-- Concrete evaluator for every RP05 registry family. -/
def currentBindingDigest : CurrentBindingPreimage → Digest
  | .note preimage => exactV8NoteCommitment preimage.opening
  | .merkle preimage =>
      poseidon2V8Compress14 poseidon2V8MerkleDomain preimage.left preimage.right
  | .authorization preimage =>
      poseidon2V8Compress14 currentAuthorizationBindingDomain
        preimage.policyKey preimage.accumulatorDigest
  | .singleKeyAuthorization key =>
      poseidon2V8Sponge currentSourceSingleKeyDomain
        (currentSourceSingleKeyWords key)
  | .accumulator preimage =>
      poseidon2V8Sponge poseidon2V8AccumulatorDomain (List.ofFn preimage)
  | .policy preimage =>
      poseidon2V8Sponge poseidon2V8PolicyDomain (List.ofFn preimage)
  | .intent preimage =>
      poseidon2V8Sponge currentIntentBindingDomain (List.ofFn preimage)

def currentBindingModel : BindingModel where
  Preimage := CurrentBindingPreimage
  Digest := Digest
  family := currentBindingFamily
  digest := currentBindingDigest

@[simp] theorem current_binding_family_note (preimage : CurrentNotePreimage) :
    currentBindingModel.family (.note preimage) = .note := rfl

@[simp] theorem current_binding_family_merkle (preimage : CurrentMerklePreimage) :
    currentBindingModel.family (.merkle preimage) = .merkle := rfl

@[simp] theorem current_binding_family_authorization
    (preimage : CurrentAuthorizationPreimage) :
    currentBindingModel.family (.authorization preimage) = .authorization := rfl

@[simp] theorem current_binding_family_single_key_authorization
    (key : Fin 5 → Nat) :
    currentBindingModel.family (.singleKeyAuthorization key) = .authorization := rfl

@[simp] theorem current_binding_family_accumulator
    (preimage : CurrentAccumulatorEncoding) :
    currentBindingModel.family (.accumulator preimage) = .accumulator := rfl

@[simp] theorem current_binding_family_policy (preimage : CurrentPolicyEncoding) :
    currentBindingModel.family (.policy preimage) = .policy := rfl

@[simp] theorem current_binding_family_intent (preimage : CurrentIntentEncoding) :
    currentBindingModel.family (.intent preimage) = .intent := rfl

abbrev BindingBreak (model : BindingModel) :=
  ConflictingPreimages model.family model.digest

/-- A conflicting pair whose common evaluator family is fixed by the origin
case, rather than merely equal on the two sides. -/
structure FamilyBreak (model : BindingModel) (expected : BindingFamily) where
  pair : BindingBreak model
  leftFamily : model.family pair.left = expected

/-- Generic deterministic collision constructor used after the branch pass
has recomputed both complete encodings. -/
def bindingBreakOfDistinct {Preimage Digest : Type*}
    {family : Preimage → BindingFamily} {digest : Preimage → Digest}
    (left right : Preimage) (sameFamily : family left = family right)
    (different : left ≠ right) (sameDigest : digest left = digest right) :
    ConflictingPreimages family digest where
  left := left
  right := right
  sameFamily := sameFamily
  different := different
  sameDigest := sameDigest

/-- T1--T3 and coinbase admission provide `rightPositive`; a zero
accumulator opening therefore cannot equal that ordinary producer opening.
Together with the authenticated equal leaf digest this constructs, rather
than assumes, the note-binding pair. -/
def zeroPositiveBindingBreak {Preimage Digest : Type*}
    {family : Preimage → BindingFamily} {digest : Preimage → Digest}
    (value : Preimage → Nat) (zeroOpening positiveOpening : Preimage)
    (sameFamily : family zeroOpening = family positiveOpening)
    (zeroValue : value zeroOpening = 0)
    (positiveValue : 0 < value positiveOpening)
    (sameDigest : digest zeroOpening = digest positiveOpening) :
    ConflictingPreimages family digest :=
  bindingBreakOfDistinct zeroOpening positiveOpening sameFamily (by
    intro openingsEqual
    subst positiveOpening
    omega) sameDigest

/-- Family-specialized form used for ordinary and coinbase producers. -/
def noteBreakOfZeroPositive (model : BindingModel)
    (value : model.Preimage → Nat)
    (zeroOpening positiveOpening : model.Preimage)
    (zeroIsNote : model.family zeroOpening = .note)
    (positiveIsNote : model.family positiveOpening = .note)
    (zeroValue : value zeroOpening = 0)
    (positiveValue : 0 < value positiveOpening)
    (sameDigest : model.digest zeroOpening = model.digest positiveOpening) :
    FamilyBreak model .note where
  pair := zeroPositiveBindingBreak value zeroOpening positiveOpening
    (zeroIsNote.trans positiveIsNote.symm) zeroValue positiveValue sameDigest
  leftFamily := zeroIsNote

/-- Family-specialized constructor for an unequal extracted opening and the
canonical empty opening with the same note commitment. -/
def emptyNoteBreak (model : BindingModel)
    (opening canonicalEmpty : model.Preimage)
    (openingIsNote : model.family opening = .note)
    (emptyIsNote : model.family canonicalEmpty = .note)
    (different : opening ≠ canonicalEmpty)
    (sameDigest : model.digest opening = model.digest canonicalEmpty) :
    FamilyBreak model .note where
  pair := bindingBreakOfDistinct opening canonicalEmpty
    (openingIsNote.trans emptyIsNote.symm) different sameDigest
  leftFamily := openingIsNote

/-- Cross-domain empty-leaf *tagged-preimage* case. This does not certify a
live primitive collision: `singleKey` does not use the call-107/108 evaluator. -/
def emptyAuthorizationBreak (model : BindingModel)
    (accumulatorAuth emptySingleAuth : model.Preimage)
    (accumulatorIsAuth : model.family accumulatorAuth = .authorization)
    (emptyIsAuth : model.family emptySingleAuth = .authorization)
    (different : accumulatorAuth ≠ emptySingleAuth)
    (sameFullIdentity : model.digest accumulatorAuth =
      model.digest emptySingleAuth) : FamilyBreak model .authorization where
  pair := bindingBreakOfDistinct accumulatorAuth emptySingleAuth
    (accumulatorIsAuth.trans emptyIsAuth.symm) different sameFullIdentity
  leftFamily := accumulatorIsAuth

/-- RP05 signer identities and policy tags contain all seven words. -/
abbrev FullTag (Word : Type*) := Fin 7 → Word

/-- A checked Approval membership comparison.  Equality is over all seven
coordinates, rather than a legacy five-word prefix. -/
structure FullTagMatch (Key Word : Type*) where
  slot : SignerSlot
  signerKey : Key
  signerIdentity : FullTag Word
  registeredTag : FullTag Word
  fullEquality : signerIdentity = registeredTag

/-- Seven coordinate equalities construct the complete tag equality used by
Approval membership. -/
def fullTagMatchOfCoordinates {Key Word : Type*}
    (slot : SignerSlot) (signerKey : Key)
    (signerIdentity registeredTag : FullTag Word)
    (coordinates : ∀ coordinate, signerIdentity coordinate =
      registeredTag coordinate) : FullTagMatch Key Word where
  slot := slot
  signerKey := signerKey
  signerIdentity := signerIdentity
  registeredTag := registeredTag
  fullEquality := funext coordinates

inductive ProducerEvidence where
  | retainedHonest
  | freshExtracted
deriving DecidableEq

/-- Exact policy, injective 104-word intent, and policy-key identity carried
unchanged down one reconstructed chain.  Their concrete representations are
left to the source/extractor refinement. -/
structure ChainContext (Policy Intent PolicyKey : Type*) where
  policy : Policy
  intent : Intent
  policyKey : PolicyKey

@[ext] theorem ChainContext.ext {Policy Intent PolicyKey : Type*}
    {left right : ChainContext Policy Intent PolicyKey}
    (policy : left.policy = right.policy)
    (intent : left.intent = right.intent)
    (policyKey : left.policyKey = right.policyKey) : left = right := by
  cases left
  cases right
  simp_all

/-- Native T1--T3 role facts used by the producer classifier.  Accumulator
input0/output0 are reserved zero/native notes, input1 is an active positive
ordinary signer note, and an active ordinary output1 is positive. -/
structure ApprovalRoleShape where
  accumulatorInputValue : Nat
  accumulatorInputAsset : Nat
  signerInputValue : Nat
  accumulatorOutputValue : Nat
  accumulatorOutputAsset : Nat
  ordinaryOutputValue : Option Nat
  accumulatorInputZero : accumulatorInputValue = 0
  accumulatorInputNative : accumulatorInputAsset = 0
  signerInputPositive : 0 < signerInputValue
  accumulatorOutputZero : accumulatorOutputValue = 0
  accumulatorOutputNative : accumulatorOutputAsset = 0
  ordinaryOutputPositive : ∀ value,
    ordinaryOutputValue = some value → 0 < value

/-! ## Local typed transition and raw producer decision -/

/-- The successful local producer case.  It contains one actual T1--T5 typed
Approval transition, its mixed honest/fresh provenance, the complete signer
tag comparison, and the T4--T5 bootstrap equivalence. -/
structure RegisteredApprovalLink
    (Handle Policy Intent PolicyKey Key Word : Type*)
    (expected : ChainContext Policy Intent PolicyKey)
    (current : ApprovalState) where
  before : ApprovalState
  slot : SignerSlot
  step : ApprovalStep before slot current
  source : ProducerEvidence
  context : ChainContext Policy Intent PolicyKey
  context_eq : context = expected
  roles : ApprovalRoleShape
  signer : FullTagMatch Key Word
  signer_slot_eq : signer.slot = slot
  predecessor : Option Handle
  /-- T4--T5: input0 is inactive exactly at the count-zero bootstrap. -/
  predecessor_none_iff : predecessor = none ↔ before.count = 0

/-- Result of the deterministic local origin reduction.  Non-Approval
constructors are not bare error labels: each contains the conflicting pair
returned by the branch pass. -/
inductive RawOrigin
    (model : BindingModel)
    (Handle Policy Intent PolicyKey Key Word : Type*)
    (expected : ChainContext Policy Intent PolicyKey) : ApprovalState → Type _ where
  | approval {current : ApprovalState}
      (link : RegisteredApprovalLink Handle Policy Intent PolicyKey Key Word
        expected current) : RawOrigin model Handle Policy Intent PolicyKey Key Word
          expected current
  | ordinary {current : ApprovalState} (pair : FamilyBreak model .note) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current
  | coinbase {current : ApprovalState} (pair : FamilyBreak model .note) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current
  | emptyNote {current : ApprovalState} (pair : FamilyBreak model .note) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current
  | emptyAuthorization {current : ApprovalState}
      (pair : FamilyBreak model .authorization) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current
  | authorization {current : ApprovalState}
      (pair : FamilyBreak model .authorization) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current
  | accumulator {current : ApprovalState}
      (pair : FamilyBreak model .accumulator) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current
  | merkle {current : ApprovalState} (pair : FamilyBreak model .merkle) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current
  | policy {current : ApprovalState} (pair : FamilyBreak model .policy) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current
  | intent {current : ApprovalState} (pair : FamilyBreak model .intent) :
      RawOrigin model Handle Policy Intent PolicyKey Key Word expected current

/-- Erase the producer label while retaining the exact pair. -/
def RawOrigin.break? {model : BindingModel}
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {expected : ChainContext Policy Intent PolicyKey} {current : ApprovalState} :
    RawOrigin model Handle Policy Intent PolicyKey Key Word expected current →
      Option (BindingBreak model)
  | .approval _ => none
  | .ordinary pair => some pair.pair
  | .coinbase pair => some pair.pair
  | .emptyNote pair => some pair.pair
  | .emptyAuthorization pair => some pair.pair
  | .authorization pair => some pair.pair
  | .accumulator pair => some pair.pair
  | .merkle pair => some pair.pair
  | .policy pair => some pair.pair
  | .intent pair => some pair.pair

theorem raw_origin_break?_eq_none_iff_approval
    {model : BindingModel}
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {expected : ChainContext Policy Intent PolicyKey} {current : ApprovalState}
    (origin : RawOrigin model Handle Policy Intent PolicyKey Key Word
      expected current) :
    origin.break? = none ↔
      ∃ link, origin = RawOrigin.approval link := by
  cases origin <;> simp [RawOrigin.break?]

/-! ## Deterministic raw producer classifier -/

/-- Projections from actual canonical encodings.  All encodings remain in
`model.Preimage`, so every reported break contains the bytes supplied by the
branch pass, not a postulated abstract collision. -/
structure OriginCodec (model : BindingModel) where
  noteValue : model.Preimage → Nat
  noteAsset : model.Preimage → Nat
  noteIdentity : model.Preimage → model.Digest
  authorizationAccumulatorDigest : model.Preimage → model.Digest
  accumulatorPolicyDigest : model.Preimage → model.Digest
  accumulatorIntentDigest : model.Preimage → model.Digest
  accumulatorState : model.Preimage → Option ApprovalState
  authorizationDomain : model.Preimage → AuthorizationDomain
  canonicalEmptyOpening : model.Preimage
  canonicalEmptySingleAuthorization : model.Preimage

/-- Typed context projections of the concrete canonical encodings. -/
structure ContextCodec (model : BindingModel)
    (Policy Intent PolicyKey : Type*) where
  policyOf : model.Preimage → Policy
  intentOf : model.Preimage → Intent
  policyKeyOfAuthorization : model.Preimage → PolicyKey

def currentAccumulatorPolicy (preimage : CurrentAccumulatorEncoding) : Digest :=
  List.ofFn fun limb : Fin 7 => preimage ⟨limb.val, by omega⟩

def currentAccumulatorIntent (preimage : CurrentAccumulatorEncoding) : Digest :=
  List.ofFn fun limb : Fin 7 => preimage ⟨7 + limb.val, by omega⟩

def currentAccumulatorState (preimage : CurrentAccumulatorEncoding) : ApprovalState where
  count := preimage 16
  bitmap := Finset.univ.filter fun slot : SignerSlot =>
    preimage ⟨17 + slot.val, by omega⟩ = 1

/-- Source `SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN` and the full
SingleKey digest of the fixed canonical nonzero key `[1,0,0,0,0]`.
The source sponge frame appends two zero words. -/
def currentKnownEmptyIdentity : Digest :=
  poseidon2V8Sponge 0x4853_4b41_5632_0001 [1, 0, 0, 0, 0, 0, 0]

/-- Exact zero-value native default opening used by the repaired note tree.
Its note commitment is a hash of a known note preimage, not raw zero words. -/
def currentKnownEmptyOpening : V8NoteOpening where
  value := 0
  assetId := 0
  recipientKey := [0, 0, 0, 0]
  authorizationKey := currentKnownEmptyIdentity.take 4
  rho := [0, 0, 0, 0]
  randomness := currentKnownEmptyIdentity.drop 4 ++ [0]

def currentKnownEmptyNotePreimage : CurrentNotePreimage where
  opening := currentKnownEmptyOpening
  authorizationIdentity := currentKnownEmptyIdentity

def currentKnownEmptyKey : Fin 5 → Nat :=
  fun limb => if limb.val = 0 then 1 else 0

theorem current_known_empty_single_authorization_digest :
    currentBindingDigest (.singleKeyAuthorization currentKnownEmptyKey) =
      currentKnownEmptyIdentity := by
  simp [currentBindingDigest, currentSourceSingleKeyDomain,
    currentSourceSingleKeyWords, currentKnownEmptyKey,
    currentKnownEmptyIdentity]

/-- Total projections for the concrete tagged encoding.  Wrong-family cases
are total defaults only; every registry record separately carries the exact
family proof, so those branches cannot be used by a successful constructor. -/
def currentOriginCodec : OriginCodec currentBindingModel where
  noteValue
    | .note preimage => preimage.opening.value
    | _ => 0
  noteAsset
    | .note preimage => preimage.opening.assetId
    | _ => 0
  noteIdentity
    | .note preimage => preimage.authorizationIdentity
    | _ => []
  authorizationAccumulatorDigest
    | .authorization preimage => preimage.accumulatorDigest
    | _ => []
  accumulatorPolicyDigest
    | .accumulator preimage => currentAccumulatorPolicy preimage
    | _ => []
  accumulatorIntentDigest
    | .accumulator preimage => currentAccumulatorIntent preimage
    | _ => []
  accumulatorState
    | .accumulator preimage => some (currentAccumulatorState preimage)
    | _ => none
  authorizationDomain
    | .authorization preimage => preimage.domain
    | .singleKeyAuthorization _ => .singleKey
    | _ => .singleKey
  canonicalEmptyOpening := .note currentKnownEmptyNotePreimage
  canonicalEmptySingleAuthorization := .singleKeyAuthorization currentKnownEmptyKey

def currentContextCodec : ContextCodec currentBindingModel
    CurrentPolicyEncoding CurrentIntentEncoding Digest where
  policyOf
    | .policy preimage => preimage
    | _ => fun _ => 0
  intentOf
    | .intent preimage => preimage
    | _ => fun _ => 0
  policyKeyOfAuthorization
    | .authorization preimage => preimage.policyKey
    | _ => []

/-! ## Staged disclosure: Approval commitments, Final preimage

Approval transactions disclose the policy and intent *digests* carried by
the 23-word accumulator, but they do not disclose a 104-word intent opening.
The latter first becomes source-bound in Final mode.  These types prevent an
Approval record from pretending to contain information absent from its
accepted witness.
-/

structure PendingAuthorization where
  policyDigest : Digest
  intentDigest : Digest
  policyKey : Digest
  accumulatorDigest : Digest
  noteIdentity : Digest
  state : ApprovalState
deriving DecidableEq

/-- One accepted Approval transition.  Context and key conservation are
explicit consequences to be supplied by the current local/source projection;
there is deliberately no `CurrentIntentEncoding` field. -/
structure PendingApprovalStep (before after : PendingAuthorization) where
  slot : SignerSlot
  step : ApprovalStep before.state slot after.state
  policyConserved : after.policyDigest = before.policyDigest
  intentConserved : after.intentDigest = before.intentDigest
  policyKeyConserved : after.policyKey = before.policyKey
  source : ProducerEvidence

/-- Final mode is the unique promotion point.  Its 104-word source opening is
checked by the live intent evaluator against the digest already carried by
the pending accumulator. -/
structure FinalizedAuthorization (pending : PendingAuthorization) where
  intentOpening : CurrentIntentEncoding
  intentBound :
    poseidon2V8Sponge currentIntentBindingDomain (List.ofFn intentOpening) =
      pending.intentDigest

theorem PendingApprovalStep.context_conserved
    {before after : PendingAuthorization}
    (transition : PendingApprovalStep before after) :
    (after.policyDigest, after.intentDigest, after.policyKey) =
      (before.policyDigest, before.intentDigest, before.policyKey) := by
  rw [transition.policyConserved, transition.intentConserved,
    transition.policyKeyConserved]

theorem FinalizedAuthorization.replay_key_state_conserved
    {pending : PendingAuthorization}
    (finalized : FinalizedAuthorization pending) :
    pending.policyKey = pending.policyKey ∧ pending.state = pending.state ∧
      currentBindingDigest (.intent finalized.intentOpening) =
        pending.intentDigest := by
  exact ⟨rfl, rfl, finalized.intentBound⟩

/-- A second Final opening for the same pending digest is either byte-for-byte
the same opening or is the concrete intent-family binding break. -/
def finalizedIntentEqOrBreak {pending : PendingAuthorization}
    (finalized : FinalizedAuthorization pending)
    (other : CurrentIntentEncoding)
    (otherBound : poseidon2V8Sponge currentIntentBindingDomain
      (List.ofFn other) = pending.intentDigest) :
    PSum (finalized.intentOpening = other)
      (FamilyBreak currentBindingModel .intent) := by
  classical
  by_cases same : finalized.intentOpening = other
  · exact PSum.inl same
  · exact PSum.inr {
      pair := bindingBreakOfDistinct (.intent finalized.intentOpening) (.intent other)
        rfl (by
          intro equal
          apply same
          cases equal
          rfl)
        (finalized.intentBound.trans otherBound.symm)
      leftFamily := rfl
    }

structure AccumulatorInput (model : BindingModel) (codec : OriginCodec model)
    {Policy Intent PolicyKey : Type*}
    (contextCodec : ContextCodec model Policy Intent PolicyKey)
    (expected : ChainContext Policy Intent PolicyKey)
    (current : ApprovalState) where
  opening : model.Preimage
  openingIsNote : model.family opening = .note
  valueZero : codec.noteValue opening = 0
  assetNative : codec.noteAsset opening = 0
  accumulatorAuthorization : model.Preimage
  authorizationIsFull : model.family accumulatorAuthorization = .authorization
  authorizationDomain :
    codec.authorizationDomain accumulatorAuthorization = .accumulator
  identityBound : codec.noteIdentity opening =
    model.digest accumulatorAuthorization
  accumulatorOpening : model.Preimage
  accumulatorIsAccumulator : model.family accumulatorOpening = .accumulator
  accumulatorBound : codec.authorizationAccumulatorDigest accumulatorAuthorization =
    model.digest accumulatorOpening
  policyEncoding : model.Preimage
  policyIsPolicy : model.family policyEncoding = .policy
  policyBound : codec.accumulatorPolicyDigest accumulatorOpening =
    model.digest policyEncoding
  policyRepresents : contextCodec.policyOf policyEncoding = expected.policy
  intentEncoding : model.Preimage
  intentIsIntent : model.family intentEncoding = .intent
  intentBound : codec.accumulatorIntentDigest accumulatorOpening =
    model.digest intentEncoding
  intentRepresents : contextCodec.intentOf intentEncoding = expected.intent
  policyKeyRepresents :
    contextCodec.policyKeyOfAuthorization accumulatorAuthorization = expected.policyKey
  stateBound : codec.accumulatorState accumulatorOpening = some current

structure ApprovalProducer
    (model : BindingModel) (codec : OriginCodec model)
    (Handle Policy Intent PolicyKey Key Word : Type*)
    (contextCodec : ContextCodec model Policy Intent PolicyKey)
    where
  current : ApprovalState
  context : ChainContext Policy Intent PolicyKey
  link : RegisteredApprovalLink Handle Policy Intent PolicyKey Key Word
    context current
  opening : model.Preimage
  openingIsNote : model.family opening = .note
  outputValueZero : codec.noteValue opening = 0
  outputAssetNative : codec.noteAsset opening = 0
  accumulatorAuthorization : model.Preimage
  authorizationIsFull : model.family accumulatorAuthorization = .authorization
  authorizationDomain :
    codec.authorizationDomain accumulatorAuthorization = .accumulator
  identityBound : codec.noteIdentity opening =
    model.digest accumulatorAuthorization
  accumulatorOpening : model.Preimage
  accumulatorIsAccumulator : model.family accumulatorOpening = .accumulator
  accumulatorBound : codec.authorizationAccumulatorDigest accumulatorAuthorization =
    model.digest accumulatorOpening
  policyEncoding : model.Preimage
  policyIsPolicy : model.family policyEncoding = .policy
  policyBound : codec.accumulatorPolicyDigest accumulatorOpening =
    model.digest policyEncoding
  policyRepresents : contextCodec.policyOf policyEncoding = context.policy
  intentEncoding : model.Preimage
  intentIsIntent : model.family intentEncoding = .intent
  intentBound : codec.accumulatorIntentDigest accumulatorOpening =
    model.digest intentEncoding
  intentRepresents : contextCodec.intentOf intentEncoding = context.intent
  policyKeyRepresents :
    contextCodec.policyKeyOfAuthorization accumulatorAuthorization = context.policyKey
  outputStateBound : codec.accumulatorState accumulatorOpening = some current

/-- A concrete current-model `AccumulatorInput` necessarily contains an
actual 104-word preimage of its stored intent digest.  This is useful both as
an elimination rule and as an exact statement of the information that must
come from the originating value-lock transaction: seven digest words alone
cannot construct this field. -/
theorem current_accumulator_input_supplies_intent_preimage
    {codec : OriginCodec currentBindingModel}
    {Policy Intent PolicyKey : Type*}
    {contextCodec : ContextCodec currentBindingModel Policy Intent PolicyKey}
    {expected : ChainContext Policy Intent PolicyKey}
    {current : ApprovalState}
    (input : AccumulatorInput currentBindingModel codec contextCodec expected current) :
    ∃ preimage : CurrentIntentEncoding,
      poseidon2V8Sponge currentIntentBindingDomain (List.ofFn preimage) =
        codec.accumulatorIntentDigest input.accumulatorOpening := by
  cases encodingEq : input.intentEncoding with
  | note preimage =>
      have family := input.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | merkle preimage =>
      have family := input.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | authorization preimage =>
      have family := input.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | singleKeyAuthorization key =>
      have family := input.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | accumulator preimage =>
      have family := input.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | policy preimage =>
      have family := input.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | intent preimage =>
      refine ⟨preimage, ?_⟩
      have bound := input.intentBound
      rw [encodingEq] at bound
      change codec.accumulatorIntentDigest input.accumulatorOpening =
        poseidon2V8Sponge currentIntentBindingDomain (List.ofFn preimage) at bound
      exact bound.symm

/-- The same unavoidable preimage requirement for an Approval producer. -/
theorem current_approval_producer_supplies_intent_preimage
    {codec : OriginCodec currentBindingModel}
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {contextCodec : ContextCodec currentBindingModel Policy Intent PolicyKey}
    (producer : ApprovalProducer currentBindingModel codec Handle Policy Intent
      PolicyKey Key Word contextCodec) :
    ∃ preimage : CurrentIntentEncoding,
      poseidon2V8Sponge currentIntentBindingDomain (List.ofFn preimage) =
        codec.accumulatorIntentDigest producer.accumulatorOpening := by
  cases encodingEq : producer.intentEncoding with
  | note preimage =>
      have family := producer.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | merkle preimage =>
      have family := producer.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | authorization preimage =>
      have family := producer.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | singleKeyAuthorization key =>
      have family := producer.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | accumulator preimage =>
      have family := producer.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | policy preimage =>
      have family := producer.intentIsIntent
      simp [currentBindingModel, currentBindingFamily, encodingEq] at family
  | intent preimage =>
      refine ⟨preimage, ?_⟩
      have bound := producer.intentBound
      rw [encodingEq] at bound
      change codec.accumulatorIntentDigest producer.accumulatorOpening =
        poseidon2V8Sponge currentIntentBindingDomain (List.ofFn preimage) at bound
      exact bound.symm

structure PositiveProducer (model : BindingModel) (codec : OriginCodec model) where
  opening : model.Preimage
  openingIsNote : model.family opening = .note
  valuePositive : 0 < codec.noteValue opening

structure EmptyProducer (model : BindingModel) (codec : OriginCodec model) where
  opening : model.Preimage
  openingIsCanonical : opening = codec.canonicalEmptyOpening
  openingIsNote : model.family opening = .note
  valueZero : codec.noteValue opening = 0
  assetNative : codec.noteAsset opening = 0
  singleKeyAuthorization : model.Preimage
  authorizationIsCanonical :
    singleKeyAuthorization = codec.canonicalEmptySingleAuthorization
  authorizationIsFull : model.family singleKeyAuthorization = .authorization
  authorizationDomain :
    codec.authorizationDomain singleKeyAuthorization = .singleKey
  identityBound : codec.noteIdentity opening =
    model.digest singleKeyAuthorization

/-- The actual known-empty producer has a call-0 SingleKey preimage.  Its
identity equality is the source sponge equation, not a compress14 premise. -/
def currentKnownEmptyProducer :
    EmptyProducer currentBindingModel currentOriginCodec where
  opening := .note currentKnownEmptyNotePreimage
  openingIsCanonical := rfl
  openingIsNote := rfl
  valueZero := rfl
  assetNative := rfl
  singleKeyAuthorization := .singleKeyAuthorization currentKnownEmptyKey
  authorizationIsCanonical := rfl
  authorizationIsFull := rfl
  authorizationDomain := rfl
  identityBound := current_known_empty_single_authorization_digest.symm

inductive TypedProducer
    (model : BindingModel) (codec : OriginCodec model)
    (Handle Policy Intent PolicyKey Key Word : Type*)
    (contextCodec : ContextCodec model Policy Intent PolicyKey)
    where
  | approval (producer : ApprovalProducer model codec Handle Policy Intent
      PolicyKey Key Word contextCodec)
  | ordinary (producer : PositiveProducer model codec)
  | coinbase (producer : PositiveProducer model codec)
  | empty (producer : EmptyProducer model codec)

def TypedProducer.opening
    {model : BindingModel} {codec : OriginCodec model}
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {contextCodec : ContextCodec model Policy Intent PolicyKey}
    : TypedProducer model codec Handle Policy Intent PolicyKey Key Word contextCodec
      → model.Preimage
  | .approval producer => producer.opening
  | .ordinary producer => producer.opening
  | .coinbase producer => producer.opening
  | .empty producer => producer.opening

/-- Raw first-divergence evidence from Merkle verification. -/
structure MerkleDivergence (model : BindingModel) where
  left : model.Preimage
  right : model.Preimage
  leftIsMerkle : model.family left = .merkle
  rightIsMerkle : model.family right = .merkle
  different : left ≠ right
  sameDigest : model.digest left = model.digest right

/-- Either the accepted path identifies the registered leaf commitment, or
it has already exposed the first differing Merkle compression inputs. -/
inductive LeafAuthentication
    (model : BindingModel) (inputOpening producerOpening : model.Preimage) where
  | exact (sameCommitment : model.digest inputOpening =
      model.digest producerOpening)
  | merkle (divergence : MerkleDivergence model)

private def merkleFamilyBreak {model : BindingModel}
    (divergence : MerkleDivergence model) : FamilyBreak model .merkle where
  pair := bindingBreakOfDistinct divergence.left divergence.right
    (divergence.leftIsMerkle.trans divergence.rightIsMerkle.symm)
    divergence.different divergence.sameDigest
  leftFamily := divergence.leftIsMerkle

private theorem authorization_preimages_differ
    {model : BindingModel} {codec : OriginCodec model}
    {accumulator single : model.Preimage}
    (accDomain : codec.authorizationDomain accumulator = .accumulator)
    (singleDomain : codec.authorizationDomain single = .singleKey) :
    accumulator ≠ single := by
  intro equal
  subst single
  rw [accDomain] at singleDomain
  cases singleDomain

/-- Deterministic classification of one accepted zero/native accumulator
input.  It compares actual canonical encodings.  Ordinary/coinbase equality
contradicts positivity; empty equality yields the cross-domain full-auth
pair; Approval mismatches yield note/full-auth/policy/intent pairs in that
order. -/
def classifyOrigin
    {model : BindingModel} [DecidableEq model.Preimage]
    {codec : OriginCodec model}
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {contextCodec : ContextCodec model Policy Intent PolicyKey}
    {expected : ChainContext Policy Intent PolicyKey}
    {current : ApprovalState}
    (input : AccumulatorInput model codec contextCodec expected current)
    (producer : TypedProducer model codec Handle Policy Intent PolicyKey Key
      Word contextCodec)
    (authentication : LeafAuthentication model input.opening producer.opening) :
    RawOrigin model Handle Policy Intent PolicyKey Key Word expected current := by
  cases authentication with
  | merkle divergence => exact .merkle (merkleFamilyBreak divergence)
  | exact sameCommitment =>
      cases producer with
      | ordinary producer =>
          exact .ordinary (noteBreakOfZeroPositive model codec.noteValue
            input.opening producer.opening input.openingIsNote
            producer.openingIsNote input.valueZero producer.valuePositive
            sameCommitment)
      | coinbase producer =>
          exact .coinbase (noteBreakOfZeroPositive model codec.noteValue
            input.opening producer.opening input.openingIsNote
            producer.openingIsNote input.valueZero producer.valuePositive
            sameCommitment)
      | empty producer =>
          if openingEq : input.opening = producer.opening then
            have identityEq : model.digest input.accumulatorAuthorization =
                model.digest producer.singleKeyAuthorization := by
              calc
                _ = codec.noteIdentity input.opening := input.identityBound.symm
                _ = codec.noteIdentity producer.opening := congrArg _ openingEq
                _ = _ := producer.identityBound
            exact .emptyAuthorization (emptyAuthorizationBreak model
              input.accumulatorAuthorization producer.singleKeyAuthorization
              input.authorizationIsFull producer.authorizationIsFull
              (authorization_preimages_differ input.authorizationDomain
                producer.authorizationDomain) identityEq)
          else
            exact .emptyNote (emptyNoteBreak model input.opening producer.opening
              input.openingIsNote producer.openingIsNote openingEq sameCommitment)
      | approval producer =>
          if openingEq : input.opening = producer.opening then
            if authorizationEq : input.accumulatorAuthorization =
                producer.accumulatorAuthorization then
              have accumulatorDigestEq : model.digest input.accumulatorOpening =
                  model.digest producer.accumulatorOpening := by
                calc
                  _ = codec.authorizationAccumulatorDigest
                      input.accumulatorAuthorization := input.accumulatorBound.symm
                  _ = codec.authorizationAccumulatorDigest
                      producer.accumulatorAuthorization := congrArg _ authorizationEq
                  _ = _ := producer.accumulatorBound
              if accumulatorEq : input.accumulatorOpening =
                  producer.accumulatorOpening then
                if policyEq : input.policyEncoding = producer.policyEncoding then
                  if intentEq : input.intentEncoding = producer.intentEncoding then
                    have policyContextEq : expected.policy = producer.context.policy := by
                      calc
                        _ = contextCodec.policyOf input.policyEncoding :=
                          input.policyRepresents.symm
                        _ = contextCodec.policyOf producer.policyEncoding :=
                          congrArg _ policyEq
                        _ = _ := producer.policyRepresents
                    have intentContextEq : expected.intent = producer.context.intent := by
                      calc
                        _ = contextCodec.intentOf input.intentEncoding :=
                          input.intentRepresents.symm
                        _ = contextCodec.intentOf producer.intentEncoding :=
                          congrArg _ intentEq
                        _ = _ := producer.intentRepresents
                    have policyKeyContextEq :
                        expected.policyKey = producer.context.policyKey := by
                      calc
                        _ = contextCodec.policyKeyOfAuthorization
                            input.accumulatorAuthorization :=
                          input.policyKeyRepresents.symm
                        _ = contextCodec.policyKeyOfAuthorization
                            producer.accumulatorAuthorization :=
                          congrArg _ authorizationEq
                        _ = _ := producer.policyKeyRepresents
                    have contextEq : expected = producer.context :=
                      ChainContext.ext policyContextEq intentContextEq policyKeyContextEq
                    have stateSomeEq : some current = some producer.current := by
                      calc
                        _ = codec.accumulatorState input.accumulatorOpening :=
                          input.stateBound.symm
                        _ = codec.accumulatorState producer.accumulatorOpening :=
                          congrArg _ accumulatorEq
                        _ = _ := producer.outputStateBound
                    have stateEq : current = producer.current := Option.some.inj stateSomeEq
                    cases contextEq
                    cases stateEq
                    exact .approval producer.link
                  else
                    have digestEq : model.digest input.intentEncoding =
                        model.digest producer.intentEncoding := by
                      calc
                        _ = codec.accumulatorIntentDigest input.accumulatorOpening :=
                          input.intentBound.symm
                        _ = codec.accumulatorIntentDigest producer.accumulatorOpening :=
                          congrArg _ accumulatorEq
                        _ = _ := producer.intentBound
                    exact .intent {
                      pair := bindingBreakOfDistinct input.intentEncoding
                        producer.intentEncoding
                        (input.intentIsIntent.trans producer.intentIsIntent.symm)
                        intentEq digestEq
                      leftFamily := input.intentIsIntent
                    }
                else
                  have digestEq : model.digest input.policyEncoding =
                      model.digest producer.policyEncoding := by
                    calc
                      _ = codec.accumulatorPolicyDigest input.accumulatorOpening :=
                        input.policyBound.symm
                      _ = codec.accumulatorPolicyDigest producer.accumulatorOpening :=
                        congrArg _ accumulatorEq
                      _ = _ := producer.policyBound
                  exact .policy {
                    pair := bindingBreakOfDistinct input.policyEncoding
                      producer.policyEncoding
                      (input.policyIsPolicy.trans producer.policyIsPolicy.symm)
                      policyEq digestEq
                    leftFamily := input.policyIsPolicy
                  }
              else
                exact .accumulator {
                  pair := bindingBreakOfDistinct input.accumulatorOpening
                    producer.accumulatorOpening
                    (input.accumulatorIsAccumulator.trans
                      producer.accumulatorIsAccumulator.symm)
                    accumulatorEq accumulatorDigestEq
                  leftFamily := input.accumulatorIsAccumulator
                }
            else
              have identityEq : model.digest input.accumulatorAuthorization =
                  model.digest producer.accumulatorAuthorization := by
                calc
                  _ = codec.noteIdentity input.opening := input.identityBound.symm
                  _ = codec.noteIdentity producer.opening := congrArg _ openingEq
                  _ = _ := producer.identityBound
              exact .authorization {
                pair := bindingBreakOfDistinct input.accumulatorAuthorization
                  producer.accumulatorAuthorization
                  (input.authorizationIsFull.trans
                    producer.authorizationIsFull.symm)
                  authorizationEq identityEq
                leftFamily := input.authorizationIsFull
              }
          else
            exact .emptyNote (emptyNoteBreak model input.opening producer.opening
              input.openingIsNote producer.openingIsNote openingEq sameCommitment)

/-! ## Accepted canonical-branch registry -/

/-- The registry is a finite-ancestry interface, not a history premise.
`originAt` may return any concrete binding break.  For an Approval result it
records only the local predecessor handle; `predecessor_state` links that
handle to the transition's `before` state.  Well-founded branch order proves
that following handles terminates. -/
structure AcceptedBranchRegistry
    (model : BindingModel)
    (Handle Policy Intent PolicyKey Key Word : Type*)
    (expected : ChainContext Policy Intent PolicyKey) where
  stateAt : Handle → ApprovalState
  originAt : (handle : Handle) →
    RawOrigin model Handle Policy Intent PolicyKey Key Word expected
      (stateAt handle)
  precedes : Handle → Handle → Prop
  branchWellFounded : WellFounded precedes
  predecessor_state :
    ∀ (handle : Handle)
      (link : RegisteredApprovalLink Handle Policy Intent PolicyKey Key Word
        expected (stateAt handle))
      (_originEq : originAt handle = RawOrigin.approval link)
      (predecessor : Handle),
      link.predecessor = some predecessor → stateAt predecessor = link.before
  predecessor_precedes :
    ∀ (handle : Handle)
      (link : RegisteredApprovalLink Handle Policy Intent PolicyKey Key Word
        expected (stateAt handle))
      (_originEq : originAt handle = RawOrigin.approval link)
      (predecessor : Handle),
      link.predecessor = some predecessor → precedes predecessor handle
  state_weight : ∀ handle, (stateAt handle).bitmap.card = (stateAt handle).count

/-- Finite staged registry used by RP05.  Approval rows are already reduced to
either a typed local link or a concrete binding break, so they need not invent
the Final-only 104-word intent opening.  Final promotion is kept separately in
`FinalizedAuthorization`. -/
structure FinitePendingBranchRegistry
    (Policy Intent PolicyKey Key Word : Type*)
    (expected : ChainContext Policy Intent PolicyKey) (size : Nat) where
  stateAt : Fin size → ApprovalState
  originAt : (index : Fin size) →
    RawOrigin currentBindingModel (Fin size) Policy Intent PolicyKey Key Word
      expected (stateAt index)
  predecessor_state :
    ∀ (index : Fin size)
      (link : RegisteredApprovalLink (Fin size) Policy Intent PolicyKey Key Word
        expected (stateAt index))
      (_originEq : originAt index = RawOrigin.approval link)
      (predecessor : Fin size),
      link.predecessor = some predecessor → stateAt predecessor = link.before
  predecessor_lt :
    ∀ (index : Fin size)
      (link : RegisteredApprovalLink (Fin size) Policy Intent PolicyKey Key Word
        expected (stateAt index))
      (_originEq : originAt index = RawOrigin.approval link)
      (predecessor : Fin size),
      link.predecessor = some predecessor → predecessor.val < index.val
  state_weight : ∀ index, (stateAt index).bitmap.card = (stateAt index).count

def FinitePendingBranchRegistry.toAccepted
    {Policy Intent PolicyKey Key Word : Type*}
    {expected : ChainContext Policy Intent PolicyKey} {size : Nat}
    (registry : FinitePendingBranchRegistry Policy Intent PolicyKey Key Word
      expected size) :
    AcceptedBranchRegistry currentBindingModel (Fin size) Policy Intent PolicyKey
      Key Word expected where
  stateAt := registry.stateAt
  originAt := registry.originAt
  precedes left right := left.val < right.val
  branchWellFounded := InvImage.wf Fin.val Nat.lt_wfRel.wf
  predecessor_state := registry.predecessor_state
  predecessor_precedes := registry.predecessor_lt
  state_weight := registry.state_weight

/-- Concrete finite canonical-branch table.  Handles are chronological
`Fin size` indices; the origin is computed from raw encodings by
`classifyOrigin`, and predecessor chronology is the ordinary index order. -/
structure FiniteAcceptedBranchRegistry
    (model : BindingModel) [DecidableEq model.Preimage]
    (codec : OriginCodec model)
    (Policy Intent PolicyKey Key Word : Type*)
    (contextCodec : ContextCodec model Policy Intent PolicyKey)
    (expected : ChainContext Policy Intent PolicyKey) (size : Nat) where
  stateAt : Fin size → ApprovalState
  inputAt : (index : Fin size) →
    AccumulatorInput model codec contextCodec expected (stateAt index)
  producerAt : (index : Fin size) →
    TypedProducer model codec (Fin size) Policy Intent PolicyKey Key Word
      contextCodec
  authenticationAt : (index : Fin size) →
    LeafAuthentication model (inputAt index).opening (producerAt index).opening
  predecessor_state :
    ∀ (index : Fin size)
      (link : RegisteredApprovalLink (Fin size) Policy Intent PolicyKey Key Word
        expected (stateAt index))
      (_originEq : classifyOrigin (inputAt index) (producerAt index)
        (authenticationAt index) = RawOrigin.approval link)
      (predecessor : Fin size),
      link.predecessor = some predecessor → stateAt predecessor = link.before
  predecessor_lt :
    ∀ (index : Fin size)
      (link : RegisteredApprovalLink (Fin size) Policy Intent PolicyKey Key Word
        expected (stateAt index))
      (_originEq : classifyOrigin (inputAt index) (producerAt index)
        (authenticationAt index) = RawOrigin.approval link)
      (predecessor : Fin size),
      link.predecessor = some predecessor → predecessor.val < index.val
  state_weight : ∀ index, (stateAt index).bitmap.card = (stateAt index).count

def FiniteAcceptedBranchRegistry.toAccepted
    {model : BindingModel} [DecidableEq model.Preimage]
    {codec : OriginCodec model}
    {Policy Intent PolicyKey Key Word : Type*}
    {contextCodec : ContextCodec model Policy Intent PolicyKey}
    {expected : ChainContext Policy Intent PolicyKey} {size : Nat}
    (registry : FiniteAcceptedBranchRegistry model codec Policy Intent PolicyKey
      Key Word contextCodec expected size) :
    AcceptedBranchRegistry model (Fin size) Policy Intent PolicyKey Key Word
      expected where
  stateAt := registry.stateAt
  originAt index := classifyOrigin (registry.inputAt index)
    (registry.producerAt index) (registry.authenticationAt index)
  precedes left right := left.val < right.val
  branchWellFounded := InvImage.wf Fin.val Nat.lt_wfRel.wf
  predecessor_state := registry.predecessor_state
  predecessor_precedes := registry.predecessor_lt
  state_weight := registry.state_weight

/-- Evidence retained for each reconstructed edge. -/
structure RegistryEdge (Key Word : Type*) where
  slot : SignerSlot
  source : ProducerEvidence
  signer : FullTagMatch Key Word
  signer_slot_eq : signer.slot = slot

def RegisteredApprovalLink.edge
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {expected : ChainContext Policy Intent PolicyKey} {current : ApprovalState}
    (link : RegisteredApprovalLink Handle Policy Intent PolicyKey Key Word
      expected current) : RegistryEdge Key Word where
  slot := link.slot
  source := link.source
  signer := link.signer
  signer_slot_eq := link.signer_slot_eq

/-! ## Backward reconstruction -/

/-- The reduction either returns the first exact binding pair or constructs
the complete chronological Approval chain. -/
inductive Reconstruction (model : BindingModel) (Key Word : Type*)
    (finish : ApprovalState) : Type _ where
  | binding (pair : BindingBreak model) : Reconstruction model Key Word finish
  | chain {start : ApprovalState} {slots : List SignerSlot}
      (history : ApprovalHistory start slots finish)
      (startCount : start.count = 0)
      (startBitmap : start.bitmap = ∅)
      (edges : List (RegistryEdge Key Word))
      (edgeSlots : edges.map RegistryEdge.slot = slots) :
      Reconstruction model Key Word finish

/-- Collision-free successful output, separated from the reduction's
failure-carrying result for convenient use by the authorization game. -/
structure ApprovalChain (Key Word : Type*) (finish : ApprovalState) where
  start : ApprovalState
  slots : List SignerSlot
  history : ApprovalHistory start slots finish
  startCount : start.count = 0
  startBitmap : start.bitmap = ∅
  edges : List (RegistryEdge Key Word)
  edgeSlots : edges.map RegistryEdge.slot = slots

/-- Typed Final entry from which the backwards pass starts.  Final input1 is
the reserved zero/native accumulator and the committed count reaches a
strictly positive policy threshold. -/
structure AcceptedFinal (Handle : Type*) (stateAt : Handle → ApprovalState) where
  handle : Handle
  accumulatorInputValue : Nat
  accumulatorInputAsset : Nat
  accumulatorInputZero : accumulatorInputValue = 0
  accumulatorInputNative : accumulatorInputAsset = 0
  threshold : Nat
  thresholdPositive : 0 < threshold
  thresholdReached : threshold ≤ (stateAt handle).count

/-- Backwards chronological induction over the actual predecessor handles.
No `ApprovalHistory` occurs among this theorem's premises. -/
noncomputable def reconstruct
    {model : BindingModel}
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {expected : ChainContext Policy Intent PolicyKey}
    (registry : AcceptedBranchRegistry model Handle Policy Intent PolicyKey
      Key Word expected) (terminal : Handle) :
    Reconstruction model Key Word (registry.stateAt terminal) := by
  refine registry.branchWellFounded.fix
    (C := fun handle => Reconstruction model Key Word (registry.stateAt handle))
    ?_ terminal
  ·
      intro terminal earlier
      by_cases countZero : (registry.stateAt terminal).count = 0
      · have bitmapZero : (registry.stateAt terminal).bitmap = ∅ := by
          apply Finset.card_eq_zero.mp
          rw [registry.state_weight terminal, countZero]
        exact Reconstruction.chain (ApprovalHistory.nil _) countZero bitmapZero
          [] (by simp)
      · generalize originEq : registry.originAt terminal = origin
        cases origin with
        | ordinary pair => exact Reconstruction.binding pair.pair
        | coinbase pair => exact Reconstruction.binding pair.pair
        | emptyNote pair => exact Reconstruction.binding pair.pair
        | emptyAuthorization pair => exact Reconstruction.binding pair.pair
        | authorization pair => exact Reconstruction.binding pair.pair
        | accumulator pair => exact Reconstruction.binding pair.pair
        | merkle pair => exact Reconstruction.binding pair.pair
        | policy pair => exact Reconstruction.binding pair.pair
        | intent pair => exact Reconstruction.binding pair.pair
        | approval link =>
            cases predecessorEq : link.predecessor with
            | none =>
                have beforeZero : link.before.count = 0 :=
                  link.predecessor_none_iff.mp predecessorEq
                have beforeBitmapZero : link.before.bitmap = ∅ := by
                  have weight : link.before.bitmap.card = link.before.count := by
                    have currentWeight := registry.state_weight terminal
                    rw [link.step.bitmap_eq,
                      Finset.card_insert_of_notMem link.step.fresh,
                      link.step.count_eq] at currentWeight
                    omega
                  apply Finset.card_eq_zero.mp
                  simpa [beforeZero] using weight
                exact Reconstruction.chain
                  (ApprovalHistory.snoc (ApprovalHistory.nil link.before) link.step)
                  beforeZero beforeBitmapZero [link.edge] (by simp [RegisteredApprovalLink.edge])
            | some predecessor =>
                have predecessorState :
                    registry.stateAt predecessor = link.before :=
                  registry.predecessor_state terminal link originEq predecessor
                    predecessorEq
                have predecessorEarlier : registry.precedes predecessor terminal :=
                  registry.predecessor_precedes terminal link originEq predecessor
                    predecessorEq
                have priorResult := earlier predecessor predecessorEarlier
                rw [predecessorState] at priorResult
                cases priorResult with
                | binding pair => exact Reconstruction.binding pair
                | @chain start slots history startCount startBitmap edges edgeSlots =>
                    exact Reconstruction.chain
                      (ApprovalHistory.snoc history link.step)
                      startCount startBitmap (edges.concat link.edge) (by
                        simp [edgeSlots, RegisteredApprovalLink.edge])

/-- Off the explicitly represented binding events, the raw registry forces
an actual bootstrap-to-terminal Approval history.  The only assumptions are
local registry refinement, well-founded branch chronology, and absence of a
stored conflicting pair; there is no historical-origin premise. -/
noncomputable def reconstruct_off_binding
    {model : BindingModel}
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {expected : ChainContext Policy Intent PolicyKey}
    (registry : AcceptedBranchRegistry model Handle Policy Intent PolicyKey
      Key Word expected)
    (noBindingBreak : ∀ handle, (registry.originAt handle).break? = none)
    (terminal : Handle) :
    ApprovalChain Key Word (registry.stateAt terminal) := by
  refine registry.branchWellFounded.fix
    (C := fun handle => ApprovalChain Key Word (registry.stateAt handle))
    ?_ terminal
  ·
      intro terminal earlier
      by_cases countZero : (registry.stateAt terminal).count = 0
      · have bitmapZero : (registry.stateAt terminal).bitmap = ∅ := by
          apply Finset.card_eq_zero.mp
          rw [registry.state_weight terminal, countZero]
        exact {
          start := registry.stateAt terminal
          slots := []
          history := ApprovalHistory.nil _
          startCount := countZero
          startBitmap := bitmapZero
          edges := []
          edgeSlots := by simp
        }
      · have existsLink :=
          (raw_origin_break?_eq_none_iff_approval
            (registry.originAt terminal)).mp (noBindingBreak terminal)
        -- This noncomputable convenience projection is not the efficient
        -- accepted-ledger extractor; that endpoint remains separate.
        let link := Classical.choose existsLink
        have originEq := Classical.choose_spec existsLink
        cases predecessorEq : link.predecessor with
        | none =>
            have beforeZero : link.before.count = 0 :=
              link.predecessor_none_iff.mp predecessorEq
            have beforeBitmapZero : link.before.bitmap = ∅ := by
              have currentWeight := registry.state_weight terminal
              have beforeWeight : link.before.bitmap.card = link.before.count := by
                rw [link.step.bitmap_eq,
                  Finset.card_insert_of_notMem link.step.fresh,
                  link.step.count_eq] at currentWeight
                omega
              apply Finset.card_eq_zero.mp
              simpa [beforeZero] using beforeWeight
            exact {
              start := link.before
              slots := [link.slot]
              history := ApprovalHistory.snoc (ApprovalHistory.nil link.before)
                link.step
              startCount := beforeZero
              startBitmap := beforeBitmapZero
              edges := [link.edge]
              edgeSlots := by simp [RegisteredApprovalLink.edge]
            }

        | some predecessor =>
            have predecessorState :
                registry.stateAt predecessor = link.before :=
              registry.predecessor_state terminal link originEq predecessor
                predecessorEq
            have predecessorEarlier : registry.precedes predecessor terminal :=
              registry.predecessor_precedes terminal link originEq predecessor
                predecessorEq
            have priorResult := earlier predecessor predecessorEarlier
            rw [predecessorState] at priorResult
            exact {
              start := priorResult.start
              slots := priorResult.slots.concat link.slot
              history := ApprovalHistory.snoc priorResult.history link.step
              startCount := priorResult.startCount
              startBitmap := priorResult.startBitmap
              edges := priorResult.edges.concat link.edge
              edgeSlots := by
                simpa [RegisteredApprovalLink.edge] using
                  congrArg (fun slots => slots.concat link.slot)
                    priorResult.edgeSlots
            }

/-- Final-facing form of `reconstruct_off_binding`. -/
noncomputable def accepted_final_chain_off_binding
    {model : BindingModel}
    {Handle Policy Intent PolicyKey Key Word : Type*}
    {expected : ChainContext Policy Intent PolicyKey}
    (registry : AcceptedBranchRegistry model Handle Policy Intent PolicyKey
      Key Word expected)
    (noBindingBreak : ∀ handle, (registry.originAt handle).break? = none)
    (finalEntry : AcceptedFinal Handle registry.stateAt) :
    ApprovalChain Key Word (registry.stateAt finalEntry.handle) := by
  exact reconstruct_off_binding registry noBindingBreak finalEntry.handle

/-- Finite branch-facing theorem: producer origins are classified from the
raw table, and chronological induction is derived from `Fin` indices. -/
noncomputable def finite_reconstruct_off_binding
    {model : BindingModel} [DecidableEq model.Preimage]
    {codec : OriginCodec model}
    {Policy Intent PolicyKey Key Word : Type*}
    {contextCodec : ContextCodec model Policy Intent PolicyKey}
    {expected : ChainContext Policy Intent PolicyKey} {size : Nat}
    (registry : FiniteAcceptedBranchRegistry model codec Policy Intent PolicyKey
      Key Word contextCodec expected size)
    (noBindingBreak : ∀ index,
      (classifyOrigin (registry.inputAt index) (registry.producerAt index)
        (registry.authenticationAt index)).break? = none)
    (terminal : Fin size) :
    ApprovalChain Key Word (registry.stateAt terminal) := by
  exact reconstruct_off_binding registry.toAccepted noBindingBreak terminal

/-- Staged finite registry endpoint: Approval entries need only digest-level
pending records; after the separately checked Final promotion, absence of a
retained concrete break still reconstructs the full chronological chain. -/
noncomputable def finite_pending_reconstruct_off_binding
    {Policy Intent PolicyKey Key Word : Type*}
    {expected : ChainContext Policy Intent PolicyKey} {size : Nat}
    (registry : FinitePendingBranchRegistry Policy Intent PolicyKey Key Word
      expected size)
    (noBindingBreak : ∀ index, (registry.originAt index).break? = none)
    (terminal : Fin size) :
    ApprovalChain Key Word (registry.stateAt terminal) := by
  exact reconstruct_off_binding registry.toAccepted noBindingBreak terminal

/-! ## Exact edge count, distinctness, and threshold consequences -/

theorem reconstructed_chain_exact
    {start finish : ApprovalState} {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish)
    (startCount : start.count = 0) :
    slots.length = finish.count ∧ slots.Nodup := by
  constructor
  · have := history_count history
    omega
  · exact history_slots_nodup history

theorem reconstructed_edges_exact
    {Key Word : Type*}
    {start finish : ApprovalState} {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish)
    (startCount : start.count = 0)
    (edges : List (RegistryEdge Key Word))
    (edgeSlots : edges.map RegistryEdge.slot = slots) :
    edges.length = finish.count ∧
      (edges.map RegistryEdge.slot).Nodup := by
  have exactFacts := reconstructed_chain_exact history startCount
  constructor
  · calc
      edges.length = (edges.map RegistryEdge.slot).length := by simp
      _ = slots.length := congrArg List.length edgeSlots
      _ = finish.count := exactFacts.1
  · simpa [edgeSlots] using exactFacts.2

theorem ApprovalChain.edges_exact
    {Key Word : Type*} {finish : ApprovalState}
    (chain : ApprovalChain Key Word finish) :
    chain.edges.length = finish.count ∧
      (chain.edges.map RegistryEdge.slot).Nodup := by
  exact reconstructed_edges_exact chain.history chain.startCount chain.edges
    chain.edgeSlots

theorem AcceptedFinal.chain_has_threshold_distinct_edges
    {Handle Key Word : Type*} {stateAt : Handle → ApprovalState}
    (finalEntry : AcceptedFinal Handle stateAt)
    (chain : ApprovalChain Key Word (stateAt finalEntry.handle)) :
    finalEntry.threshold ≤ chain.edges.length ∧
      (chain.edges.map RegistryEdge.slot).Nodup := by
  have exactEdges := chain.edges_exact
  constructor
  · rw [exactEdges.1]
    exact finalEntry.thresholdReached
  · exact exactEdges.2

/-- Every reconstructed slot has a concrete producer record and its complete
seven-word signer/tag equality. -/
theorem ApprovalChain.slot_has_full_tag_match
    {Key Word : Type*} {finish : ApprovalState}
    (chain : ApprovalChain Key Word finish) {slot : SignerSlot}
    (slotMem : slot ∈ chain.slots) :
    ∃ edge ∈ chain.edges, edge.slot = slot ∧
      edge.signer.signerIdentity = edge.signer.registeredTag := by
  rw [← chain.edgeSlots] at slotMem
  obtain ⟨edge, edgeMem, edgeSlot⟩ := List.mem_map.mp slotMem
  exact ⟨edge, edgeMem, edgeSlot, edge.signer.fullEquality⟩

theorem reconstructed_threshold_has_uncovered_edge
    {start finish : ApprovalState} {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish)
    (startCount : start.count = 0)
    (threshold : Nat) (thresholdReached : threshold ≤ finish.count)
    (corrupted honestlyAuthorized : Finset SignerSlot)
    (authorizedSmall : (corrupted ∪ honestlyAuthorized).card < threshold) :
    ∃ slot ∈ slots, slot ∉ corrupted ∪ honestlyAuthorized := by
  exact terminal_threshold_has_uncovered_edge history startCount threshold
    thresholdReached corrupted honestlyAuthorized authorizedSmall

end HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
