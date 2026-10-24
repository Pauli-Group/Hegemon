import Hegemon.Transaction.QualifiedAssetSourceReadoutV1

/-!
Source-owned134-word binding and SAME-execution event adapters. These derive
concrete binding-failure witnesses and pull them back along one readout without
resampling or replacing its query ledger. They do not construct the physical
CMS readout, establish Born-mass bounds, or claim efficient extraction/privacy.
The retained Fin77/fixed-row endpoint is NOT imported under a new asset name.
-/
namespace Hegemon.Transaction.QualifiedAssetSameExecutionV1

open Hegemon.Transaction.QualifiedAssetSourceReadoutV1
set_option autoImplicit false

local instance digestDecidableEq : DecidableEq Digest := fun left right =>
  match (inferInstance : Decidable (∀ i : Fin 7, left i = right i)) with
  | isTrue same => isTrue (funext same)
  | isFalse different => isFalse (fun same => different (congrFun same))

structure LeafInput where
  statement : Public
  saltWords : List Nat
  index : Nat
  tapeWords : List Nat
  committed : List Nat
  masking : List Nat

/-- Literal engine `strict_zk_merkle_leaf_words`, before unchanged SHA512
profile/domain/word/counter framing. Tape words are u64 data, not field values. -/
def leafWords (input : LeafInput) : List Nat :=
  List.ofFn (fun i => (input.statement i).val) ++
  (input.saltWords ++ [input.index] ++ input.tapeWords ++
    [input.committed.length] ++ input.committed ++ [input.masking.length] ++ input.masking)

theorem leaf_words_recover_whole_public_prefix (input : LeafInput) :
    (leafWords input).take 134 = List.ofFn (fun i => (input.statement i).val) := by
  exact (by simpa only [leafWords, List.length_ofFn] using
    (List.take_append_length (l₁ := List.ofFn (fun i => (input.statement i).val))
      (l₂ := input.saltWords ++ [input.index] ++ input.tapeWords ++
        [input.committed.length] ++ input.committed ++ [input.masking.length] ++ input.masking)))

theorem same_leaf_words_have_identical_all134_public_words (left right : LeafInput)
    (same : leafWords left = leafWords right) : left.statement = right.statement := by
  have headWords := congrArg (fun words : List Nat => words.take 134) same
  rw [leaf_words_recover_whole_public_prefix, leaf_words_recover_whole_public_prefix] at headWords
  funext i
  apply Fin.ext
  have atWord := congrArg (fun words : List Nat => words[i.val]?) headWords
  simpa only [List.getElem?_ofFn, dif_pos i.isLt, Option.some.injEq] using atWord

def smzeProfile : String := "hegemon.smallwood.asset-spend.smze.compff01.sha512.profile.v1"
def smzeLeafDomain : String := "hegemon.smallwood.strict-zk.merkle-leaf.asset-spend.v1"
abbrev Sha512Digest := Fin 64 → UInt8
abbrev Sha512Commit := String → String → List Nat → Nat → Sha512Digest

/-- Native `u64` representation, including raw tape words; no implicit
truncation is allowed when using the retained byte-framing injectivity. -/
def LeafCanonical (input : LeafInput) : Prop :=
  ∀ word ∈ leafWords input, word < 2^64

/-- A concrete collision game witness at the source's whole-statement leaf
role, not a new primitive-hardness assumption or a claim about its probability. -/
def PublicLeafCollision (sha512 : Sha512Commit) (left right : LeafInput) : Prop :=
  LeafCanonical left ∧ LeafCanonical right ∧ leafWords left ≠ leafWords right ∧
  sha512 smzeProfile smzeLeafDomain (leafWords left) 0 =
    sha512 smzeProfile smzeLeafDomain (leafWords right) 0

theorem different_public_same_leaf_digest_is_concrete_collision
    (sha512 : Sha512Commit) (left right : LeafInput)
    (canonicalLeft : LeafCanonical left) (canonicalRight : LeafCanonical right)
    (different : left.statement ≠ right.statement)
    (sameDigest : sha512 smzeProfile smzeLeafDomain (leafWords left) 0 =
      sha512 smzeProfile smzeLeafDomain (leafWords right) 0) :
    PublicLeafCollision sha512 left right := by
  refine ⟨canonicalLeft, canonicalRight, ?_, sameDigest⟩
  intro same
  exact different (same_leaf_words_have_identical_all134_public_words left right same)

def credentialNodeDomain : Nat := 0x4153_4352_4e44_0000
def children (right : Bool) (current sibling : Digest) : Digest × Digest :=
  if right then (sibling, current) else (current, sibling)
def credentialStep (crypto : Primitives) (level : Nat) (right : Bool)
    (current sibling : Digest) : Digest :=
  crypto.compress (credentialNodeDomain + level)
    (children right current sibling).1 (children right current sibling).2

def credentialRoot (crypto : Primitives) : Nat → Digest → List (Bool × Digest) → Digest
  | _, current, [] => current
  | level, current, (direction, sibling) :: tail =>
      credentialRoot crypto (level + 1) (credentialStep crypto level direction current sibling) tail

/-- Same index means identical direction words. Siblings may differ. -/
def SameDirections (left right : List (Bool × Digest)) : Prop :=
  left.map Prod.fst = right.map Prod.fst

/-- Literal new credential-node compression game, with its level domain. -/
def NodeCollision (crypto : Primitives) : Prop :=
  ∃ level : Nat, ∃ left right : Digest × Digest, left ≠ right ∧
    crypto.compress (credentialNodeDomain + level) left.1 left.2 =
      crypto.compress (credentialNodeDomain + level) right.1 right.2

theorem equal_current_credential_roots_same_index_give_same_leaf_or_node_collision
    (crypto : Primitives) (level : Nat) (left right : Digest)
    (pathLeft pathRight : List (Bool × Digest))
    (directions : SameDirections pathLeft pathRight)
    (root : credentialRoot crypto level left pathLeft = credentialRoot crypto level right pathRight) :
    left = right ∨ NodeCollision crypto := by
  induction pathLeft generalizing level left right pathRight with
  | nil =>
      cases pathRight with
      | nil => exact Or.inl root
      | cons head tail => simp [SameDirections] at directions
  | cons head tail ih =>
      cases pathRight with
      | nil => simp [SameDirections] at directions
      | cons other rest =>
          have sameDirs : head.1 = other.1 ∧ SameDirections tail rest := by
            simpa [SameDirections] using directions
          have result := ih (level + 1)
            (credentialStep crypto level head.1 left head.2)
            (credentialStep crypto level other.1 right other.2) rest sameDirs.2 root
          rcases result with sameStep | collision
          · by_cases sameInput : children head.1 left head.2 = children other.1 right other.2
            · left
              rw [← sameDirs.1] at sameInput
              cases direction : head.1 with
              | false => simp [children, direction] at sameInput; exact sameInput.1
              | true => simp [children, direction] at sameInput; exact sameInput.2
            · exact Or.inr ⟨level, children head.1 left head.2,
                children other.1 right other.2, sameInput, sameStep⟩
          · exact Or.inr collision

def CredentialLeafCollision (crypto : Primitives) : Prop :=
  ∃ left right : List F, left.length = 14 ∧ right.length = 14 ∧ left ≠ right ∧
    crypto.sponge credentialDomain left = crypto.sponge credentialDomain right

theorem current_credential_membership_at_same_index_or_concrete_failure
    (crypto : Primitives) (left right : List F)
    (leftLength : left.length = 14) (rightLength : right.length = 14)
    (pathLeft pathRight : List (Bool × Digest)) (sameIndex : SameDirections pathLeft pathRight)
    (sameRoot : credentialRoot crypto 0 (crypto.sponge credentialDomain left) pathLeft =
      credentialRoot crypto 0 (crypto.sponge credentialDomain right) pathRight) :
    left = right ∨ CredentialLeafCollision crypto ∨ NodeCollision crypto := by
  by_cases same : left = right
  · exact Or.inl same
  have found := equal_current_credential_roots_same_index_give_same_leaf_or_node_collision
    crypto 0 _ _ pathLeft pathRight sameIndex sameRoot
  rcases found with leafDigest | node
  · exact Or.inr (Or.inl ⟨left, right, leftLength, rightLength, same, leafDigest⟩)
  · exact Or.inr (Or.inr node)

/-- Join the actual source leaf call to the current tree comparison, instead
of assuming the credential leaf hash equals its desired fourteen-word value.
Current root/same-index authentication is an explicit state interface. -/
theorem source_credential_current_tree_readback_or_concrete_game
    {crypto : Primitives} {g : Graph} {input z : Nat → F}
    (sem : Interpreted crypto g input z) {r : CredentialRoles}
    (checked : CredentialCallChecked g r) (expected : List F)
    (expectedLength : expected.length = 14)
    (pathActual pathExpected : List (Bool × Digest))
    (sameIndex : SameDirections pathActual pathExpected)
    (currentRoot : credentialRoot crypto 0 (fun i => read z (r.leaf i)) pathActual =
      credentialRoot crypto 0 (crypto.sponge credentialDomain expected) pathExpected) :
    (credentialMessage r.p r.note r.subject r.expiry).map (read z) = expected ∨
      CredentialLeafCollision crypto ∨ NodeCollision crypto := by
  have leaf := credential_leaf_from_actual_fourteen_source_words sem checked
  change (fun i => read z (r.leaf i)) =
    crypto.sponge credentialDomain ((credentialMessage r.p r.note r.subject r.expiry).map (read z)) at leaf
  rw [leaf] at currentRoot
  apply current_credential_membership_at_same_index_or_concrete_failure crypto _ expected
    _ expectedLength pathActual pathExpected sameIndex currentRoot
  simp [credentialMessage]

inductive QueryRole where
  | decsMatrix | piopMatrix | piopOpening | decsSample | leaf | node | other
  deriving DecidableEq

structure OracleQuery where
  /-- Raw input, including profile/role/word-count/counter framing. -/
  rawInput : List UInt8
  output : Sha512Digest
  role : QueryRole

structure Observation where
  namespaceBytes : List UInt8
  relation : List UInt8
  stage : Nat
  statement : Public
  /-- Entire original raw ledger, including other families and failed attempts. -/
  ledger : List OracleQuery
  /-- Original physical-prefix counter, NOT inferred from a classical log's
  length. Its binding to the CMS execution is part of readout construction. -/
  physicalQueries : Nat
  sourceReads : Nat

structure Packet (crypto : Primitives) where
  source : RecoveredSource crypto
  observation : Observation
  publicSame : source.statement = observation.statement

/-- This is the exact remaining F1 readout target. It contains NO security or
failure-coverage field. `sameObservation` retains original raw query history,
stage, namespace and relation; no new run, conditioning or budget reset occurs.
Constructing it from actual accepted backend execution remains open. -/
structure SameExecutionReadout (Basis : Type) (crypto : Primitives) where
  original : Basis → Observation
  recover : Basis → Option (Packet crypto)
  sameObservation : ∀ basis packet, recover basis = some packet →
    packet.observation = original basis

def pullback {Basis : Type} {crypto : Primitives} (r : SameExecutionReadout Basis crypto)
    (event : Packet crypto → Prop) (basis : Basis) : Prop :=
  ∃ packet, r.recover basis = some packet ∧ event packet

theorem recovered_public_readout_matches_original_all134
    {Basis : Type} {crypto : Primitives} (r : SameExecutionReadout Basis crypto)
    (basis : Basis) (packet : Packet crypto) (readout : r.recover basis = some packet) :
    packet.source.publicReadout = (r.original basis).statement := by
  rw [recovered_source_public_all134, packet.publicSame,
    r.sameObservation basis packet readout]

theorem recovered_original_query_ledger_is_unchanged
    {Basis : Type} {crypto : Primitives} (r : SameExecutionReadout Basis crypto)
    (basis : Basis) (packet : Packet crypto) (readout : r.recover basis = some packet) :
    packet.observation.ledger = (r.original basis).ledger :=
  congrArg Observation.ledger (r.sameObservation basis packet readout)

theorem recovered_original_query_budget_is_not_reset
    {Basis : Type} {crypto : Primitives} (r : SameExecutionReadout Basis crypto)
    (basis : Basis) (packet : Packet crypto) (readout : r.recover basis = some packet)
    (cap : Nat) (originalBudget : (r.original basis).ledger.length ≤ cap) :
    packet.observation.ledger.length ≤ cap := by
  rw [recovered_original_query_ledger_is_unchanged r basis packet readout]
  exact originalBudget

theorem recovered_original_physical_query_and_read_budget_is_not_reset
    {Basis : Type} {crypto : Primitives} (r : SameExecutionReadout Basis crypto)
    (basis : Basis) (packet : Packet crypto) (readout : r.recover basis = some packet)
    (cap : Nat) (originalBudget : (r.original basis).physicalQueries +
      (r.original basis).sourceReads ≤ cap) :
    packet.observation.physicalQueries + packet.observation.sourceReads ≤ cap := by
  rw [r.sameObservation basis packet readout]
  exact originalBudget

/-- Missing/None outcomes cannot disappear behind the optional source readout.
Bounding this FIRST alternative is an actual physical-source obligation. -/
theorem every_accepted_basis_requires_missing_or_same_source_readout
    {Basis : Type} {crypto : Primitives} (r : SameExecutionReadout Basis crypto)
    (accepted : Basis → Prop) (basis : Basis) (yes : accepted basis) :
    r.recover basis = none ∨ ∃ packet, r.recover basis = some packet ∧
      accepted basis ∧ packet.observation = r.original basis := by
  cases found : r.recover basis with
  | none => exact Or.inl rfl
  | some packet => exact Or.inr ⟨packet, rfl, yes, r.sameObservation basis packet found⟩

theorem pullback_preserves_same_sample_event_union
    {Basis : Type} {crypto : Primitives} (r : SameExecutionReadout Basis crypto)
    (left right : Packet crypto → Prop) (basis : Basis) :
    pullback r (fun packet => left packet ∨ right packet) basis ↔
      pullback r left basis ∨ pullback r right basis := by
  constructor
  · rintro ⟨packet, found, l | rr⟩
    · exact Or.inl ⟨packet, found, l⟩
    · exact Or.inr ⟨packet, found, rr⟩
  · rintro (⟨packet, found, l⟩ | ⟨packet, found, rr⟩)
    · exact ⟨packet, found, Or.inl l⟩
    · exact ⟨packet, found, Or.inr rr⟩

/-- The unchanged native seven-game interface can be transported ONLY for its
same derived source event and same basis. This lemma creates no asset/admin
coverage or new advantage bound; the premise must be the retained native proof,
not a renamed unauthorized-asset assertion. -/
theorem retained_seven_game_interface_pullback
    {Basis : Type} {crypto : Primitives} (r : SameExecutionReadout Basis crypto)
    (nativeFailure : Packet crypto → Prop) (nativeGame : Fin 7 → Packet crypto → Prop)
    (retainedCoverage : ∀ packet, nativeFailure packet → ∃ kind, nativeGame kind packet)
    (basis : Basis) (bad : pullback r nativeFailure basis) :
    ∃ kind, pullback r (nativeGame kind) basis := by
  obtain ⟨packet, found, failed⟩ := bad
  obtain ⟨kind, game⟩ := retainedCoverage packet failed
  exact ⟨kind, packet, found, game⟩

end Hegemon.Transaction.QualifiedAssetSameExecutionV1
