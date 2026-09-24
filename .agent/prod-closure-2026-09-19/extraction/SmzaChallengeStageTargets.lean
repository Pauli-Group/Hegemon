import SmallWoodV8SmzaOnlineParserR2

/-! Four source-owned q38 FS roles, each with one VC starting target.
This extends the final-only selector without changing any serialized bytes.
The live VC step is a parameter so the repaired context parser can be used;
the old RP03 pin is not silently accepted as the RP04 relation. This module
proves the selected-domain partition and its arity-based counting step, not
the complete QROM execution or accepted-transcript theorem. -/

namespace HegemonCrypto.SmallWood.SmzaChallengeStageTargets

open HegemonCrypto.CanonicalBytes HegemonCrypto.SmallWoodTranscript
open V8SmzaOracleParser V8SmzaOnlineParser

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 512

abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev Records (Input Output : Type*) :=
  V8Smz9CoherentMerkleGeometry.Records Input Output

inductive Role where
  | decsMatrix | piopMatrix | piopOpening | decsSample
deriving DecidableEq, Fintype

def roleDomain : Role → List Byte
  | .decsMatrix => decsCoefficientDomain
  | .piopMatrix => piopCoefficientDomain
  | .piopOpening => piopOpeningDomain
  | .decsSample => decsFixedSamplingDomain

def roleStage : Role → Stage
  | .decsMatrix => .root
  | .piopMatrix => .fpp
  | .piopOpening => .piop
  | .decsSample => .decs

def decodeChallengeRole (bytes : List Byte) : Option Role :=
  if bytes = roleDomain .decsMatrix then some .decsMatrix
  else if bytes = roleDomain .piopMatrix then some .piopMatrix
  else if bytes = roleDomain .piopOpening then some .piopOpening
  else if bytes = roleDomain .decsSample then some .decsSample else none

theorem role_roundtrip (role : Role) :
    decodeChallengeRole (roleDomain role) = some role := by
  cases role <;> decide

def payloadLength : Role → Nat
  | .piopOpening => 72
  | _ => 64

def digestOffset : Role → Nat
  | .piopOpening => 8
  | _ => 0

structure StageQuery where
  role : Role
  target : RawDigest
  nonce : Nat
  counter : Nat

/-- One parser classifies every raw input at most once. Rejecting a frame
only routes it to the live complement; it does not erase that oracle input. -/
def parseStageQuery (input : RawInput) : Option StageQuery := do
  let (profileLength, rest) ← readFixed 8 input
  let (profile, rest) ← readFixed (decodeLE profileLength) rest
  let (roleLength, rest) ← readFixed 8 rest
  let (roleBytes, rest) ← readFixed (decodeLE roleLength) rest
  let role ← decodeChallengeRole roleBytes
  let (wordCount, rest) ← readFixed 8 rest
  let (payload, rest) ← readFixed (8 * decodeLE wordCount) rest
  let (counter, suffix) ← readFixed 8 rest
  let nonce := if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0
  if profile = profileDomain ∧ payload.length = payloadLength role ∧
      suffix = [] ∧ nonce < 2^32 then
    some ⟨role, digestAt payload (digestOffset role), nonce, decodeLE counter⟩
  else none

def InRoleDomain (role : Role) (input : RawInput) : Prop :=
  ∃ parsed, parseStageQuery input = some parsed ∧ parsed.role = role

/-- Only the finitely consumed counter blocks are grouped into a vector.
Higher counters stay in the live raw complement, including valid frames. -/
def InBoundedRoleDomain (role : Role) (blockCap : Nat) (input : RawInput) : Prop :=
  ∃ parsed, parseStageQuery input = some parsed ∧ parsed.role = role ∧ parsed.counter < blockCap

theorem bounded_role_domain_subset (role : Role) (blockCap : Nat) (input : RawInput)
    (bounded : InBoundedRoleDomain role blockCap input) : InRoleDomain role input := by
  obtain ⟨parsed, readback, roleMatch, _⟩ := bounded
  exact ⟨parsed, readback, roleMatch⟩

/-- Includes malformed/raw inputs: one input cannot enter two selected-role
tables. Everything outside their union belongs to the live complement. -/
theorem selected_role_domains_disjoint (left right : Role) (different : left ≠ right)
    (input : RawInput) (inLeft : InRoleDomain left input) :
    ¬ InRoleDomain right input := by
  rintro ⟨rightQuery, rightParsed, rightRole⟩
  obtain ⟨leftQuery, leftParsed, leftRole⟩ := inLeft
  have same : leftQuery = rightQuery := Option.some.inj (leftParsed.symm.trans rightParsed)
  exact different (leftRole.symm.trans ((congrArg StageQuery.role same).trans rightRole))

def selectedTarget (role : Role) (input : RawInput) : Option (Stage × RawDigest) := do
  let parsed ← parseStageQuery input
  if parsed.role = role then some (roleStage role, parsed.target) else none

def selectedTargets (role : Role) (queries : List RawInput) : List (Stage × RawDigest) :=
  queries.filterMap (selectedTarget role)

theorem selected_targets_length_le (role : Role) (queries : List RawInput) :
    (selectedTargets role queries).length ≤ queries.length :=
  List.length_filterMap_le _ _

/-- Same numerical trace-instability input for all four starting stages.
The child-coverage premise concerns syntax only, not extraction success. -/
theorem selected_stage_change_probability_le
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (children : ∀ stage input edges,
      next stage input = some edges → ∀ edge ∈ edges, edge.2 ∈ rawChildren input)
    (role : Role) (records : Records RawInput RawDigest) (input : RawInput)
    (queries : List RawInput) (fuel cap : Nat)
    (recordBound : records.card < cap) (queryBound : queries.length ≤ cap) :
    V8Smz9CoherentMerkleGeometry.uniformChangeProbability next records input fuel (selectedTargets role queries) ≤
      (3 * cap : Rat) / (2^512 : Rat) := by
  have targetCount := (selected_targets_length_le role queries).trans queryBound
  have countBound :
      (selectedTargets role queries).length + records.card * 2 ≤ 3 * cap := by omega
  have probabilityBound :=
    V8Smz9CoherentMerkleGeometry.uniform_change_probability_le
      (next := next) (children := rawChildren) children 2 raw_children_arity
      records input fuel (selectedTargets role queries)
  have cardEq : (Fintype.card RawDigest : Rat) = (2 : Rat) ^ 512 := by
    rw [V8Smz9CoherentMerkleGeometry.raw_digest_cardinality]
    norm_cast
  unfold V8Smz9CoherentMerkleGeometry.uniformChangeProbability
  rw [← cardEq]
  calc
    _ ≤ ((selectedTargets role queries).length + records.card * 2 : ℕ) /
        (Fintype.card RawDigest : Rat) := by
      exact probabilityBound
    _ ≤ (3 * cap : Rat) / (Fintype.card RawDigest : Rat) := by
      apply div_le_div_of_nonneg_right
      · exact_mod_cast countBound
      · exact_mod_cast (Nat.zero_le (Fintype.card RawDigest))

end

end HegemonCrypto.SmallWood.SmzaChallengeStageTargets
