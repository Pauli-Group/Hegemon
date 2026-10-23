import Std
import Lean.Elab.Tactic.Omega

/-!
Bounded private-spend policy semantic delta. Two branches, each a conjunction
of a full seven-limb authority, an absolute reference-parent height and an
optional SHA-256 preimage. This is a semantic model, not a proof that native
acceptance recovers a satisfying assignment, of SHA-256 security, of zero
knowledge, or of production authorization. Hash and source-binding premises
remain explicit; the old crypto/SMZD evidence is not relabelled as this delta.
-/
namespace Hegemon.Policy.BoundedPrivateSpend

set_option autoImplicit false
set_option maxHeartbeats 500000

abbrev Authority := Fin 7 → Nat
abbrev Secret := Fin 32 → UInt8
abbrev HashWords := Fin 8 → Nat
abbrev ChainWords := Fin 8 → Nat
abbrev NullifierKey := Fin 5 → Nat
abbrev Descriptor := Fin 39 → Nat

def zeroSecret : Secret := fun _ => 0
def zeroHash : HashWords := fun _ => 0
def heightBound : Nat := 2^48
def valueBound : Nat := 2^56
def modulus : Nat := 18446744069414584321

structure Branch where
  enabled : Bool
  authority : Authority
  notBefore : Nat
  hashRequired : Bool
  hashlock : HashWords
  releaseSecret : Bool

structure Policy where
  branches : Fin 2 → Branch
  nullifierKey : NullifierKey

/-- Canonical layout is version 1 followed by two 19-word branch records:
enabled, authority[7], notBefore, hashRequired, hashlock[8], releaseSecret.
`hashlock` contains eight little-endian u32 words of SHA-256 output. -/
def branchWords (branch : Branch) : List Nat :=
  [branch.enabled.toNat] ++ List.ofFn branch.authority ++
  [branch.notBefore, branch.hashRequired.toNat] ++ List.ofFn branch.hashlock ++
  [branch.releaseSecret.toNat]

def descriptorWords (policy : Policy) : List Nat :=
  [1] ++ branchWords (policy.branches 0) ++ branchWords (policy.branches 1)

theorem branch_words_length (branch : Branch) : (branchWords branch).length = 19 := by
  simp [branchWords]

theorem descriptor_words_length (policy : Policy) :
    (descriptorWords policy).length = 39 := by
  simp [descriptorWords, branch_words_length]

/-- Inactive branch padding and disabled-hash padding are part of validation,
not alternative ways to satisfy an enabled policy. -/
structure BranchCanonical (branch : Branch) : Prop where
  boundedHeight : branch.notBefore < heightBound
  authorityRange : ∀ i, branch.authority i < modulus
  hashWordRange : ∀ i, branch.hashlock i < 2^32
  enabledAuthority : branch.enabled = true → branch.authority ≠ (fun _ => 0)
  disabledPadding : branch.enabled = false → branch.authority = (fun _ => 0) ∧
    branch.notBefore = 0 ∧ branch.hashRequired = false ∧
    branch.hashlock = zeroHash ∧ branch.releaseSecret = false
  noHashPadding : branch.hashRequired = false → branch.hashlock = zeroHash ∧
    branch.releaseSecret = false

def PolicyCanonical (policy : Policy) : Prop :=
  (policy.branches 0).enabled = true ∧
  (∀ i, BranchCanonical (policy.branches i)) ∧
  policy.nullifierKey 0 ≠ 0 ∧
  (∀ i, policy.nullifierKey i < modulus)

structure SpendWitness where
  /-- Derived from the private spending credential by the circuit. -/
  authority : Authority
  secret : Secret

structure PublicRelease where
  flag : Bool
  preimage : Secret

/-- Release is forced by the selected branch. The always-present public bytes
are zero when release is disabled. Authorization is equality of all 7 limbs. -/
def BranchSatisfied (sha256 : Secret → HashWords) (branch : Branch)
    (referenceParent : Nat) (witness : SpendWitness) (release : PublicRelease) : Prop :=
  branch.enabled = true ∧
  witness.authority = branch.authority ∧
  branch.notBefore ≤ referenceParent ∧
  (branch.hashRequired = true → sha256 witness.secret = branch.hashlock) ∧
  release.flag = branch.releaseSecret ∧
  (branch.releaseSecret = true → release.preimage = witness.secret) ∧
  (branch.releaseSecret = false → release.preimage = zeroSecret)

def selected (choice : Bool) : Fin 2 := if choice then 1 else 0

/-- Asset compliance wraps the branch choice. An OR branch never bypasses it.
The predicates represent their corresponding constrained semantic premises. -/
def Accepted (assetCompliant : Prop) (sha256 : Secret → HashWords)
    (policy : Policy) (choice : Bool) (referenceParent : Nat)
    (witness : SpendWitness) (release : PublicRelease) : Prop :=
  PolicyCanonical policy ∧ referenceParent < heightBound ∧ assetCompliant ∧
    BranchSatisfied sha256 (policy.branches (selected choice)) referenceParent witness release

theorem selected_branch_authority (compliance : Prop) (sha256 : Secret → HashWords)
    (policy : Policy) (choice : Bool) (referenceParent : Nat)
    (witness : SpendWitness) (release : PublicRelease)
    (accepted : Accepted compliance sha256 policy choice referenceParent witness release) :
    ∀ limb : Fin 7, witness.authority limb =
      (policy.branches (selected choice)).authority limb := by
  intro limb
  exact congrFun accepted.2.2.2.2.1 limb

theorem selected_branch_has_nonzero_authority
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent : Nat) (witness : SpendWitness)
    (release : PublicRelease)
    (accepted : Accepted compliance sha256 policy choice referenceParent witness release) :
    witness.authority ≠ (fun _ => 0) := by
  have branchCanonical := accepted.1.2.1 (selected choice)
  have enabled := accepted.2.2.2.1
  have sameAuthority := accepted.2.2.2.2.1
  rw [sameAuthority]
  exact branchCanonical.enabledAuthority enabled

theorem wrong_authority_limb_rejects
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent : Nat) (witness : SpendWitness)
    (release : PublicRelease) (limb : Fin 7)
    (wrong : witness.authority limb ≠
      (policy.branches (selected choice)).authority limb) :
    ¬ Accepted compliance sha256 policy choice referenceParent witness release := by
  intro accepted
  exact wrong (selected_branch_authority compliance sha256 policy choice
    referenceParent witness release accepted limb)

theorem disabled_branch_rejects (compliance : Prop) (sha256 : Secret → HashWords)
    (policy : Policy) (choice : Bool) (referenceParent : Nat)
    (witness : SpendWitness) (release : PublicRelease)
    (disabled : (policy.branches (selected choice)).enabled = false) :
    ¬ Accepted compliance sha256 policy choice referenceParent witness release := by
  intro accepted
  have enabled := accepted.2.2.2.1
  simp [disabled] at enabled

theorem selected_false_branch_does_not_authorize
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent : Nat) (witness : SpendWitness)
    (release : PublicRelease)
    (failed : ¬ BranchSatisfied sha256 (policy.branches (selected choice))
      referenceParent witness release) :
    ¬ Accepted compliance sha256 policy choice referenceParent witness release :=
  fun accepted => failed accepted.2.2.2

theorem absolute_height_no_early_spend
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent actualParent : Nat) (witness : SpendWitness)
    (release : PublicRelease)
    (accepted : Accepted compliance sha256 policy choice referenceParent witness release)
    (authenticated : referenceParent ≤ actualParent) :
    (policy.branches (selected choice)).notBefore + 1 ≤ actualParent + 1 := by
  have mature := accepted.2.2.2.2.2.1
  omega

theorem before_absolute_height_rejects
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent actualParent : Nat) (witness : SpendWitness)
    (release : PublicRelease)
    (authenticated : referenceParent ≤ actualParent)
    (tooEarly : actualParent < (policy.branches (selected choice)).notBefore) :
    ¬ Accepted compliance sha256 policy choice referenceParent witness release := by
  intro accepted
  have bound := absolute_height_no_early_spend compliance sha256 policy choice
    referenceParent actualParent witness release accepted authenticated
  omega

theorem mandatory_release_no_opt_out
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent : Nat) (witness : SpendWitness)
    (release : PublicRelease)
    (accepted : Accepted compliance sha256 policy choice referenceParent witness release)
    (mandatory : (policy.branches (selected choice)).releaseSecret = true) :
    release.flag = true ∧ release.preimage = witness.secret := by
  exact ⟨accepted.2.2.2.2.2.2.2.1.trans mandatory,
    accepted.2.2.2.2.2.2.2.2.1 mandatory⟩

theorem released_preimage_matches_hashlock
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent : Nat) (witness : SpendWitness)
    (release : PublicRelease)
    (accepted : Accepted compliance sha256 policy choice referenceParent witness release)
    (mandatory : (policy.branches (selected choice)).releaseSecret = true) :
    sha256 release.preimage = (policy.branches (selected choice)).hashlock := by
  have canonical := accepted.1.2.1 (selected choice)
  have required : (policy.branches (selected choice)).hashRequired = true := by
    cases h : (policy.branches (selected choice)).hashRequired with
    | false => have bad := (canonical.noHashPadding h).2; simp [mandatory] at bad
    | true => rfl
  rw [(mandatory_release_no_opt_out compliance sha256 policy choice referenceParent
    witness release accepted mandatory).2]
  exact accepted.2.2.2.2.2.2.1 required

theorem no_release_has_zero_public_bytes
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent : Nat) (witness : SpendWitness)
    (release : PublicRelease)
    (accepted : Accepted compliance sha256 policy choice referenceParent witness release)
    (privateBranch : (policy.branches (selected choice)).releaseSecret = false) :
    release.flag = false ∧ release.preimage = zeroSecret := by
  exact ⟨accepted.2.2.2.2.2.2.2.1.trans privateBranch,
    accepted.2.2.2.2.2.2.2.2.2 privateBranch⟩

theorem asset_compliance_outside_or
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (referenceParent : Nat) (witness : SpendWitness) (release : PublicRelease) :
    (∃ choice, Accepted compliance sha256 policy choice referenceParent witness release) ↔
    PolicyCanonical policy ∧ referenceParent < heightBound ∧ compliance ∧
      (BranchSatisfied sha256 (policy.branches 0) referenceParent witness release ∨
       BranchSatisfied sha256 (policy.branches 1) referenceParent witness release) := by
  constructor
  · rintro ⟨choice, accepted⟩
    refine ⟨accepted.1, accepted.2.1, accepted.2.2.1, ?_⟩
    cases choice with
    | false => exact Or.inl accepted.2.2.2
    | true => exact Or.inr accepted.2.2.2
  · rintro ⟨canonical, bounded, compliant, left | right⟩
    · exact ⟨false, canonical, bounded, compliant, left⟩
    · exact ⟨true, canonical, bounded, compliant, right⟩

theorem missing_asset_compliance_rejects_both_branches
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (referenceParent : Nat) (witness : SpendWitness) (release : PublicRelease)
    (missing : ¬ compliance) :
    ¬ ∃ choice, Accepted compliance sha256 policy choice referenceParent witness release := by
  rintro ⟨choice, accepted⟩
  exact missing accepted.2.2.1

/-- The real nullifier call uses the one policy-bound, nonzero five-field key,
value and position. No branch selector enters this input. This proves identical
inputs across choices, not collision resistance or recovery of the bound key. -/
def policyNullifier (nullify : NullifierKey → Nat → Nat → Authority)
    (policy : Policy) (value position : Nat) (_choice : Bool) : Authority :=
  nullify policy.nullifierKey value position

theorem both_branches_share_nullifier
    (nullify : NullifierKey → Nat → Nat → Authority) (policy : Policy)
    (value position : Nat) (leftChoice rightChoice : Bool) :
    policyNullifier nullify policy value position leftChoice =
      policyNullifier nullify policy value position rightChoice := rfl

theorem accepted_has_nonzero_shared_nullifier_key
    (compliance : Prop) (sha256 : Secret → HashWords) (policy : Policy)
    (choice : Bool) (referenceParent : Nat) (witness : SpendWitness)
    (release : PublicRelease)
    (accepted : Accepted compliance sha256 policy choice referenceParent witness release) :
    policy.nullifierKey 0 ≠ 0 ∧ (∀ i, policy.nullifierKey i < modulus) :=
  accepted.1.2.2

/-- The owner-policy hash binds the chain, asset and all 39 descriptor words.
The hash remains abstract; collision resistance is an external crypto premise. -/
def policyCommitment (hash : ChainWords → Nat → List Nat → Authority)
    (chain : ChainWords) (asset : Nat) (policy : Policy) : Authority :=
  hash chain asset (descriptorWords policy)

/-- Existing bounded integer conservation is unaffected by policy branch,
creation, rollover or release when the same bounded balance equation is kept.
The modular equation is the explicit finite-field semantic premise. -/
theorem conservation_from_unchanged_bounded_balance
    (input0 input1 output0 output1 fee : Nat)
    (hi0 : input0 < valueBound) (hi1 : input1 < valueBound)
    (ho0 : output0 < valueBound) (ho1 : output1 < valueBound) (hf : fee < valueBound)
    (balance : (input0 + input1) % modulus = (output0 + output1 + fee) % modulus) :
    input0 + input1 = output0 + output1 + fee := by
  have leftBound : input0 + input1 < modulus := by
    unfold valueBound at hi0 hi1
    unfold modulus
    omega
  have rightBound : output0 + output1 + fee < modulus := by
    unfold valueBound at ho0 ho1 hf
    unfold modulus
    omega
  simpa only [Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] using balance

end Hegemon.Policy.BoundedPrivateSpend
