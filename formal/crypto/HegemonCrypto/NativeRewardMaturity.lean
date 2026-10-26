import Std

/-!
Small arithmetic model of native reward-note admission with 120-block maturity.

The ledger admits a reward created at height `h` to note membership at height
`h + 119`. A spend uses membership at its canonical reference height `r`, and
the reference must strictly precede inclusion height `b`. These two conditions
imply `h + 120 ≤ b`, for both miner and treasury reward roles.

This module proves the arithmetic rule only. It does not establish canonical
membership, authenticate a reward's origin, refine Rust, model machine-word
overflow, prove transaction soundness, or authorize a release. Those remain
separate implementation and validation obligations. Natural-number heights
here model the successful, overflow-checked branch of the implementation.
-/
namespace HegemonCrypto.NativeRewardMaturity

inductive RewardRole where
  | miner
  | treasury
  deriving DecidableEq

inductive NoteOrigin where
  | reward (role : RewardRole) (createdAt : Nat)
  | ordinary
  deriving DecidableEq

def membershipAdmissionHeight : NoteOrigin → Nat
  | .reward _ h => h + 119
  | .ordinary => 0

def MembershipEligible (origin : NoteOrigin) (referenceHeight : Nat) : Prop :=
  membershipAdmissionHeight origin ≤ referenceHeight

def SpendAccepted (origin : NoteOrigin) (referenceHeight inclusionHeight : Nat) : Prop :=
  MembershipEligible origin referenceHeight ∧ referenceHeight < inclusionHeight

theorem reward_role_independent (first second : RewardRole) (h : Nat) :
    membershipAdmissionHeight (.reward first h) =
      membershipAdmissionHeight (.reward second h) := by
  rfl

theorem reward_reference_eligible_iff (role : RewardRole) (h r : Nat) :
    MembershipEligible (.reward role h) r ↔ h + 119 ≤ r := by
  rfl

theorem reward_spend_mature (role : RewardRole) (h r b : Nat)
    (accepted : SpendAccepted (.reward role h) r b) : h + 120 ≤ b := by
  rcases accepted with ⟨eligible, referenceBeforeInclusion⟩
  change h + 119 ≤ r at eligible
  omega

theorem miner_spend_mature (h r b : Nat)
    (accepted : SpendAccepted (.reward .miner h) r b) : h + 120 ≤ b := by
  exact reward_spend_mature .miner h r b accepted

theorem treasury_spend_mature (h r b : Nat)
    (accepted : SpendAccepted (.reward .treasury h) r b) : h + 120 ≤ b := by
  exact reward_spend_mature .treasury h r b accepted

theorem reward_before_maturity_rejected (role : RewardRole) (h r b : Nat)
    (tooEarly : b < h + 120) : ¬ SpendAccepted (.reward role h) r b := by
  intro accepted
  have mature := reward_spend_mature role h r b accepted
  omega

theorem reward_boundary_before_rejected (role : RewardRole) (h : Nat) :
    ¬ ∃ r, SpendAccepted (.reward role h) r (h + 119) := by
  rintro ⟨r, accepted⟩
  have mature := reward_spend_mature role h r (h + 119) accepted
  omega

theorem reward_boundary_at_maturity_accepted (role : RewardRole) (h : Nat) :
    SpendAccepted (.reward role h) (h + 119) (h + 120) := by
  constructor
  · exact Nat.le_refl _
  · omega

theorem reward_spend_exists_iff_mature (role : RewardRole) (h b : Nat) :
    (∃ r, SpendAccepted (.reward role h) r b) ↔ h + 120 ≤ b := by
  constructor
  · rintro ⟨r, accepted⟩
    exact reward_spend_mature role h r b accepted
  · intro mature
    refine ⟨h + 119, Nat.le_refl _, ?_⟩
    omega

theorem ordinary_no_age_condition (r : Nat) :
    MembershipEligible .ordinary r := by
  exact Nat.zero_le r

theorem ordinary_acceptance_iff_reference_precedes (r b : Nat) :
    SpendAccepted .ordinary r b ↔ r < b := by
  constructor
  · exact And.right
  · intro referenceBeforeInclusion
    exact ⟨ordinary_no_age_condition r, referenceBeforeInclusion⟩

#print axioms reward_role_independent
#print axioms reward_reference_eligible_iff
#print axioms reward_spend_mature
#print axioms miner_spend_mature
#print axioms treasury_spend_mature
#print axioms reward_before_maturity_rejected
#print axioms reward_boundary_before_rejected
#print axioms reward_boundary_at_maturity_accepted
#print axioms reward_spend_exists_iff_mature
#print axioms ordinary_no_age_condition
#print axioms ordinary_acceptance_iff_reference_precedes

end HegemonCrypto.NativeRewardMaturity
