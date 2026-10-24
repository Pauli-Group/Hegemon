import Lean.Elab.Tactic.Omega

namespace Hegemon.Native.RewardFunding

/-- Integer allocation of issued subsidy; all fees belong to miners. -/
def funding (subsidy : Nat) : Nat := subsidy / 5

def miner (subsidy fees : Nat) : Nat := subsidy - funding subsidy + fees

theorem allocated_reward_conserves_subsidy_and_fees (subsidy fees : Nat) :
    miner subsidy fees + funding subsidy = subsidy + fees := by
  have floorBound : subsidy / 5 ≤ subsidy := Nat.div_le_self subsidy 5
  unfold miner funding
  omega

theorem funding_does_not_depend_on_transaction_fees
    (subsidy fees₁ fees₂ : Nat) :
    (miner subsidy fees₁ + funding subsidy) - fees₁ =
    (miner subsidy fees₂ + funding subsidy) - fees₂ := by
  rw [allocated_reward_conserves_subsidy_and_fees,
      allocated_reward_conserves_subsidy_and_fees]
  omega

/-- The complete recipient identity includes four recipient and seven
    authorization field words; the Rust source also validates note hashes,
    canonical field words, ciphertext framing and the network manifest. -/
structure Recipient where
  recipient : Fin 4 → Nat
  authorization : Fin 7 → Nat

/-- This models exact allocation and recipient binding, not an external
    cryptographic or complete Rust verifier refinement theorem. -/
def accepts (subsidy fees observedMiner : Nat)
    (observedFunding : Option Nat) (expected actual : Recipient) : Prop :=
  observedMiner = miner subsidy fees ∧
  observedFunding = (if funding subsidy = 0 then none else some (funding subsidy)) ∧
  (observedFunding ≠ none → actual = expected)

theorem accepted_reward_has_exact_miner_amount
    {subsidy fees observedMiner : Nat}
    {observedFunding : Option Nat} {expected actual : Recipient}
    (accepted : accepts subsidy fees observedMiner observedFunding expected actual) :
    observedMiner = miner subsidy fees := accepted.1

theorem accepted_positive_funding_has_exact_recipient
    {subsidy fees observedMiner value : Nat} {expected actual : Recipient}
    (accepted : accepts subsidy fees observedMiner (some value) expected actual) :
    actual = expected := accepted.2.2 (by simp)

theorem no_partial_funding_omission_when_subsidy_has_positive_share
    {subsidy fees observedMiner : Nat} {expected actual : Recipient}
    (positive : funding subsidy ≠ 0) :
    ¬ accepts subsidy fees observedMiner none expected actual := by
  intro accepted
  have impossible := accepted.2.1
  simp [positive] at impossible

end Hegemon.Native.RewardFunding
