import Q38CmsInitializedFullDomainPerBasis

namespace HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainSupportInterface
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

/-- Abstract adapter from initialized CMS support to any database statistic
already bounded by `size`.  Its finite index and output types stay abstract,
so the concrete 8,388,608-coordinate function enumerator is never normalized
while the implication is checked. -/
theorem recorded_card_le_of_initialized_bounded
    {Input Output Phase Work Index Branch Recorded : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    [Fintype Index] [DecidableEq Index]
    [Fintype Branch] [DecidableEq Branch]
    (recorded : (Input → Option Output) → Finset Recorded)
    (recordedLeSize : ∀ database, (recorded database).card ≤ size database)
    (core : Core Input Branch (Input × Phase × Work) Output → ℂ)
    (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := Index) core))
    (basis : Core Input Branch (Input × Phase × Work) Output)
    (nonzero : core basis ≠ 0) :
    (recorded basis.2.1).card ≤ queries :=
  (recordedLeSize basis.2.1).trans
    (core_database_size_le_of_bounded
      (Input := Input) (Output := Output) (Phase := Phase) (Work := Work)
      (Index := Index) (Branch := Branch)
      core queries bounded basis nonzero)

end
end HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainSupportInterface
