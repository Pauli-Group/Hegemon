import HegemonCrypto.CmsOracleDatabaseBridge

/-! A consistent transcript can be completed without changing its supplied
nonchallenge view. Only claims whose keys lie in that view must already hold
there; challenge entries are supplied by the consistent completion. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentClaimsXViewCompletion

open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)

set_option autoImplicit false

noncomputable section

/-- Extend a partial database view while retaining every literal branch
claim. This is a finite consistency statement, not a probability assumption. -/
theorem claims_completion_preserving_view
    {Key Output : Type} [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output]
    (claims : List (Key × Output)) (keys : Finset Key)
    (view : {key : Key // key ∈ keys} → Option Output)
    (consistent : ∃ database : Database Key Output,
      ClaimsDatabaseEvent claims database)
    (viewClaims : ∀ claim ∈ claims, ∀ member : claim.1 ∈ keys,
      view ⟨claim.1, member⟩ = some claim.2) :
    ∃ database : Database Key Output,
      ClaimsDatabaseEvent claims database ∧
      ∀ key (member : key ∈ keys), database key = view ⟨key, member⟩ := by
  obtain ⟨completion, completionClaims⟩ := consistent
  let database : Database Key Output := fun key =>
    if member : key ∈ keys then view ⟨key, member⟩ else completion key
  refine ⟨database, ?_, ?_⟩
  · intro claim recorded
    by_cases member : claim.1 ∈ keys
    · simpa only [database, dif_pos member] using viewClaims claim recorded member
    · simpa only [database, dif_neg member] using completionClaims claim recorded
  · intro key member
    simp only [database, dif_pos member]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentClaimsXViewCompletion
