import HegemonCrypto.CmsOracleDatabaseBridge

/-!
# Consistent claim deduplication

Physical adaptive branches may repeat an address, so their key lists need not
be nodup.  A branch with a consistent database assignment can instead use the
Finset of exact input/output claims: it has distinct inputs, preserves the
database event, and is no longer than the original claim list.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentClaimDedup

open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.FiniteOracleDatabase

set_option autoImplicit false

variable {Input Output : Type*} [DecidableEq Input] [DecidableEq Output]

omit [DecidableEq Input] [DecidableEq Output] in
/-- Membership in a list of consistent claims makes its input projection
injective: one database coordinate cannot carry two different outputs. -/
private theorem map_fst_nodup_of_consistent
    (claims : List (Input × Output))
    (database : Database Input Output)
    (nodup : claims.Nodup)
    (consistent : ∀ claim ∈ claims, database claim.1 = some claim.2) :
    (claims.map Prod.fst).Nodup := by
  induction claims with
  | nil => simp
  | cons head tail ih =>
      change List.Nodup (head.1 :: tail.map Prod.fst)
      simp only [List.nodup_cons] at nodup ⊢
      rcases nodup with ⟨headNotTail, tailNodup⟩
      refine ⟨?_, ih tailNodup (by
        intro claim member
        exact consistent claim (List.mem_cons_of_mem _ member))⟩
      intro member
      rcases List.mem_map.mp member with ⟨claim, claimMember, firstEq⟩
      have outputEq : claim.2 = head.2 := by
        have claimConsistent := consistent claim (List.mem_cons_of_mem _ claimMember)
        have headConsistent := consistent head (by simp)
        rw [firstEq] at claimConsistent
        exact Option.some.inj (claimConsistent.symm.trans headConsistent)
      have pairEq : claim = head := Prod.ext firstEq outputEq
      subst claim
      apply headNotTail
      exact claimMember

/-- If some database realizes every claim, exact-pair deduplication has no
repeated input address. Conflicting outputs are excluded by consistency, not
by assuming the original physical claim list is duplicate-free. -/
theorem consistent_claims_dedup
    (claims : List (Input × Output))
    (consistent : ∃ database : Database Input Output,
      ClaimsDatabaseEvent claims database) :
    ((claims.toFinset.toList).map Prod.fst).Nodup := by
  classical
  rcases consistent with ⟨database, records⟩
  apply map_fst_nodup_of_consistent (claims.toFinset.toList) database
    (Finset.nodup_toList _)
  intro claim member
  apply records claim
  exact List.mem_toFinset.mp (Finset.mem_toList.mp member)

/-- Deduplicating exact claim pairs preserves the complete database event. -/
theorem claims_event_dedup_iff
    (claims : List (Input × Output))
    (database : Database Input Output) :
    ClaimsDatabaseEvent claims database ↔
      ClaimsDatabaseEvent (claims.toFinset.toList) database := by
  constructor
  · intro records claim member
    apply records claim
    exact List.mem_toFinset.mp (Finset.mem_toList.mp member)
  · intro records claim member
    apply records claim
    exact Finset.mem_toList.mpr (List.mem_toFinset.mpr member)

/-- The exact-pair deduplicated claim list cannot be longer than its source. -/
theorem claims_dedup_length_le
    (claims : List (Input × Output)) :
    (claims.toFinset.toList).length ≤ claims.length := by
  classical
  rw [Finset.length_toList]
  exact List.toFinset_card_le claims

end HegemonCrypto.SmallWood.SmzaRp05CurrentClaimDedup
