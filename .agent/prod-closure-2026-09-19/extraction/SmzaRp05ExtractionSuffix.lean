import SmzaRp05CurrentRoleLabels
import SmzaRp05TerminalKnownClaims

/-!
# One-batch extraction query schedule

The verifier's X claims are read before the single X measurement.  After
measurement the extractor issues only the four bounded challenge roles,
including the earlier-role reads needed to compute every prefix.  No mark or
oracle write occurs in this suffix.  The plan is allowed to depend on the
measured X relation; it never requires a separate extraction run per proof.

This module proves the exact finite query/claim accounting.  The physical
read instrument and the partial-compression identities are separate modules;
the classical interpreter below is not presented as a quantum run theorem.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ExtractionSuffix

open scoped BigOperators Classical
open SmzaChallengeStageTargets

noncomputable section
set_option autoImplicit false

inductive Domain where
  | raw
  | role (value : Role)
deriving DecidableEq, Fintype

variable {Key Output : Type*} [DecidableEq Key]

/-- A single canonical, deduplicated list for a whole batch.  Domain tags are
the physical parser partition, not the accepted-proof sequence number. -/
structure Plan (Key : Type*) [DecidableEq Key] where
  keys : Finset Key
  domain : Key → Domain

def domainKeys (plan : Plan Key) (domain : Domain) : Finset Key :=
  plan.keys.filter fun key => plan.domain key = domain

theorem domain_keys_disjoint (plan : Plan Key) (left right : Domain)
    (different : left ≠ right) :
    Disjoint (domainKeys plan left) (domainKeys plan right) := by
  apply Finset.disjoint_left.mpr
  intro key first second
  exact different ((Finset.mem_filter.mp first).2.symm.trans
    (Finset.mem_filter.mp second).2)

theorem sum_domain_claims_eq (plan : Plan Key) :
    (∑ domain : Domain, (domainKeys plan domain).card) = plan.keys.card := by
  classical
  simp only [domainKeys, Finset.card_filter]
  rw [Finset.sum_comm]
  simp

def reads (oracle : Key → Output) (keys : List Key) : List (Key × Output) :=
  keys.map fun key => (key, oracle key)

def claims (plan : Plan Key) (oracle : Key → Output) (domain : Domain) :
    List (Key × Output) :=
  reads oracle (domainKeys plan domain).toList

theorem claims_nodup (plan : Plan Key) (oracle : Key → Output) (domain : Domain) :
    ((claims plan oracle domain).map Prod.fst).Nodup := by
  simpa [claims, reads, List.map_map, Function.comp_def] using
    (domainKeys plan domain).nodup_toList

theorem claims_exact_readback (plan : Plan Key) (oracle : Key → Output)
    (domain : Domain) (key : Key) (output : Output)
    (member : (key, output) ∈ claims plan oracle domain) :
    key ∈ domainKeys plan domain ∧ output = oracle key := by
  obtain ⟨source, present, same⟩ := List.mem_map.mp member
  have keyEq : source = key := congrArg Prod.fst same
  have outputEq : oracle source = output := congrArg Prod.snd same
  subst source
  exact ⟨Finset.mem_toList.mp present, outputEq.symm⟩

theorem total_claims_eq (plan : Plan Key) (oracle : Key → Output) :
    (∑ domain : Domain, (claims plan oracle domain).length) = plan.keys.card := by
  simpa [claims, reads] using sum_domain_claims_eq plan

/-- The raw prefix is read before measurement.  This is the complete
post-measurement key list; every member is a role key and none is X. -/
def afterMeasurement (plan : Plan Key) : List Key :=
  (plan.keys.filter fun key => plan.domain key ≠ .raw).toList

theorem post_measurement_reads_are_roles (plan : Plan Key) (key : Key)
    (member : key ∈ afterMeasurement plan) :
    ∃ role, plan.domain key = .role role := by
  have notRaw := (Finset.mem_filter.mp (Finset.mem_toList.mp member)).2
  cases kind : plan.domain key with
  | raw => exact (notRaw kind).elim
  | role role => exact ⟨role, rfl⟩

theorem post_measurement_read_count (plan : Plan Key) :
    (afterMeasurement plan).length ≤ plan.keys.card := by
  simpa [afterMeasurement] using
    Finset.card_filter_le (s := plan.keys) (p := fun key => plan.domain key ≠ .raw)

/-- No statement or proof multiplicity factor: all five claim classes share
one deduplicated physical key set.  The global T also charges prior queries
and simulator programming touches, so it bounds this suffix subset. -/
theorem total_claims_le_lifetime (plan : Plan Key) (oracle : Key → Output)
    (priorTouches lifetime : Nat)
    (budget : priorTouches + plan.keys.card ≤ lifetime) :
    (∑ domain : Domain, (claims plan oracle domain).length) ≤ lifetime := by
  rw [total_claims_eq]
  omega

end
end HegemonCrypto.SmallWood.SmzaRp05ExtractionSuffix
