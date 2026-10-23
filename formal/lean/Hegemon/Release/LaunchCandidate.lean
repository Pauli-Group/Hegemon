import Std

/-!
# Narrow pre-mainnet candidate obligations

These results describe arithmetic and chronological relation premises for the
new reward, network, threshold-custody and HTLC paths. They do not assert that
the Rust compiler implements these predicates, that SmallWood is sound or zero
knowledge for a new geometry, or that any release is authorized. The adjacent
LaunchCandidate.md maps each premise to its source enforcement and states the
remaining proof/artifact/lifecycle checks.
-/

namespace Hegemon.Release.LaunchCandidate

def funding (subsidy : Nat) : Nat := subsidy / 5
def miner (subsidy fees : Nat) : Nat := subsidy - funding subsidy + fees

theorem funding_does_not_exceed_subsidy (subsidy : Nat) :
    funding subsidy ≤ subsidy := by
  unfold funding
  omega

theorem reward_conservation (subsidy fees : Nat) :
    miner subsidy fees + funding subsidy = subsidy + fees := by
  unfold miner funding
  omega

theorem funding_rounding (subsidy : Nat) :
    5 * funding subsidy ≤ subsidy ∧ subsidy < 5 * (funding subsidy + 1) := by
  unfold funding
  omega

theorem all_fees_go_to_miner (subsidy fees extra : Nat) :
    miner subsidy (fees + extra) = miner subsidy fees + extra := by
  unfold miner
  omega

theorem checked_reward_fits (subsidy fees : Nat)
    (fits : subsidy + fees < 2^64) :
    miner subsidy fees < 2^64 ∧ funding subsidy < 2^64 := by
  have := reward_conservation subsidy fees
  omega

/- The Rust representation is eight consecutive groups of four bytes. Group
   i, byte j denotes original byte 4*i+j; no byte or high limb is discarded. -/
structure ByteQuad where
  b0 : Fin 256
  b1 : Fin 256
  b2 : Fin 256
  b3 : Fin 256
  deriving DecidableEq

abbrev Network32 := Fin 8 → ByteQuad

def pack32 (b : ByteQuad) : Nat :=
  b.b0.val + 256 * b.b1.val + 65536 * b.b2.val + 16777216 * b.b3.val

theorem pack32_bound (b : ByteQuad) : pack32 b < 2^32 := by
  obtain ⟨a,b,c,d⟩ := b
  unfold pack32
  have := a.isLt
  have := b.isLt
  have := c.isLt
  have := d.isLt
  omega

theorem pack32_injective (a b : ByteQuad) (same : pack32 a = pack32 b) : a = b := by
  obtain ⟨a0,a1,a2,a3⟩ := a
  obtain ⟨b0,b1,b2,b3⟩ := b
  dsimp [pack32] at same
  have ha0 := a0.isLt
  have ha1 := a1.isLt
  have ha2 := a2.isLt
  have ha3 := a3.isLt
  have hb0 := b0.isLt
  have hb1 := b1.isLt
  have hb2 := b2.isLt
  have hb3 := b3.isLt
  have h0 : a0 = b0 := Fin.ext (by omega)
  have h1 : a1 = b1 := Fin.ext (by omega)
  have h2 : a2 = b2 := Fin.ext (by omega)
  have h3 : a3 = b3 := Fin.ext (by omega)
  cases h0; cases h1; cases h2; cases h3
  rfl

def encodeNetwork (network : Network32) : Fin 8 → Nat := fun i => pack32 (network i)

theorem network_encoding_injective (a b : Network32)
    (same : encodeNetwork a = encodeNetwork b) : a = b := by
  funext i
  exact pack32_injective (a i) (b i) (congrFun same i)

theorem network_words_are_canonical (network : Network32) (i : Fin 8) :
    encodeNetwork network i < 18446744069414584321 := by
  have bound := pack32_bound (network i)
  unfold encodeNetwork
  omega

/- Exact RP06 source-index constants. These are coordinates of the derived
   intent preimage, not a reinterpretation of the historical public schema. -/
def rp06NetworkPositions : List Nat := [49,50,51,52,53,87,88,89]
def rp06SourcePositions : List Nat := [90,91,92,93,113,114,115]
def retainedIntentPosition (i : Nat) : Bool :=
  !(decide (4 ≤ i ∧ i < 18) || decide (47 ≤ i ∧ i < 49))

theorem rp06_projection_has_104_words :
    ((List.range 120).filter retainedIntentPosition).length = 104 := by decide

theorem rp06_network_source_slots_disjoint :
    (rp06NetworkPositions ++ rp06SourcePositions).Nodup := by decide

theorem rp06_all_network_source_words_retained :
    ((rp06NetworkPositions ++ rp06SourcePositions).all retainedIntentPosition) = true := by
  decide

abbrev Digest7 := Fin 7 → Nat
abbrev OwnerSlots := (Fin 4 → Nat) × (Fin 3 → Nat)

def splitOwner (digest : Digest7) : OwnerSlots :=
  (fun i => digest ⟨i.val, by omega⟩,
   fun i => digest ⟨i.val + 4, by omega⟩)

def joinOwner (slots : OwnerSlots) : Digest7 := fun i =>
  if h : i.val < 4 then slots.1 ⟨i.val, h⟩
  else slots.2 ⟨i.val - 4, by omega⟩

theorem full_seven_owner_roundtrip (digest : Digest7) :
    joinOwner (splitOwner digest) = digest := by
  funext i
  unfold joinOwner splitOwner
  split
  · rfl
  · dsimp
    congr 1
    apply Fin.ext
    dsimp
    omega

theorem full_seven_owner_injective (a b : Digest7)
    (same : splitOwner a = splitOwner b) : a = b := by
  have h := congrArg joinOwner same
  simpa only [full_seven_owner_roundtrip] using h

/- This is the semantic input to the RP06 intent projection, before hashing.
   Dynamic parent height, anchor and disabled stablecoin roots are deliberately
   absent. Equality of hash outputs implies equality of this tuple only under
   a separate hash-binding premise; no collision freedom is asserted here. -/
structure EconomicIntent where
  network : Network32
  sourceNullifier : Digest7
  outputCommitmentsAndCiphertexts : List Nat
  otherPublicOperationWords : List Nat
  fee : Nat

def encodeEconomicIntent (intent : EconomicIntent) :=
  (encodeNetwork intent.network, intent.sourceNullifier,
   intent.outputCommitmentsAndCiphertexts, intent.otherPublicOperationWords,
   intent.fee)

theorem economic_intent_encoding_injective (a b : EconomicIntent)
    (same : encodeEconomicIntent a = encodeEconomicIntent b) : a = b := by
  obtain ⟨an,asrc,ao,aa,af⟩ := a
  obtain ⟨bn,bsrc,bo,ba,bf⟩ := b
  simp only [encodeEconomicIntent, Prod.mk.injEq] at same
  obtain ⟨hn,hs,ho,ha,hf⟩ := same
  have hn' := network_encoding_injective an bn hn
  cases hn'; cases hs; cases ho; cases ha; cases hf
  rfl

/- An initialized chronological approval history starts empty. A step carries
   the actual credential whose complete seven-word tag matches the selected
   policy slot, and cannot select an already approved slot. Membership and
   note-binding connect the predecessor to this history in the implementation;
   the theorem does not assume that an arbitrary supplied bitmap has a history. -/
inductive ApprovalHistory {Secret : Type} (credentialTag : Secret → Digest7)
    (policy : Fin 6 → Digest7) : List (Fin 6) → Prop where
  | empty : ApprovalHistory credentialTag policy []
  | step {past : List (Fin 6)} {signer : Fin 6}
      (history : ApprovalHistory credentialTag policy past)
      (fresh : signer ∉ past) (secret : Secret)
      (matching : credentialTag secret = policy signer) :
      ApprovalHistory credentialTag policy (signer :: past)

theorem approval_history_distinct {Secret : Type} {tag : Secret → Digest7}
    {policy : Fin 6 → Digest7} {past : List (Fin 6)}
    (history : ApprovalHistory tag policy past) : past.Nodup := by
  induction history with
  | empty => simp
  | step history fresh secret matching ih =>
    exact List.nodup_cons.mpr ⟨fresh, ih⟩

theorem approval_history_origins {Secret : Type} {tag : Secret → Digest7}
    {policy : Fin 6 → Digest7} {past : List (Fin 6)}
    (history : ApprovalHistory tag policy past) :
    ∀ signer ∈ past, ∃ secret, tag secret = policy signer := by
  induction history with
  | empty => simp
  | @step past signer history fresh secret matching ih =>
    intro other member
    simp only [List.mem_cons] at member
    rcases member with same | older
    · subst other
      exact ⟨secret, matching⟩
    · exact ih other older

theorem threshold_two_has_two_distinct_origins {Secret : Type}
    {tag : Secret → Digest7} {policy : Fin 6 → Digest7} {past : List (Fin 6)}
    (history : ApprovalHistory tag policy past) (threshold : 2 ≤ past.length) :
    ∃ first second : Fin 6, first ≠ second ∧ first ∈ past ∧ second ∈ past ∧
      (∃ key, tag key = policy first) ∧ (∃ key, tag key = policy second) := by
  cases past with
  | nil => simp at threshold
  | cons first tail =>
    cases tail with
    | nil => simp at threshold
    | cons second rest =>
      have nodup := approval_history_distinct history
      have origins := approval_history_origins history
      refine ⟨first, second, ?_, by simp, by simp, ?_, ?_⟩
      · have absent := (List.nodup_cons.mp nodup).1
        intro same
        apply absent
        simp [same]
      · exact origins first (by simp)
      · exact origins second (by simp)

theorem first_limb_distinct_implies_full_tag_distinct
    (policy : Fin 6 → Digest7) (past : List (Fin 6))
    (distinct : ∀ i ∈ past, ∀ j ∈ past, i ≠ j → policy i 0 ≠ policy j 0) :
    ∀ i ∈ past, ∀ j ∈ past, i ≠ j → policy i ≠ policy j := by
  intro i memberI j memberJ different same
  exact distinct i memberI j memberJ different (congrFun same 0)

theorem threshold_two_distinct_credentials {Secret : Type}
    {tag : Secret → Digest7} {policy : Fin 6 → Digest7} {past : List (Fin 6)}
    (history : ApprovalHistory tag policy past) (threshold : 2 ≤ past.length)
    (distinct : ∀ i ∈ past, ∀ j ∈ past, i ≠ j → policy i ≠ policy j) :
    ∃ firstKey secondKey : Secret, firstKey ≠ secondKey ∧
      ∃ first second : Fin 6, first ≠ second ∧
        tag firstKey = policy first ∧ tag secondKey = policy second := by
  obtain ⟨i,j,different,memberI,memberJ,⟨keyI,originI⟩,⟨keyJ,originJ⟩⟩ :=
    threshold_two_has_two_distinct_origins history threshold
  refine ⟨keyI,keyJ,?_,i,j,different,originI,originJ⟩
  intro same
  subst keyJ
  exact distinct i memberI j memberJ different (originI.symm.trans originJ)

def goldilocks : Nat := 18446744069414584321
def heightBound : Nat := 2^48
def valueBound : Nat := 2^56
def fieldSub (a b : Nat) : Nat := (a + goldilocks - b) % goldilocks

theorem refund_range_proves_maturity (parent timeout : Nat)
    (hp : parent < heightBound) (ht : timeout < heightBound)
    (range : fieldSub parent timeout < heightBound) : timeout ≤ parent := by
  unfold fieldSub goldilocks heightBound at *
  omega

theorem lock_range_proves_future_timeout (parent timeout : Nat)
    (hp : parent < heightBound) (ht : timeout < heightBound)
    (range : (timeout + goldilocks - parent - 1) % goldilocks < heightBound) :
    parent < timeout := by
  unfold goldilocks heightBound at *
  omega

theorem htlc_field_balance_is_integer_balance (input output fee : Nat)
    (hi : input < valueBound) (ho : output < valueBound) (hf : fee < valueBound)
    (equation : input = (output + fee) % goldilocks) : input = output + fee := by
  unfold goldilocks valueBound at *
  omega

structure NullifierOpening where
  key : Fin 5 → Nat
  position : Nat
  rho : Fin 4 → Nat

def nullifierPreimage (note : NullifierOpening) : List Nat :=
  (List.ofFn note.key) ++ [0, 0, note.position] ++ List.ofFn note.rho

inductive HtlcBranch where | claim | refund

/- Branch, claimant credential, output, fee and maturity are intentionally not
   part of the nullifier preimage. Binding this key to the opened locked owner
   and enforcing membership are independent relation premises. -/
def branchNullifier (hash : List Nat → Nat) (note : NullifierOpening)
    (_branch : HtlcBranch) : Nat := hash (nullifierPreimage note)

theorem claim_refund_same_nullifier (hash : List Nat → Nat) (note : NullifierOpening) :
    branchNullifier hash note .claim = branchNullifier hash note .refund := rfl

def consume (spent : List Nat) (nullifier : Nat) : Option (List Nat) :=
  if nullifier ∈ spent then none else some (nullifier :: spent)

theorem accepted_claim_blocks_refund (hash : List Nat → Nat) (note : NullifierOpening)
    (spent next : List Nat)
    (accepted : consume spent (branchNullifier hash note .claim) = some next) :
    consume next (branchNullifier hash note .refund) = none := by
  unfold consume at accepted
  split at accepted
  · contradiction
  · cases accepted
    simp [consume, branchNullifier]

theorem accepted_refund_blocks_claim (hash : List Nat → Nat) (note : NullifierOpening)
    (spent next : List Nat)
    (accepted : consume spent (branchNullifier hash note .refund) = some next) :
    consume next (branchNullifier hash note .claim) = none := by
  unfold consume at accepted
  split at accepted
  · contradiction
  · cases accepted
    simp [consume, branchNullifier]

#print axioms reward_conservation
#print axioms network_encoding_injective
#print axioms full_seven_owner_injective
#print axioms economic_intent_encoding_injective
#print axioms threshold_two_has_two_distinct_origins
#print axioms threshold_two_distinct_credentials
#print axioms refund_range_proves_maturity
#print axioms lock_range_proves_future_timeout
#print axioms htlc_field_balance_is_integer_balance
#print axioms accepted_claim_blocks_refund
#print axioms accepted_refund_blocks_claim

end Hegemon.Release.LaunchCandidate
