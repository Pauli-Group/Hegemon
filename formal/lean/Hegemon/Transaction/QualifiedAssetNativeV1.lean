import Hegemon.Transaction.QualifiedAssetBalanceV1
import Lean.Elab.Tactic.Omega

/-!
Bounded arithmetic and coordinate consequences of the current SMZE asset
graph. `FieldRows` is an interpretation of particular satisfied graph rows in
canonical Goldilocks representatives. It is NOT proof acceptance, extraction,
or a source-lowering certificate. The existing trusted compiler/primitive
interpretation must supply these row premises from an accepted assignment.

There is no new cryptographic axiom here. Credential hash/path binding, issuer
knowledge extraction, authenticated registry accounting, persistent admission,
the changed public-head/abort/query-ledger interpretation and proof privacy
remain separate. In particular this module does not adapt the retained native
77-word security readout to this 134-word asset/admin wire identity.
-/
namespace Hegemon.Transaction.QualifiedAssetNativeV1

set_option autoImplicit false

def modulus : Nat := 18446744069414584321
def valueBound : Nat := 2^56
def heightBound : Nat := 2^48
def assetBound : Nat := 2^32

/-- The source `boolean` primitive's interpretation, not a new Boolean test. -/
def bit (b : Bool) : Nat := if b then 1 else 0

theorem bit_le_one (b : Bool) : bit b ≤ 1 := by cases b <;> decide

/-- Public offsets are literal `asset_spend_v1/types.rs` coordinates. -/
abbrev PublicWords := Fin 134 → Nat
abbrev NoteWords := Fin 18 → Nat
abbrev Digest := Fin 7 → Nat
abbrev Recipient := Fin 4 → Nat

def noteOwner (note : NoteWords) (i : Fin 7) : Nat :=
  if h : i.val < 4 then note ⟨14 + i.val, by omega⟩
  else note ⟨6 + i.val, by omega⟩

def noteRecipient (note : NoteWords) (i : Fin 4) : Nat :=
  note ⟨2 + i.val, by omega⟩

/-- Exactly fourteen leaf words: asset, version, recipient[4], owner[7], expiry.
The full owner is the selected ordinary SINGLE digest or complete policy owner;
the chosen branch authority is not substituted for that policy owner. -/
def credentialWords (asset version : Nat) (recipient : Recipient)
    (owner : Digest) (expiry : Nat) : List Nat :=
  [asset, version] ++ List.ofFn recipient ++ List.ofFn owner ++ [expiry]

/-- Ordinary credentials name the SINGLE authority, while ordinary notes commit
`ordinaryOwner authority`. Policy credentials and notes both name the complete
policy owner. The old integer model's `note.owner` is therefore not a literal
wire map for ordinary credentials; its source refinement must distinguish these
roles. This definition records the distinction without altering retained claims. -/
structure SubjectBinding (ordinaryOwner : Digest → Digest) (scripted : Bool)
    (authority policyOwner credentialSubject committedOwner : Digest) : Prop where
  credential : credentialSubject = if scripted then policyOwner else authority
  committed : committedOwner = if scripted then policyOwner else ordinaryOwner authority

theorem ordinary_subject_and_committed_owner_have_distinct_roles
    {ordinaryOwner : Digest → Digest} {authority policyOwner credentialSubject committedOwner : Digest}
    (roles : SubjectBinding ordinaryOwner false authority policyOwner credentialSubject committedOwner) :
    credentialSubject = authority ∧ committedOwner = ordinaryOwner authority := by
  exact ⟨roles.credential, roles.committed⟩

theorem policy_subject_is_complete_committed_owner
    {ordinaryOwner : Digest → Digest} {authority policyOwner credentialSubject committedOwner : Digest}
    (roles : SubjectBinding ordinaryOwner true authority policyOwner credentialSubject committedOwner) :
    credentialSubject = policyOwner ∧ committedOwner = policyOwner := by
  exact ⟨roles.credential, roles.committed⟩

theorem credential_subject_uses_every_limb
    {ordinaryOwner : Digest → Digest} {scripted : Bool}
    {authority policyOwner credentialSubject committedOwner : Digest}
    (roles : SubjectBinding ordinaryOwner scripted authority policyOwner credentialSubject committedOwner)
    (i : Fin 7) : credentialSubject i = (if scripted then policyOwner else authority) i :=
  congrFun roles.credential i

theorem wrong_credential_subject_limb_rejects
    {ordinaryOwner : Digest → Digest} {scripted : Bool}
    {authority policyOwner credentialSubject committedOwner : Digest} (i : Fin 7)
    (wrong : credentialSubject i ≠ (if scripted then policyOwner else authority) i) :
    ¬ SubjectBinding ordinaryOwner scripted authority policyOwner credentialSubject committedOwner :=
  fun roles => wrong (credential_subject_uses_every_limb roles i)

theorem credential_words_length (asset version expiry : Nat)
    (recipient : Recipient) (owner : Digest) :
    (credentialWords asset version recipient owner expiry).length = 14 := by
  simp [credentialWords]

theorem note_owner_uses_all_seven_coordinates (note : NoteWords) :
    List.ofFn (noteOwner note) =
      [note 14, note 15, note 16, note 17, note 10, note 11, note 12] := by
  simp [List.ofFn_succ, noteOwner]

/-- Small sums are below the ACTUAL field modulus, not just below a power of 2. -/
theorem three_values_below_goldilocks (a b c : Nat)
    (ha : a < valueBound) (hb : b < valueBound) (hc : c < valueBound) :
    a + b + c < modulus := by
  unfold valueBound at ha hb hc
  unfold modulus
  omega

theorem two_values_below_goldilocks (a b : Nat)
    (ha : a < valueBound) (hb : b < valueBound) : a + b < modulus := by
  have := three_values_below_goldilocks a b 0 ha hb (by decide)
  simpa using this

/-- Current circuit.rs asset equation, with source Boolean-selector semantics.
The modular equality is an explicit row premise; both sides lift uniquely. -/
theorem asset_balance_lifts (input recipient change magnitude : Nat)
    (mint burn : Bool)
    (hi : input < valueBound) (hr : recipient < valueBound)
    (hc : change < valueBound) (hm : magnitude < valueBound)
    (row : (input + bit mint * magnitude) % modulus =
      (recipient + change + bit burn * magnitude) % modulus) :
    input + bit mint * magnitude = recipient + change + bit burn * magnitude := by
  have mintBound : bit mint * magnitude < valueBound := by
    cases mint <;> simp_all [bit, valueBound]
  have burnBound : bit burn * magnitude < valueBound := by
    cases burn <;> simp_all [bit, valueBound]
  have left := two_values_below_goldilocks input (bit mint * magnitude) hi mintBound
  have right := three_values_below_goldilocks recipient change (bit burn * magnitude)
    hr hc burnBound
  simpa only [Nat.mod_eq_of_lt left, Nat.mod_eq_of_lt right] using row

theorem native_fee_balance_lifts (input change fee : Nat)
    (hi : input < valueBound) (hc : change < valueBound) (hf : fee < valueBound)
    (row : input % modulus = (change + fee) % modulus) : input = change + fee := by
  have left : input < modulus := by unfold valueBound at hi; unfold modulus; omega
  have right := two_values_below_goldilocks change fee hc hf
  simpa only [Nat.mod_eq_of_lt left, Nat.mod_eq_of_lt right] using row

theorem selector_sum_lifts (transfer mint burn : Bool)
    (row : (bit transfer + bit mint + bit burn) % modulus = 1) :
    bit transfer + bit mint + bit burn = 1 := by
  have small : bit transfer + bit mint + bit burn < modulus := by
    have := bit_le_one transfer; have := bit_le_one mint; have := bit_le_one burn
    unfold modulus; omega
  simpa only [Nat.mod_eq_of_lt small] using row

theorem selector_exactly_one (transfer mint burn : Bool)
    (row : (bit transfer + bit mint + bit burn) % modulus = 1) :
    (transfer = true ∧ mint = false ∧ burn = false) ∨
    (transfer = false ∧ mint = true ∧ burn = false) ∨
    (transfer = false ∧ mint = false ∧ burn = true) := by
  have sum := selector_sum_lifts transfer mint burn row
  cases transfer <;> cases mint <;> cases burn <;> simp_all [bit]

/-- A canonical field public operation cannot disguise a fourth route. -/
theorem operation_lifts (operation : Nat) (mint burn : Bool)
    (canonical : operation < modulus)
    (row : operation % modulus = (bit mint + 2 * bit burn) % modulus) :
    operation = bit mint + 2 * bit burn := by
  have small : bit mint + 2 * bit burn < modulus := by
    have := bit_le_one mint; have := bit_le_one burn
    unfold modulus; omega
  simpa only [Nat.mod_eq_of_lt canonical, Nat.mod_eq_of_lt small] using row

theorem operation_has_only_three_routes (operation : Nat) (transfer mint burn : Bool)
    (canonical : operation < modulus)
    (oneHot : (bit transfer + bit mint + bit burn) % modulus = 1)
    (row : operation % modulus = (bit mint + 2 * bit burn) % modulus) :
    operation = 0 ∨ operation = 1 ∨ operation = 2 := by
  have op := operation_lifts operation mint burn canonical row
  rcases selector_exactly_one transfer mint burn oneHot with h | h | h <;>
    rcases h with ⟨rfl, rfl, rfl⟩ <;> simp_all [bit]

/-- Canonical field subtraction, not truncated natural subtraction. If an
active credential is expired, its residue lies near p and cannot be 48-bit. -/
def subRepresentative (left right : Nat) : Nat := (left + modulus - right) % modulus

theorem active_expiry_cannot_wrap (expiry height : Nat)
    (he : expiry < heightBound) (hh : height < heightBound)
    (deltaRange : subRepresentative expiry height < heightBound) : height ≤ expiry := by
  by_cases good : height ≤ expiry
  · exact good
  have bad : ¬ height ≤ expiry := good
  have early : expiry < height := by omega
  have small : expiry + modulus - height < modulus := by unfold modulus; omega
  unfold subRepresentative at deltaRange
  rw [Nat.mod_eq_of_lt small] at deltaRange
  unfold heightBound at he hh deltaRange
  unfold modulus at deltaRange
  omega

/-- A canonical equality of individual asset fields is exact, independently
of the balance lift. `gates` supplies this equality only on active inputs. -/
theorem canonical_field_equality_is_exact (a b : Nat)
    (ha : a < modulus) (hb : b < modulus)
    (row : a % modulus = b % modulus) : a = b := by
  simpa only [Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] using row

/-- Explicit, local row interpretation. Supplying it from Rust, lowering and
proof acceptance remains the changed graph binding obligation. Neither a
whole-result Boolean nor assumed integer conservation occurs in this record. -/
structure FieldRows (p : PublicWords) (inputs : Fin 2 → NoteWords)
    (outputs : Fin 3 → NoteWords) (transfer mint burn : Bool) : Prop where
  publicCanonical : ∀ i, p i < modulus
  nonnative : p 31 ≠ 0
  inputRange : ∀ i, inputs i 0 < valueBound
  outputRange : ∀ i, outputs i 0 < valueBound
  magnitudeRange : p 51 < valueBound
  feeRange : p 52 < valueBound
  oneHot : (bit transfer + bit mint + bit burn) % modulus = 1
  operation : p 50 % modulus = (bit mint + 2 * bit burn) % modulus
  inputAsset : mint = false → inputs 0 1 = p 31
  inputNative : inputs 1 1 = 0
  outputAssets : outputs 0 1 = p 31 ∧ outputs 1 1 = p 31 ∧ outputs 2 1 = 0
  mintInput : mint = true → inputs 0 0 = 0
  assetBalance : (inputs 0 0 + bit mint * p 51) % modulus =
    (outputs 0 0 + outputs 1 0 + bit burn * p 51) % modulus
  nativeBalance : inputs 1 0 % modulus = (outputs 2 0 + p 52) % modulus

/-- These rows apply outside every policy choice. Authenticated current registry
binding is still required to identify public controls with ledger controls. -/
structure ControlRows (p : PublicWords) (mint : Bool) : Prop where
  unfrozen : p 41 = 0
  mintEnabled : mint = true → p 42 = 1

theorem public_freeze_rejects_every_policy_choice {p : PublicWords} {mint : Bool}
    (frozen : p 41 = 1) : ¬ ControlRows p mint := by
  intro rows
  have := rows.unfrozen
  omega

theorem mint_disabled_rejects_mint_only {p : PublicWords}
    (disabled : p 42 = 0) : ¬ ControlRows p true := by
  intro rows
  have := rows.mintEnabled rfl
  omega

theorem transfer_and_burn_do_not_require_mint_enabled {p : PublicWords}
    (unfrozen : p 41 = 0) : ControlRows p false :=
  ⟨unfrozen, by intro h; cases h⟩

theorem current_field_rows_integer_conservation
    {p : PublicWords} {inputs : Fin 2 → NoteWords} {outputs : Fin 3 → NoteWords}
    {transfer mint burn : Bool} (rows : FieldRows p inputs outputs transfer mint burn) :
    inputs 0 0 + bit mint * p 51 = outputs 0 0 + outputs 1 0 + bit burn * p 51 ∧
    inputs 1 0 = outputs 2 0 + p 52 := by
  exact ⟨asset_balance_lifts _ _ _ _ mint burn (rows.inputRange 0)
    (rows.outputRange 0) (rows.outputRange 1) rows.magnitudeRange rows.assetBalance,
    native_fee_balance_lifts _ _ _ (rows.inputRange 1) (rows.outputRange 2)
      rows.feeRange rows.nativeBalance⟩

theorem current_field_rows_native_fee_isolation
    {p : PublicWords} {inputs : Fin 2 → NoteWords} {outputs : Fin 3 → NoteWords}
    {transfer mint burn : Bool} (rows : FieldRows p inputs outputs transfer mint burn) :
    p 31 ≠ 0 ∧ inputs 1 1 = 0 ∧ outputs 2 1 = 0 ∧
    outputs 0 1 ≠ 0 ∧ outputs 1 1 ≠ 0 ∧ inputs 1 0 = outputs 2 0 + p 52 := by
  exact ⟨rows.nonnative, rows.inputNative, rows.outputAssets.2.2,
    rows.outputAssets.1.symm ▸ rows.nonnative,
    rows.outputAssets.2.1.symm ▸ rows.nonnative,
    (current_field_rows_integer_conservation rows).2⟩

theorem current_field_rows_supported_operation
    {p : PublicWords} {inputs : Fin 2 → NoteWords} {outputs : Fin 3 → NoteWords}
    {transfer mint burn : Bool} (rows : FieldRows p inputs outputs transfer mint burn) :
    p 50 = 0 ∨ p 50 = 1 ∨ p 50 = 2 :=
  operation_has_only_three_routes _ transfer mint burn (rows.publicCanonical 50)
    rows.oneHot rows.operation

/-- Policy choice is immaterial to the arithmetic lift: mandatory compliance
and the same row interpretation must hold for the SAME accepted witness. -/
theorem policy_alternative_keeps_field_conservation
    {p : PublicWords} {inputs : Fin 2 → NoteWords} {outputs : Fin 3 → NoteWords}
    {transfer mint burn : Bool} (rows : FieldRows p inputs outputs transfer mint burn)
    (mandatory : Prop) (sha : Hegemon.Policy.BoundedPrivateSpend.Secret →
      Hegemon.Policy.BoundedPrivateSpend.HashWords)
    (policy : Hegemon.Policy.BoundedPrivateSpend.Policy) (choice : Bool)
    (height : Nat) (spend : Hegemon.Policy.BoundedPrivateSpend.SpendWitness)
    (release : Hegemon.Policy.BoundedPrivateSpend.PublicRelease)
    (accepted : Hegemon.Policy.BoundedPrivateSpend.Accepted mandatory sha policy choice
      height spend release) :
    mandatory ∧
    inputs 0 0 + bit mint * p 51 = outputs 0 0 + outputs 1 0 + bit burn * p 51 ∧
    inputs 1 0 = outputs 2 0 + p 52 :=
  ⟨accepted.2.2.1, current_field_rows_integer_conservation rows⟩

end Hegemon.Transaction.QualifiedAssetNativeV1
