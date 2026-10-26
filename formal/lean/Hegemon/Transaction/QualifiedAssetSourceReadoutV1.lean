import Hegemon.Transaction.QualifiedAssetNativeV1

/-!
Current asset/admin primitive-call readout. This is a compiler/primitive
interface, analogous to retained CurrentSourceCallContract: the checked data
describe calls, operand locators and equality rows WITHOUT mentioning the
assignment or the desired output equations. A single interpreted assignment
then yields the concrete role equations below.

`Graph` is the primitive-call abstraction after the RETAINED trusted compiler
and primitive interpretation; it is not another Rust interpreter or a claim
that all source locators have been mechanically generated. Constructing the
checked records from the actual recovered SMZE source remains an explicit F1
interface. No proof-acceptance, soundness, extraction or privacy axiom is added.
-/
namespace Hegemon.Transaction.QualifiedAssetSourceReadoutV1

set_option autoImplicit false

def modulus : Nat := Hegemon.Transaction.QualifiedAssetNativeV1.modulus
abbrev F := Fin modulus
abbrev Digest := Fin 7 → F
abbrev Key := Fin 5 → F
abbrev Public := Fin 134 → F

def zero : F := ⟨0, by decide⟩
def one : F := ⟨1, by decide⟩
def add (a b : F) : F := ⟨(a.val + b.val) % modulus, Nat.mod_lt _ (by decide)⟩
def mul (a b : F) : F := ⟨(a.val * b.val) % modulus, Nat.mod_lt _ (by decide)⟩

inductive Word where
  | constant : F → Word
  | wire : Nat → Word
  deriving DecidableEq

def read (z : Nat → F) : Word → F
  | .constant k => k
  | .wire i => z i

abbrev Words (n : Nat) := Fin n → Word

/-- Actual primitive functions, not injectivity/security assumptions. The
retained primitive interpretation supplies their implementation meaning. -/
structure Primitives where
  sponge : Nat → List F → Digest
  compress : Nat → Digest → Digest → Digest

inductive Node where
  | input : Nat → Node
  | sponge : Nat → List Word → Fin 7 → Node
  | compress : Nat → Words 7 → Words 7 → Fin 7 → Node
  | product : Word → Word → Node
  | sum : List Word → Node

def Node.meaning (crypto : Primitives) (input z : Nat → F) : Node → F
  | .input i => input i
  | .sponge domain message limb => crypto.sponge domain (message.map (read z)) limb
  | .compress domain left right limb => crypto.compress domain
      (fun i => read z (left i)) (fun i => read z (right i)) limb
  | .product a b => mul (read z a) (read z b)
  | .sum terms => (terms.map (read z)).foldl add zero

structure Graph where
  count : Nat
  nodes : Fin count → Node
  equalities : List (Word × Word)
  gates : List (Word × Word × Word)
  nonzero : List Word

/-- RETAINED compiler/primitive interpretation, local to one source assignment.
The gate implication is the unchanged gate primitive's active-one semantics.
This interface supplies neither accepted-proof extraction nor authorization. -/
structure Interpreted (crypto : Primitives) (g : Graph) (input z : Nat → F) : Prop where
  nodes : ∀ i, z i.val = (g.nodes i).meaning crypto input z
  equalities : ∀ a b, (a, b) ∈ g.equalities → read z a = read z b
  gates : ∀ active a b, (active, a, b) ∈ g.gates →
    read z active = one → read z a = read z b
  nonzero : ∀ w, w ∈ g.nonzero → read z w ≠ zero

structure SpongeChecked (g : Graph) (domain : Nat) (message : List Word)
    (output : Words 7) where
  node : Fin 7 → Fin g.count
  kind : ∀ i, g.nodes (node i) = .sponge domain message i
  locator : ∀ i, output i = .wire (node i).val

structure CompressChecked (g : Graph) (domain : Nat) (left right output : Words 7) where
  node : Fin 7 → Fin g.count
  kind : ∀ i, g.nodes (node i) = .compress domain left right i
  locator : ∀ i, output i = .wire (node i).val

theorem source_sponge {crypto : Primitives} {g : Graph} {input z : Nat → F}
    (sem : Interpreted crypto g input z) {domain : Nat} {message : List Word}
    {output : Words 7} (checked : SpongeChecked g domain message output) :
    (fun i => read z (output i)) = crypto.sponge domain (message.map (read z)) := by
  funext i
  have h := sem.nodes (checked.node i)
  rw [checked.kind] at h
  simpa only [checked.locator, read, Node.meaning] using h

theorem source_compress {crypto : Primitives} {g : Graph} {input z : Nat → F}
    (sem : Interpreted crypto g input z) {domain : Nat} {left right output : Words 7}
    (checked : CompressChecked g domain left right output) :
    (fun i => read z (output i)) = crypto.compress domain
      (fun i => read z (left i)) (fun i => read z (right i)) := by
  funext i
  have h := sem.nodes (checked.node i)
  rw [checked.kind] at h
  simpa only [checked.locator, read, Node.meaning] using h

/-- Every one of the134 actual public input wires is bound, without a Fin77
projection, ignored suffix or changed issuer/admin intent after the readout. -/
def PublicChecked (g : Graph) (p : Words 134) (statement : Public) : Prop :=
  ∀ i, (p i, .constant (statement i)) ∈ g.equalities

theorem whole_public_readout {crypto : Primitives} {g : Graph} {input z : Nat → F}
    (sem : Interpreted crypto g input z) {p : Words 134} {statement : Public}
    (checked : PublicChecked g p statement) :
    (fun i => read z (p i)) = statement := by
  funext i
  exact sem.equalities _ _ (checked i)

theorem two_public_readouts_cannot_change_any_word
    {crypto : Primitives} {g : Graph} {input z : Nat → F}
    (sem : Interpreted crypto g input z) {p : Words 134} {left right : Public}
    (l : PublicChecked g p left) (r : PublicChecked g p right) : left = right :=
  (whole_public_readout sem l).symm.trans (whole_public_readout sem r)

def singleDomain : Nat := 0x4853_4b41_5632_0001
def ordinaryOwnerDomain : Nat := 0x5053_4f57_4e52_0001
def nullifierDomain : Nat := 0x484e_554c_5632_0001
def issuerDomain : Nat := 0x4853_4338_4953_434d
def adminDomain : Nat := 0x4150_4144_4d49_0001
def credentialDomain : Nat := 0x4153_4352_4544_0001

def key7 (key : Words 5) : Words 7 := fun i =>
  if h : i.val < 5 then key ⟨i.val, h⟩ else .constant zero
def zeroWords : Words 7 := fun _ => .constant zero
def owner (note : Words 18) : Words 7 := fun i =>
  if h : i.val < 4 then note ⟨14 + i.val, by omega⟩
  else note ⟨6 + i.val, by omega⟩
def rho (note : Words 18) : Words 4 := fun i => note ⟨6 + i.val, by omega⟩
def recipient (note : Words 18) : Words 4 := fun i => note ⟨2 + i.val, by omega⟩
def slice7 (p : Words 134) (start : Nat) (bound : start + 7 ≤ 134) : Words 7 :=
  fun i => p ⟨start + i.val, by omega⟩
def realNullifierMessage (key : Words 5) (position : Word) (note : Words 18) : List Word :=
  List.ofFn (key7 key) ++ [position] ++ List.ofFn (rho note)
def issuerBinding (p : Words 134) : Words 7 := fun i =>
  if i.val = 0 then p 31 else if i.val = 1 then p 32 else .constant zero
def adminBinding (p : Words 134) : Words 7 := fun i =>
  if i.val = 0 then p 32 else .constant zero
def credentialMessage (p : Words 134) (note : Words 18)
    (subject : Words 7) (expiry : Word) : List Word :=
  [p 31, p 32] ++ List.ofFn (recipient note) ++ List.ofFn subject ++ [expiry]

theorem actual_message_lengths (key : Words 5) (position : Word) (note : Words 18)
    (p : Words 134) (subject : Words 7) (expiry : Word) :
    (realNullifierMessage key position note).length = 12 ∧
    (credentialMessage p note subject expiry).length = 14 := by
  simp [realNullifierMessage, credentialMessage]

/-- No branch argument enters the actual real-NF message. Rho4 is present;
the imported policy model's abstract value/position signature is not substituted. -/
def policyNullifierMessage (key : Words 5) (position : Word) (note : Words 18)
    (_branch : Bool) : List Word := realNullifierMessage key position note

theorem same_shared_key_note_and_position_same_nullifier_message
    (key : Words 5) (position : Word) (note : Words 18) (left right : Bool) :
    policyNullifierMessage key position note left =
      policyNullifierMessage key position note right := rfl

structure AssetRoles where
  p : Words 134
  note : Words 18
  spendKey : Words 5
  nullifierKey : Words 5
  position : Word
  authority : Words 7
  ordinaryOwner : Words 7
  realNullifier : Words 7
  issuerSecret : Words 7
  issuerCommitment : Words 7
  occupied : Word
  ordinaryActive : Word
  mint : Word

/-- Finite call/operand/equality data, independent of `input`, `z`, or role
equations. The current Rust source-to-locator instance is still required. -/
structure AssetCallsChecked (g : Graph) (r : AssetRoles) where
  authority : SpongeChecked g singleDomain (List.ofFn (key7 r.spendKey)) r.authority
  ordinary : SpongeChecked g ordinaryOwnerDomain (List.ofFn r.authority) r.ordinaryOwner
  nullifier : SpongeChecked g nullifierDomain
    (realNullifierMessage r.nullifierKey r.position r.note) r.realNullifier
  issuer : CompressChecked g issuerDomain r.issuerSecret (issuerBinding r.p) r.issuerCommitment
  noteOwner : ∀ i, (r.ordinaryActive, owner r.note i, r.ordinaryOwner i) ∈ g.gates
  publicNullifier : ∀ i, (r.occupied, r.realNullifier i, slice7 r.p 53 (by decide) i) ∈ g.gates
  publicIssuer : ∀ i, (r.mint, r.issuerCommitment i, slice7 r.p 43 (by decide) i) ∈ g.gates

theorem ordinary_authority_and_note_owner_from_source_calls
    {crypto : Primitives} {g : Graph} {input z : Nat → F} (sem : Interpreted crypto g input z)
    {r : AssetRoles} (checked : AssetCallsChecked g r) (active : read z r.ordinaryActive = one) :
    (fun i => read z (r.authority i)) =
      crypto.sponge singleDomain ((List.ofFn (key7 r.spendKey)).map (read z)) ∧
    (fun i => read z (owner r.note i)) =
      crypto.sponge ordinaryOwnerDomain ((List.ofFn r.authority).map (read z)) := by
  refine ⟨source_sponge sem checked.authority, ?_⟩
  have eq : (fun i => read z (owner r.note i)) = (fun i => read z (r.ordinaryOwner i)) := by
    funext i
    exact sem.gates _ _ _ (checked.noteOwner i) active
  exact eq.trans (source_sponge sem checked.ordinary)

theorem real_nullifier_from_exact_source_tuple
    {crypto : Primitives} {g : Graph} {input z : Nat → F} (sem : Interpreted crypto g input z)
    {r : AssetRoles} (checked : AssetCallsChecked g r) (active : read z r.occupied = one) :
    (fun i => read z (slice7 r.p 53 (by decide) i)) =
      crypto.sponge nullifierDomain
        ((realNullifierMessage r.nullifierKey r.position r.note).map (read z)) := by
  have eq : (fun i => read z (slice7 r.p 53 (by decide) i)) =
      (fun i => read z (r.realNullifier i)) := by
    funext i
    exact (sem.gates _ _ _ (checked.publicNullifier i) active).symm
  exact eq.trans (source_sponge sem checked.nullifier)

theorem issuer_secret_binds_actual_asset_version_public_commitment
    {crypto : Primitives} {g : Graph} {input z : Nat → F} (sem : Interpreted crypto g input z)
    {r : AssetRoles} (checked : AssetCallsChecked g r) (mint : read z r.mint = one) :
    (fun i => read z (slice7 r.p 43 (by decide) i)) =
      crypto.compress issuerDomain (fun i => read z (r.issuerSecret i))
        (fun i => read z (issuerBinding r.p i)) := by
  have eq : (fun i => read z (slice7 r.p 43 (by decide) i)) =
      (fun i => read z (r.issuerCommitment i)) := by
    funext i
    exact (sem.gates _ _ _ (checked.publicIssuer i) mint).symm
  exact eq.trans (source_compress sem checked.issuer)

structure AdminRoles where
  p : Words 134
  secret : Words 7
  commitment : Words 7

structure AdminCallsChecked (g : Graph) (r : AdminRoles) where
  commitment : CompressChecked g adminDomain r.secret (adminBinding r.p) r.commitment
  publicAdmin : ∀ i, (r.commitment i, slice7 r.p 35 (by decide) i) ∈ g.equalities

theorem admin_secret_binds_actual_asset_public_commitment
    {crypto : Primitives} {g : Graph} {input z : Nat → F} (sem : Interpreted crypto g input z)
    {r : AdminRoles} (checked : AdminCallsChecked g r) :
    (fun i => read z (slice7 r.p 35 (by decide) i)) =
      crypto.compress adminDomain (fun i => read z (r.secret i))
        (fun i => read z (adminBinding r.p i)) := by
  have eq : (fun i => read z (slice7 r.p 35 (by decide) i)) =
      (fun i => read z (r.commitment i)) := by
    funext i
    exact (sem.equalities _ _ (checked.publicAdmin i)).symm
  exact eq.trans (source_compress sem checked.commitment)

structure CredentialRoles where
  p : Words 134
  note : Words 18
  subject : Words 7
  expiry : Word
  leaf : Words 7

/-- The subject locator is the ordinary authority or complete policy owner,
exactly as chosen by the actual source selection; it is not `owner note` for
an ordinary note. No branch-authority substitution is introduced here. -/
def CredentialCallChecked (g : Graph) (r : CredentialRoles) :=
  SpongeChecked g credentialDomain (credentialMessage r.p r.note r.subject r.expiry) r.leaf

theorem credential_leaf_from_actual_fourteen_source_words
    {crypto : Primitives} {g : Graph} {input z : Nat → F} (sem : Interpreted crypto g input z)
    {r : CredentialRoles} (checked : CredentialCallChecked g r) :
    (fun i => read z (r.leaf i)) = crypto.sponge credentialDomain
      (([r.p 31, r.p 32] ++ List.ofFn (recipient r.note) ++
        List.ofFn r.subject ++ [r.expiry]).map (read z)) :=
  source_sponge sem checked

theorem whole134_admin_intent_and_secret_share_one_source_assignment
    {crypto : Primitives} {g : Graph} {input z : Nat → F} (sem : Interpreted crypto g input z)
    {r : AdminRoles} (checked : AdminCallsChecked g r) {statement : Public}
    (publicRows : PublicChecked g r.p statement) :
    (fun i => read z (r.p i)) = statement ∧
    (fun i => read z (slice7 r.p 35 (by decide) i)) =
      crypto.compress adminDomain (fun i => read z (r.secret i))
        (fun i => read z (adminBinding r.p i)) :=
  ⟨whole_public_readout sem publicRows,
    admin_secret_binds_actual_asset_public_commitment sem checked⟩

def adminContextTag : F := ⟨0x4847_5041_444d_0002, by decide⟩

/-- The shared SMZE transcript/profile does not identify spend and admin
statements: admin word0 exceeds the spend word0's source32-bit bound. -/
theorem asset_and_admin_whole_statements_are_disjoint (asset admin : Public)
    (assetWord : (asset 0).val < 2^32) (adminWord : admin 0 = adminContextTag) : asset ≠ admin := by
  intro same
  have h := congrArg (fun p : Public => p 0) same
  rw [adminWord] at h
  have hv := congrArg Fin.val h
  change (asset 0).val = 0x4847_5041_444d_0002 at hv
  omega

/-- This output carries the SAME interpreted assignment/public statement.
It does not contain authorization, event coverage, or assumed proof soundness. -/
structure RecoveredSource (crypto : Primitives) where
  graph : Graph
  input : Nat → F
  assignment : Nat → F
  interpreted : Interpreted crypto graph input assignment
  publicWires : Words 134
  statement : Public
  publicChecked : PublicChecked graph publicWires statement

def RecoveredSource.publicReadout {crypto : Primitives} (source : RecoveredSource crypto) : Public :=
  fun i => read source.assignment (source.publicWires i)

theorem recovered_source_public_all134 {crypto : Primitives} (source : RecoveredSource crypto) :
    source.publicReadout = source.statement := whole_public_readout source.interpreted source.publicChecked

end Hegemon.Transaction.QualifiedAssetSourceReadoutV1
