import HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics
import HegemonCrypto.NativePrivateSpendCurrentRoleGames

/-! Total, source-addressed zero-value Approval reconstruction. Records are
DATA: no successful history, authorized bitmap, extracted assignment validity
or collision-free output is a record field. The replay either constructs a
input-order lineage or returns the first concrete unavailable/mismatched
record. Its input still needs the G3 same-execution/native-history projection;
this module deliberately makes no verifier-acceptance assertion. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentAcceptedHistory
open NativePrivateSpendCurrentSixCaseSemantics
open NativePrivateSpendCurrentRoleGames
open NativePrivateSpendRoleBridge NativePrivateSpendCurrentSourceCallContract
open NativePrivateSpendSelectedNullifier NativePrivateSpendG1SourceComposition
open NativePrivateSpendSpongeBridge NativePrivateSpendSymbolicBridge
open NativePrivateSpendArithmeticTopology NativePrivateSpendLocalSemantics
open NativeLaunchConstraintAdapterBridge
open NativePrivateSpendPackedLowering NativePrivateSpendCsrCertificate
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.NativePrivateSpendCompffPrimitiveGames
noncomputable section

abbrev Slot := Fin 3
structure Context where
  key : Key
  tags : Tags
  intent : Intent

def bitmapBits (bitmap : Finset Slot) : ApprovalBits := fun i =>
  if i ∈ bitmap then 1 else 0

def encodedAccumulator (context : Context) (bitmap : Finset Slot) : Digest :=
  accumulatorOwner ⟨context.key, context.tags, context.intent, bitmapBits bitmap⟩

/-- Actual values, output location and predecessor location are data carried
from the original history. Source-address interpretation must be authenticated
separately; a transaction index alone does not authenticate an occupied note. -/
structure Record where
  stage : Nat
  outputPosition : Nat
  packed : Current.Values
  public77 : Fin 77 → K
  context : Context
  approvalSelected : Bool
  occupied : Bool
  predecessor : Option Nat
  before : Finset Slot
  after : Finset Slot
  signer : Slot
  signerKey : Key
  signerAuthority : Digest
  beforeValue : Nat
  afterValue : Nat
  beforeOwner : Digest
  afterOwner : Digest

/-- Canonical limbs are read directly from the same Goldilocks assignment. -/
def canonicalWord (z : Nat → K) (word : Word K) : Fin fieldModulus :=
  ⟨natural z word, ZMod.val_lt _⟩

def sourceBitmap (z : Nat → K) (bits : Bits3) : Finset Slot :=
  Finset.univ.filter fun i => read z (bits i) = 1

def sourceSigner (z : Nat → K) (bits : Bits3) : Slot :=
  if read z (bits 0) = 1 then 0 else if read z (bits 1) = 1 then 1 else 2

section ApprovalProjection
variable [Fact (Nat.Prime modulus)]

theorem sourceSigner_unique (z : Nat → K) (r : Roles)
    (inputValue outputValue : Word K)
    (sem : ApprovalConsequences z r inputValue outputValue) (i : Slot) :
    read z (r.signer i) = 1 ↔ i = sourceSigner z r.signer := by
  have oneVal : ZMod.val (1 : K) = 1 := by
    exact (ZMod.val_one_eq_one_mod modulus).trans (Nat.mod_eq_of_lt (by decide))
  have twoVal : ZMod.val (2 : K) = 2 := by
    exact ZMod.val_ofNat_of_lt (by decide : 2 < modulus)
  have threeVal : ZMod.val (3 : K) = 3 := by
    exact ZMod.val_ofNat_of_lt (by decide : 3 < modulus)
  have sum := congrArg ZMod.val sem.oneSigner
  rcases sem.signerBits 0 with h0 | h0
  <;> rcases sem.signerBits 1 with h1 | h1
  <;> rcases sem.signerBits 2 with h2 | h2
  <;> norm_num [h0, h1, h2, modulus] at sum
  <;> fin_cases i
  <;> simp_all (config := { instances := true }) [sourceSigner]

/-- The freshness and exact insertion checked by advance are consequences of
the actual Approval graph equations, not validity fields of the record. -/
theorem sourceApproval_bitmap_step (z : Nat → K) (r : Roles)
    (inputValue outputValue : Word K)
    (sem : ApprovalConsequences z r inputValue outputValue) :
    sourceSigner z r.signer ∉ sourceBitmap z r.approved ∧
    sourceBitmap z r.next = insert (sourceSigner z r.signer) (sourceBitmap z r.approved) := by
  classical
  let slot := sourceSigner z r.signer
  have signerOne : read z (r.signer slot) = 1 :=
    (sourceSigner_unique z r inputValue outputValue sem slot).mpr rfl
  have beforeZero := sem.disjoint slot
  rw [signerOne, mul_one] at beforeZero
  refine ⟨?_, ?_⟩
  · change slot ∉ sourceBitmap z r.approved
    simp only [sourceBitmap, Finset.mem_filter, Finset.mem_univ, true_and]
    change read z (r.approved slot) ≠ (1 : K)
    intro one
    exact zero_ne_one (beforeZero.symm.trans one)
  · apply Finset.ext
    intro i
    simp only [sourceBitmap, Finset.mem_filter, Finset.mem_univ, true_and,
      Finset.mem_insert]
    change read z (r.next i) = (1 : K) ↔
      i = slot ∨ read z (r.approved i) = (1 : K)
    by_cases same : i = slot
    · subst i
      have nextOne := sem.next slot
      rw [beforeZero, signerOne, zero_add] at nextOne
      exact ⟨fun _ => Or.inl rfl, fun _ => nextOne⟩
    · have signerZero : read z (r.signer i) = 0 := by
        rcases sem.signerBits i with zero | one
        · exact zero
        · exact False.elim (same ((sourceSigner_unique z r inputValue outputValue sem i).mp one))
      have nextEq := sem.next i
      rw [signerZero, add_zero] at nextEq
      constructor
      · intro one
        exact Or.inr (nextEq.symm.trans one)
      · intro member
        rcases member with equal | one
        · exact False.elim (same equal)
        · exact nextEq.trans one
end ApprovalProjection

/-- This constructor supplies values, not correctness. Its role/Word locators
must be those authenticated in SourceBinding/RecipientChecked/OutputNoteCall.
The native history supplies the actual append position; input predecessor is
always the actual circuit position, including an occupied value-zero note. -/
def recordFromSource (stage outputPosition : Nat) (packed : Current.Values)
    (r : Roles) (v : RouteRoles) (w : Nat → Word K)
    (signerAuthority : DigestWords) (output : Fin 18 → Word K) : Record := by
  classical
  letI : Fact (Nat.Prime modulus) := ⟨by exact HegemonCrypto.SmallWood.goldilocks_prime⟩
  let z := sourceAssignment packed
  let active := decide (read z (occupied w (0 : Fin 2)) = 1)
  exact {
    stage := stage
    outputPosition := outputPosition
    packed := packed
    public77 := fun i => z i.val
    context := {
      key := fun i => canonicalWord z (r.treasuryKey i)
      tags := fun i lane => canonicalWord z (r.tags ⟨7*i.val+lane.val, by omega⟩)
      intent := fun i => canonicalWord z (r.intent i) }
    approvalSelected := decide (read z (v.modes 1) = 1)
    occupied := active
    predecessor := if active then some (natural z (position w (0 : Fin 2))) else none
    before := sourceBitmap z r.approved
    after := sourceBitmap z r.next
    signer := sourceSigner z r.signer
    signerKey := fun i => canonicalWord z (key w (1 : Fin 2) i)
    signerAuthority := List.ofFn fun i => natural z (signerAuthority i)
    beforeValue := natural z (NativePrivateSpendMerkleContinuation.noteWords w (0 : Fin 2) 0)
    afterValue := natural z (output 0)
    beforeOwner := List.ofFn fun i => natural z (owner w (0 : Fin 2) i)
    afterOwner := List.ofFn fun i : Fin 7 =>
      natural z (output ⟨if i.val < 4 then 14+i.val else 6+i.val, by split <;> omega⟩) }

section RecordProjection
variable [Fact (Nat.Prime modulus)]

/-- Four concrete advance checks on the actual projected record are derived
from relation satisfaction and graph operation data. Credential/owner and
native predecessor/order joins remain separate obligations. -/
theorem relation_record_approval_checks (relation : Current.Relation)
    (packed : Current.Values) (valid : Current.Satisfies relation packed)
    (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (certificate : RelationCertificate relation g layout csr)
    (stage outputPosition : Nat) (r : Roles) (v : RouteRoles) (w : Nat → Word K)
    (signerAuthority : DigestWords) (output : Fin 18 → Word K)
    (checked : ApprovalChecked g r v
      (NativePrivateSpendMerkleContinuation.noteWords w (0 : Fin 2) 0) (output 0))
    (selected : natural (sourceAssignment packed) (v.modes 1) = 1) :
    let record := recordFromSource stage outputPosition packed r v w signerAuthority output
    record.signer ∉ record.before ∧ record.after = insert record.signer record.before ∧
      record.beforeValue = 0 ∧ record.afterValue = 0 := by
  have structural := relation_derives_structural_semantics relation packed valid g layout csr certificate
  have arithmetic := approval_consequences g layout (sourceAssignment packed) structural
    r v _ _ checked selected
  have bitmap := sourceApproval_bitmap_step (sourceAssignment packed) r _ _ arithmetic
  exact ⟨bitmap.1, bitmap.2, arithmetic.inputZero, arithmetic.outputZero⟩
end RecordProjection

/-- A derived edge retains the original record, including its packed witness.
The proofs are created only by concrete checks in advance below. -/
structure Edge (context : Context) (before after : Finset Slot) where
  record : Record
  sameContext : record.context = context
  beforeEq : record.before = before
  afterEq : record.after = after
  fresh : record.signer ∉ before
  insertEq : after = insert record.signer before
  inputZero : record.beforeValue = 0
  outputZero : record.afterValue = 0
  authorityEq : singleKeyEvaluator record.signerKey = record.signerAuthority
  policySlot : record.signerAuthority = canonicalDigestWords (context.tags record.signer)
  outputOwner : record.afterOwner = encodedAccumulator context after

inductive Lineage (context : Context) : Finset Slot → List Slot → Prop where
  | empty : Lineage context ∅ []
  | snoc {before after : Finset Slot} {slots : List Slot}
      (prior : Lineage context before slots) (edge : Edge context before after) :
      Lineage context after (slots.concat edge.record.signer)

theorem lineage_bitmap {context : Context} {bitmap : Finset Slot}
    {slots : List Slot} (history : Lineage context bitmap slots) :
    bitmap = slots.toFinset := by
  induction history with
  | empty => simp
  | snoc prior edge ih =>
      exact edge.insertEq.trans
        ((congrArg (fun bitmap : Finset Slot => insert edge.record.signer bitmap) ih).trans
          (by simp))

theorem lineage_distinct {context : Context} {bitmap : Finset Slot}
    {slots : List Slot} (history : Lineage context bitmap slots) : slots.Nodup := by
  induction history with
  | empty => simp
  | snoc prior edge ih =>
      rw [List.nodup_concat]
      refine ⟨?_, ih⟩
      intro member
      apply edge.fresh
      exact (congrArg (fun bitmap : Finset Slot => edge.record.signer ∈ bitmap)
        (lineage_bitmap prior)).mpr (List.mem_toFinset.mpr member)

theorem lineage_count {context : Context} {bitmap : Finset Slot}
    {slots : List Slot} (history : Lineage context bitmap slots) :
    bitmap.card = slots.length := by
  rw [lineage_bitmap history]
  exact List.toFinset_card_of_nodup (lineage_distinct history)

structure CertifiedAccumulator where
  position : Nat
  context : Context
  bitmap : Finset Slot
  slots : List Slot
  history : Lineage context bitmap slots
  records : List Record
  recordSlots : records.map Record.signer = slots

inductive Failure where
  | occupiedPredecessorMissing (stage : Nat) (position : Option Nat)
  | unexpectedPredecessor (stage : Nat)
  | contextMismatch (stage position : Nat)
  | sourceFieldMismatch (stage : Nat)
  | duplicateOutputPosition (stage position : Nat)

/-- One actual record check. No semantic result is supplied by a callback.
The fresh signer proof derives global distinctness through Lineage.snoc. -/
def advance (record : Record) (prior : CertifiedAccumulator)
    (same : prior.context = record.context) : Except Failure CertifiedAccumulator := by
  classical
  let context := record.context
  let before := prior.bitmap
  if checks : record.before = before ∧
      record.after = insert record.signer before ∧
      record.signer ∉ before ∧ record.beforeValue = 0 ∧ record.afterValue = 0 ∧
      singleKeyEvaluator record.signerKey = record.signerAuthority ∧
      record.signerAuthority = canonicalDigestWords (context.tags record.signer) ∧
      record.afterOwner = encodedAccumulator context record.after then
    let edge : Edge context before record.after :=
      ⟨record, rfl, checks.1, rfl, checks.2.2.1, checks.2.1,
        checks.2.2.2.1, checks.2.2.2.2.1, checks.2.2.2.2.2.1,
        checks.2.2.2.2.2.2.1, checks.2.2.2.2.2.2.2⟩
    have history : Lineage context before prior.slots := by
      simpa only [same] using prior.history
    exact .ok ⟨record.outputPosition, context, record.after,
      prior.slots.concat record.signer, .snoc history edge,
      prior.records.concat record, by simp [prior.recordSlots]⟩
  else exact .error (.sourceFieldMismatch record.stage)

def firstAccumulator (record : Record) : Except Failure CertifiedAccumulator :=
  advance record ⟨0, record.context, ∅, [], .empty, [], rfl⟩ rfl

theorem advance_records (record : Record) (prior next : CertifiedAccumulator)
    (same : prior.context = record.context)
    (success : advance record prior same = .ok next) :
    next.records = prior.records.concat record := by
  classical
  dsimp only [advance] at success
  split at success
  · cases success
    rfl
  · cases success

theorem firstAccumulator_records (record : Record) (next : CertifiedAccumulator)
    (success : firstAccumulator record = .ok next) : next.records = [record] := by
  exact advance_records record _ next rfl success

/-- Lookup checks the actual occupied zero-value predecessor, including its
entire contextual encoding. Zero monetary value never skips this lookup. -/
def reconstructRecord (registry : List CertifiedAccumulator) (record : Record) :
    Except Failure CertifiedAccumulator := by
  classical
  if record.occupied then
    match record.predecessor with
    | none => exact .error (.occupiedPredecessorMissing record.stage none)
    | some position =>
      match registry.find? (fun prior => prior.position == position) with
      | none => exact .error (.occupiedPredecessorMissing record.stage (some position))
      | some prior =>
        if same : prior.context = record.context then
          if record.beforeOwner = encodedAccumulator prior.context prior.bitmap then
            exact advance record prior same
          else exact .error (.sourceFieldMismatch record.stage)
        else exact .error (.contextMismatch record.stage position)
  else
    match record.predecessor with
    | some _ => exact .error (.unexpectedPredecessor record.stage)
    | none => exact firstAccumulator record

/-- Input-order processing exposes a concrete first failure. Registry entries
are added only by checks; no initially authorized accumulator exists. Native
stage order and global append-position uniqueness need the G3 history join. -/
def replayFrom (registry : List CertifiedAccumulator) :
    List Record → Except Failure (List CertifiedAccumulator)
  | [] => .ok registry
  | record :: rest => by
    classical
    if record.approvalSelected = false then
      exact replayFrom registry rest
    else if ∃ prior ∈ registry, prior.position = record.outputPosition then
      exact .error (.duplicateOutputPosition record.stage record.outputPosition)
    else
      match reconstructRecord registry record with
      | .error failure => exact .error failure
      | .ok next => exact replayFrom (next :: registry) rest

def replay (records : List Record) : Except Failure (List CertifiedAccumulator) :=
  replayFrom [] records

/-- A provenance property of original records, independent of their validity. -/
def Origin (allowed : List Record) (registry : List CertifiedAccumulator) : Prop :=
  ∀ accumulator ∈ registry, ∀ record ∈ accumulator.records, record ∈ allowed

theorem reconstructRecord_origin (registry : List CertifiedAccumulator)
    (record : Record) (next : CertifiedAccumulator) (allowed : List Record)
    (origin : Origin allowed registry)
    (success : reconstructRecord registry record = .ok next) :
    ∀ item ∈ next.records, item ∈ record :: allowed := by
  classical
  unfold reconstructRecord at success
  split at success
  · split at success
    · cases success
    · rename_i position
      split at success
      · cases success
      · rename_i prior found
        split at success
        · rename_i same
          split at success
          · rw [advance_records record prior next same success]
            intro item member
            have member' : item ∈ prior.records ∨ item = record := by simpa using member
            rcases member' with member | equal
            · exact List.mem_cons_of_mem _ (origin prior (List.mem_of_find?_eq_some found) item member)
            · exact List.mem_cons.mpr (Or.inl equal)
          · cases success
        · cases success
  · split at success
    · cases success
    · rw [firstAccumulator_records record next success]
      intro item member
      exact List.mem_cons.mpr (Or.inl (List.mem_singleton.mp member))

theorem replayFrom_origin (records : List Record) (registry : List CertifiedAccumulator)
    (allowed : List Record) (origin : Origin allowed registry) :
    match replayFrom registry records with
    | .error _ => True
    | .ok result => Origin (records ++ allowed) result := by
  classical
  induction records generalizing registry allowed with
  | nil => exact origin
  | cons record rest ih =>
      by_cases selected : record.approvalSelected = false
      · have head : replayFrom registry (record :: rest) = replayFrom registry rest := by
          simp only [replayFrom, dif_pos selected]
        rw [head]
        have result := ih registry allowed origin
        cases outcome : replayFrom registry rest with
        | error failure => trivial
        | ok resultRegistry =>
            rw [outcome] at result
            intro acc mem item inAcc
            exact List.mem_append.mpr (by
              rcases List.mem_append.mp (result acc mem item inAcc) with inRest | inAllowed
              · exact Or.inl (List.mem_cons_of_mem _ inRest)
              · exact Or.inr inAllowed)
      · by_cases duplicate : ∃ prior ∈ registry, prior.position = record.outputPosition
        · simp only [replayFrom, dif_neg selected, dif_pos duplicate]
        · cases reconstructed : reconstructRecord registry record with
          | error failure =>
              simp only [replayFrom, dif_neg selected, dif_neg duplicate, reconstructed]
          | ok next =>
              have head : replayFrom registry (record :: rest) =
                  replayFrom (next :: registry) rest := by
                simp only [replayFrom, dif_neg selected, dif_neg duplicate, reconstructed]
              rw [head]
              have nextOrigin := reconstructRecord_origin registry record next allowed origin reconstructed
              have extended : Origin (record :: allowed) (next :: registry) := by
                intro acc mem item inAcc
                rcases List.mem_cons.mp mem with equal | prior
                · subst acc
                  exact nextOrigin item inAcc
                · exact List.mem_cons_of_mem _ (origin acc prior item inAcc)
              have result := ih (next :: registry) (record :: allowed) extended
              cases outcome : replayFrom (next :: registry) rest with
              | error failure => trivial
              | ok resultRegistry =>
                  rw [outcome] at result
                  intro acc mem item inAcc
                  rcases List.mem_append.mp (result acc mem item inAcc) with inRest | inAllowed
                  · exact List.mem_append.mpr (Or.inl (List.mem_cons_of_mem _ inRest))
                  · rcases List.mem_cons.mp inAllowed with equal | prior
                    · exact List.mem_append.mpr (Or.inl (List.mem_cons.mpr (Or.inl equal)))
                    · exact List.mem_append.mpr (Or.inr prior)

theorem replay_original_records (records : List Record) :
    match replay records with
    | .error _ => True
    | .ok registry => Origin records registry := by
  have result := replayFrom_origin records [] [] (by
    intro acc member
    cases member)
  simpa only [replay, List.append_nil] using result

theorem certified_record_slots (accumulator : CertifiedAccumulator) :
    (accumulator.records.map Record.signer).Nodup ∧
      accumulator.bitmap.card = accumulator.records.length := by
  rw [accumulator.recordSlots]
  refine ⟨lineage_distinct accumulator.history, ?_⟩
  rw [lineage_count accumulator.history, ← accumulator.recordSlots, List.length_map]

/-- Every returned accumulator certifies distinct source-record signer slots,
zero-valued transitions and exact bitmap weight. This theorem imposes no
successful replay premise: each accumulator is produced by the total reducer. -/
theorem certified_distinct_and_count (accumulator : CertifiedAccumulator) :
    accumulator.slots.Nodup ∧ accumulator.bitmap.card = accumulator.slots.length :=
  ⟨lineage_distinct accumulator.history, lineage_count accumulator.history⟩

/-- Total endpoint: the caller supplies only the original data records. There
is no successful replay/lineage premise. The failure arm is preserved, and any
returned registry has derived distinctness/count. Original-record membership
is the separate replay_original_records theorem above. -/
theorem replay_lineages (records : List Record) :
    match replay records with
    | .error _ => True
    | .ok registry => ∀ accumulator ∈ registry,
        (accumulator.records.map Record.signer).Nodup ∧
          accumulator.bitmap.card = accumulator.records.length := by
  cases result : replay records with
  | error failure => trivial
  | ok registry =>
      intro accumulator _
      exact certified_record_slots accumulator

theorem threshold_requires_two_records (accumulator : CertifiedAccumulator)
    (threshold : 2 ≤ accumulator.bitmap.card) : 2 ≤ accumulator.slots.length := by
  rw [← lineage_count accumulator.history]
  exact threshold
end
end HegemonCrypto.NativePrivateSpendCurrentAcceptedHistory
