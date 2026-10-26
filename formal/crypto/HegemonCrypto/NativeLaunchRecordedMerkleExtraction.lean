import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleGeometry
import HegemonCrypto.NativeLaunchMerklePathBinding

/-!
Native finite-record extraction for arbitrary wrapped-root digests. This uses
only the GENERIC finite-record kernel, not its historical sourceNext grammar.
Exact current family framing and full root/node/leaf parsers are reused. A
selected index follows exactly 23 binary levels; missing or malformed records
remain explicit and canonical cells/masks default to zero. Defaults are NOT
asserted to rehash to the root. No full adversarial tree, polynomial origin,
accepted execution, chronology, QROM or multiquery bound is assumed/proved.
Outputs here are 64-byte functions. Transport to the native eight-word oracle,
including digest-encoding roundtrips, remains unproved. Invalid/wrong-context
records are filtered before selection and normally appear as missing; malformed
status describes generic trace completion, not a database diagnosis.
-/
set_option autoImplicit false
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchRecordedMerkleExtraction
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchMerklePathBinding (parseRoot parseNode saltBytes)
open NativeLaunchLeafReadback
open SmallWood.V8Smz9CoherentMerkleGeometry
  (Records ExtractionTrace selectedInput extract extractTargets targetDigests databaseChildren
   changed_extraction_implies_target_or_child changed_outputs_card_le
   uniformChangeProbability uniform_change_probability_le raw_digest_cardinality)

abbrev Output := Fin 64 → Byte
abbrev Database := Records RawInput Output
abbrev Position := Fin (2^23)
local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq
noncomputable section
open Classical

/-- Full digest bytes, without truncation or field reduction. Exact parsers
check the 64-byte extent before these projections are used. -/
def digest (bytes : RawInput) : Output := fun index => bytes.getD index.val 0

inductive Parsed where
  | wrapper (salt : RawInput) (root : Output) (statement : RawInput)
  | node (left right : Output)
  | leaf (fields : DecodedLeaf)

/-- Each reused parser checks family profile, literal role, zero counter,
complete payload width and final framing. Complete leaves range-check index
and all 140+5 field values and reject wrong counts/trailing bytes. -/
def parseInput (family : Family) (raw : RawInput) : Option Parsed :=
  match parseRoot family raw with
  | some (salt, root, statement) => some (.wrapper salt (digest root) statement)
  | none => match parseNode family raw with
    | some (left, right) => some (.node (digest left) (digest right))
    | none => (parseCompleteLeaf family raw).map Parsed.leaf

structure Context (family : Family) where
  salt : Fin 4 → Word
  statement : Statement family

inductive Stage (family : Family) where
  | wrapped (context : Context family) (index : Position)
  | tree (context : Context family) (depth : Nat) (index : Position)

/-- Context remains fixed along a selected original index's whole route. -/
def leafMatches {family : Family} (context : Context family) (index : Position) (leaf : DecodedLeaf) : Prop :=
  leaf.salt = saltBytes context.salt ∧ leaf.statement = statementBytes context.statement ∧ leaf.index = index

def parsedNext {family : Family} : Stage family → Parsed → Option (List (Stage family × Output))
  | .wrapped context index, .wrapper salt root statement =>
      if salt = saltBytes context.salt ∧ statement = statementBytes context.statement then
        some [(.tree context 23 index, root)] else none
  | .tree context (depth + 1) index, .node left right =>
      some [(.tree context depth index, if (index.val / 2^depth) % 2 = 0 then left else right)]
  | .tree context 0 index, .leaf fields => if leafMatches context index fields then some [] else none
  | _, _ => none

def next (family : Family) (stage : Stage family) (raw : RawInput) : Option (List (Stage family × Output)) :=
  (parseInput family raw).bind (parsedNext stage)

def parsedChildren : Parsed → Finset Output
  | .wrapper _ root _ => {root}
  | .node left right => {left, right}
  | .leaf _ => ∅

def children (family : Family) (raw : RawInput) : Finset Output :=
  match parseInput family raw with
  | none => ∅
  | some parsed => parsedChildren parsed

theorem parsed_children_arity (parsed : Parsed) : (parsedChildren parsed).card ≤ 2 := by
  cases parsed <;> simp [parsedChildren]
  exact Finset.card_le_two

theorem children_arity (family : Family) (raw : RawInput) : (children family raw).card ≤ 2 := by
  cases parsed : parseInput family raw with
  | none => simp [children, parsed]
  | some value => simpa only [children, parsed] using parsed_children_arity value

theorem parsed_next_child {family : Family} (stage : Stage family) (parsed : Parsed)
    (edges : List (Stage family × Output)) (success : parsedNext stage parsed = some edges)
    (edge : Stage family × Output) (member : edge ∈ edges) : edge.2 ∈ parsedChildren parsed := by
  cases stage with
  | wrapped context index =>
      cases parsed <;> simp only [parsedNext] at success
      · split at success
        · cases success
          simp only [List.mem_singleton] at member
          subst edge
          simp [parsedChildren]
        · contradiction
      all_goals contradiction
  | tree context depth index =>
      cases depth with
      | zero =>
          cases parsed <;> simp only [parsedNext] at success
          · contradiction
          · contradiction
          · split at success
            · cases success; simp at member
            · contradiction
      | succ depth =>
          cases parsed <;> simp only [parsedNext] at success
          · contradiction
          · cases success
            simp only [List.mem_singleton] at member
            subst edge
            dsimp only
            split <;> simp [parsedChildren]
          · contradiction

theorem next_child (family : Family) (stage : Stage family) (raw : RawInput)
    (edges : List (Stage family × Output)) (success : next family stage raw = some edges)
    (edge : Stage family × Output) (member : edge ∈ edges) : edge.2 ∈ children family raw := by
  cases parsed : parseInput family raw with
  | none => simp [next, parsed] at success
  | some value =>
      simp only [next, parsed, Option.bind_some] at success
      simpa only [children, parsed] using parsed_next_child stage value edges success edge member

/-- Exact depth/index transition; the original index is never replaced by a
caller-supplied path bit. At depth d+1 this selects its bit d. -/
theorem native_node_route {family : Family} (context : Context family) (depth : Nat)
    (index : Position) (left right : Output) :
    parsedNext (.tree context (depth+1) index) (.node left right) =
      some [(.tree context depth index, if (index.val / 2^depth) % 2 = 0 then left else right)] := rfl

inductive Status where
  | missing | budget | malformed | complete
  deriving DecidableEq

/-- Raw keys are retained even when a terminal record fails final context
checks. Missingness is never converted into an apparently present zero leaf. -/
structure Readback where
  keys : List RawInput
  status : Status
  leaf : Option DecodedLeaf

def finish {family : Family} (context : Context family) (index : Position) : ExtractionTrace RawInput → Readback
  | .missing => ⟨[], .missing, none⟩
  | .budget => ⟨[], .budget, none⟩
  | .record raw [] =>
      match parseInput family raw with
      | some (.leaf fields) =>
          if leafMatches context index fields then ⟨[raw], .complete, some fields⟩
          else ⟨[raw], .malformed, none⟩
      | _ => ⟨[raw], .malformed, none⟩
  | .record raw [child] =>
      let result := finish context index child
      ⟨raw :: result.keys, result.status, result.leaf⟩
  | .record raw (_ :: _ :: _) => ⟨[raw], .malformed, none⟩

/-- 1 wrapper + 23 internal nodes + 1 terminal leaf. Symbolic pointwise
extraction does not enumerate 2^23 positions or require a complete tree. -/
def readback {family : Family} (records : Database) (context : Context family)
    (root : Output) (index : Position) : Readback :=
  finish context index (extract (next family) records 25 (.wrapped context index) root)

def cells (result : Readback) (column : Fin 140) : FieldWord :=
  match result.leaf with | none => 0 | some fields => fields.committed.getD column.val 0

def masks (result : Readback) (row : Fin 5) : FieldWord :=
  match result.leaf with | none => 0 | some fields => fields.masks.getD row.val 0

def sourceCells {family : Family} (records : Database) (context : Context family)
    (root : Output) (index : Position) (column : Fin 140) : FieldWord :=
  cells (readback records context root index) column

def sourceMasks {family : Family} (records : Database) (context : Context family)
    (root : Output) (index : Position) (row : Fin 5) : FieldWord :=
  masks (readback records context root index) row

/-- A genuinely selected recorded complete leaf gives its decoded projections;
this is a terminal-stage calculation, not an accepted-root existence premise. -/
theorem selected_leaf_projection {family : Family} (records : Database)
    (context : Context family) (index : Position) (target : Output) (raw : RawInput) (fields : DecodedLeaf)
    (selected : selectedInput (next family) records (.tree context 0 index) target = some raw)
    (parsed : parseInput family raw = some (.leaf fields))
    (contextOk : leafMatches context index fields) (fuel : Nat) :
    finish context index (extract (next family) records (fuel+1) (.tree context 0 index) target) =
      ⟨[raw], .complete, some fields⟩ := by
  simp [extract, selected, next, parsed, parsedNext, contextOk, finish]

/-- Unrelated record insertions do not become a global failure flag. Actual
changes are confined to the selected targets or parsed existing child digests. -/
theorem changed_trace_target_or_child (family : Family) (records : Database) (input : RawInput)
    (output : Output) (fuel : Nat) (targets : List (Stage family × Output))
    (changed : extractTargets (next family) (insert (input, output) records) fuel targets ≠
      extractTargets (next family) records fuel targets) :
    output ∈ targetDigests targets ∪ databaseChildren (children family) records :=
  changed_extraction_implies_target_or_child (next family) (children family) (next_child family)
    records input output fuel targets changed

/-- The exceptional event is an actual change of completed extraction,
including its missingness metadata. It is not assumed impossible. -/
def SourceChanged {family : Family} (records : Database) (input : RawInput) (output : Output)
    (context : Context family) (root : Output) : Prop :=
  ∃ index, readback (insert (input, output) records) context root index ≠ readback records context root index

theorem source_changed_target_or_child {family : Family} (records : Database) (input : RawInput)
    (output : Output) (context : Context family) (root : Output)
    (changed : SourceChanged records input output context root) :
    output ∈ {root} ∪ databaseChildren (children family) records := by
  obtain ⟨index, changed⟩ := changed
  have traceChanged : extractTargets (next family) (insert (input, output) records) 25 [(.wrapped context index, root)] ≠
      extractTargets (next family) records 25 [(.wrapped context index, root)] := by
    intro same
    have traces := List.cons.inj same
    exact changed (congrArg (finish context index) traces.1)
  simpa [targetDigests] using changed_trace_target_or_child family records input output 25
    [(.wrapped context index, root)] traceChanged

/-- Actual changes of the completed total source, not an assumed bad flag. -/
def changedSourceOutputs {family : Family} (records : Database) (input : RawInput)
    (context : Context family) (root : Output) : Finset Output :=
  Finset.univ.filter fun output => SourceChanged records input output context root

theorem changed_source_outputs_card_le {family : Family} (records : Database) (input : RawInput)
    (context : Context family) (root : Output) :
    (changedSourceOutputs records input context root).card ≤ 1 + records.card * 2 := by
  have subset : changedSourceOutputs records input context root ⊆
      {root} ∪ databaseChildren (children family) records := by
    intro output member
    exact source_changed_target_or_child records input output context root (Finset.mem_filter.mp member).2
  calc
    _ ≤ ({root} ∪ databaseChildren (children family) records).card := Finset.card_le_card subset
    _ ≤ ({root} : Finset Output).card + (databaseChildren (children family) records).card := Finset.card_union_le _ _
    _ ≤ 1 + records.card * 2 := by
      simpa only [Finset.card_singleton] using Nat.add_le_add_left
        (SmallWood.V8Smz9CoherentMerkleGeometry.database_children_card_le
          (children family) records 2 (children_arity family)) 1

/-- One fresh uniform CLASSICAL output only: no QROM or multiquery theorem. -/
theorem classical_uniform_trace_change_le (family : Family) (records : Database) (input : RawInput)
    (fuel : Nat) (targets : List (Stage family × Output)) :
    uniformChangeProbability (next family) records input fuel targets ≤
      ((targets.length + records.card * 2 : Nat) : ℚ) / (2^512 : ℚ) := by
  have bound := uniform_change_probability_le (next family) (children family) (next_child family)
    2 (children_arity family) records input fuel targets
  simpa only [raw_digest_cardinality, Nat.cast_pow, Nat.cast_ofNat] using bound

end
end HegemonCrypto.NativeLaunchRecordedMerkleExtraction
