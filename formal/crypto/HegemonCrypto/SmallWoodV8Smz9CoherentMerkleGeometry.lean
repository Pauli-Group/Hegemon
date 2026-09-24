import HegemonCrypto.SmallWoodV8Smz9HiddenLeafQrom
import HegemonCrypto.SmallWoodV8Smz9WholeViewObservation
import Mathlib.Data.List.Lex
import Mathlib.Data.Finset.Max

/-!
# Classical instability geometry for coherent SMZ9 Merkle extraction

The algorithm scans a finite recorded relation in lexicographic input order.
It never rejects an entire database because of an unrelated collision. The
classical insertion bound is proved from the parser's outgoing edges, not
assumed as an extraction-success or quantum-distance premise.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CoherentMerkleGeometry

open scoped BigOperators Classical

set_option maxRecDepth 5000
set_option maxHeartbeats 1000000

section FiniteExtractor

variable {Input Output Stage : Type*} [LinearOrder Input] [DecidableEq Output]

abbrev Records (Input Output : Type*) := Finset (Input × Output)

/-- Finite queried-map validity. The stronger relation theorem below does not
need this property, so it applies in particular to every valid queried map. -/
def Functional (records : Records Input Output) : Prop :=
  ∀ left ∈ records, ∀ right ∈ records, left.1 = right.1 → left.2 = right.2

def Fresh (records : Records Input Output) (input : Input) : Prop :=
  ∀ record ∈ records, record.1 ≠ input

theorem insert_functional (records : Records Input Output) (valid : Functional records)
    (input : Input) (output : Output) (fresh : Fresh records input) :
    Functional (insert (input, output) records) := by
  intro left leftMem right rightMem same
  simp only [Finset.mem_insert] at leftMem rightMem
  rcases leftMem with rfl | leftMem <;> rcases rightMem with rfl | rightMem
  · rfl
  · exact False.elim (fresh right rightMem same.symm)
  · exact False.elim (fresh left leftMem same)
  · exact valid left leftMem right rightMem same

/-- Retains the complete selected raw preimage, including wrapper context and
response payloads. Missingness and the finite recursion budget are explicit. -/
inductive ExtractionTrace (Input : Type*) where
  | missing
  | budget
  | record (input : Input) (children : List (ExtractionTrace Input))

noncomputable instance : DecidableEq (ExtractionTrace Input) := Classical.decEq _

variable (next : Stage → Input → Option (List (Stage × Output)))

def candidateInputs (records : Records Input Output) (stage : Stage) (target : Output) : Finset Input :=
  (records.filter fun record => record.2 = target ∧ (next stage record.1).isSome).image Prod.fst

/-- Deterministic least valid preimage; unrelated records and collisions are ignored. -/
def selectedInput (records : Records Input Output) (stage : Stage) (target : Output) : Option Input :=
  let candidates := candidateInputs next records stage target
  if present : candidates.Nonempty then some (candidates.min' present) else none

theorem selected_input_recorded (records : Records Input Output) (stage : Stage) (target : Output)
    (input : Input) (selected : selectedInput next records stage target = some input) :
    (input, target) ∈ records := by
  unfold selectedInput at selected
  dsimp only at selected
  split at selected
  · next present =>
    have equality := Option.some.inj selected
    have member := Finset.min'_mem (candidateInputs next records stage target) present
    rw [equality] at member
    obtain ⟨record, membership, sameInput⟩ := Finset.mem_image.mp member
    obtain ⟨recorded, sameOutput, _⟩ := Finset.mem_filter.mp membership
    rcases record with ⟨key, value⟩
    dsimp only at sameInput sameOutput
    subst key
    subst value
    exact recorded
  · contradiction

theorem candidate_inputs_insert_other (records : Records Input Output) (stage : Stage)
    (target output : Output) (input : Input) (different : output ≠ target) :
    candidateInputs next (insert (input, output) records) stage target =
      candidateInputs next records stage target := by
  simp [candidateInputs, Finset.filter_insert, different]

theorem selected_input_insert_other (records : Records Input Output) (stage : Stage)
    (target output : Output) (input : Input) (different : output ≠ target) :
    selectedInput next (insert (input, output) records) stage target =
      selectedInput next records stage target := by
  simp only [selectedInput, candidate_inputs_insert_other next records stage target output input different]

def extract (records : Records Input Output) : ℕ → Stage → Output → ExtractionTrace Input
  | 0, _, _ => .budget
  | fuel + 1, stage, target =>
      match selectedInput next records stage target with
      | none => .missing
      | some input => match next stage input with
        | none => .missing
        | some edges => .record input (edges.map fun edge => extract records fuel edge.1 edge.2)

variable (children : Input → Finset Output)

def databaseChildren (records : Records Input Output) : Finset Output :=
  records.biUnion fun record => children record.1

theorem extraction_stable_of_output_avoids
    (edgeSound : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ children input)
    (records : Records Input Output) (input : Input) (output : Output)
    (avoidsChildren : output ∉ databaseChildren children records)
    (fuel : ℕ) (stage : Stage) (target : Output) (avoidsTarget : output ≠ target) :
    extract next (insert (input, output) records) fuel stage target =
      extract next records fuel stage target := by
  induction fuel generalizing stage target with
  | zero => rfl
  | succ fuel induction =>
    simp only [extract, selected_input_insert_other next records stage target output input avoidsTarget]
    cases selected : selectedInput next records stage target with
    | none => rfl
    | some key =>
      dsimp only
      cases parsed : next stage key with
      | none => rfl
      | some edges =>
        apply congrArg (ExtractionTrace.record key)
        apply List.map_congr_left
        intro edge member
        apply induction edge.1 edge.2
        intro sameOutput
        apply avoidsChildren
        apply Finset.mem_biUnion.mpr
        refine ⟨(key, target), selected_input_recorded next records stage target key selected, ?_⟩
        rw [sameOutput]
        exact edgeSound stage key edges parsed edge member

omit [LinearOrder Input] in
theorem database_children_card_le (records : Records Input Output) (arity : ℕ)
    (bounded : ∀ input, (children input).card ≤ arity) :
    (databaseChildren children records).card ≤ records.card * arity := by
  calc
    _ ≤ ∑ record ∈ records, (children record.1).card := Finset.card_biUnion_le
    _ ≤ ∑ _record ∈ records, arity := Finset.sum_le_sum fun record _ => bounded record.1
    _ = _ := by simp [Nat.mul_comm]

def extractTargets (records : Records Input Output) (fuel : ℕ) (targets : List (Stage × Output)) :
    List (ExtractionTrace Input) := targets.map fun target => extract next records fuel target.1 target.2

def targetDigests (targets : List (Stage × Output)) : Finset Output := (targets.map Prod.snd).toFinset

theorem changed_extraction_implies_target_or_child
    (edgeSound : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ children input)
    (records : Records Input Output) (input : Input) (output : Output)
    (fuel : ℕ) (targets : List (Stage × Output))
    (changed : extractTargets next (insert (input, output) records) fuel targets ≠
      extractTargets next records fuel targets) :
    output ∈ targetDigests targets ∪ databaseChildren children records := by
  by_contra outside
  have notTarget : output ∉ targetDigests targets := fun member => outside (Finset.mem_union_left _ member)
  have notChild : output ∉ databaseChildren children records := fun member => outside (Finset.mem_union_right _ member)
  apply changed
  apply List.map_congr_left
  intro target member
  apply extraction_stable_of_output_avoids next children edgeSound records input output notChild fuel target.1 target.2
  intro same
  apply notTarget
  simp only [targetDigests, List.mem_toFinset, List.mem_map]
  exact ⟨target, member, same.symm⟩

variable [Fintype Output]

noncomputable def changedOutputs (records : Records Input Output) (input : Input)
    (fuel : ℕ) (targets : List (Stage × Output)) : Finset Output :=
  Finset.univ.filter fun output =>
    extractTargets next (insert (input, output) records) fuel targets ≠
      extractTargets next records fuel targets

theorem changed_outputs_subset
    (edgeSound : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ children input)
    (records : Records Input Output) (input : Input) (fuel : ℕ) (targets : List (Stage × Output)) :
    changedOutputs next records input fuel targets ⊆
      targetDigests targets ∪ databaseChildren children records := by
  intro output member
  exact changed_extraction_implies_target_or_child next children edgeSound records input output
    fuel targets (Finset.mem_filter.mp member).2

theorem changed_outputs_card_le
    (edgeSound : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ children input)
    (arity : ℕ) (arityBound : ∀ input, (children input).card ≤ arity)
    (records : Records Input Output) (input : Input) (fuel : ℕ) (targets : List (Stage × Output)) :
    (changedOutputs next records input fuel targets).card ≤ targets.length + records.card * arity := by
  have targetBound : (targetDigests targets).card ≤ targets.length := by
    simpa only [targetDigests, List.length_map] using List.toFinset_card_le (targets.map Prod.snd)
  calc
    _ ≤ (targetDigests targets ∪ databaseChildren children records).card :=
      Finset.card_le_card (changed_outputs_subset next children edgeSound records input fuel targets)
    _ ≤ (targetDigests targets).card + (databaseChildren children records).card := Finset.card_union_le _ _
    _ ≤ targets.length + records.card * arity :=
      Nat.add_le_add targetBound (database_children_card_le children records arity arityBound)

/-- Exact counting probability under one fresh uniform output. No independent
event-probability assumption is supplied. -/
noncomputable def uniformChangeProbability (records : Records Input Output) (input : Input)
    (fuel : ℕ) (targets : List (Stage × Output)) : ℚ :=
  (changedOutputs next records input fuel targets).card / (Fintype.card Output : ℚ)

theorem uniform_change_probability_le
    (edgeSound : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ children input)
    (arity : ℕ) (arityBound : ∀ input, (children input).card ≤ arity)
    (records : Records Input Output) (input : Input) (fuel : ℕ) (targets : List (Stage × Output)) :
    uniformChangeProbability next records input fuel targets ≤
      ((targets.length + records.card * arity : ℕ) : ℚ) / (Fintype.card Output : ℚ) := by
  apply div_le_div_of_nonneg_right
  · exact_mod_cast changed_outputs_card_le next children edgeSound arity arityBound records input fuel targets
  · exact Nat.cast_nonneg _

noncomputable def observedChangeProbability {View : Type*}
    (observe : List (ExtractionTrace Input) → View)
    (records : Records Input Output) (input : Input) (fuel : ℕ) (targets : List (Stage × Output)) : ℚ :=
  ((Finset.univ.filter fun output =>
    observe (extractTargets next (insert (input, output) records) fuel targets) ≠
      observe (extractTargets next records fuel targets)).card : ℚ) / (Fintype.card Output : ℚ)

/-- Deterministic source completion, wrapper-payload projection and missingness
flags cannot increase the insertion instability of the complete extraction trace. -/
theorem observed_change_probability_le {View : Type*}
    (observe : List (ExtractionTrace Input) → View)
    (records : Records Input Output) (input : Input) (fuel : ℕ) (targets : List (Stage × Output)) :
    observedChangeProbability next observe records input fuel targets ≤
      uniformChangeProbability next records input fuel targets := by
  apply div_le_div_of_nonneg_right
  · apply Nat.cast_le.mpr
    apply Finset.card_le_card
    intro output member
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ _, ?_⟩
    intro same
    exact (Finset.mem_filter.mp member).2 (congrArg observe same)
  · exact Nat.cast_nonneg _

end FiniteExtractor

section RawSourceGrammar

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

abbrev RawInput := List Byte
abbrev RawDigest := Fin 64 → Byte

local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq

/-- The complete 64-byte raw output, with no field reduction or truncation. -/
theorem raw_digest_cardinality : Fintype.card RawDigest = 2 ^ 512 :=
  V8Smz9HiddenLeafQrom.leaf_tape_cardinality

/-- Parse the exact common raw SHA-512 framing. Length words are read before
allocation, and readFixed fails when a claimed length exceeds the actual input. -/
def parseFramed (input : RawInput) : Option (List Byte × List Byte) := do
  let (profileLength, afterProfileLength) ← readFixed 8 input
  let (profile, afterProfile) ← readFixed (decodeLE profileLength) afterProfileLength
  let (roleLength, afterRoleLength) ← readFixed 8 afterProfile
  let (role, afterRole) ← readFixed (decodeLE roleLength) afterRoleLength
  let (wordCount, afterWordCount) ← readFixed 8 afterRole
  let (payload, afterPayload) ← readFixed (8 * decodeLE wordCount) afterWordCount
  let (counter, suffix) ← readFixed 8 afterPayload
  if profile = V8Smz9WholeViewObservation.smz9ProfileDomain ∧
      decodeLE counter = 0 ∧ suffix = [] then some (role, payload) else none

def framedInput (role : List Byte) (wordCount : ℕ) (payload : List Byte) : RawInput :=
  encodeLE 8 53 ++ V8Smz9WholeViewObservation.smz9ProfileDomain ++
    encodeLE 8 role.length ++ role ++ encodeLE 8 wordCount ++ payload ++ encodeLE 8 0

theorem parse_framed_roundtrip (role payload : List Byte) (wordCount : ℕ)
    (roleBound : role.length < 256 ^ 8) (countBound : wordCount < 256 ^ 8)
    (payloadLength : payload.length = 8 * wordCount) :
    parseFramed (framedInput role wordCount payload) = some (role, payload) := by
  have profileLength : V8Smz9WholeViewObservation.smz9ProfileDomain.length = 53 := by decide
  have roleMod : role.length % 18446744073709551616 = role.length := Nat.mod_eq_of_lt roleBound
  have countMod : wordCount % 18446744073709551616 = wordCount := Nat.mod_eq_of_lt countBound
  simp [parseFramed, framedInput, List.append_assoc, readFixed, encodeLE_length,
    decodeLE_encodeLE, roleMod, countMod, profileLength, payloadLength]
  decide

theorem framed_input_is_source_key (role : List Byte) (words : List ℕ) :
    framedInput role words.length ((words.map (encodeLE 8)).flatten) =
      (V8Smz9WholeViewObservation.RawSha512OracleKey.mk
        (some V8Smz9WholeViewObservation.smz9ProfileDomain) role words 0).preimage := by
  simp only [framedInput, V8Smz9WholeViewObservation.RawSha512OracleKey.preimage, List.append_assoc]
  rfl

theorem source_key_framing_roundtrip (role : List Byte) (words : List ℕ)
    (roleBound : role.length < 256 ^ 8) (countBound : words.length < 256 ^ 8) :
    parseFramed
      (V8Smz9WholeViewObservation.RawSha512OracleKey.mk
        (some V8Smz9WholeViewObservation.smz9ProfileDomain) role words 0).preimage =
      some (role, (words.map (encodeLE 8)).flatten) := by
  rw [← framed_input_is_source_key]
  apply parse_framed_roundtrip role _ words.length roleBound countBound
  clear countBound
  induction words with
  | nil => rfl
  | cons word words induction =>
    simp only [List.map_cons, List.flatten_cons, List.length_append, encodeLE_length,
      induction, List.length_cons, Nat.mul_add, Nat.mul_one, Nat.add_comm]

def digestAt (payload : List Byte) (offset : ℕ) : RawDigest :=
  fun byte => payload.getD (offset + byte.val) 0

def wordAt (payload : List Byte) (word : ℕ) : ℕ := decodeLE ((payload.drop (8 * word)).take 8)

/-- Source leaf geometry: four salt words, index, eight tape words, 140 data
values and five masks. Only the 145 field words are range-checked as fields. -/
def leafPayloadValid (payload : List Byte) : Prop :=
  payload.length = 1280 ∧ wordAt payload 4 < 8388608 ∧
    wordAt payload 13 = 140 ∧ wordAt payload 154 = 5 ∧
    (∀ index : Fin 140, wordAt payload (14 + index.val) < goldilocksModulus) ∧
    (∀ index : Fin 5, wordAt payload (155 + index.val) < goldilocksModulus)

instance (payload : List Byte) : Decidable (leafPayloadValid payload) := by
  unfold leafPayloadValid
  infer_instance

/-- Valid syntax records only genuine outgoing hash references. In particular,
field coefficients, salts, tapes and binding bytes never become child digests. -/
inductive ParsedInput where
  | leaf
  | unaryNode (child : RawDigest)
  | binaryNode (left right : RawDigest)
  | rootWrapper (bareRoot : RawDigest)
  | piopWrapper (hashMt : RawDigest)

def parsePayload (role payload : List Byte) : Option ParsedInput :=
  if role = V8Smz9WholeViewObservation.strictZkMerkleLeafDomain then
    if leafPayloadValid payload then some .leaf else none
  else if role = merkleNodeDomain then
    if payload.length = 128 then some (.binaryNode (digestAt payload 0) (digestAt payload 64))
    else if payload.length = 64 then some (.unaryNode (digestAt payload 0)) else none
  else if role = merkleRootDomain then
    if 96 ≤ payload.length then some (.rootWrapper (digestAt payload 32)) else none
  else if role = piopInputDomain then
    if 15584 ≤ payload.length ∧
        (∀ coefficient : Fin 1940, wordAt payload (8 + coefficient.val) < goldilocksModulus)
      then some (.piopWrapper (digestAt payload 0)) else none
  else none

def parseSource (input : RawInput) : Option ParsedInput := do
  let (role, payload) ← parseFramed input
  parsePayload role payload

def parsedChildren : ParsedInput → Finset RawDigest
  | .leaf => ∅
  | .unaryNode child => {child}
  | .binaryNode left right => {left, right}
  | .rootWrapper root => {root}
  | .piopWrapper root => {root}

def sourceChildren (input : RawInput) : Finset RawDigest :=
  match parseSource input with
  | none => ∅
  | some parsed => parsedChildren parsed

theorem parsed_children_arity (parsed : ParsedInput) : (parsedChildren parsed).card ≤ 2 := by
  cases parsed <;> simp [parsedChildren]
  exact Finset.card_le_two

theorem source_children_arity (input : RawInput) : (sourceChildren input).card ≤ 2 := by
  cases parsed : parseSource input with
  | none => simp [sourceChildren, parsed]
  | some value => simpa only [sourceChildren, parsed] using parsed_children_arity value

inductive SourceStage where
  | tree (remainingDepth : ℕ)
  | decs
  | piopGamma
deriving DecidableEq

/-- DECS follows one root wrapper; PIOP gamma follows its input wrapper and then
the root wrapper. A leaf appears only after 23 internal levels. -/
def parsedNext : SourceStage → ParsedInput → Option (List (SourceStage × RawDigest))
  | .tree 0, .leaf => some []
  | .tree (depth + 1), .unaryNode child => some [(.tree depth, child)]
  | .tree (depth + 1), .binaryNode left right => some [(.tree depth, left), (.tree depth, right)]
  | .decs, .rootWrapper root => some [(.tree 23, root)]
  | .piopGamma, .piopWrapper root => some [(.decs, root)]
  | _, _ => none

def sourceNext (stage : SourceStage) (input : RawInput) : Option (List (SourceStage × RawDigest)) :=
  (parseSource input).bind (parsedNext stage)

theorem parsed_next_child (stage : SourceStage) (parsed : ParsedInput)
    (edges : List (SourceStage × RawDigest)) (decoded : parsedNext stage parsed = some edges)
    (edge : SourceStage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ parsedChildren parsed := by
  cases stage with
  | tree depth =>
    cases depth <;> cases parsed <;> cases decoded
    all_goals simp_all [parsedChildren]
    all_goals aesop
  | decs =>
    cases parsed <;> cases decoded
    simp_all [parsedChildren]
  | piopGamma =>
    cases parsed <;> cases decoded
    simp_all [parsedChildren]

theorem source_next_child (stage : SourceStage) (input : RawInput)
    (edges : List (SourceStage × RawDigest)) (decoded : sourceNext stage input = some edges)
    (edge : SourceStage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ sourceChildren input := by
  cases parsed : parseSource input with
  | none => simp [sourceNext, parsed] at decoded
  | some value =>
    simp only [sourceNext, parsed, Option.bind_some] at decoded
    simpa only [sourceChildren, parsed] using parsed_next_child stage value edges decoded edge member

def stageHeight : SourceStage → ℕ
  | .tree depth => depth + 1
  | .decs => 25
  | .piopGamma => 26

theorem source_next_height_decreases (stage : SourceStage) (input : RawInput)
    (edges : List (SourceStage × RawDigest)) (decoded : sourceNext stage input = some edges)
    (edge : SourceStage × RawDigest) (member : edge ∈ edges) : stageHeight edge.1 < stageHeight stage := by
  cases parsed : parseSource input with
  | none => simp [sourceNext, parsed] at decoded
  | some value =>
    simp only [sourceNext, parsed, Option.bind_some] at decoded
    cases stage with
    | tree depth =>
      cases depth <;> cases value <;> cases decoded
      all_goals simp_all [stageHeight]
      all_goals aesop
    | decs =>
      cases value <;> cases decoded
      simp_all [stageHeight]
    | piopGamma =>
      cases value <;> cases decoded
      simp_all [stageHeight]

def extractDecs (records : Records RawInput RawDigest) (hashMt : RawDigest) : ExtractionTrace RawInput :=
  extract sourceNext records 25 .decs hashMt

def extractPiopGamma (records : Records RawInput RawDigest) (hashFpp : RawDigest) : ExtractionTrace RawInput :=
  extract sourceNext records 26 .piopGamma hashFpp

theorem source_extraction_changes_only_at_target_or_child
    (records : Records RawInput RawDigest) (input : RawInput) (output : RawDigest)
    (targets : List (SourceStage × RawDigest))
    (changed : extractTargets sourceNext (insert (input, output) records) 26 targets ≠
      extractTargets sourceNext records 26 targets) :
    output ∈ targetDigests targets ∪ databaseChildren sourceChildren records :=
  changed_extraction_implies_target_or_child sourceNext sourceChildren source_next_child
    records input output 26 targets changed

/-- The CDHZ classical partition-instability numerator: one target per tracked
prefix, at most two outgoing digests per old record. Wrappers add no multiplicative factor. -/
theorem source_uniform_change_probability_le
    (records : Records RawInput RawDigest) (input : RawInput) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) :
    uniformChangeProbability sourceNext records input fuel targets ≤
      ((targets.length + 2 * records.card : ℕ) : ℚ) / (2 ^ 512 : ℚ) := by
  have bound := uniform_change_probability_le sourceNext sourceChildren source_next_child
    2 source_children_arity records input fuel targets
  simpa only [raw_digest_cardinality, Nat.cast_pow, Nat.cast_ofNat, Nat.mul_comm] using bound

theorem source_classical_instability_three_t
    (records : Records RawInput RawDigest) (input : RawInput) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) (queryBound : ℕ)
    (recordBudget : records.card < queryBound) (targetBudget : targets.length ≤ queryBound) :
    uniformChangeProbability sourceNext records input fuel targets ≤
      (3 * queryBound : ℚ) / (2 ^ 512 : ℚ) := by
  refine (source_uniform_change_probability_le records input fuel targets).trans ?_
  apply div_le_div_of_nonneg_right
  · have bound : targets.length + 2 * records.card ≤ 3 * queryBound := by omega
    exact_mod_cast bound
  · positivity

theorem source_observed_instability_three_t {View : Type*}
    (observe : List (ExtractionTrace RawInput) → View)
    (records : Records RawInput RawDigest) (input : RawInput) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) (queryBound : ℕ)
    (recordBudget : records.card < queryBound) (targetBudget : targets.length ≤ queryBound) :
    observedChangeProbability sourceNext observe records input fuel targets ≤
      (3 * queryBound : ℚ) / (2 ^ 512 : ℚ) :=
  (observed_change_probability_le sourceNext observe records input fuel targets).trans
    (source_classical_instability_three_t records input fuel targets queryBound recordBudget targetBudget)

end RawSourceGrammar

end HegemonCrypto.SmallWood.V8Smz9CoherentMerkleGeometry
