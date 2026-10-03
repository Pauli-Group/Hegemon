import SmzaRp05FilteredDecoderInstability
import SmzaRawDatabaseRecords
import SmzaRp04StatementRecordFilter

/-!
# Direct adaptive role-event transport

The selected-role event is defined on the physical CMS database.  There is
no indexed-label split and no substitution of the final authorization set
for the set present at an earlier query.  A simulator leaf write can mix
`none` and `some` at its coordinate: the proof uses equality off that key.

The selected-role/raw-complement partition is explicit.  Programming an X
key cannot itself create a populated selected-role cell.  Marking removes
events, and programming a marked leaf preserves every enabled label.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveDynamicBad

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentVectorMerkle
open SmzaRawDatabaseRecords SmzaRp04StatementRecordFilter
open SmzaRp04AuthorizedLabelTransport SmzaDynamicDatabaseSoundness
open SmzaRp05FilteredDecoderInstability

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev RawRecords := V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

variable {Key Output Statement Label : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output]
variable [DecidableEq Statement]

/-- An input-only filter erases the entire local coordinate, not just the
answer currently stored there. -/
theorem filtered_records_eq_off_ignored_key
    (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (keep : RawInput → Prop) (key : Key) (ignored : ¬ keep (keyBytes key))
    (left right : Database Key Output)
    (sameOutside : ∀ other, other ≠ key → left other = right other) :
    (rawRecords keyBytes outputBytes left).filter (fun record => keep record.1) =
      (rawRecords keyBytes outputBytes right).filter (fun record => keep record.1) := by
  have inclusion : ∀ first second : Database Key Output,
      (∀ other, other ≠ key → first other = second other) →
      (rawRecords keyBytes outputBytes first).filter (fun record => keep record.1) ⊆
        (rawRecords keyBytes outputBytes second).filter (fun record => keep record.1) := by
    intro first second same record member
    obtain ⟨recorded, retained⟩ := Finset.mem_filter.mp member
    obtain ⟨source, output, present, inputEq, outputEq⟩ :=
      (mem_raw_records_iff keyBytes outputBytes first record.1 record.2).mp recorded
    have different : source ≠ key := by
      intro equal
      subst source
      exact ignored (inputEq.symm ▸ retained)
    apply Finset.mem_filter.mpr
    exact ⟨(mem_raw_records_iff keyBytes outputBytes second record.1 record.2).mpr
      ⟨source, output, (same source different) ▸ present, inputEq, outputEq⟩, retained⟩
  exact Finset.Subset.antisymm (inclusion left right sameOutside)
    (inclusion right left (fun other different => (sameOutside other different).symm))

theorem complete_labels_eq_off_marked_key
    (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (leafStatement : StatementParser RawInput Statement)
    (outer : RawRecords → Key → Option Statement)
    (fullLabel : Statement → RawRecords → Key → Label)
    (authorized : Finset Statement) (statement : Statement)
    (marked : statement ∈ authorized) (key : Key)
    (parsed : leafStatement (keyBytes key) = some statement)
    (left right : Database Key Output)
    (sameOutside : ∀ other, other ≠ key → left other = right other)
    (target : Key) :
    completeFilteredLabel leafStatement outer fullLabel authorized
        (rawRecords keyBytes outputBytes left) target =
      completeFilteredLabel leafStatement outer fullLabel authorized
        (rawRecords keyBytes outputBytes right) target := by
  have nonleaf : nonleafFilter leafStatement (rawRecords keyBytes outputBytes left) =
      nonleafFilter leafStatement (rawRecords keyBytes outputBytes right) := by
    unfold nonleafFilter
    apply Finset.Subset.antisymm
    · intro record member
      obtain ⟨recorded, retained⟩ := Finset.mem_filter.mp member
      obtain ⟨source, output, present, inputEq, outputEq⟩ :=
        (mem_raw_records_iff keyBytes outputBytes left record.1 record.2).mp recorded
      have different : source ≠ key := by
        intro equal
        subst source
        have atKey : leafStatement (keyBytes key) = none := inputEq.symm ▸ retained
        rw [parsed] at atKey
        contradiction
      apply Finset.mem_filter.mpr
      refine ⟨(mem_raw_records_iff keyBytes outputBytes right record.1 record.2).mpr ?_, retained⟩
      exact ⟨source, output, (sameOutside source different) ▸ present, inputEq, outputEq⟩
    · intro record member
      obtain ⟨recorded, retained⟩ := Finset.mem_filter.mp member
      obtain ⟨source, output, present, inputEq, outputEq⟩ :=
        (mem_raw_records_iff keyBytes outputBytes right record.1 record.2).mp recorded
      have different : source ≠ key := by
        intro equal
        subst source
        have atKey : leafStatement (keyBytes key) = none := inputEq.symm ▸ retained
        rw [parsed] at atKey
        contradiction
      apply Finset.mem_filter.mpr
      refine ⟨(mem_raw_records_iff keyBytes outputBytes left record.1 record.2).mpr ?_, retained⟩
      exact ⟨source, output, (sameOutside source different).symm ▸ present, inputEq, outputEq⟩
  unfold completeFilteredLabel
  rw [nonleaf]
  cases selected : outer
      (nonleafFilter leafStatement (rawRecords keyBytes outputBytes right)) target with
  | none => rfl
  | some chosen =>
      by_cases fresh : chosen ∈ authorized
      · simp only [fresh, if_pos]
      · have different : statement ≠ chosen := by
          intro same
          exact fresh (same ▸ marked)
        have inner :
            oneStatementFilter leafStatement chosen (rawRecords keyBytes outputBytes left) =
              oneStatementFilter leafStatement chosen (rawRecords keyBytes outputBytes right) := by
          apply filtered_records_eq_off_ignored_key keyBytes outputBytes
            (keepOneStatement leafStatement chosen) key
          · simp [keepOneStatement, parsed, different]
          · exact sameOutside
        simp only [fresh, inner]

/-- X coordinates are excluded even if a malformed prefix would otherwise
give them a label.  The output predicate is tested only at physical keys of
the selected challenge role. -/
def selectedBad (selected : Key → Prop)
    (bad : Statement → Label → Output → Prop)
    (label : AuthorizedLabel Statement Label) (key : Key) (output : Output) : Prop :=
  selected key ∧ AuthorizedBad bad label output

def roleEvent
    (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (leafStatement : StatementParser RawInput Statement)
    (outer : RawRecords → Key → Option Statement)
    (fullLabel : Statement → RawRecords → Key → Label)
    (selected : Key → Prop) (bad : Statement → Label → Output → Prop)
    (authorized : Finset Statement) : Database Key Output → Prop :=
  DynamicBad
    (fun database key => completeFilteredLabel leafStatement outer fullLabel authorized
      (rawRecords keyBytes outputBytes database) key)
    (selectedBad selected bad)

theorem role_event_mark_mono
    (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (leafStatement : StatementParser RawInput Statement)
    (outer : RawRecords → Key → Option Statement)
    (fullLabel : Statement → RawRecords → Key → Label)
    (selected : Key → Prop) (bad : Statement → Label → Output → Prop)
    (authorized : Finset Statement) (statement : Statement)
    (database : Database Key Output)
    (after : roleEvent keyBytes outputBytes leafStatement outer fullLabel selected bad
      (insert statement authorized) database) :
    roleEvent keyBytes outputBytes leafStatement outer fullLabel selected bad
      authorized database := by
  obtain ⟨key, output, recorded, isSelected, badOutput⟩ := after
  exact ⟨key, output, recorded, isSelected,
    authorized_bad_mark_mono leafStatement outer fullLabel bad authorized statement
      (rawRecords keyBytes outputBytes database) key output badOutput⟩

theorem role_event_iff_off_marked_key
    (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (leafStatement : StatementParser RawInput Statement)
    (outer : RawRecords → Key → Option Statement)
    (fullLabel : Statement → RawRecords → Key → Label)
    (selected : Key → Prop) (bad : Statement → Label → Output → Prop)
    (authorized : Finset Statement) (statement : Statement)
    (marked : statement ∈ authorized) (key : Key) (notSelected : ¬ selected key)
    (parsed : leafStatement (keyBytes key) = some statement)
    (left right : Database Key Output)
    (sameOutside : ∀ other, other ≠ key → left other = right other) :
    roleEvent keyBytes outputBytes leafStatement outer fullLabel selected bad
        authorized left ↔
      roleEvent keyBytes outputBytes leafStatement outer fullLabel selected bad
        authorized right := by
  have transfer : ∀ first second : Database Key Output,
      (∀ other, other ≠ key → first other = second other) →
      roleEvent keyBytes outputBytes leafStatement outer fullLabel selected bad
        authorized first →
      roleEvent keyBytes outputBytes leafStatement outer fullLabel selected bad
        authorized second := by
    intro first second same event
    obtain ⟨target, output, recorded, isSelected, badOutput⟩ := event
    have different : target ≠ key := by
      intro equal
      exact notSelected (equal ▸ isSelected)
    have labels := complete_labels_eq_off_marked_key keyBytes outputBytes leafStatement
      outer fullLabel authorized statement marked key parsed first second same target
    have badAtFirst : AuthorizedBad bad
        (completeFilteredLabel leafStatement outer fullLabel authorized
          (rawRecords keyBytes outputBytes first) target) output := by
      simpa [roleEvent, DynamicBad, selectedBad] using badOutput
    have badAtSecond : AuthorizedBad bad
        (completeFilteredLabel leafStatement outer fullLabel authorized
          (rawRecords keyBytes outputBytes second) target) output := by
      rw [← labels]
      exact badAtFirst
    exact ⟨target, output, (same target different) ▸ recorded, isSelected,
      badAtSecond⟩
  exact ⟨transfer left right sameOutside,
    transfer right left (fun other different => (sameOutside other different).symm)⟩

/-- A uniform fixed-label density remains valid after excluding X keys. -/
theorem selected_bad_density
    (selected : Key → Prop) (bad : Statement → Label → Output → Prop)
    (epsilon : Rat) (nonnegative : 0 ≤ epsilon)
    (density : ∀ statement label, outputEventProbability (bad statement label) ≤ epsilon)
    (label : AuthorizedLabel Statement Label) (key : Key) :
    outputEventProbability (selectedBad selected bad label key) ≤ epsilon := by
  by_cases selectedKey : selected key
  · cases label with
    | disabled => simpa [selectedBad, AuthorizedBad, outputEventProbability] using nonnegative
    | active statement value =>
        have eventEq : selectedBad selected bad (.active statement value) key =
            bad statement value := by
          funext output
          apply propext
          simp [selectedBad, selectedKey, AuthorizedBad]
        rw [eventEq]
        exact density statement value
  · simpa [selectedBad, selectedKey, outputEventProbability] using nonnegative

/-- The only numerical input is the actual fixed-prefix algebra density.
The complete decoder-change bound is derived from the global all-salt parser.
It is uniform in the current authorization set. -/
theorem rp05_role_instability
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (outerTarget : Key → V8SmzaOracleParser.Stage × RawDigest)
    (outerDecode : Key → Trace → Option (List Byte))
    (innerTarget : List Byte → Key → V8SmzaOracleParser.Stage × RawDigest)
    (innerDecode : List Byte → Key → Trace → Label)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte)) (cap : Nat)
    (selected : Key → Prop) (bad : List Byte → Label → VectorOutput Counter → Prop)
    (epsilon : Rat) (nonnegative : 0 ≤ epsilon)
    (density : ∀ statement label, outputEventProbability (bad statement label) ≤ epsilon) :
    InstabilityBound
      (roleEvent keyBytes (vectorOutputBytes counter)
        (SmzaRp05FilteredReadback.globalLeafStatement ns)
        (rawTraceDecoder (globalOnlineNext ns) outerTarget outerDecode outerFuel)
        (statementTraceDecoder (globalOnlineNext ns) innerTarget innerDecode innerFuel)
        selected bad authorized)
      cap ((6 * cap : Rat) / (2^512 : Rat) + epsilon) := by
  apply dynamic_bad_instability _ _ cap epsilon ((6 * cap : Rat) / (2^512 : Rat))
    nonnegative (by positivity)
  · exact selected_bad_density selected bad epsilon nonnegative density
  · exact global_complete_filtered_two_pass_change_bound ns keyBytes counter
      outerTarget outerDecode innerTarget innerDecode outerFuel innerFuel authorized cap

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveDynamicBad
