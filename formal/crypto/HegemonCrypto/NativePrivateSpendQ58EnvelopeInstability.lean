import SmzaRp05FilteredDecoderInstability

/-! One child-envelope generalization. All extraction/filter/trace definitions
are imported unchanged. Constructor inclusion and arity are syntactic laws;
no desired decoder instability or accepted-event premise is supplied. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58EnvelopeInstability

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8SmzaOnlineParser
open HegemonCrypto.CanonicalBytes
open SmzaRp05FilteredDecoderInstability
open SmzaRp04StatementRecordFilter SmzaRp04AuthorizedLabelTransport
open SmzaDynamicDatabaseSoundness

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 0
abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Stage := V8SmzaOracleParser.Stage
abbrev Trace := ExtractionTrace RawInput
abbrev RawRecords := SmzaRp05FilteredDecoderInstability.RawRecords
abbrev Next := Stage → RawInput → Option (List (Stage × RawDigest))

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

theorem filtered_database_children_subset {Index : Type*}
    (childrenOf : RawInput → Finset RawDigest)
    (keep : Index → RawInput → Prop) (index : Index) (records : RawRecords) :
    databaseChildren childrenOf
        (restrictedRecords keep index records) ⊆
      databaseChildren childrenOf records := by
  intro digest member
  obtain ⟨record, recorded, child⟩ := Finset.mem_biUnion.mp member
  exact Finset.mem_biUnion.mpr
    ⟨record, (Finset.mem_filter.mp recorded).1, child⟩

theorem restricted_extraction_change_implies_global_target_or_child
    {Index : Type*}
    (childrenOf : RawInput → Finset RawDigest)
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ childrenOf input)
    (keep : Index → RawInput → Prop) (index : Index)
    (target : Stage × RawDigest) (records : RawRecords)
    (input : RawInput) (output : RawDigest) (fuel : Nat)
    (changed :
      extract next
          (restrictedRecords keep index (insert (input, output) records)) fuel
          target.1 target.2 ≠
        extract next (restrictedRecords keep index records) fuel
          target.1 target.2) :
    output ∈ ({target.2} : Finset RawDigest) ∪
      databaseChildren childrenOf records := by
  by_cases retained : keep index input
  · have filterInsert :
        restrictedRecords keep index (insert (input, output) records) =
          insert (input, output) (restrictedRecords keep index records) := by
      ext record
      by_cases same : record = (input, output)
      · subst record
        simp [restrictedRecords, retained]
      · simp [restrictedRecords, same]
    rw [filterInsert] at changed
    have chargedLocal := changed_extraction_implies_target_or_child next
      childrenOf children
      (restrictedRecords keep index records) input output fuel [target]
      (by simpa [extractTargets] using changed)
    rcases Finset.mem_union.mp chargedLocal with atTarget | atChild
    · exact Finset.mem_union_left _ (by simpa [targetDigests] using atTarget)
    · exact Finset.mem_union_right _
        (filtered_database_children_subset childrenOf keep index records atChild)
  · have filterInsert :
        restrictedRecords keep index (insert (input, output) records) =
          restrictedRecords keep index records := by
      ext record
      by_cases same : record = (input, output)
      · subst record
        simp [restrictedRecords, retained]
      · simp [restrictedRecords, same]
    exact False.elim (changed (by rw [filterInsert]))

theorem filtered_family_change_implies_global_target_or_child {Index : Type*}
    (childrenOf : RawInput → Finset RawDigest)
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ childrenOf input)
    (keep : Index → RawInput → Prop) (target : Index → Stage × RawDigest)
    (fuel : Nat) (records : RawRecords) (indices : List Index)
    (input : RawInput) (output : RawDigest)
    (changed : filteredFamilyTrace next keep target fuel (insert (input, output) records) indices ≠
      filteredFamilyTrace next keep target fuel records indices) :
    output ∈ targetDigests (indices.map target) ∪
      databaseChildren childrenOf records := by
  obtain ⟨index, member, localChange⟩ :=
    filtered_family_change_witness next keep target fuel records indices input output changed
  have charged := restricted_extraction_change_implies_global_target_or_child
    childrenOf next children keep index (target index) records input output fuel localChange
  rcases Finset.mem_union.mp charged with atTarget | atChild
  · apply Finset.mem_union_left
    simp only [targetDigests, List.mem_toFinset, List.mem_map]
    have same : output = (target index).2 := by
      simpa using atTarget
    exact ⟨target index, ⟨index, member, rfl⟩, same.symm⟩
  · exact Finset.mem_union_right _ atChild

theorem filtered_family_step_change_bound
    {Key Counter Index : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (childrenOf : RawInput → Finset RawDigest)
    (arity : ∀ input, (childrenOf input).card ≤ 2)
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ childrenOf input)
    (keyBytes : Key → RawInput) (counter : Counter)
    (keep : Index → RawInput → Prop) (target : Index → Stage × RawDigest)
    (fuel : Nat) (indices : List Index) (cap : Nat)
    (targetBound : indices.length ≤ cap)
    (database : Database Key (VectorOutput Counter)) (recordBound : size database < cap)
    (queried : Key) (event : Property Key (VectorOutput Counter))
    (changed : ∀ output, event (query database queried output) →
      filteredFamilyTrace next keep target fuel
          (rawRecords keyBytes (vectorOutputBytes counter)
            (query database queried output)) indices ≠
        filteredFamilyTrace next keep target fuel
          (rawRecords keyBytes (vectorOutputBytes counter) database) indices) :
    stepProbability event database queried ≤ (3 * cap : Rat) / (2^512 : Rat) := by
  by_cases absent : database queried = none
  · let records := rawRecords keyBytes (vectorOutputBytes counter) database
    let charged := targetDigests (indices.map target) ∪
      databaseChildren childrenOf records
    have subset : successfulAnswers event database queried ⊆
        Finset.univ.filter (fun vector : VectorOutput Counter =>
          rawDigestBits.symm (vector counter) ∈ charged) := by
      intro output member
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ _, ?_⟩
      have traceChange := changed output (Finset.mem_filter.mp member).2
      have inserted :
          rawRecords keyBytes (vectorOutputBytes counter)
              (query database queried output) =
            insert (keyBytes queried, vectorOutputBytes counter output) records := by
        simpa [records, query_of_absent absent] using
          raw_records_insert keyBytes (vectorOutputBytes counter) database queried output absent
      rw [inserted] at traceChange
      exact filtered_family_change_implies_global_target_or_child childrenOf next children keep target fuel records
        indices (keyBytes queried) (vectorOutputBytes counter output) traceChange
    have digestCard : (Finset.univ.filter fun output : V8Smz9HiddenLeafQrom.DigestRegister =>
        rawDigestBits.symm output ∈ charged).card = charged.card :=
      equiv_event_card rawDigestBits.symm charged
    have targetCard : (targetDigests (indices.map target)).card ≤ indices.length := by
      simpa [targetDigests] using
        (List.toFinset_card_le ((indices.map target).map Prod.snd))
    have childCard := database_children_card_le childrenOf records 2
      arity
    have recordsCard : records.card < cap :=
      lt_of_le_of_lt (raw_records_card_le keyBytes (vectorOutputBytes counter) database)
        recordBound
    have chargedCard : charged.card ≤ 3 * cap := by
      calc
        charged.card ≤ (targetDigests (indices.map target)).card +
            (databaseChildren childrenOf records).card :=
          Finset.card_union_le _ _
        _ ≤ indices.length + records.card * 2 := Nat.add_le_add targetCard childCard
        _ ≤ 3 * cap := by omega
    calc
      stepProbability event database queried ≤
          ((Finset.univ.filter fun vector : VectorOutput Counter =>
            rawDigestBits.symm (vector counter) ∈ charged).card : Rat) /
            Fintype.card (VectorOutput Counter) := by
        apply div_le_div_of_nonneg_right
        · exact_mod_cast Finset.card_le_card subset
        · positivity
      _ = (charged.card : Rat) / (2^512 : Rat) := by
        rw [coordinate_event_probability counter
          (fun output => rawDigestBits.symm output ∈ charged), digestCard,
          V8Smz9RawCounterCompiler.digest_register_cardinality]
        simp only [Nat.cast_pow, Nat.cast_ofNat]
      _ ≤ (3 * cap : Rat) / (2^512 : Rat) := by
        apply div_le_div_of_nonneg_right
        · exact_mod_cast chargedCard
        · positivity
  · rw [step_probability_eq_zero_of_never event database queried]
    · positivity
    · intro output accepted
      apply changed output accepted
      simp [query, absent]

theorem tracked_outer_change_bound
    {Key Counter Statement : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [DecidableEq Statement]
    (childrenOf : RawInput → Finset RawDigest)
    (arity : ∀ input, (childrenOf input).card ≤ 2)
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ childrenOf input)
    (keyBytes : Key → RawInput) (counter : Counter)
    (leafStatement : StatementParser RawInput Statement)
    (outerTarget : Key → Stage × RawDigest) (outerDecode : Key → Trace → Option Statement)
    (outerFuel cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability
        (TrackedOuterChange
          (rawRecords keyBytes (vectorOutputBytes counter)) leafStatement
          (rawTraceDecoder next outerTarget outerDecode outerFuel) database queried)
        database queried ≤ (3 * cap : Rat) / (2^512 : Rat) := by
  let indices := trackedInputs database queried
  let keep : Key → RawInput → Prop := fun _ raw => leafStatement raw = none
  apply filtered_family_step_change_bound childrenOf arity next children keyBytes counter keep outerTarget outerFuel
    indices cap (tracked_inputs_length_le database queried cap bounded)
    database bounded queried
  intro output changed
  obtain ⟨input, tracked, different⟩ := changed
  intro sameFamily
  apply different
  unfold rawTraceDecoder
  have traceEqual := filtered_family_eq_at next keep outerTarget outerFuel
    (rawRecords keyBytes (vectorOutputBytes counter) (query database queried output))
    (rawRecords keyBytes (vectorOutputBytes counter) database) indices sameFamily input
    (tracked_inputs_mem database queried input tracked)
  exact congrArg (outerDecode input) (by
    simpa [keep, restrictedRecords, nonleafFilter] using traceEqual.symm)

theorem tracked_inner_change_bound
    {Key Counter Statement Label : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [DecidableEq Statement]
    (childrenOf : RawInput → Finset RawDigest)
    (arity : ∀ input, (childrenOf input).card ≤ 2)
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ childrenOf input)
    (keyBytes : Key → RawInput) (counter : Counter)
    (leafStatement : StatementParser RawInput Statement)
    (outer : RawRecords → Key → Option Statement)
    (innerTarget : Statement → Key → Stage × RawDigest)
    (innerDecode : Statement → Key → Trace → Label)
    (innerFuel : Nat) (authorized : Finset Statement) (cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability
        (TrackedInnerChange
          (rawRecords keyBytes (vectorOutputBytes counter)) leafStatement outer
          (statementTraceDecoder next innerTarget innerDecode innerFuel) authorized
          database queried) database queried ≤ (3 * cap : Rat) / (2^512 : Rat) := by
  let records := rawRecords keyBytes (vectorOutputBytes counter) database
  let indices := selectedTrackedInputs leafStatement outer records database queried
  let keep : (Key × Statement) → RawInput → Prop := fun index raw =>
    leafStatement raw = none ∨ leafStatement raw = some index.2
  let target : (Key × Statement) → Stage × RawDigest := fun index =>
    innerTarget index.2 index.1
  apply filtered_family_step_change_bound childrenOf arity next children keyBytes counter keep target innerFuel indices cap
    (selected_tracked_inputs_length_le leafStatement outer records database queried cap bounded)
    database bounded queried
  intro output changed
  obtain ⟨input, tracked, statement, _fresh, selectedBefore, _selectedAfter,
    different⟩ := changed
  intro sameFamily
  apply different
  unfold statementTraceDecoder
  have traceEqual := filtered_family_eq_at next keep target innerFuel
    (rawRecords keyBytes (vectorOutputBytes counter) (query database queried output))
    records indices sameFamily (input, statement)
    (selected_tracked_inputs_mem leafStatement outer records database queried input statement
      tracked selectedBefore)
  exact congrArg (innerDecode statement input) (by
    simpa [keep, target, restrictedRecords, oneStatementFilter, keepOneStatement,
      records] using traceEqual.symm)

theorem complete_filtered_two_pass_change_bound
    {Key Counter Statement Label : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [DecidableEq Statement]
    (childrenOf : RawInput → Finset RawDigest)
    (arity : ∀ input, (childrenOf input).card ≤ 2)
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ childrenOf input)
    (keyBytes : Key → RawInput) (counter : Counter)
    (leafStatement : StatementParser RawInput Statement)
    (outerTarget : Key → Stage × RawDigest) (outerDecode : Key → Trace → Option Statement)
    (innerTarget : Statement → Key → Stage × RawDigest)
    (innerDecode : Statement → Key → Trace → Label)
    (outerFuel innerFuel : Nat) (authorized : Finset Statement) (cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability
        (TrackedLabelChange
          (fun db input => completeFilteredLabel leafStatement
            (rawTraceDecoder next outerTarget outerDecode outerFuel)
            (statementTraceDecoder next innerTarget innerDecode innerFuel) authorized
            (rawRecords keyBytes (vectorOutputBytes counter) db) input)
          database queried) database queried ≤ (6 * cap : Rat) / (2^512 : Rat) := by
  have keyDecEq : (inferInstance : DecidableEq Key) = Classical.decEq Key := by
    funext a b
    exact Subsingleton.elim _ _
  have outerBound := tracked_outer_change_bound childrenOf arity next children keyBytes counter leafStatement
    outerTarget outerDecode outerFuel cap database bounded queried
  have innerBound := tracked_inner_change_bound childrenOf arity next children keyBytes counter leafStatement
    (rawTraceDecoder next outerTarget outerDecode outerFuel) innerTarget innerDecode innerFuel
    authorized cap database bounded queried
  have queryEq (db : Database Key (VectorOutput Counter))
      (output : VectorOutput Counter) :
      @query Key (VectorOutput Counter) (inferInstance : DecidableEq Key) db queried output =
        @query Key (VectorOutput Counter) (Classical.decEq Key) db queried output := by
    rw [keyDecEq]
  simp only [stepProbability, successfulAnswers] at outerBound innerBound ⊢
  simp only [queryEq] at outerBound innerBound ⊢
  have compositeBound := tracked_complete_change_probability_le_six
    (rawRecords keyBytes (vectorOutputBytes counter)) leafStatement
    (rawTraceDecoder next outerTarget outerDecode outerFuel)
    (statementTraceDecoder next innerTarget innerDecode innerFuel) authorized
    database queried cap (2^512)
    (by simpa only [stepProbability, successfulAnswers, Nat.cast_pow, Nat.cast_ofNat] using outerBound)
    (by simpa only [stepProbability, successfulAnswers, Nat.cast_pow, Nat.cast_ofNat] using innerBound)
  simpa only [stepProbability, successfulAnswers, Nat.cast_pow, Nat.cast_ofNat] using compositeBound

/-- Same proposition as the retained historical theorem, with its old envelope. -/
theorem historical_complete_filtered_two_pass_change_bound
    {Key Counter Statement Label : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [DecidableEq Statement]
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (keyBytes : Key → RawInput) (counter : Counter)
    (leafStatement : StatementParser RawInput Statement)
    (outerTarget : Key → Stage × RawDigest) (outerDecode : Key → Trace → Option Statement)
    (innerTarget : Statement → Key → Stage × RawDigest)
    (innerDecode : Statement → Key → Trace → Label)
    (outerFuel innerFuel : Nat) (authorized : Finset Statement) (cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability
        (TrackedLabelChange
          (fun db input => completeFilteredLabel leafStatement
            (rawTraceDecoder next outerTarget outerDecode outerFuel)
            (statementTraceDecoder next innerTarget innerDecode innerFuel) authorized
            (rawRecords keyBytes (vectorOutputBytes counter) db) input)
          database queried) database queried ≤ (6 * cap : Rat) / (2^512 : Rat) := by
  exact complete_filtered_two_pass_change_bound
    V8SmzaOracleParser.rawChildren V8SmzaOracleParser.raw_children_arity
    next children keyBytes counter leafStatement outerTarget outerDecode
    innerTarget innerDecode outerFuel innerFuel authorized cap database bounded queried

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58EnvelopeInstability
