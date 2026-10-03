import SmzaRp04AuthorizedLabelTransport
import SmzaRp05FilteredReadback
import SmzaDynamicStageLabels

/-!
# Filtered least-preimage decoder instability

The restriction predicate depends only on a raw input, never on the sampled
digest.  A fresh CMS answer therefore either inserts one record into a
restricted relation or inserts nothing.  For a family of statement-indexed
relations, a change at any member is still charged to the union of the target
digests and the children of the single unfiltered database.  Thus varying
statements do not multiply the `3T/M` count.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05FilteredDecoderInstability

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle
open V8SmzaOnlineParser
open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets SmzaRp05LeafNamespace SmzaRp05FilteredReadback
open SmzaRp04StatementRecordFilter SmzaRp04AuthorizedLabelTransport
open SmzaDynamicDatabaseSoundness

noncomputable section
set_option autoImplicit false
set_option exponentiation.threshold 1024
set_option maxRecDepth 10000

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Stage := V8SmzaOracleParser.Stage
abbrev Trace := ExtractionTrace RawInput
abbrev RawRecords := V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest
abbrev Next := Stage → RawInput → Option (List (Stage × RawDigest))

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

/-- The current RP05 decoder has no v2-leaf edges, while every preserved
nonleaf edge lies in the historical context-free raw-child envelope. -/
theorem current_online_next_child
    (ns : Namespace) (salt : List Byte)
    (stage : Stage) (input : RawInput) (edges : List (Stage × RawDigest))
    (decoded : currentOnlineNext ns salt stage input = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) :
    edge.2 ∈ V8SmzaOracleParser.rawChildren input := by
  cases current : parseCurrentLeaf ns salt input with
  | some leaf =>
      have normalized : normalizedPayload ns salt input = some leaf.normalized := by
        simp [normalizedPayload, current]
      cases stage with
      | tree depth =>
          cases depth with
          | zero =>
              simp [currentOnlineNext, normalized, CurrentLeaf.normalized, payloadNext] at decoded
              subst edges
              simp at member
          | succ depth =>
              simp [currentOnlineNext, normalized, CurrentLeaf.normalized, payloadNext] at decoded
      | root | fpp | piop | decs =>
          simp [currentOnlineNext, normalized, CurrentLeaf.normalized, payloadNext] at decoded
  | none =>
      cases historical : V8SmzaOracleParser.rawPayload input with
      | none => simp [currentOnlineNext, normalizedPayload, current, historical] at decoded
      | some payload =>
          by_cases leaf : payload.kind = .leaf
          · simp [currentOnlineNext, normalizedPayload, current, historical, leaf] at decoded
          · have payloadDecoded : payloadNext stage payload = some edges := by
              simpa [currentOnlineNext, normalizedPayload, current, historical, leaf] using decoded
            have child := payload_next_child stage payload edges payloadDecoded edge member
            simpa [V8SmzaOracleParser.rawChildren, historical] using child

/-- Global normalization derives the leaf salt from that raw frame.  For
nonleaf roles the derived value is irrelevant because normalization preserves
the historical payload independently of salt. -/
def globalNormalizedPayload (ns : Namespace) (input : RawInput) :
    Option V8SmzaOracleParser.Payload := do
  let (_, bytes) ← V8SmzaOracleParser.parseFramed input
  normalizedPayload ns ((bytes.drop preambleBytes).take 32) input

def globalOnlineNext (ns : Namespace) : Next :=
  fun stage input => do
    let parsed ← globalNormalizedPayload ns input
    payloadNext stage parsed

theorem global_online_next_child
    (ns : Namespace) (stage : Stage) (input : RawInput)
    (edges : List (Stage × RawDigest))
    (decoded : globalOnlineNext ns stage input = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) :
    edge.2 ∈ V8SmzaOracleParser.rawChildren input := by
  cases framed : V8SmzaOracleParser.parseFramed input with
  | none => simp [globalOnlineNext, globalNormalizedPayload, framed] at decoded
  | some framedValue =>
      rcases framedValue with ⟨role, bytes⟩
      apply current_online_next_child ns ((bytes.drop preambleBytes).take 32)
        stage input edges
      · simpa [globalOnlineNext, globalNormalizedPayload, framed, currentOnlineNext]
          using decoded
      · exact member

def restrictedRecords {Index : Type*}
    (keep : Index → RawInput → Prop) (index : Index) (records : RawRecords) :
    RawRecords :=
  records.filter fun record => keep index record.1

def filteredFamilyTrace {Index : Type*}
    (next : Next) (keep : Index → RawInput → Prop) (target : Index → Stage × RawDigest)
    (fuel : Nat) (records : RawRecords) (indices : List Index) : List Trace :=
  indices.map fun index =>
    extract next (restrictedRecords keep index records) fuel
      (target index).1 (target index).2

theorem filtered_database_children_subset {Index : Type*}
    (keep : Index → RawInput → Prop) (index : Index) (records : RawRecords) :
    databaseChildren V8SmzaOracleParser.rawChildren
        (restrictedRecords keep index records) ⊆
      databaseChildren V8SmzaOracleParser.rawChildren records := by
  intro digest member
  obtain ⟨record, recorded, child⟩ := Finset.mem_biUnion.mp member
  exact Finset.mem_biUnion.mpr
    ⟨record, (Finset.mem_filter.mp recorded).1, child⟩

/-- The key restriction lemma.  It charges a changed restricted extraction to
the target digest or to a child of the original, unfiltered relation. -/
theorem restricted_extraction_change_implies_global_target_or_child
    {Index : Type*} (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
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
      databaseChildren V8SmzaOracleParser.rawChildren records := by
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
      V8SmzaOracleParser.rawChildren children
      (restrictedRecords keep index records) input output fuel [target]
      (by simpa [extractTargets] using changed)
    rcases Finset.mem_union.mp chargedLocal with atTarget | atChild
    · exact Finset.mem_union_left _ (by simpa [targetDigests] using atTarget)
    · exact Finset.mem_union_right _
        (filtered_database_children_subset keep index records atChild)
  · have filterInsert :
        restrictedRecords keep index (insert (input, output) records) =
          restrictedRecords keep index records := by
      ext record
      by_cases same : record = (input, output)
      · subst record
        simp [restrictedRecords, retained]
      · simp [restrictedRecords, same]
    exact False.elim (changed (by rw [filterInsert]))

theorem filtered_family_change_witness {Index : Type*}
    (next : Next) (keep : Index → RawInput → Prop) (target : Index → Stage × RawDigest)
    (fuel : Nat) (records : RawRecords) (indices : List Index)
    (input : RawInput) (output : RawDigest)
    (changed : filteredFamilyTrace next keep target fuel (insert (input, output) records) indices ≠
      filteredFamilyTrace next keep target fuel records indices) :
    ∃ index ∈ indices,
      extract next
          (restrictedRecords keep index (insert (input, output) records)) fuel
          (target index).1 (target index).2 ≠
        extract next (restrictedRecords keep index records) fuel
          (target index).1 (target index).2 := by
  by_contra absent
  apply changed
  unfold filteredFamilyTrace
  apply List.map_congr_left
  intro index member
  by_contra different
  exact absent ⟨index, member, different⟩

theorem filtered_family_change_implies_global_target_or_child {Index : Type*}
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (keep : Index → RawInput → Prop) (target : Index → Stage × RawDigest)
    (fuel : Nat) (records : RawRecords) (indices : List Index)
    (input : RawInput) (output : RawDigest)
    (changed : filteredFamilyTrace next keep target fuel (insert (input, output) records) indices ≠
      filteredFamilyTrace next keep target fuel records indices) :
    output ∈ targetDigests (indices.map target) ∪
      databaseChildren V8SmzaOracleParser.rawChildren records := by
  obtain ⟨index, member, localChange⟩ :=
    filtered_family_change_witness next keep target fuel records indices input output changed
  have charged := restricted_extraction_change_implies_global_target_or_child
    next children keep index (target index) records input output fuel localChange
  rcases Finset.mem_union.mp charged with atTarget | atChild
  · apply Finset.mem_union_left
    simp only [targetDigests, List.mem_toFinset, List.mem_map]
    have same : output = (target index).2 := by
      simpa using atTarget
    exact ⟨target index, ⟨index, member, rfl⟩, same.symm⟩
  · exact Finset.mem_union_right _ atChild

/-- Actual full-vector CMS step bound for an arbitrary family of raw
least-preimage decoders.  The family may use a different input restriction at
every target; only its number of targets and the one physical database count. -/
theorem filtered_family_step_change_bound
    {Key Counter Index : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
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
      databaseChildren V8SmzaOracleParser.rawChildren records
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
      exact filtered_family_change_implies_global_target_or_child next children keep target fuel records
        indices (keyBytes queried) (vectorOutputBytes counter output) traceChange
    have digestCard : (Finset.univ.filter fun output : V8Smz9HiddenLeafQrom.DigestRegister =>
        rawDigestBits.symm output ∈ charged).card = charged.card :=
      equiv_event_card rawDigestBits.symm charged
    have targetCard : (targetDigests (indices.map target)).card ≤ indices.length := by
      simpa [targetDigests] using
        (List.toFinset_card_le ((indices.map target).map Prod.snd))
    have childCard := database_children_card_le V8SmzaOracleParser.rawChildren records 2
      V8SmzaOracleParser.raw_children_arity
    have recordsCard : records.card < cap :=
      lt_of_le_of_lt (raw_records_card_le keyBytes (vectorOutputBytes counter) database)
        recordBound
    have chargedCard : charged.card ≤ 3 * cap := by
      calc
        charged.card ≤ (targetDigests (indices.map target)).card +
            (databaseChildren V8SmzaOracleParser.rawChildren records).card :=
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

/-! ## The actual two decoder passes -/

def rawTraceDecoder {Index Value : Type*}
    (next : Next) (target : Index → Stage × RawDigest) (decode : Index → Trace → Value)
    (fuel : Nat) (records : RawRecords) (index : Index) : Value :=
  decode index (extract next records fuel
    (target index).1 (target index).2)

def statementTraceDecoder {Key Statement Label : Type*}
    (next : Next) (target : Statement → Key → Stage × RawDigest)
    (decode : Statement → Key → Trace → Label)
    (fuel : Nat) (statement : Statement) (records : RawRecords) (key : Key) : Label :=
  decode statement key (extract next records fuel
    (target statement key).1 (target statement key).2)

def trackedInputs {Key Output : Type*} [Fintype Key] [DecidableEq Key]
    (database : Database Key Output) (queried : Key) : List Key :=
  queried :: (support database).toList

theorem tracked_inputs_length_le {Key Output : Type*}
    [Fintype Key] [DecidableEq Key]
    (database : Database Key Output) (queried : Key) (cap : Nat)
    (bounded : size database < cap) :
    (trackedInputs database queried).length ≤ cap := by
  simpa [trackedInputs, size] using Nat.succ_le_of_lt bounded

theorem tracked_inputs_mem {Key Output : Type*}
    [Fintype Key] [DecidableEq Key]
    (database : Database Key Output) (queried input : Key)
    (tracked : input = queried ∨ database input ≠ none) :
    input ∈ trackedInputs database queried := by
  rcases tracked with rfl | present
  · simp [trackedInputs]
  · simp only [trackedInputs, List.mem_cons]
    right
    exact Finset.mem_toList.mpr ((mem_support_iff database input).mpr
      (Option.ne_none_iff_exists'.mp present))

theorem filtered_family_eq_at {Index : Type*}
    (next : Next) (keep : Index → RawInput → Prop) (target : Index → Stage × RawDigest)
    (fuel : Nat) (left right : RawRecords) (indices : List Index)
    (same : filteredFamilyTrace next keep target fuel left indices =
      filteredFamilyTrace next keep target fuel right indices)
    (index : Index) (member : index ∈ indices) :
    extract next (restrictedRecords keep index left) fuel
        (target index).1 (target index).2 =
      extract next (restrictedRecords keep index right) fuel
        (target index).1 (target index).2 := by
  induction indices with
  | nil => simp at member
  | cons head tail induction =>
      simp only [filteredFamilyTrace, List.map_cons, List.cons.injEq] at same
      rcases List.mem_cons.mp member with rfl | inTail
      · exact same.1
      · exact induction same.2 inTail

theorem tracked_outer_change_bound
    {Key Counter Statement : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [DecidableEq Statement]
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
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
  apply filtered_family_step_change_bound next children keyBytes counter keep outerTarget outerFuel
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

def selectedTrackedInputs {Key Output Statement : Type*}
    [Fintype Key] [DecidableEq Key]
    (leafStatement : StatementParser RawInput Statement)
    (outer : RawRecords → Key → Option Statement)
    (records : RawRecords) (database : Database Key Output) (queried : Key) :
    List (Key × Statement) :=
  (trackedInputs database queried).filterMap fun input =>
    (outer (nonleafFilter leafStatement records) input).map fun statement =>
      (input, statement)

theorem selected_tracked_inputs_length_le
    {Key Output Statement : Type*} [Fintype Key] [DecidableEq Key]
    (leafStatement : StatementParser RawInput Statement)
    (outer : RawRecords → Key → Option Statement)
    (records : RawRecords) (database : Database Key Output) (queried : Key)
    (cap : Nat) (bounded : size database < cap) :
    (selectedTrackedInputs leafStatement outer records database queried).length ≤ cap := by
  exact (List.length_filterMap_le _ _).trans
    (tracked_inputs_length_le database queried cap bounded)

theorem selected_tracked_inputs_mem
    {Key Output Statement : Type*} [Fintype Key] [DecidableEq Key]
    (leafStatement : StatementParser RawInput Statement)
    (outer : RawRecords → Key → Option Statement)
    (records : RawRecords) (database : Database Key Output) (queried input : Key)
    (statement : Statement) (tracked : input = queried ∨ database input ≠ none)
    (selected : outer (nonleafFilter leafStatement records) input = some statement) :
    (input, statement) ∈ selectedTrackedInputs leafStatement outer records database queried := by
  apply List.mem_filterMap.mpr
  refine ⟨input, tracked_inputs_mem database queried input tracked, ?_⟩
  simp [selected]

theorem tracked_inner_change_bound
    {Key Counter Statement Label : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [DecidableEq Statement]
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
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
  apply filtered_family_step_change_bound next children keyBytes counter keep target innerFuel indices cap
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

/-- The concrete two-pass ordinary-query seam.  Each pass is an actual raw
least-preimage decoder and the deterministic composite inclusion is supplied
by `completeFilteredLabel`; no decoder-change probability remains assumed. -/
theorem complete_filtered_two_pass_change_bound
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
  have keyDecEq : (inferInstance : DecidableEq Key) = Classical.decEq Key := by
    funext a b
    exact Subsingleton.elim _ _
  have outerBound := tracked_outer_change_bound next children keyBytes counter leafStatement
    outerTarget outerDecode outerFuel cap database bounded queried
  have innerBound := tracked_inner_change_bound next children keyBytes counter leafStatement
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

/-- RP05 specialization: traversal and record partition both derive each
leaf's salt from its own raw frame, so one global execution handles every
canonical embedded salt without adding salt to the statement identifier. -/
theorem global_complete_filtered_two_pass_change_bound
    {Key Counter Label : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (ns : Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (outerTarget : Key → Stage × RawDigest)
    (outerDecode : Key → Trace → Option (List Byte))
    (innerTarget : List Byte → Key → Stage × RawDigest)
    (innerDecode : List Byte → Key → Trace → Label)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte)) (cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability
        (TrackedLabelChange
          (fun db input => completeFilteredLabel (globalLeafStatement ns)
            (rawTraceDecoder (globalOnlineNext ns)
              outerTarget outerDecode outerFuel)
            (statementTraceDecoder (globalOnlineNext ns)
              innerTarget innerDecode innerFuel)
            authorized (rawRecords keyBytes (vectorOutputBytes counter) db) input)
          database queried) database queried ≤ (6 * cap : Rat) / (2^512 : Rat) := by
  exact complete_filtered_two_pass_change_bound
    (globalOnlineNext ns) (global_online_next_child ns)
    keyBytes counter (globalLeafStatement ns) outerTarget outerDecode
    innerTarget innerDecode outerFuel innerFuel authorized cap database bounded queried

end
end HegemonCrypto.SmallWood.SmzaRp05FilteredDecoderInstability
