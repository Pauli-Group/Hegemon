import SmzaRp05ExtractionSuffix

/-!
# Concrete RP05 terminal query suffix

This file replaces an arbitrary extraction `Plan` by the plan computed from
one accepted batch.  Every proof supplies its already-retained verifier/X
queries, four measured extraction traces, and the exact framed role prefixes.
The suffix walks those traces, reads the `digestAt` dependencies used by
`SmzaRp05TracePrefixes`, generates every required capped counter query after
measurement, and deduplicates the resulting physical inputs once for the batch.

The plan cardinality is charged explicitly in the lifetime query ledger.  No
inequality from the number of accepted proofs to the global query bound is
assumed here.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ConcreteSuffix

open scoped BigOperators Classical
open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets
open SmzaRp05LeafNamespace SmzaRp05StatementNamespace SmzaRp05TracePrefixes
open SmzaRp05CurrentRoleLabels
open SmzaRp05ExtractionSuffix
open V8Smz9RawCounterCompiler V8Smz9AdaptiveFiniteAccounting
open V8Smz9WholeViewObservation

noncomputable section
set_option autoImplicit false

abbrev PhysicalInput := V8SmzaOracleParser.RawInput
abbrev Digest := V8SmzaOracleParser.RawDigest

def allRoles : List Role :=
  [.decsMatrix, .piopMatrix, .piopOpening, .decsSample]

theorem role_mem_all_roles (role : Role) : role ∈ allRoles := by
  cases role <;> simp [allRoles]

/-- One selected role target and the exact trace decoded from that target. -/
structure RoleView where
  target : Digest
  nonce : Nat
  /-- Exact framed prefix through the payload, excluding the final counter. -/
  leading : PhysicalInput
  trace : Trace

/-- Concrete data retained from one accepted verifier call.  Each role view
retains the literal framed prefix, so suffix counters are generated without
guessing either the target or the opening nonce. -/
structure ProofView where
  statement : SmzaRp05StatementNamespace.Statement
  preamble : List CanonicalBytes.Byte
  retainedXQueries : List PhysicalInput
  measuredRecords : Finset PhysicalInput
  roleView : Role → RoleView

/-- Bounded structural walk of every record input in a current extraction
trace.  This includes all nodes subsequently inspected by `payload`, `child`,
and `rootOracle`; it does not synthesize a hash preimage. -/
def traceInputs : Nat → Trace → List PhysicalInput
  | 0, _ => []
  | _ + 1, .missing => []
  | _ + 1, .budget => []
  | fuel + 1, .record input children =>
      input :: children.flatMap (traceInputs fuel)

structure Selector where
  role : Role
  target : Digest
  nonce : Nat
  leading : PhysicalInput
deriving DecidableEq

def selectorFromPayload (nameSpace : Namespace) (view : ProofView) (role : Role)
    (kind : V8SmzaOracleParser.Kind) (trace : Trace) (offset : Nat) :
    List Selector :=
  match payload nameSpace kind trace with
  | none => []
  | some value =>
      [⟨role, V8SmzaOracleParser.digestAt value.bytes offset,
        (view.roleView role).nonce, (view.roleView role).leading⟩]

/-- Exactly the earlier-role digest lookups performed by `prefixLabels`.
The child depths and offsets are copied from `matrixLabel`, `openingLabel`,
and `queryLabels`; no abstract dependency relation is supplied by a caller. -/
def earlierSelectors (nameSpace : Namespace) (view : ProofView) (role : Role)
    (trace : Trace) :
    List Selector :=
  match role with
  | .decsMatrix => []
  | .piopMatrix =>
      selectorFromPayload nameSpace view .decsMatrix .fpp trace 0
  | .piopOpening =>
      selectorFromPayload nameSpace view .decsMatrix .fpp (child trace 0) 0 ++
      selectorFromPayload nameSpace view .piopMatrix .piop trace 0
  | .decsSample =>
      selectorFromPayload nameSpace view .decsMatrix .fpp
          (child (child trace 0) 0) 0 ++
      selectorFromPayload nameSpace view .piopOpening .decs trace 0

def neededSelectors (nameSpace : Namespace) (view : ProofView) (role : Role) :
    List Selector :=
  ⟨role, (view.roleView role).target, (view.roleView role).nonce,
    (view.roleView role).leading⟩ ::
    earlierSelectors nameSpace view role (view.roleView role).trace

theorem matrix_label_decs_selector
    (nameSpace : Namespace) (view : ProofView) (fpp : SmzaRp05TracePrefixes.Payload)
    (found : payload nameSpace .fpp (view.roleView .piopMatrix).trace = some fpp) :
    (⟨.decsMatrix, V8SmzaOracleParser.digestAt fpp.bytes 0,
      (view.roleView .decsMatrix).nonce,
      (view.roleView .decsMatrix).leading⟩ : Selector) ∈
      neededSelectors nameSpace view .piopMatrix := by
  simp [neededSelectors, earlierSelectors, selectorFromPayload, found]

theorem opening_label_decs_selector
    (nameSpace : Namespace) (view : ProofView) (fpp : SmzaRp05TracePrefixes.Payload)
    (found : payload nameSpace .fpp
      (child (view.roleView .piopOpening).trace 0) = some fpp) :
    (⟨.decsMatrix, V8SmzaOracleParser.digestAt fpp.bytes 0,
      (view.roleView .decsMatrix).nonce,
      (view.roleView .decsMatrix).leading⟩ : Selector) ∈
      neededSelectors nameSpace view .piopOpening := by
  simp [neededSelectors, earlierSelectors, selectorFromPayload, found]

theorem opening_label_matrix_selector
    (nameSpace : Namespace) (view : ProofView) (piop : SmzaRp05TracePrefixes.Payload)
    (found : payload nameSpace .piop (view.roleView .piopOpening).trace = some piop) :
    (⟨.piopMatrix, V8SmzaOracleParser.digestAt piop.bytes 0,
      (view.roleView .piopMatrix).nonce,
      (view.roleView .piopMatrix).leading⟩ : Selector) ∈
      neededSelectors nameSpace view .piopOpening := by
  simp [neededSelectors, earlierSelectors, selectorFromPayload, found]

theorem query_label_decs_selector
    (nameSpace : Namespace) (view : ProofView) (fpp : SmzaRp05TracePrefixes.Payload)
    (found : payload nameSpace .fpp
      (child (child (view.roleView .decsSample).trace 0) 0) = some fpp) :
    (⟨.decsMatrix, V8SmzaOracleParser.digestAt fpp.bytes 0,
      (view.roleView .decsMatrix).nonce,
      (view.roleView .decsMatrix).leading⟩ : Selector) ∈
      neededSelectors nameSpace view .decsSample := by
  simp [neededSelectors, earlierSelectors, selectorFromPayload, found]

theorem query_label_opening_selector
    (nameSpace : Namespace) (view : ProofView) (decs : SmzaRp05TracePrefixes.Payload)
    (found : payload nameSpace .decs (view.roleView .decsSample).trace = some decs) :
    (⟨.piopOpening, V8SmzaOracleParser.digestAt decs.bytes 0,
      (view.roleView .piopOpening).nonce,
      (view.roleView .piopOpening).leading⟩ : Selector) ∈
      neededSelectors nameSpace view .decsSample := by
  simp [neededSelectors, earlierSelectors, selectorFromPayload, found]

/-- Number of raw 512-bit counter blocks consumed by the current capped
sampler.  These are precisely the four arities of `TypedRoutes`. -/
def routeReadCount (model : RelationModel)
    (statement : SmzaRp05StatementNamespace.Statement) : Role → Nat
  | .decsMatrix => digestCallCap (140 * 5)
  | .piopMatrix => digestCallCap (5 * model.width statement)
  | .piopOpening => digestCallCap V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings
  | .decsSample => digestCallCap SmzaRp04RawRoleSampling.q38CandidateCount

/-- Generated-source ceilings fixed before the oracle game.  The current DSL
has at most 818 nonlinear expressions and 20,588 retained CSR attempts; the
latter is the largest possible batching width. -/
def protocolNonlinearCap : Nat := 818
def protocolCsrAttemptCap : Nat := 20588

/-- Ex-ante grouped-table partition.  It is independent of the accepted
batch, measured database, and adaptive history. -/
def protocolBlockCap : Role → Nat
  | .decsMatrix => digestCallCap (140 * 5)
  | .piopMatrix => digestCallCap (5 * protocolCsrAttemptCap)
  | .piopOpening => digestCallCap V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings
  | .decsSample => digestCallCap SmzaRp04RawRoleSampling.q38CandidateCount

theorem protocol_block_caps_exact :
    protocolBlockCap .decsMatrix = 92 ∧
    protocolBlockCap .piopMatrix = 12872 ∧
    protocolBlockCap .piopOpening = 5 ∧
    protocolBlockCap .decsSample = 11 := by
  decide

def ModelWithinProtocol (model : RelationModel) : Prop :=
  ∀ statement, model.width statement ≤ protocolCsrAttemptCap

theorem digest_call_cap_mono {left right : Nat} (bounded : left ≤ right) :
    digestCallCap left ≤ digestCallCap right := by
  unfold digestCallCap
  by_cases leftZero : left = 0
  · simp [leftZero]
  · have rightNonzero : right ≠ 0 := by omega
    simp only [leftZero, rightNonzero, if_false]
    exact Nat.div_le_div_right (Nat.add_le_add_right bounded 39)

theorem route_read_count_le_protocol_cap
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (statement : SmzaRp05StatementNamespace.Statement) (role : Role) :
    routeReadCount model statement role ≤ protocolBlockCap role := by
  cases role with
  | decsMatrix => rfl
  | piopMatrix =>
      apply digest_call_cap_mono
      exact Nat.mul_le_mul_left 5 (bounded statement)
  | piopOpening => rfl
  | decsSample => rfl

/-- Exact post-measurement query synthesized from a trace-derived framed
prefix.  The prefix already contains the role and target/nonce payload; only
the final little-endian counter is appended. -/
def generatedRoleInput (selector : Selector) (counter : Nat) : PhysicalInput :=
  selector.leading ++ encodeLE 8 counter

theorem protocol_block_cap_le_u64 (role : Role) :
    protocolBlockCap role ≤ 2^64 := by
  cases role <;> decide

def generatedRoleInputFin (selector : Selector)
    (counter : Fin (protocolBlockCap selector.role)) : PhysicalInput :=
  generatedRoleInput selector counter.val

/-- Exact hook for `fullRawPaddedCoordinate`: the synthesized physical query
is the existing bounded-counter embedding at `(leading,counter)`. -/
theorem generated_role_input_fin_eq_bounded_counter_input
    (selector : Selector) (counter : Fin (protocolBlockCap selector.role)) :
    generatedRoleInputFin selector counter =
      boundedCounterInput (protocolBlockCap selector.role)
        (protocol_block_cap_le_u64 selector.role) (selector.leading, counter) := by
  rfl

def generatedSelectorInputs (model : RelationModel)
    (statement : SmzaRp05StatementNamespace.Statement)
    (selector : Selector) : List PhysicalInput :=
  (List.range (routeReadCount model statement selector.role)).map
    (generatedRoleInput selector)

theorem generated_selector_inputs_length
    (model : RelationModel)
    (statement : SmzaRp05StatementNamespace.Statement) (selector : Selector) :
    (generatedSelectorInputs model statement selector).length =
      routeReadCount model statement selector.role := by
  simp [generatedSelectorInputs]

def proofGeneratedInputs (model : RelationModel) (nameSpace : Namespace)
    (view : ProofView) : List PhysicalInput :=
  allRoles.flatMap fun role =>
    (neededSelectors nameSpace view role).flatMap
      (generatedSelectorInputs model view.statement)

def proofInputs (model : RelationModel) (nameSpace : Namespace)
    (view : ProofView) : List PhysicalInput :=
  view.retainedXQueries ++ proofGeneratedInputs model nameSpace view

def batchGeneratedInputs (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : List PhysicalInput :=
  batch.flatMap (proofGeneratedInputs model nameSpace)

def batchInputs (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : List PhysicalInput :=
  batch.flatMap (proofInputs model nameSpace)

/-- The new post-measurement physical queries, deduplicated independently of
the already charged verifier/X prefix. -/
def generatedReadKeys (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : Finset PhysicalInput :=
  (batchGeneratedInputs model nameSpace batch).toFinset

def generatedReadSchedule (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : List PhysicalInput :=
  (generatedReadKeys model nameSpace batch).toList

theorem generated_read_schedule_nodup
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView) :
    (generatedReadSchedule model nameSpace batch).Nodup :=
  (generatedReadKeys model nameSpace batch).nodup_toList

theorem generated_read_count_exact
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView) :
    (generatedReadSchedule model nameSpace batch).length =
      (generatedReadKeys model nameSpace batch).card := by
  simp [generatedReadSchedule]

theorem generated_read_count_le_expanded
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView) :
    (generatedReadSchedule model nameSpace batch).length ≤
      (batchGeneratedInputs model nameSpace batch).length := by
  rw [generated_read_count_exact]
  exact List.toFinset_card_le _

/-- Every synthesized counter query, including the 32-word rejection
allowance encoded by `digestCallCap`, is charged to the lifetime bound. -/
theorem generated_new_reads_lifetime_bound
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (priorTouches T : Nat)
    (charged : priorTouches +
      (batchGeneratedInputs model nameSpace batch).length ≤ T) :
    priorTouches +
      (generatedReadSchedule model nameSpace batch).length ≤ T := by
  exact (Nat.add_le_add_left
    (generated_read_count_le_expanded model nameSpace batch)
    priorTouches).trans charged

def physicalDomain (input : PhysicalInput) : Domain :=
  match parseStageQuery input with
  | none => .raw
  | some query =>
      if query.counter < protocolBlockCap query.role then
        .role query.role
      else .raw

theorem physical_domain_of_unparsed
    (input : PhysicalInput)
    (unparsed : parseStageQuery input = none) :
    physicalDomain input = .raw := by
  simp [physicalDomain, unparsed]

theorem physical_domain_of_high_counter
    (input : PhysicalInput)
    (query : StageQuery) (parsed : parseStageQuery input = some query)
    (high : ¬ query.counter < protocolBlockCap query.role) :
    physicalDomain input = .raw := by
  simp [physicalDomain, parsed, high]

theorem physical_domain_of_bounded_counter
    (input : PhysicalInput)
    (query : StageQuery) (parsed : parseStageQuery input = some query)
    (bounded : query.counter < protocolBlockCap query.role) :
    physicalDomain input = .role query.role := by
  simp [physicalDomain, parsed, bounded]

/-- The actual one-batch physical plan.  `toFinset` is the sole deduplication
step; identical queries shared by proofs or prefixes are read only once. -/
def currentPlan (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : Plan PhysicalInput where
  keys := (batchInputs model nameSpace batch).toFinset
  domain := physicalDomain

/-- Finite check on data exported by an accepted verifier call.  The supplied
preamble is the statement being decoded, and each trace-derived selector has
every bounded counter block at its exact recorded nonce. -/
structure CanonicalProofView (model : RelationModel) (nameSpace : Namespace)
    (view : ProofView) : Prop where
  preambleExact : view.preamble = view.statement.toBytes
  tracePreamble : ∀ role,
    SmzaRp05CurrentRoleLabels.preambleFromTrace nameSpace role
      (view.roleView role).trace = some view.preamble
  xQueriesCanonical : ∀ input ∈ view.retainedXQueries,
    ∃ key : V8Smz9WholeViewObservation.RawSha512OracleKey,
      key.Canonical ∧ key.preimage = input
  routeFraming : ∀ role selector,
    selector ∈ neededSelectors nameSpace view role →
      ∀ counter, counter < routeReadCount model view.statement selector.role →
        ∃ query,
          parseStageQuery (generatedRoleInput selector counter) = some query ∧
          query.role = selector.role ∧ query.target = selector.target ∧
          query.nonce = selector.nonce ∧ query.counter = counter

/-- Receipt from the single measured raw database.  Prefix traversal consumes
these classical records locally and issues no post-measurement X query. -/
structure MeasuredTraceView (fuel : Nat) (view : ProofView) : Prop where
  traceCovered : ∀ role input,
    input ∈ traceInputs fuel (view.roleView role).trace →
      input ∈ view.measuredRecords

theorem retained_x_query_mem_current_plan
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (view : ProofView) (viewMem : view ∈ batch) (input : PhysicalInput)
    (inputMem : input ∈ view.retainedXQueries) :
    input ∈ (currentPlan model nameSpace batch).keys := by
  simp only [currentPlan, batchInputs, List.mem_toFinset, List.mem_flatMap]
  exact ⟨view, viewMem, List.mem_append_left _ inputMem⟩

theorem generated_role_query_mem_current_plan
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (view : ProofView) (viewMem : view ∈ batch) (role : Role)
    (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role)
    (counter : Nat)
    (counterBound : counter < routeReadCount model view.statement selector.role) :
    generatedRoleInput selector counter ∈
      (currentPlan model nameSpace batch).keys := by
  simp only [currentPlan, batchInputs, List.mem_toFinset, List.mem_flatMap]
  refine ⟨view, viewMem, List.mem_append_right _ ?_⟩
  refine List.mem_flatMap.mpr ⟨role, role_mem_all_roles role, ?_⟩
  refine List.mem_flatMap.mpr ⟨selector, selectorMem, ?_⟩
  apply List.mem_map.mpr
  exact ⟨counter, List.mem_range.mpr counterBound, rfl⟩

theorem generated_role_query_mem_read_schedule
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (view : ProofView) (viewMem : view ∈ batch) (role : Role)
    (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role)
    (counter : Nat)
    (counterBound : counter < routeReadCount model view.statement selector.role) :
    generatedRoleInput selector counter ∈
      generatedReadSchedule model nameSpace batch := by
  apply Finset.mem_toList.mpr
  simp only [generatedReadKeys, batchGeneratedInputs, List.mem_toFinset]
  apply List.mem_flatMap.mpr
  refine ⟨view, viewMem, ?_⟩
  apply List.mem_flatMap.mpr
  refine ⟨role, role_mem_all_roles role, ?_⟩
  apply List.mem_flatMap.mpr
  refine ⟨selector, selectorMem, ?_⟩
  exact List.mem_map.mpr ⟨counter, List.mem_range.mpr counterBound, rfl⟩

/-- Prefix traversal is local to the once-measured record set.  This theorem
does not place record preimages in the post-measurement oracle schedule. -/
theorem trace_query_mem_measured_records
    (fuel : Nat) (view : ProofView) (measured : MeasuredTraceView fuel view)
    (role : Role) (input : PhysicalInput)
    (used : input ∈ traceInputs fuel (view.roleView role).trace) :
    input ∈ view.measuredRecords :=
  measured.traceCovered role input used

/-- Every counter block required by every current or earlier-role selector is
present in the deduplicated plan at the exact trace-recorded nonce, including
the PIOP-opening retry path. -/
theorem selector_counter_mem_current_plan
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (view : ProofView) (viewMem : view ∈ batch)
    (valid : CanonicalProofView model nameSpace view)
    (role : Role) (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role) :
    ∀ counter, counter < routeReadCount model view.statement selector.role →
      ∃ input ∈ (currentPlan model nameSpace batch).keys, ∃ query,
        parseStageQuery input = some query ∧
        query.role = selector.role ∧ query.target = selector.target ∧
        query.nonce = selector.nonce ∧ query.counter = counter := by
  have framed := valid.routeFraming role selector selectorMem
  intro counter counterBound
  obtain ⟨query, parsed, sameRole, sameTarget, sameNonce, sameCounter⟩ :=
    framed counter counterBound
  exact ⟨generatedRoleInput selector counter,
    generated_role_query_mem_current_plan model nameSpace batch view viewMem role
      selector selectorMem counter counterBound,
    query, parsed, sameRole, sameTarget, sameNonce, sameCounter⟩

theorem selector_counter_mem_generated_read_schedule
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (view : ProofView) (viewMem : view ∈ batch)
    (valid : CanonicalProofView model nameSpace view)
    (role : Role) (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role) :
    ∀ counter, counter < routeReadCount model view.statement selector.role →
      ∃ input ∈ generatedReadSchedule model nameSpace batch, ∃ query,
        input = generatedRoleInput selector counter ∧
        parseStageQuery input = some query ∧
        query.role = selector.role ∧ query.target = selector.target ∧
        query.nonce = selector.nonce ∧ query.counter = counter := by
  intro counter counterBound
  obtain ⟨query, parsed, sameRole, sameTarget, sameNonce, sameCounter⟩ :=
    valid.routeFraming role selector selectorMem counter counterBound
  refine ⟨generatedRoleInput selector counter,
    generated_role_query_mem_read_schedule model nameSpace batch view viewMem
      role selector selectorMem counter counterBound,
    query, rfl, parsed, sameRole, sameTarget, sameNonce, sameCounter⟩

theorem x_and_role_keys_disjoint (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) (role : Role) :
    Disjoint (domainKeys (currentPlan model nameSpace batch) .raw)
      (domainKeys (currentPlan model nameSpace batch) (.role role)) :=
  domain_keys_disjoint _ _ _ (by simp)

/-- A finite code for exactly one raw-counter key in the deduplicated physical
plan.  This is not a grouped-vector cell key; the raw-to-group adapter maps
these codes separately. -/
abbrev ScheduledKey (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) :=
  { input : PhysicalInput // input ∈ (currentPlan model nameSpace batch).keys }

def scheduledKeys (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : Finset (ScheduledKey model nameSpace batch) :=
  (currentPlan model nameSpace batch).keys.attach

instance scheduledKeyFintype (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : Fintype (ScheduledKey model nameSpace batch) :=
  Fintype.ofFinset (currentPlan model nameSpace batch).keys (by
    intro key
    rfl)

def xSchedule (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : List (ScheduledKey model nameSpace batch) :=
  (Finset.univ.filter fun key =>
    (currentPlan model nameSpace batch).domain key.1 = .raw).toList

def roleSchedule (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : List (ScheduledKey model nameSpace batch) :=
  (Finset.univ.filter fun key =>
    (currentPlan model nameSpace batch).domain key.1 ≠ .raw).toList

theorem x_schedule_nodup (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) :
    (xSchedule model nameSpace batch).Nodup := by
  exact (Finset.univ.filter fun key : ScheduledKey model nameSpace batch =>
    (currentPlan model nameSpace batch).domain key.1 = .raw).nodup_toList

theorem role_schedule_nodup (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) :
    (roleSchedule model nameSpace batch).Nodup := by
  exact (Finset.univ.filter fun key : ScheduledKey model nameSpace batch =>
    (currentPlan model nameSpace batch).domain key.1 ≠ .raw).nodup_toList

theorem x_role_schedule_disjoint
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView) :
    ∀ roleKey ∈ roleSchedule model nameSpace batch,
      roleKey ∉ xSchedule model nameSpace batch := by
  intro roleKey roleMem xMem
  have roleNotRaw := (Finset.mem_filter.mp
    (Finset.mem_toList.mp roleMem)).2
  have xRaw := (Finset.mem_filter.mp (Finset.mem_toList.mp xMem)).2
  exact roleNotRaw xRaw

theorem retained_x_query_has_scheduled_code
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (view : ProofView) (viewMem : view ∈ batch)
    (input : PhysicalInput) (inputMem : input ∈ view.retainedXQueries)
    (classified : physicalDomain input = .raw) :
    ∃ key ∈ xSchedule model nameSpace batch, key.1 = input := by
  let key : ScheduledKey model nameSpace batch :=
    ⟨input, retained_x_query_mem_current_plan model nameSpace batch view viewMem
      input inputMem⟩
  refine ⟨key, ?_, rfl⟩
  apply Finset.mem_toList.mpr
  apply Finset.mem_filter.mpr
  refine ⟨Finset.mem_univ key, ?_⟩
  simpa [currentPlan] using classified

/-- The bounded selector traversal produces literal scheduled codes, not just
membership in an abstract plan. -/
theorem selector_counter_has_scheduled_code
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (modelBounded : ModelWithinProtocol model)
    (view : ProofView) (viewMem : view ∈ batch)
    (valid : CanonicalProofView model nameSpace view)
    (role : Role) (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role) :
    ∀ counter, counter < routeReadCount model view.statement selector.role →
      ∃ key ∈ roleSchedule model nameSpace batch, ∃ query,
        key.1 = generatedRoleInput selector counter ∧
        parseStageQuery key.1 = some query ∧
        query.role = selector.role ∧ query.target = selector.target ∧
        query.nonce = selector.nonce ∧ query.counter = counter := by
  intro counter counterBound
  obtain ⟨query, parsed, sameRole, sameTarget, sameNonce, sameCounter⟩ :=
    valid.routeFraming role selector selectorMem counter counterBound
  let key : ScheduledKey model nameSpace batch :=
    ⟨generatedRoleInput selector counter,
      generated_role_query_mem_current_plan model nameSpace batch view viewMem
        role selector selectorMem counter counterBound⟩
  have withinProtocol : query.counter < protocolBlockCap query.role := by
    have withinRoute :
        query.counter < routeReadCount model view.statement query.role := by
      simpa only [sameRole, sameCounter] using counterBound
    exact withinRoute.trans_le
      (route_read_count_le_protocol_cap model modelBounded view.statement query.role)
  have keyMem : key ∈ roleSchedule model nameSpace batch := by
    apply Finset.mem_toList.mpr
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ key, ?_⟩
    simp [key, currentPlan, physicalDomain, parsed, withinProtocol]
  refine ⟨key, keyMem, query, rfl, ?_, sameRole, sameTarget, sameNonce,
    sameCounter⟩
  exact parsed

/-! ## Finite coding of the physical raw-query plan -/

/-- A finite presentation of every physical raw-counter input in the concrete
plan.  This must not be instantiated by one representative per grouped vector
cell; the separate raw-to-group adapter performs that quotient. -/
structure PhysicalPlanPullback (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) (Key : Type*)
    (keyBytes : Key → PhysicalInput) : Prop where
  injective : Function.Injective keyBytes
  covers : ∀ input ∈ (currentPlan model nameSpace batch).keys,
    ∃ key, keyBytes key = input

/-- Canonical finite presentation requiring no caller-supplied encoding. -/
theorem scheduledPhysicalKeyPullback (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) :
    PhysicalPlanPullback model nameSpace batch
      (ScheduledKey model nameSpace batch)
      Subtype.val where
  injective := Subtype.val_injective
  covers input member := ⟨⟨input, member⟩, rfl⟩

def pulledRoleReadKeys {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) (role : Role) : Finset Key :=
  Finset.univ.filter fun key =>
    keyBytes key ∈ (currentPlan model nameSpace batch).keys ∧
      (currentPlan model nameSpace batch).domain (keyBytes key) = .role role

def pulledRoleReadSchedule {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) (role : Role) : List Key :=
  (pulledRoleReadKeys model nameSpace batch keyBytes role).toList

/-- One deduplicated post-measurement read schedule for all four roles. -/
def pulledReadKeys {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) : Finset Key :=
  Finset.univ.filter fun key =>
    keyBytes key ∈ (currentPlan model nameSpace batch).keys ∧
      (currentPlan model nameSpace batch).domain (keyBytes key) ≠ .raw

def pulledReadSchedule {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) : List Key :=
  (pulledReadKeys model nameSpace batch keyBytes).toList

/-- Every key in the one physical role-read schedule parses as a bounded
stage query. This is the parser-recognition premise of scheduled totality,
derived from the concrete plan rather than postulated for its keys. -/
theorem pulled_read_schedule_recognized {Key : Type*}
    [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) :
    ∀ key ∈ pulledReadSchedule model nameSpace batch keyBytes,
      ∃ query, parseStageQuery (keyBytes key) = some query := by
  intro key member
  have selected := Finset.mem_toList.mp member
  have nonRaw := (Finset.mem_filter.mp selected).2.2
  cases parsed : parseStageQuery (keyBytes key) with
  | none =>
      exact False.elim (nonRaw (by simp [currentPlan, physicalDomain, parsed]))
  | some query => exact ⟨query, rfl⟩

theorem scheduled_pullback_read_schedule_eq
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView) :
    pulledReadSchedule model nameSpace batch
        (Subtype.val : ScheduledKey model nameSpace batch → PhysicalInput) =
      roleSchedule model nameSpace batch := by
  unfold pulledReadSchedule pulledReadKeys roleSchedule
  apply congrArg Finset.toList
  ext key
  simp

theorem pulled_role_read_schedule_nodup
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) (role : Role) :
    (pulledRoleReadSchedule model nameSpace batch keyBytes role).Nodup :=
  (pulledRoleReadKeys model nameSpace batch keyBytes role).nodup_toList

theorem pulled_read_schedule_nodup
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) :
    (pulledReadSchedule model nameSpace batch keyBytes).Nodup :=
  (pulledReadKeys model nameSpace batch keyBytes).nodup_toList

theorem pulled_role_read_subset_batch_schedule
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) (role : Role) :
    ∀ key ∈ pulledRoleReadSchedule model nameSpace batch keyBytes role,
      key ∈ pulledReadSchedule model nameSpace batch keyBytes := by
  intro key member
  apply Finset.mem_toList.mpr
  apply Finset.mem_filter.mpr
  have selected := (Finset.mem_filter.mp (Finset.mem_toList.mp member)).2
  exact ⟨Finset.mem_univ key, selected.1, by simp [selected.2]⟩

theorem pulled_role_read_count_exact
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) (role : Role) :
    (pulledRoleReadSchedule model nameSpace batch keyBytes role).length =
      (pulledRoleReadKeys model nameSpace batch keyBytes role).card := by
  simp [pulledRoleReadSchedule]

theorem pulled_role_read_count_le_plan
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) (role : Role)
    (injective : Function.Injective keyBytes) :
    (pulledRoleReadSchedule model nameSpace batch keyBytes role).length ≤
      (currentPlan model nameSpace batch).keys.card := by
  rw [pulled_role_read_count_exact]
  rw [← Finset.card_image_of_injective _ injective]
  apply Finset.card_le_card
  intro input inputMem
  obtain ⟨key, keyMem, rfl⟩ := Finset.mem_image.mp inputMem
  exact (Finset.mem_filter.mp keyMem).2.1

theorem pulled_read_count_exact
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) :
    (pulledReadSchedule model nameSpace batch keyBytes).length =
      (pulledReadKeys model nameSpace batch keyBytes).card := by
  simp [pulledReadSchedule]

theorem pulled_read_count_le_plan
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput)
    (injective : Function.Injective keyBytes) :
    (pulledReadSchedule model nameSpace batch keyBytes).length ≤
      (currentPlan model nameSpace batch).keys.card := by
  rw [pulled_read_count_exact]
  rw [← Finset.card_image_of_injective _ injective]
  apply Finset.card_le_card
  intro input inputMem
  obtain ⟨key, keyMem, rfl⟩ := Finset.mem_image.mp inputMem
  exact (Finset.mem_filter.mp keyMem).2.1

theorem plan_role_key_has_pullback
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput)
    (pullback : PhysicalPlanPullback model nameSpace batch Key keyBytes)
    (input : PhysicalInput)
    (inPlan : input ∈ (currentPlan model nameSpace batch).keys)
    (role : Role)
    (inRole : (currentPlan model nameSpace batch).domain input = .role role) :
    ∃ key ∈ pulledRoleReadSchedule model nameSpace batch keyBytes role,
      keyBytes key = input := by
  obtain ⟨key, same⟩ := pullback.covers input inPlan
  refine ⟨key, ?_, same⟩
  apply Finset.mem_toList.mpr
  apply Finset.mem_filter.mpr
  exact ⟨Finset.mem_univ key, same.symm ▸ ⟨inPlan, inRole⟩⟩

/-- Final concrete traversal API: every counter coordinate needed by a
trace-derived prefix selector has an actual key in the one deduplicated finite
read schedule for that physical role. -/
theorem selector_counter_has_pullback_key
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput)
    (pullback : PhysicalPlanPullback model nameSpace batch Key keyBytes)
    (modelBounded : ModelWithinProtocol model)
    (view : ProofView) (viewMem : view ∈ batch)
    (valid : CanonicalProofView model nameSpace view)
    (role : Role) (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role) :
    ∀ counter, counter < routeReadCount model view.statement selector.role →
      ∃ key ∈ pulledRoleReadSchedule model nameSpace batch keyBytes
          selector.role,
        ∃ query, parseStageQuery (keyBytes key) = some query ∧
          query.role = selector.role ∧ query.target = selector.target ∧
          query.nonce = selector.nonce ∧ query.counter = counter := by
  intro counter counterBound
  obtain ⟨input, inPlan, query, parsed, sameRole, sameTarget, sameNonce,
      sameCounter⟩ := selector_counter_mem_current_plan model nameSpace batch
        view viewMem valid role selector selectorMem counter counterBound
  have perStatement : query.counter <
      routeReadCount model view.statement query.role := by
    simpa only [sameRole, sameCounter] using counterBound
  have withinProtocol : query.counter < protocolBlockCap query.role :=
    perStatement.trans_le
      (route_read_count_le_protocol_cap model modelBounded view.statement query.role)
  have inRole :
      (currentPlan model nameSpace batch).domain input = .role selector.role := by
    have withinSelector : query.counter < protocolBlockCap selector.role := by
      simpa only [sameRole] using withinProtocol
    simp [currentPlan, physicalDomain, parsed, withinSelector, sameRole]
  obtain ⟨key, keyMem, keyValue⟩ := plan_role_key_has_pullback
    model nameSpace batch keyBytes pullback input inPlan selector.role inRole
  refine ⟨key, keyMem, query, ?_, sameRole, sameTarget, sameNonce, sameCounter⟩
  simpa only [keyValue] using parsed

def scheduledOracle {Output : Type*}
    {model : RelationModel} {nameSpace : Namespace} {batch : List ProofView}
    (oracle : PhysicalInput → Output) :
    ScheduledKey model nameSpace batch → Output :=
  fun key => oracle key.1

def currentClaims {Output : Type*} (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) (oracle : PhysicalInput → Output) :
    List (ScheduledKey model nameSpace batch × Output) :=
  reads (scheduledOracle oracle) (roleSchedule model nameSpace batch)

def currentXClaims {Output : Type*} (model : RelationModel)
    (nameSpace : Namespace) (batch : List ProofView)
    (oracle : PhysicalInput → Output) :
    List (ScheduledKey model nameSpace batch × Output) :=
  reads (scheduledOracle oracle) (xSchedule model nameSpace batch)

theorem current_claim_key_scheduled {Output : Type*}
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (oracle : PhysicalInput → Output)
    (claim : ScheduledKey model nameSpace batch × Output)
    (member : claim ∈ currentClaims model nameSpace batch oracle) :
    claim.1 ∈ roleSchedule model nameSpace batch := by
  unfold currentClaims reads at member
  obtain ⟨input, inputMem, rfl⟩ := List.mem_map.mp member
  exact inputMem

theorem current_total_claims_eq {Output : Type*}
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (oracle : PhysicalInput → Output) :
    (∑ domain : Domain,
      (claims (currentPlan model nameSpace batch) oracle domain).length) =
      (currentPlan model nameSpace batch).keys.card :=
  total_claims_eq _ _

theorem current_claims_length {Output : Type*}
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (oracle : PhysicalInput → Output) :
    (currentClaims model nameSpace batch oracle).length =
      (roleSchedule model nameSpace batch).length := by
  simp [currentClaims, reads]

/-- `priorTouches` already includes the pre-measurement X queries.  Every new
post-measurement physical read is one member of the deduplicated role schedule,
and is therefore charged separately here. -/
theorem current_new_reads_lifetime_bound {Output : Type*}
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (oracle : PhysicalInput → Output) (priorTouches T : Nat)
    (charged : priorTouches + (roleSchedule model nameSpace batch).length ≤ T) :
    priorTouches + (currentClaims model nameSpace batch oracle).length ≤ T := by
  simpa only [current_claims_length] using charged

/-- Optional finite coding of the physical raw-query scheduler.  This is not
the grouped-vector terminal readout; the read count is nevertheless charged
to the same global lifetime, with no independent `C ≤ T` premise. -/
theorem pulled_new_reads_lifetime_bound
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (keyBytes : Key → PhysicalInput) (injective : Function.Injective keyBytes)
    (priorTouches T : Nat)
    (charged : priorTouches +
      (currentPlan model nameSpace batch).keys.card ≤ T) :
    priorTouches +
      (pulledReadSchedule model nameSpace batch keyBytes).length ≤ T := by
  exact (Nat.add_le_add_left
    (pulled_read_count_le_plan model nameSpace batch keyBytes injective)
    priorTouches).trans charged

/-- Explicit global charge: the suffix cardinality is added to every earlier
ordinary query/programming touch before comparison with `T`. -/
theorem current_plan_lifetime_bound {Output : Type*}
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (oracle : PhysicalInput → Output) (priorTouches T : Nat)
    (charged : priorTouches + (currentPlan model nameSpace batch).keys.card ≤ T) :
    (∑ domain : Domain,
      (claims (currentPlan model nameSpace batch) oracle domain).length) ≤ T :=
  total_claims_le_lifetime _ _ priorTouches T charged

end
end HegemonCrypto.SmallWood.SmzaRp05ConcreteSuffix
