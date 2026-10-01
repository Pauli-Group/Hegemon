import SmzaRp05ConcreteSuffix
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle
import HegemonCrypto.SmallWoodV8Smz9HonestFinalGame

/-!
# Exact RP05 raw-to-grouped-vector suffix

Only canonical challenge-role counter frames enter a grouped vector. Every
other physical raw input, including malformed inputs, VC/X inputs, and role
counters above the fixed cap, remains an individual complement key at counter
zero. Thus a canonical representative cannot replace a nonzero-counter X
query.

The common counter width is the ex-ante protocol maximum 12,872. Once a
canonical role prefix is used, the suffix physically reads all 12,872 raw
coordinates and charges every deduplicated physical read to `T`. Smaller
per-role decoders ignore surplus coordinates, but those coordinates are real
reads, not free padding.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05GroupedSuffix

open scoped Classical ENNReal
open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets SmzaRp05TracePrefixes
open SmzaRp05LeafNamespace
open SmzaRp05ConcreteSuffix SmzaRp05ExtractionSuffix
open V8Smz9RawCounterCompiler V8Smz9CoherentVectorMerkle
open V8Smz9RuntimeDistribution

noncomputable section
set_option autoImplicit false

/-! ## Fixed complete-vector compiler -/

def groupBlockCap : Nat := protocolBlockCap .piopMatrix

theorem group_block_cap_eq : groupBlockCap = 12872 :=
  protocol_block_caps_exact.2.1

theorem group_block_cap_positive : 0 < groupBlockCap := by
  rw [group_block_cap_eq]
  decide

theorem group_block_cap_le_u64 : groupBlockCap ≤ 2^64 := by
  simpa only [groupBlockCap] using protocol_block_cap_le_u64 .piopMatrix

abbrev GroupCounter := Fin groupBlockCap

def groupZero : GroupCounter := ⟨0, group_block_cap_positive⟩

@[simp] theorem group_zero_val : groupZero.val = 0 := rfl

/-- A rolePrefix is admitted only if appending counter zero produces a literal
query accepted by the four-role parser. The witness is a parser receipt, not
an assumed routing equality. -/
def IsCanonicalRolePrefix (role : Role) (leading : PhysicalInput) : Prop :=
  ∃ query,
    parseStageQuery (leading ++ encodeLE 8 0) = some query ∧
      query.role = role

structure CanonicalRolePrefix where
  role : Role
  leading : PhysicalInput
  canonical : IsCanonicalRolePrefix role leading

theorem canonical_role_prefix_eq_of_leading_eq
    (left right : CanonicalRolePrefix)
    (same : left.leading = right.leading) : left = right := by
  rcases left with ⟨leftRoleValue, leftLeading, leftCanonical⟩
  rcases right with ⟨rightRoleValue, rightLeading, rightCanonical⟩
  dsimp only [CanonicalRolePrefix.leading] at same
  subst rightLeading
  obtain ⟨leftQuery, leftParsed, leftRole⟩ := leftCanonical
  obtain ⟨rightQuery, rightParsed, rightRole⟩ := rightCanonical
  have querySame : leftQuery = rightQuery :=
    Option.some.inj (leftParsed.symm.trans rightParsed)
  have roleSame : leftRoleValue = rightRoleValue :=
    leftRole.symm.trans ((congrArg StageQuery.role querySame).trans rightRole)
  cases roleSame
  rfl

/-- Every coordinate of an admitted rolePrefix is a real raw input. -/
def groupEncode : CanonicalRolePrefix × GroupCounter → PhysicalInput :=
  fun key => boundedCounterInput groupBlockCap group_block_cap_le_u64
    (key.1.leading, key.2)

theorem group_encode_injective : Function.Injective groupEncode := by
  intro left right equal
  have pairEqual : (left.1.leading, left.2) = (right.1.leading, right.2) :=
    bounded_counter_input_injective groupBlockCap group_block_cap_le_u64 equal
  exact Prod.ext
    (canonical_role_prefix_eq_of_leading_eq left.1 right.1
      (congrArg Prod.fst pairEqual))
    (congrArg (fun pair : PhysicalInput × GroupCounter => pair.2) pairEqual)

abbrev GroupComplement := Complement groupEncode
abbrev GroupKey := CanonicalRolePrefix ⊕ GroupComplement

def groupAddress : PhysicalInput → GroupKey × GroupCounter :=
  fullRawPaddedCoordinate groupEncode group_encode_injective groupZero

theorem group_address_injective : Function.Injective groupAddress :=
  full_raw_padded_coordinate_injective groupEncode group_encode_injective groupZero

def groupRepresentative : GroupKey → PhysicalInput :=
  canonicalRepresentative groupEncode groupZero

theorem group_representative_address (key : GroupKey) :
    groupAddress (groupRepresentative key) = (key, groupZero) :=
  canonical_representative_address groupEncode group_encode_injective groupZero key

def groupKeyOf (input : PhysicalInput) : GroupKey := (groupAddress input).1
def groupCounterOf (input : PhysicalInput) : GroupCounter := (groupAddress input).2

@[simp] theorem group_address_encode
    (rolePrefix : CanonicalRolePrefix) (counter : GroupCounter) :
    groupAddress (groupEncode (rolePrefix, counter)) =
      (Sum.inl rolePrefix, counter) := by
  simp [groupAddress, fullRawPaddedCoordinate,
    paddedCoordinate]

@[simp] theorem group_address_complement (input : GroupComplement) :
    groupAddress input.1 = (Sum.inr input, groupZero) := by
  simp [groupAddress, fullRawPaddedCoordinate,
    paddedCoordinate]

def selectorPrefix (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading) :
    CanonicalRolePrefix := ⟨selector.role, selector.leading, canonical⟩

theorem group_encode_eq_generated_role_input
    (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading)
    (counter : GroupCounter) :
    groupEncode (selectorPrefix selector canonical, counter) =
      generatedRoleInput selector counter.val := by
  rfl

/-- Exact generated-input adapter. It is derived from the literal append
constructor and `fullRawPaddedCoordinate`; no address equality is a premise. -/
theorem group_address_generated_role_input
    (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading)
    (counter : GroupCounter) :
    groupAddress (generatedRoleInput selector counter.val) =
      (Sum.inl (selectorPrefix selector canonical), counter) := by
  rw [← group_encode_eq_generated_role_input selector canonical counter]
  exact group_address_encode (selectorPrefix selector canonical) counter

theorem group_key_of_generated_role_input
    (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading)
    (counter : GroupCounter) :
    groupKeyOf (generatedRoleInput selector counter.val) =
      Sum.inl (selectorPrefix selector canonical) := by
  unfold groupKeyOf
  rw [group_address_generated_role_input selector canonical counter]

/-- Different counters of one canonical selector read the same full-vector
cell and select their literal coordinates. -/
theorem generated_selector_same_group
    (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading)
    (left right : GroupCounter) :
    groupKeyOf (generatedRoleInput selector left.val) =
      groupKeyOf (generatedRoleInput selector right.val) := by
  rw [group_key_of_generated_role_input selector canonical left,
    group_key_of_generated_role_input selector canonical right]

/-! ## Expanded physical suffix and charged grouped reads -/

/-- All physical coordinates of one used canonical role rolePrefix. -/
def fullSelectorInputs (selector : Selector) : List PhysicalInput :=
  (List.range groupBlockCap).map (generatedRoleInput selector)

theorem full_selector_inputs_length (selector : Selector) :
    (fullSelectorInputs selector).length = groupBlockCap := by
  simp [fullSelectorInputs]

def proofFullGeneratedInputs (nameSpace : Namespace) (view : ProofView) :
    List PhysicalInput :=
  allRoles.flatMap fun role =>
    (neededSelectors nameSpace view role).flatMap fullSelectorInputs

def batchFullGeneratedInputs (nameSpace : Namespace) (batch : List ProofView) :
    List PhysicalInput :=
  batch.flatMap (proofFullGeneratedInputs nameSpace)

def expandedPhysicalReadKeys (nameSpace : Namespace) (batch : List ProofView) :
    Finset PhysicalInput :=
  (batchFullGeneratedInputs nameSpace batch).toFinset

def expandedPhysicalReadSchedule (nameSpace : Namespace) (batch : List ProofView) :
    List PhysicalInput :=
  (expandedPhysicalReadKeys nameSpace batch).toList

theorem expanded_physical_read_schedule_nodup
    (nameSpace : Namespace) (batch : List ProofView) :
    (expandedPhysicalReadSchedule nameSpace batch).Nodup :=
  (expandedPhysicalReadKeys nameSpace batch).nodup_toList

theorem expanded_physical_read_count_le_generated
    (nameSpace : Namespace) (batch : List ProofView) :
    (expandedPhysicalReadSchedule nameSpace batch).length ≤
      (batchFullGeneratedInputs nameSpace batch).length := by
  simp only [expandedPhysicalReadSchedule, expandedPhysicalReadKeys,
    Finset.length_toList]
  exact List.toFinset_card_le _

/-- The cap expansion is charged explicitly. In particular this theorem does
not conclude `T ≤ 3Q`; that relation needs a separate cost proof. -/
theorem expanded_suffix_lifetime_bound
    (nameSpace : Namespace) (batch : List ProofView) (priorTouches T : Nat)
    (charged : priorTouches +
      (batchFullGeneratedInputs nameSpace batch).length ≤ T) :
    priorTouches +
      (expandedPhysicalReadSchedule nameSpace batch).length ≤ T := by
  exact (Nat.add_le_add_left
    (expanded_physical_read_count_le_generated nameSpace batch) priorTouches).trans
      charged

theorem selector_counter_mem_expanded_physical_schedule
    (nameSpace : Namespace) (batch : List ProofView)
    (view : ProofView) (viewMem : view ∈ batch) (role : Role)
    (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role)
    (counter : GroupCounter) :
    generatedRoleInput selector counter.val ∈
      expandedPhysicalReadSchedule nameSpace batch := by
  apply Finset.mem_toList.mpr
  simp only [expandedPhysicalReadKeys, batchFullGeneratedInputs,
    proofFullGeneratedInputs, List.mem_toFinset, List.mem_flatMap]
  refine ⟨view, viewMem, role, role_mem_all_roles role, selector, selectorMem, ?_⟩
  apply List.mem_map.mpr
  exact ⟨counter.val, List.mem_range.mpr counter.isLt, rfl⟩

/-- `CanonicalProofView` supplies the restricted-rolePrefix parser receipt at
counter zero whenever the route is nonempty. -/
theorem selector_is_canonical_role_prefix
    (model : RelationModel) (nameSpace : Namespace) (view : ProofView)
    (valid : CanonicalProofView model nameSpace view)
    (role : Role) (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role)
    (routeNonempty : 0 < routeReadCount model view.statement selector.role) :
    IsCanonicalRolePrefix selector.role selector.leading := by
  obtain ⟨query, parsed, sameRole, sameTarget, sameNonce, sameCounter⟩ :=
    valid.routeFraming role selector selectorMem 0 routeNonempty
  exact ⟨query, by simpa only [generatedRoleInput] using parsed, sameRole⟩

/-- Structural receipt for an accepted batch. Positivity is separate because
the relation-generic model permits width zero, unlike concrete RP05. -/
structure CanonicalBatch (model : RelationModel) (nameSpace : Namespace)
    (batch : List ProofView) : Prop where
  viewCanonical : ∀ view ∈ batch, CanonicalProofView model nameSpace view
  routeNonempty : ∀ view ∈ batch, ∀ role selector,
    selector ∈ neededSelectors nameSpace view role →
      0 < routeReadCount model view.statement selector.role

def groupedQueryKeys (nameSpace : Namespace) (batch : List ProofView) :
    Finset GroupKey :=
  (expandedPhysicalReadKeys nameSpace batch).image groupKeyOf

def groupedQuerySchedule (nameSpace : Namespace) (batch : List ProofView) :
    List GroupKey :=
  (groupedQueryKeys nameSpace batch).toList

theorem grouped_query_schedule_nodup
    (nameSpace : Namespace) (batch : List ProofView) :
    (groupedQuerySchedule nameSpace batch).Nodup :=
  (groupedQueryKeys nameSpace batch).nodup_toList

theorem grouped_query_count_le_physical_reads
    (nameSpace : Namespace) (batch : List ProofView) :
    (groupedQuerySchedule nameSpace batch).length ≤
      (expandedPhysicalReadSchedule nameSpace batch).length := by
  simp only [groupedQuerySchedule, groupedQueryKeys,
    expandedPhysicalReadSchedule, Finset.length_toList]
  exact Finset.card_image_le

theorem selector_counter_mem_grouped_query_schedule
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (canonical : CanonicalBatch model nameSpace batch)
    (view : ProofView) (viewMem : view ∈ batch) (role : Role)
    (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role)
    (counter : GroupCounter) :
    Sum.inl (selectorPrefix selector
      (selector_is_canonical_role_prefix model nameSpace view
        (canonical.viewCanonical view viewMem) role selector selectorMem
        (canonical.routeNonempty view viewMem role selector selectorMem))) ∈
      groupedQuerySchedule nameSpace batch := by
  let prefixProof := selector_is_canonical_role_prefix model nameSpace view
    (canonical.viewCanonical view viewMem) role selector selectorMem
    (canonical.routeNonempty view viewMem role selector selectorMem)
  have physical := selector_counter_mem_expanded_physical_schedule nameSpace batch
    view viewMem role selector selectorMem counter
  apply Finset.mem_toList.mpr
  apply Finset.mem_image.mpr
  refine ⟨generatedRoleInput selector counter.val,
    Finset.mem_toList.mp physical, ?_⟩
  exact group_key_of_generated_role_input selector prefixProof counter

/-! ## Fixed role-tagged compression domains and finite implementations -/

/-- Parser-derived role tag of a grouped key. Complement keys, including all
X/VC inputs, have no selected-role tag. -/
def groupRole : GroupKey → Option Role
  | .inl rolePrefix => some rolePrefix.role
  | .inr _ => none

def InRoleGroup (role : Role) (key : GroupKey) : Prop :=
  groupRole key = some role

/-- Union of the four ex-ante selected-role domains. -/
def IsRoleGroupKey (key : GroupKey) : Prop := (groupRole key).isSome

theorem selector_group_key_is_role
    (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading) :
    IsRoleGroupKey (Sum.inl (selectorPrefix selector canonical)) := by
  rfl

@[simp] theorem selector_group_role
    (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading) :
    groupRole (Sum.inl (selectorPrefix selector canonical)) =
      some selector.role := rfl

def groupedRoleQueryKeys (nameSpace : Namespace) (batch : List ProofView)
    (role : Role) : Finset GroupKey :=
  (groupedQueryKeys nameSpace batch).filter (InRoleGroup role)

def groupedRoleQuerySchedule (nameSpace : Namespace) (batch : List ProofView)
    (role : Role) : List GroupKey :=
  (groupedRoleQueryKeys nameSpace batch role).toList

theorem grouped_role_query_schedule_nodup
    (nameSpace : Namespace) (batch : List ProofView) (role : Role) :
    (groupedRoleQuerySchedule nameSpace batch role).Nodup :=
  (groupedRoleQueryKeys nameSpace batch role).nodup_toList

theorem grouped_role_query_count_le_physical_reads
    (nameSpace : Namespace) (batch : List ProofView) (role : Role) :
    (groupedRoleQuerySchedule nameSpace batch role).length ≤
      (expandedPhysicalReadSchedule nameSpace batch).length := by
  calc
    (groupedRoleQuerySchedule nameSpace batch role).length =
        (groupedRoleQueryKeys nameSpace batch role).card := by
          simp [groupedRoleQuerySchedule]
    _ ≤ (groupedQueryKeys nameSpace batch).card := Finset.card_filter_le _ _
    _ = (groupedQuerySchedule nameSpace batch).length := by
      simp [groupedQuerySchedule]
    _ ≤ (expandedPhysicalReadSchedule nameSpace batch).length :=
      grouped_query_count_le_physical_reads nameSpace batch

theorem selector_counter_mem_grouped_role_query_schedule
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (canonical : CanonicalBatch model nameSpace batch)
    (view : ProofView) (viewMem : view ∈ batch) (role : Role)
    (selector : Selector)
    (selectorMem : selector ∈ neededSelectors nameSpace view role)
    (counter : GroupCounter) :
    Sum.inl (selectorPrefix selector
      (selector_is_canonical_role_prefix model nameSpace view
        (canonical.viewCanonical view viewMem) role selector selectorMem
        (canonical.routeNonempty view viewMem role selector selectorMem))) ∈
      groupedRoleQuerySchedule nameSpace batch selector.role := by
  let prefixProof := selector_is_canonical_role_prefix model nameSpace view
    (canonical.viewCanonical view viewMem) role selector selectorMem
    (canonical.routeNonempty view viewMem role selector selectorMem)
  apply Finset.mem_toList.mpr
  apply Finset.mem_filter.mpr
  exact ⟨Finset.mem_toList.mp
      (selector_counter_mem_grouped_query_schedule model nameSpace batch
        canonical view viewMem role selector selectorMem counter),
    selector_group_role selector prefixProof⟩

/-- Every key in the batch-derived read set lies in the fixed ex-ante role
domain. The batch chooses which role cells to read, never which cells belong
to the compression domain. -/
theorem grouped_query_key_is_role
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (canonical : CanonicalBatch model nameSpace batch)
    (group : GroupKey) (member : group ∈ groupedQueryKeys nameSpace batch) :
    IsRoleGroupKey group := by
  obtain ⟨input, inputMember, groupSame⟩ := Finset.mem_image.mp member
  have inBatch : input ∈ batchFullGeneratedInputs nameSpace batch := by
    simpa only [expandedPhysicalReadKeys, List.mem_toFinset] using inputMember
  obtain ⟨view, viewMem, inProof⟩ := List.mem_flatMap.mp inBatch
  obtain ⟨role, roleMem, inRole⟩ := List.mem_flatMap.mp inProof
  obtain ⟨selector, selectorMem, inSelector⟩ := List.mem_flatMap.mp inRole
  obtain ⟨counter, counterMem, inputSame⟩ := List.mem_map.mp inSelector
  let coordinate : GroupCounter :=
    ⟨counter, List.mem_range.mp counterMem⟩
  let prefixProof := selector_is_canonical_role_prefix model nameSpace view
    (canonical.viewCanonical view viewMem) role selector selectorMem
    (canonical.routeNonempty view viewMem role selector selectorMem)
  have address := group_address_generated_role_input selector prefixProof coordinate
  have generatedRole : IsRoleGroupKey
      (groupKeyOf (generatedRoleInput selector coordinate.val)) := by
    rw [show groupKeyOf (generatedRoleInput selector coordinate.val) =
      Sum.inl (selectorPrefix selector prefixProof) from congrArg Prod.fst address]
    exact selector_group_key_is_role selector prefixProof
  have inputRole : IsRoleGroupKey (groupKeyOf input) := by
    exact inputSame ▸ generatedRole
  exact groupSame ▸ inputRole

/-- A finite implementation embeds its CMS key universe into the exact group
key type and covers every queried group. -/
structure FiniteGroupPullback (nameSpace : Namespace) (batch : List ProofView)
    (Key : Type*) [Fintype Key] [DecidableEq Key]
    (keyGroup : Key → GroupKey) : Prop where
  injective : Function.Injective keyGroup
  coversQueries : ∀ group ∈ groupedQueryKeys nameSpace batch,
    ∃ key, keyGroup key = group

def pulledGroupedReadKeys {Key : Type*} [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey) : Finset Key :=
  Finset.univ.filter fun key =>
    keyGroup key ∈ groupedQueryKeys nameSpace batch

def pulledGroupedReadSchedule {Key : Type*} [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey) : List Key :=
  (pulledGroupedReadKeys nameSpace batch keyGroup).toList

/-- Full analytical compression domain in the finite implementation. Unlike
the read schedule, this is not computed from the accepted batch. -/
def fixedGroupedCompressionKeys {Key : Type*} [Fintype Key] [DecidableEq Key]
    (keyGroup : Key → GroupKey) : Finset Key :=
  Finset.univ.filter fun key => IsRoleGroupKey (keyGroup key)

def fixedGroupedCompressionSchedule {Key : Type*}
    [Fintype Key] [DecidableEq Key] (keyGroup : Key → GroupKey) : List Key :=
  (fixedGroupedCompressionKeys keyGroup).toList

/-- Full ex-ante compression domain for one selected role. It is independent
of the accepted batch and leaves the other three role tables available as
fixed advice. -/
def fixedRoleCompressionKeys {Key : Type*} [Fintype Key] [DecidableEq Key]
    (keyGroup : Key → GroupKey) (role : Role) : Finset Key :=
  Finset.univ.filter fun key => InRoleGroup role (keyGroup key)

def fixedRoleCompressionSchedule {Key : Type*}
    [Fintype Key] [DecidableEq Key]
    (keyGroup : Key → GroupKey) (role : Role) : List Key :=
  (fixedRoleCompressionKeys keyGroup role).toList

def pulledGroupedRoleReadKeys {Key : Type*} [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey) (role : Role) : Finset Key :=
  Finset.univ.filter fun key =>
    keyGroup key ∈ groupedRoleQueryKeys nameSpace batch role

def pulledGroupedRoleReadSchedule {Key : Type*}
    [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey) (role : Role) : List Key :=
  (pulledGroupedRoleReadKeys nameSpace batch keyGroup role).toList

theorem pulled_grouped_read_schedule_nodup
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey) :
    (pulledGroupedReadSchedule nameSpace batch keyGroup).Nodup :=
  (pulledGroupedReadKeys nameSpace batch keyGroup).nodup_toList

theorem fixed_grouped_compression_schedule_nodup
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (keyGroup : Key → GroupKey) :
    (fixedGroupedCompressionSchedule keyGroup).Nodup :=
  (fixedGroupedCompressionKeys keyGroup).nodup_toList

theorem fixed_role_compression_schedule_nodup
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (keyGroup : Key → GroupKey) (role : Role) :
    (fixedRoleCompressionSchedule keyGroup role).Nodup :=
  (fixedRoleCompressionKeys keyGroup role).nodup_toList

theorem pulled_grouped_role_read_schedule_nodup
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey) (role : Role) :
    (pulledGroupedRoleReadSchedule nameSpace batch keyGroup role).Nodup :=
  (pulledGroupedRoleReadKeys nameSpace batch keyGroup role).nodup_toList

theorem pulled_grouped_role_read_mem_fixed_role_compression
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey) (role : Role) (key : Key)
    (member : key ∈
      pulledGroupedRoleReadSchedule nameSpace batch keyGroup role) :
    key ∈ fixedRoleCompressionSchedule keyGroup role := by
  have selected := (Finset.mem_filter.mp (Finset.mem_toList.mp member)).2
  have roleTagged := (Finset.mem_filter.mp selected).2
  apply Finset.mem_toList.mpr
  apply Finset.mem_filter.mpr
  exact ⟨Finset.mem_univ key, roleTagged⟩

theorem pulled_grouped_role_read_count_le_physical_reads
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey)
    (pullback : FiniteGroupPullback nameSpace batch Key keyGroup)
    (role : Role) :
    (pulledGroupedRoleReadSchedule nameSpace batch keyGroup role).length ≤
      (expandedPhysicalReadSchedule nameSpace batch).length := by
  let selected := pulledGroupedRoleReadKeys nameSpace batch keyGroup role
  have imageSubset : selected.image keyGroup ⊆
      groupedRoleQueryKeys nameSpace batch role := by
    intro group groupMember
    obtain ⟨key, keyMember, rfl⟩ := Finset.mem_image.mp groupMember
    exact (Finset.mem_filter.mp keyMember).2
  calc
    (pulledGroupedRoleReadSchedule nameSpace batch keyGroup role).length =
        selected.card := by
          simp [pulledGroupedRoleReadSchedule, selected]
    _ = (selected.image keyGroup).card :=
      (Finset.card_image_of_injective selected pullback.injective).symm
    _ ≤ (groupedRoleQueryKeys nameSpace batch role).card :=
      Finset.card_le_card imageSubset
    _ = (groupedRoleQuerySchedule nameSpace batch role).length := by
      simp [groupedRoleQuerySchedule]
    _ ≤ (expandedPhysicalReadSchedule nameSpace batch).length :=
      grouped_role_query_count_le_physical_reads nameSpace batch role

theorem pulled_grouped_read_mem_fixed_compression
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (model : RelationModel) (nameSpace : Namespace) (batch : List ProofView)
    (canonical : CanonicalBatch model nameSpace batch)
    (keyGroup : Key → GroupKey) (key : Key)
    (member : key ∈ pulledGroupedReadSchedule nameSpace batch keyGroup) :
    key ∈ fixedGroupedCompressionSchedule keyGroup := by
  have selected := (Finset.mem_filter.mp (Finset.mem_toList.mp member)).2
  apply Finset.mem_toList.mpr
  apply Finset.mem_filter.mpr
  exact ⟨Finset.mem_univ key,
    grouped_query_key_is_role model nameSpace batch canonical (keyGroup key)
      selected⟩

theorem grouped_query_has_pulled_read_key
    {Key : Type*} [Fintype Key] [DecidableEq Key]
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey)
    (pullback : FiniteGroupPullback nameSpace batch Key keyGroup)
    (group : GroupKey) (member : group ∈ groupedQuerySchedule nameSpace batch) :
    ∃ key ∈ pulledGroupedReadSchedule nameSpace batch keyGroup,
      keyGroup key = group := by
  have groupMember : group ∈ groupedQueryKeys nameSpace batch :=
    Finset.mem_toList.mp member
  obtain ⟨key, same⟩ := pullback.coversQueries group groupMember
  refine ⟨key, ?_, same⟩
  apply Finset.mem_toList.mpr
  apply Finset.mem_filter.mpr
  exact ⟨Finset.mem_univ key, same ▸ groupMember⟩

/-! ## Coordinate readback and genuine padding -/

def groupedRawOracle {Output : Type*}
    (vectors : GroupKey → GroupCounter → Output) : PhysicalInput → Output :=
  fun input => vectors (groupKeyOf input) (groupCounterOf input)

/-- Literal source-program view of the same grouped vector oracle at the
production raw-input bound. This is the oracle accepted by
`SourceVerifierOpeningAccepted`; no second table or advice function is added. -/
def groupedOtherRawOracle
    (vectors : GroupKey → GroupCounter →
      V8Smz9HiddenLeafQrom.DigestRegister) :
    V8Smz9HonestFinalGame.OtherRawInput 25029 →
      V8Smz9HiddenLeafQrom.DigestRegister :=
  fun input => groupedRawOracle vectors
    (V8Smz9HonestFinalGame.rawBytes (Sum.inr input))

@[simp] theorem grouped_other_raw_oracle_apply
    (vectors : GroupKey → GroupCounter →
      V8Smz9HiddenLeafQrom.DigestRegister)
    (input : V8Smz9HonestFinalGame.OtherRawInput 25029) :
    groupedOtherRawOracle vectors input =
      groupedRawOracle vectors
        (V8Smz9HonestFinalGame.rawBytes (Sum.inr input)) := rfl

theorem generated_role_answer_eq_group_vector {Output : Type*}
    (vectors : GroupKey → GroupCounter → Output)
    (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading)
    (counter : GroupCounter) :
    groupedRawOracle vectors (generatedRoleInput selector counter.val) =
      vectors (Sum.inl (selectorPrefix selector canonical)) counter := by
  unfold groupedRawOracle groupKeyOf groupCounterOf
  rw [group_address_generated_role_input selector canonical counter]

def factoredVectors {Output : Type*} (oracle : PhysicalInput → Output) :
    CanonicalRolePrefix → GroupCounter → Output :=
  (rawTableFactorization groupEncode group_encode_injective oracle).1

theorem factored_vector_generated_readback {Output : Type*}
    (oracle : PhysicalInput → Output) (selector : Selector)
    (canonical : IsCanonicalRolePrefix selector.role selector.leading)
    (counter : GroupCounter) :
    factoredVectors oracle (selectorPrefix selector canonical) counter =
      oracle (generatedRoleInput selector counter.val) := by
  rw [← group_encode_eq_generated_role_input selector canonical counter]
  exact raw_table_factorization_block groupEncode group_encode_injective oracle
    (selectorPrefix selector canonical) counter

/-- Role cells use every coordinate. Complement cells use only counter zero;
their other vector coordinates are the genuine independent padding introduced
by `paddedCoordinate`. -/
def declaredCoordinates : GroupKey → Finset GroupCounter
  | .inl _ => Finset.univ
  | .inr _ => {groupZero}

def paddingCoordinates (key : GroupKey) : Finset GroupCounter :=
  Finset.univ \ declaredCoordinates key

theorem declared_padding_disjoint (key : GroupKey) :
    Disjoint (declaredCoordinates key) (paddingCoordinates key) := by
  apply Finset.disjoint_left.mpr
  intro counter declared padding
  exact (Finset.mem_sdiff.mp padding).2 declared

theorem declared_union_padding (key : GroupKey) :
    declaredCoordinates key ∪ paddingCoordinates key = Finset.univ := by
  ext counter
  simp [paddingCoordinates]

theorem role_has_no_padding (rolePrefix : CanonicalRolePrefix) :
    paddingCoordinates (Sum.inl rolePrefix) = ∅ := by
  simp [paddingCoordinates, declaredCoordinates]

theorem complement_declares_only_zero (input : GroupComplement) :
    declaredCoordinates (Sum.inr input) = {groupZero} := rfl

abbrev DeclaredCoordinate (key : GroupKey) :=
  {counter : GroupCounter // counter ∈ declaredCoordinates key}

abbrev PaddingCoordinate (key : GroupKey) :=
  {counter : GroupCounter // counter ∉ declaredCoordinates key}

def coordinatePartitionEquiv (key : GroupKey) :
    (DeclaredCoordinate key ⊕ PaddingCoordinate key) ≃ GroupCounter :=
  Equiv.Set.sumCompl {counter | counter ∈ declaredCoordinates key}

def vectorDeclaredPaddingEquiv {Output : Type*} (key : GroupKey) :
    (GroupCounter → Output) ≃
      (DeclaredCoordinate key → Output) ×
        (PaddingCoordinate key → Output) :=
  ((Equiv.arrowCongr (coordinatePartitionEquiv key) (Equiv.refl Output)).symm.trans
    (Equiv.sumArrowEquivProdArrow
      (DeclaredCoordinate key) (PaddingCoordinate key) Output))

theorem uniform_vector_declared_padding
    {Output : Type*} [Fintype Output] [Nonempty Output] (key : GroupKey) :
    pmfMap (uniformFintypePMF (GroupCounter → Output))
        (vectorDeclaredPaddingEquiv key) =
      uniformFintypePMF
        ((DeclaredCoordinate key → Output) ×
          (PaddingCoordinate key → Output)) := by
  exact V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv
    (vectorDeclaredPaddingEquiv key)

end
end HegemonCrypto.SmallWood.SmzaRp05GroupedSuffix
