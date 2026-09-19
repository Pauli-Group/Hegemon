import SmallWoodV8SmzaOnlineParserR2
import SmzaControlledCmsR2
import SmzaPrefixTransportR2
import SmzaCoherentRecord
import SmzaRecordSupportR5

/-!
Actual SMZA raw-prefix geometry to the physical CMS controlled-permutation
bound. Targets are derived from the actual raw fixed-sampler query frames;
no later expected PB02 context is supplied to extraction. The complete raw
trace is the label. This does not supply offline extraction, source refinement,
or the unrestricted q38 constructor.
-/
namespace HegemonCrypto.SmallWood.SmzaOnlineAssemblyR6

open V8SmzaOnlineParser
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentMerklePartition V8Smz9HiddenLeafQrom
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsFullOperatorProof
open SmzaControlledCmsR2
open scoped BigOperators Classical
noncomputable section

set_option maxRecDepth 5000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 1024

local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq

/- Only actual h_decs bytes are used; counter is retained by parseFinalQuery,
but is not a grinding nonce and does not change the commitment target. -/
def actualTargets (rawQueries : List RawInput) : List (V8SmzaOracleParser.Stage × RawDigest) :=
  rawQueries.filterMap fun raw =>
    (parseFinalQuery raw).map fun query => (V8SmzaOracleParser.Stage.decs, query.target)

theorem actual_targets_length_le (rawQueries : List RawInput) :
    (actualTargets rawQueries).length ≤ rawQueries.length :=
  List.length_filterMap_le _ _

/- Four wrappers plus tree depths23..0: no artificial recursion truncation
is needed on a complete syntactically valid chain. -/
def prefixFuel : ℕ := 28

def rawPrefixLabel (records : Records RawInput RawDigest) (rawQueries : List RawInput) :=
  extractTargets onlineNext records prefixFuel (actualTargets rawQueries)

theorem smza_uniform_change_probability_le
    (records : Records RawInput RawDigest) (input : RawInput)
    (rawQueries : List RawInput) (cap : ℕ)
    (recordBound : records.card < cap) (targetBound : rawQueries.length ≤ cap) :
    uniformChangeProbability onlineNext records input prefixFuel (actualTargets rawQueries) ≤
      (3 * cap : ℚ) / (2 ^ 512 : ℚ) := by
  have count := online_changed_outputs_card_le records input prefixFuel (actualTargets rawQueries)
  have targetCount := (actual_targets_length_le rawQueries).trans targetBound
  have countBound :
      (changedOutputs onlineNext records input prefixFuel (actualTargets rawQueries)).card ≤ 3 * cap := by
    omega
  unfold uniformChangeProbability
  rw [raw_digest_cardinality]
  apply div_le_div_of_nonneg_right
  · exact_mod_cast countBound
  · positivity

/- Equality of the complete prefix vector determines every individual online
label on its actual raw-query list, including invalid-query missing labels. -/
theorem raw_prefix_label_eq_online_labels
    (left right : Records RawInput RawDigest) (rawQueries : List RawInput)
    (same : rawPrefixLabel left rawQueries = rawPrefixLabel right rawQueries)
    (raw : RawInput) (member : raw ∈ rawQueries) :
    onlineLabel left prefixFuel raw = onlineLabel right prefixFuel raw := by
  have aux : ∀ queries : List RawInput,
      rawPrefixLabel left queries = rawPrefixLabel right queries →
      ∀ raw, raw ∈ queries → onlineLabel left prefixFuel raw = onlineLabel right prefixFuel raw := by
    intro queries
    induction queries with
    | nil => intro _ raw member; simp at member
    | cons head tail ih =>
      intro same raw member
      cases parsed : parseFinalQuery head with
      | none =>
        have tailSame : rawPrefixLabel left tail = rawPrefixLabel right tail := by
          simpa [rawPrefixLabel, actualTargets, parsed, extractTargets] using same
        rcases List.mem_cons.mp member with equal | inTail
        · subst raw
          simp [onlineLabel, parsed]
        · exact ih tailSame raw inTail
      | some query =>
        have parts :
            extract onlineNext left prefixFuel V8SmzaOracleParser.Stage.decs query.target =
              extract onlineNext right prefixFuel V8SmzaOracleParser.Stage.decs query.target ∧
            rawPrefixLabel left tail = rawPrefixLabel right tail := by
          simpa [rawPrefixLabel, actualTargets, parsed, extractTargets] using same
        rcases List.mem_cons.mp member with equal | inTail
        · subst raw
          simpa [onlineLabel, parsed] using parts.1
        · exact ih parts.2 raw inTail
  exact aux rawQueries same raw member

variable {Key : Type*} [Fintype Key] [DecidableEq Key]

def physicalPrefixLabel (keyBytes : Key → RawInput) (rawQueries : List RawInput)
    (database : Database Key DigestRegister) :=
  rawPrefixLabel (rawRecords keyBytes rawDigestBits.symm database) rawQueries

/- Symbolic finite representation of the ACTUAL complete traces. It does not
assert that any trace is successful, nor enumerate an exponential oracle. -/
def PrefixRange (keyBytes : Key → RawInput) (rawQueries : List RawInput) :=
  Set.range (physicalPrefixLabel keyBytes rawQueries)

instance (keyBytes : Key → RawInput) (rawQueries : List RawInput) :
    Fintype (PrefixRange keyBytes rawQueries) :=
  Fintype.ofSurjective
    (fun database : Database Key DigestRegister =>
      (⟨physicalPrefixLabel keyBytes rawQueries database, ⟨database, rfl⟩⟩ :
        PrefixRange keyBytes rawQueries))
    (by rintro ⟨label, ⟨database, rfl⟩⟩; exact ⟨database, rfl⟩)

def prefixValue (keyBytes : Key → RawInput) (rawQueries : List RawInput)
    (database : Database Key DigestRegister) : PrefixRange keyBytes rawQueries :=
  ⟨physicalPrefixLabel keyBytes rawQueries database, ⟨database, rfl⟩⟩

/- Prove the counting bridge with an abstract output equivalence. This avoids
unfolding the concrete 512-bit conversion during finite-image elaboration. -/
theorem prefix_step_change_bound_with_equiv {Output : Type*}
    [Fintype Output] [DecidableEq Output] (keyBytes : Key ↪ RawInput)
    (outputBytes : Output ≃ RawDigest) (rawQueries : List RawInput) (cap : ℕ) (targetBound : rawQueries.length ≤ cap)
    (database : Database Key Output) (recordBound : size database < cap)
    (key : Key) (event : Property Key Output)
    (changed : ∀ output, event (query database key output) →
      rawPrefixLabel (rawRecords keyBytes outputBytes (query database key output)) rawQueries ≠
        rawPrefixLabel (rawRecords keyBytes outputBytes database) rawQueries) :
    stepProbability event database key ≤ (3 * cap : ℚ) / (2 ^ 512 : ℚ) := by
  by_cases absent : database key = none
  · have subset : (successfulAnswers event database key).image outputBytes ⊆
        changedOutputs onlineNext (rawRecords keyBytes outputBytes database)
          (keyBytes key) prefixFuel (actualTargets rawQueries) := by
      intro digest member
      obtain ⟨output, success, same⟩ : ∃ output : Output,
          output ∈ successfulAnswers event database key ∧ outputBytes output = digest :=
        Finset.mem_image.mp member
      rw [← same]
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ _, ?_⟩
      have changes := changed output (Finset.mem_filter.mp success).2
      simpa only [query_of_absent absent, rawPrefixLabel,
        raw_records_insert keyBytes outputBytes database key output absent] using changes
    have countBound : (successfulAnswers event database key).card ≤
        (changedOutputs onlineNext (rawRecords keyBytes outputBytes database)
          (keyBytes key) prefixFuel (actualTargets rawQueries)).card := by
      rw [← Finset.card_image_of_injective _ outputBytes.injective]
      exact Finset.card_le_card subset
    have outputCard := Fintype.card_congr outputBytes
    calc
      stepProbability event database key ≤
          uniformChangeProbability onlineNext (rawRecords keyBytes outputBytes database)
            (keyBytes key) prefixFuel (actualTargets rawQueries) := by
        unfold stepProbability uniformChangeProbability
        rw [outputCard]
        exact div_le_div_of_nonneg_right (by exact_mod_cast countBound) (by positivity)
      _ ≤ _ := smza_uniform_change_probability_le _ _ rawQueries cap
        (lt_of_le_of_lt (raw_records_card_le keyBytes outputBytes database) recordBound)
        targetBound
  · rw [step_probability_eq_zero_of_never event database key]
    · positivity
    · intro output accepted
      apply changed output accepted
      simp [query, absent]

theorem prefix_step_change_bound (keyBytes : Key ↪ RawInput)
    (rawQueries : List RawInput) (cap : ℕ) (targetBound : rawQueries.length ≤ cap)
    (database : Database Key DigestRegister) (recordBound : size database < cap)
    (key : Key) (event : Property Key DigestRegister)
    (changed : ∀ output, event (query database key output) →
      physicalPrefixLabel keyBytes rawQueries (query database key output) ≠
        physicalPrefixLabel keyBytes rawQueries database) :
    stepProbability event database key ≤ (3 * cap : ℚ) / (2 ^ 512 : ℚ) := by
  exact prefix_step_change_bound_with_equiv keyBytes rawDigestBits.symm rawQueries cap
    targetBound database recordBound key event changed

theorem prefix_value_instability (keyBytes : Key ↪ RawInput)
    (rawQueries : List RawInput) (cap : ℕ) (targetBound : rawQueries.length ≤ cap)
    (test : PrefixRange keyBytes rawQueries → Prop) :
    InstabilityBound (fun database => test (prefixValue keyBytes rawQueries database)) cap
      ((3 * cap : ℚ) / (2 ^ 512 : ℚ)) := by
  have stable : ∀ left right,
      physicalPrefixLabel keyBytes rawQueries left = physicalPrefixLabel keyBytes rawQueries right →
      prefixValue keyBytes rawQueries left = prefixValue keyBytes rawQueries right := by
    intro left right same
    exact Subtype.ext same
  constructor
  · refine ⟨by positivity, ?_⟩
    intro database outside recordBound key
    apply prefix_step_change_bound keyBytes rawQueries cap targetBound database recordBound key _
    intro output accepted same
    apply outside
    change test (prefixValue keyBytes rawQueries (query database key output)) at accepted
    simpa only [stable _ _ same] using accepted
  · refine ⟨by positivity, ?_⟩
    intro database inside recordBound key
    apply prefix_step_change_bound keyBytes rawQueries cap targetBound database recordBound key _
    intro output rejected same
    apply rejected
    rw [stable _ _ same]
    exact inside

variable {Workspace : Type*} [Fintype Workspace] [DecidableEq Workspace]

/- Physical local bound for ANY permutation controlled by the complete actual
SMZA prefix trace. In particular its label need not assert preimage availability.
The only size hypotheses are reachable database support and raw-target count. -/
theorem smza_prefix_controlled_actual_query_bound (keyBytes : Key ↪ RawInput)
    (rawQueries : List RawInput) (cap support : ℕ)
    (targetBound : rawQueries.length ≤ cap) (below : support < cap)
    (permutation : PrefixRange keyBytes rawQueries →
      (PrefixRange keyBytes rawQueries × Workspace) ≃ (PrefixRange keyBytes rawQueries × Workspace))
    (state : State Key DigestRegister DigestRegister (PrefixRange keyBytes rawQueries × Workspace))
    (bounded : BoundedState support state) :
    normSquared
      (permute (controlledBasis (prefixValue keyBytes rawQueries) permutation)
          (queryState digestPhaseSystem cap state) -
        queryState digestPhaseSystem cap
          (permute (controlledBasis (prefixValue keyBytes rawQueries) permutation) state)) ≤
      (576 * cap / (2 ^ 512 : ℝ)) * normSquared state := by
  have result := controlled_actual_query_bound digestPhaseSystem cap support
    (prefixValue keyBytes rawQueries) permutation
    (((3 * cap : ℚ) / (2 ^ 512 : ℚ)) : ℝ)
    (fun test => by
      simpa only [Rat.cast_div] using
        (prefix_value_instability keyBytes rawQueries cap targetBound test).toReal)
    state below bounded
  convert result using 1
  push_cast
  ring

section Execution

variable {H : Type*} [PseudoMetricSpace H]

/- Two-game telescope: FS steps use the checked exact Record/Split conjugation;
VC steps use the preceding actual-source bound; private unitary computation
commutes. This lemma keeps the local operator facts explicit rather than
supplying a global extraction-success coefficient. -/
theorem intertwined_execution_transport
    (original indexed : ℕ → H → H) (split : H → H) (initial : H)
    (epsilon : ℝ) (count : ℕ)
    (contractive : ∀ n < count, ∀ left right,
      dist (indexed n left) (indexed n right) ≤ dist left right)
    (localBound : ∀ n < count,
      dist (split (original n (SmzaPrefixTransportR2.evolve original initial n)))
        (indexed n (split (SmzaPrefixTransportR2.evolve original initial n))) ≤ epsilon) :
    dist (split (SmzaPrefixTransportR2.evolve original initial count))
      (SmzaPrefixTransportR2.evolve indexed (split initial) count) ≤ (count : ℝ) * epsilon := by
  have inductionBound : ∀ n ≤ count,
      dist (split (SmzaPrefixTransportR2.evolve original initial n))
        (SmzaPrefixTransportR2.evolve indexed (split initial) n) ≤ (n : ℝ) * epsilon := by
    intro n
    induction n with
    | zero => intro _; simp [SmzaPrefixTransportR2.evolve]
    | succ n ih =>
      intro hn
      have before : n < count := Nat.lt_of_lt_of_le (Nat.lt_succ_self n) hn
      have previous := ih (Nat.le_of_lt before)
      calc
        _ ≤ dist (split (original n (SmzaPrefixTransportR2.evolve original initial n)))
              (indexed n (split (SmzaPrefixTransportR2.evolve original initial n))) +
            dist (indexed n (split (SmzaPrefixTransportR2.evolve original initial n)))
              (indexed n (SmzaPrefixTransportR2.evolve indexed (split initial) n)) := dist_triangle _ _ _
        _ ≤ epsilon + dist (split (SmzaPrefixTransportR2.evolve original initial n))
              (SmzaPrefixTransportR2.evolve indexed (split initial) n) :=
          add_le_add (localBound n before) (contractive n before _ _)
        _ ≤ epsilon + (n : ℝ) * epsilon := add_le_add (le_refl epsilon) previous
        _ = ((n + 1 : ℕ) : ℝ) * epsilon := by push_cast; ring
  exact inductionBound count (Nat.le_refl count)

end Execution

end
end HegemonCrypto.SmallWood.SmzaOnlineAssemblyR6


/-! Restrict the actual Record/Split permutation to the physically active
record-target sector. Labels of inactive targets are irrelevant exactly, not
approximately and not by a successful-extraction premise. -/
namespace HegemonCrypto.SmallWood.SmzaOnlineAssemblyActiveR6

open SmzaRecordSplitR3 SmzaRecordSupportR5 V8Smz9CoherentMerklePartition
open scoped BigOperators Classical
noncomputable section

variable {Target Label Cell Database : Type*}
variable [DecidableEq Target] [DecidableEq Label] [Fintype Target]

def restrictedSlotSplit (selected : Finset Target) (label : Target → Label) :
    Slot Target Label ≃ Slot Target Label :=
  Equiv.prodCongrRight fun target =>
    if target ∈ selected then Equiv.swap none (some (label target)) else Equiv.refl _

def restrictedSplitRegisters (selected : Finset Target) (label : Target → Label) :
    Registers Target Label Cell ≃ Registers Target Label Cell :=
  reindex (restrictedSlotSplit selected label)

omit [DecidableEq Target] [DecidableEq Label] in
theorem inactive_coordinate (empty : Cell) (registers : Registers Target Label Cell)
    (selected : Finset Target) (supported : activeTargets empty registers ⊆ selected)
    (target : Target) (outside : target ∉ selected) (index : Option Label) :
    registers (target, index) = empty := by
  by_contra different
  apply outside
  apply supported
  exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, index, different⟩

theorem full_split_eq_restricted_on_sector (empty : Cell) (selected : Finset Target)
    (label : Target → Label) (registers : Registers Target Label Cell)
    (supported : activeTargets empty registers ⊆ selected) :
    splitRegisters label registers = restrictedSplitRegisters selected label registers := by
  funext slot
  rcases slot with ⟨target, index⟩
  by_cases member : target ∈ selected
  · simp [splitRegisters, restrictedSplitRegisters, reindex, slotSplit, restrictedSlotSplit, member]
  · change registers (target, Equiv.swap none (some (label target)) index) =
      registers (restrictedSlotSplit selected label (target, index))
    simp only [restrictedSlotSplit, Equiv.prodCongrRight_apply, member, ite_false, Equiv.refl_apply]
    rw [inactive_coordinate empty registers selected supported target member,
      inactive_coordinate empty registers selected supported target member]

/- A restricted Split depends only on the extraction labels of the selected
targets. This is the factorization needed by the source-label partition. -/
omit [Fintype Target] in
theorem restricted_split_eq_of_labels_agree (selected : Finset Target)
    (left right : Target → Label) (agree : ∀ target ∈ selected, left target = right target) :
    restrictedSplitRegisters (Cell := Cell) selected left =
      restrictedSplitRegisters selected right := by
  have slots : restrictedSlotSplit selected left = restrictedSlotSplit selected right := by
    apply Equiv.ext
    rintro ⟨target, index⟩
    by_cases member : target ∈ selected
    · simp [restrictedSlotSplit, member, agree target member]
    · simp [restrictedSlotSplit, member]
  exact congrArg reindex slots

/- Actual SMZA source-trace equality supplies the restricted-permutation
factorization, rather than an assumed successful-extraction record. -/
omit [Fintype Target] in
theorem source_restricted_split_factorization
    (left right : V8Smz9CoherentMerkleGeometry.Records
      V8Smz9CoherentMerkleGeometry.RawInput V8Smz9CoherentMerkleGeometry.RawDigest)
    (selected : Finset Target)
    (rawBytes : Target → V8Smz9CoherentMerkleGeometry.RawInput)
    (code : V8Smz9CoherentMerkleGeometry.ExtractionTrace V8Smz9CoherentMerkleGeometry.RawInput → Label)
    (same : SmzaOnlineAssemblyR6.rawPrefixLabel left (selected.toList.map rawBytes) =
      SmzaOnlineAssemblyR6.rawPrefixLabel right (selected.toList.map rawBytes)) :
    restrictedSplitRegisters (Cell := Cell) selected
        (fun target => code (V8SmzaOnlineParser.onlineLabel left SmzaOnlineAssemblyR6.prefixFuel (rawBytes target))) =
      restrictedSplitRegisters selected
        (fun target => code (V8SmzaOnlineParser.onlineLabel right SmzaOnlineAssemblyR6.prefixFuel (rawBytes target))) := by
  apply restricted_split_eq_of_labels_agree
  intro target member
  apply congrArg code
  apply SmzaOnlineAssemblyR6.raw_prefix_label_eq_online_labels left right _ same
  exact List.mem_map.mpr ⟨target, Finset.mem_toList.mpr member, rfl⟩


section QuantumSupport

variable {Basis : Type*} [Fintype Basis]

/- Two basis permutations that agree wherever the amplitude is nonzero act
identically on the full state; no measurement of the support sector occurs. -/
omit [Fintype Basis] in
theorem permute_eq_on_support (left right : Basis ≃ Basis) (state : Basis → ℂ)
    (agree : ∀ basis, state basis ≠ 0 → left basis = right basis) :
    permute left state = permute right state := by
  funext target
  change state (left.symm target) = state (right.symm target)
  by_cases nonzero : state (left.symm target) ≠ 0
  · have equal : right.symm target = left.symm target := by
      simpa using congrArg right.symm (agree (left.symm target) nonzero)
    rw [equal]
  · have zeroLeft : state (left.symm target) = 0 := not_ne_iff.mp nonzero
    by_cases zeroRight : state (right.symm target) = 0
    · rw [zeroLeft, zeroRight]
    · have equal : left.symm target = right.symm target := by
        simpa using (congrArg left.symm (agree (right.symm target) zeroRight)).symm
      rw [equal] at zeroLeft
      exact False.elim (zeroRight zeroLeft)

end QuantumSupport

variable [Fintype Label] [Fintype Cell]

omit [Fintype Label] [Fintype Cell] in
theorem full_split_operator_eq_restricted_on_sector (empty : Cell)
    (selected : Finset Target) (label : Target → Label)
    (state : Registers Target Label Cell → ℂ)
    (supported : ∀ registers, state registers ≠ 0 → activeTargets empty registers ⊆ selected) :
    permute (splitRegisters label) state =
      permute (restrictedSplitRegisters selected label) state := by
  apply permute_eq_on_support
  intro registers nonzero
  exact full_split_eq_restricted_on_sector empty selected label registers (supported registers nonzero)

end
end HegemonCrypto.SmallWood.SmzaOnlineAssemblyActiveR6


namespace HegemonCrypto.SmallWood.SmzaOnlineAssemblySupportR6

open SmzaRecordSplitR3 SmzaRecordSupportR5 SmzaCoherentRecord
open V8Smz9CoherentMerklePartition
open scoped BigOperators Classical
noncomputable section

variable {Database Target Label Answer Cell : Type*}
variable [DecidableEq Label] [DecidableEq Target] [Fintype Target]

omit [DecidableEq Target] in
theorem coherent_split_preserves_active (empty : Cell)
    (extract : Database → Target → Label)
    (basis : JointBasis Database Target Label Answer Cell) :
    activeTargets empty (coherentSplit extract basis).2.2.2 =
      activeTargets empty basis.2.2.2 :=
  split_preserves_active_targets empty (extract basis.1) basis.2.2.2

omit [DecidableEq Label] in
theorem coherent_nonzero_kernel_active_card (empty : Cell)
    (selector : Database → Target → Option Label)
    (gate : Target → (Answer × Cell) → (Answer × Cell) → ℂ)
    (source target : JointBasis Database Target Label Answer Cell)
    (nonzero : jointRecordKernel selector gate source target ≠ 0) :
    (activeTargets empty target.2.2.2).card ≤
      (activeTargets empty source.2.2.2).card + 1 := by
  have localNonzero : localRecordKernel (source.2.1, selector source.1 source.2.1)
      (gate source.2.1) source.2.2 target.2.2 ≠ 0 := by
    unfold jointRecordKernel at nonzero
    split_ifs at nonzero with same
    · exact nonzero
    · exact False.elim (nonzero rfl)
  exact nonzero_record_kernel_active_card empty _ _ _ _ localNonzero

variable [Fintype Database] [Fintype Label] [Fintype Answer] [Fintype Cell]

/- The active-target support grows by at most one under the entire coherent
oracle call, not only when the query target is classical. -/
theorem coherent_query_support_growth (empty : Cell)
    (selector : Database → Target → Option Label)
    (gate : Target → (Answer × Cell) → (Answer × Cell) → ℂ)
    (state : JointBasis Database Target Label Answer Cell → ℂ) (bound : ℕ)
    (supported : ∀ basis, bound < (activeTargets empty basis.2.2.2).card → state basis = 0) :
    ∀ basis, bound + 1 < (activeTargets empty basis.2.2.2).card →
      applyKernel (jointRecordKernel selector gate) state basis = 0 := by
  intro target tooLarge
  unfold applyKernel
  apply Finset.sum_eq_zero
  intro source _
  by_cases zero : state source = 0
  · rw [zero, zero_mul]
  · have before : (activeTargets empty source.2.2.2).card ≤ bound := by
      by_contra greater
      exact zero (supported source (Nat.lt_of_not_ge greater))
    by_cases zeroKernel : jointRecordKernel selector gate source target = 0
    · rw [zeroKernel, mul_zero]
    · have growth := coherent_nonzero_kernel_active_card empty selector gate source target zeroKernel
      have impossible : (activeTargets empty target.2.2.2).card ≤ bound + 1 :=
        growth.trans (Nat.add_le_add_right before 1)
      exact False.elim (Nat.not_lt_of_ge impossible tooLarge)

end
end HegemonCrypto.SmallWood.SmzaOnlineAssemblySupportR6


