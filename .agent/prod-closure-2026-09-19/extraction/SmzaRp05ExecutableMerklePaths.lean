import SmzaRp05ExecutableMerkleVerifier
import SmzaRp05FilteredDecoderInstability
import SmzaRecordedTracePath
import Mathlib.Data.List.GetD
import Init.Data.Nat.Bitwise.Lemmas

/-! Checked path proof for the executable compact verifier.
`accepted_recorded_paths` takes only a successful ordinary program result
and constructs all 38 canonical depth-23 RecordedPath witnesses in that
same program's instrumented log, with one root-wrapper edge. It uses no
collision, successful extraction, or separately supplied acceptance facts.

First remaining deterministic bridge: identify those internally generated
paths with ReceiptMerklePaths' role-filtered level-major candidate arrays
(and hence validateReceiptPaths=true). Full verifier composition still
needs the source sampler/scalar stages and typed statement/proof decoder;
no full RP05/Rust acceptance or physical X-retention is asserted here.
The ordinary verifier does not call the path validator used by extraction.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier

open HegemonCrypto.CanonicalBytes
open SmzaRp05LeafNamespace hiding RawInput
open SmzaRp05FilteredDecoderInstability
open SmzaRecordedTracePath
set_option autoImplicit false

/-- Definitionally the same raw-log relation as VerifierRunReadback.logRecords;
kept here to avoid importing its unrelated accepted-opening algebra chain. -/
private def logRecords (log : Log) : RawRecords := log.toFinset

private theorem global_normalized_leaf_roundtrip (ns : Namespace)
    (salt : List Byte) (leaf : CurrentLeaf ns salt) :
    globalNormalizedPayload ns (encodeLeaf leaf.preamble leaf.legacyPayload) =
      some leaf.normalized := by
  have framed := encode_frame_roundtrip leaf.preamble leaf.legacyPayload
    leaf.preamble_length leaf.legacy_payload_length
  have dropped : (leaf.preamble ++ leaf.legacyPayload).drop preambleBytes =
      leaf.legacyPayload := by
    rw [← leaf.preamble_length]
    exact List.drop_left
  have saltRead : leaf.legacyPayload.take 32 = salt := leaf.legacyCanonical.2.2.1
  simp [globalNormalizedPayload, framed, dropped, saltRead,
    normalized_roundtrip ns salt leaf]

private theorem recorded_path_mono
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (left right : RawRecords) (included : left ⊆ right)
    (stage : Stage) (target : RawDigest) (path : List Nat) (leaf : RawInput)
    (recorded : RecordedPath next left stage target path leaf) :
    RecordedPath next right stage target path leaf := by
  induction recorded with
  | here stage target input member valid =>
      exact RecordedPath.here stage target input (included member) valid
  | step stage target input edges index childStage childTarget rest leaf
      member parsed edge below ih =>
      exact RecordedPath.step stage target input edges index childStage childTarget
        rest leaf (included member) parsed edge ih

theorem Program.record_bind_success {α β : Type} (oracle : Oracle)
    (program : Program α) (next : α → Program β) (value : α)
    (succeeded : program.eval oracle = some value) :
    (program.bind next).record oracle =
      (((next value).record oracle).1,
        ((program.record oracle).2 ++ ((next value).record oracle).2)) := by
  induction program with
  | done result =>
      have equal : result = some value := succeeded
      subst result
      rfl
  | read input cont ih =>
      have below := ih (oracle input) succeeded
      simpa only [Program.bind, Program.record, List.cons_append] using
        congrArg (fun outcome : Option β × Log =>
          (outcome.1, (input, oracle input) :: outcome.2)) below

theorem Program.bind_log_left {α β : Type} (oracle : Oracle)
    (program : Program α) (next : α → Program β) (value : α)
    (succeeded : program.eval oracle = some value) :
    (program.record oracle).2 ⊆ ((program.bind next).record oracle).2 := by
  rw [Program.record_bind_success oracle program next value succeeded]
  intro call member
  exact List.mem_append.mpr (Or.inl member)

theorem Program.bind_log_right {α β : Type} (oracle : Oracle)
    (program : Program α) (next : α → Program β) (value : α)
    (succeeded : program.eval oracle = some value) :
    ((next value).record oracle).2 ⊆ ((program.bind next).record oracle).2 := by
  rw [Program.record_bind_success oracle program next value succeeded]
  intro call member
  exact List.mem_append.mpr (Or.inr member)

theorem sequence_log_subset {α : Type} (oracle : Oracle) (count : Nat)
    (entries : Fin count → Program α) (result : Fin count → α)
    (succeeded : (sequence count entries).eval oracle = some result) :
    ∀ j, ((entries j).record oracle).2 ⊆ ((sequence count entries).record oracle).2 := by
  induction count with
  | zero =>
      intro j
      exact Fin.elim0 j
  | succ count ih =>
      have firstRead := sequence_pointwise oracle (count + 1) entries result succeeded 0
      have composed :
          ((sequence count (fun i => entries i.succ)).eval oracle).bind (fun rest =>
            some (Fin.cons (result 0) rest)) = some result := by
        simpa only [sequence, Program.eval_bind, firstRead, Option.bind_some,
          Program.eval] using succeeded
      cases restRead : (sequence count (fun i => entries i.succ)).eval oracle with
      | none => simp [restRead] at composed
      | some rest =>
          intro j
          refine Fin.cases ?_ (fun i => ?_) j
          · exact Program.bind_log_left oracle (entries 0) _ (result 0) firstRead
          · intro call member
            have inRest := ih (fun i => entries i.succ) rest restRead i member
            have inContinuation := Program.bind_log_left oracle
              (sequence count (fun i => entries i.succ))
              (fun rest : Fin count → α =>
                (.done (some (Fin.cons (result 0) rest)) : Program (Fin (count + 1) → α)))
              rest restRead inRest
            exact Program.bind_log_right oracle (entries 0) _ (result 0)
              firstRead inContinuation

theorem global_nonleaf_frame (ns : Namespace) (kind : V8SmzaOracleParser.Kind)
    (bytes : List Byte) (notLeaf : kind ≠ .leaf)
    (length : bytes.length = V8SmzaOracleParser.payloadBytes kind) :
    globalNormalizedPayload ns
      (V8SmzaOracleParser.framedInput (V8SmzaOracleParser.roleName kind) bytes) =
        some ⟨kind, bytes⟩ := by
  have framed : V8SmzaOracleParser.parseFramed
      (V8SmzaOracleParser.framedInput (V8SmzaOracleParser.roleName kind) bytes) =
        some (V8SmzaOracleParser.roleName kind, bytes) := by
    apply V8SmzaOracleParser.frame_roundtrip
    · cases kind <;> decide
    · cases kind <;> simp [length, V8SmzaOracleParser.payloadBytes]
    · cases kind <;> simp [length, V8SmzaOracleParser.payloadBytes]
  simpa [globalNormalizedPayload, framed] using
    framed_nonleaf_payload_preserved ns ((bytes.drop preambleBytes).take 32)
      bytes kind notLeaf length

theorem digest_at_ofFn_append (digest : RawDigest) (tail : List Byte) :
    V8Smz9CoherentMerkleGeometry.digestAt (List.ofFn digest ++ tail) 0 = digest := by
  funext i
  unfold V8Smz9CoherentMerkleGeometry.digestAt
  have bounded : i.val < (List.ofFn digest).length := by
    rw [List.length_ofFn]
    exact i.isLt
  rw [Nat.zero_add, List.getD_append _ _ _ _ bounded,
    List.getD_eq_getElem _ _ bounded, List.getElem_ofFn]

theorem digest_at_prefix_ofFn (headBytes tail : List Byte) (digest : RawDigest) :
    V8Smz9CoherentMerkleGeometry.digestAt (headBytes ++ (List.ofFn digest ++ tail))
      headBytes.length = digest := by
  funext i
  unfold V8Smz9CoherentMerkleGeometry.digestAt
  rw [List.getD_append_right _ _ _ _ (by omega), Nat.add_sub_cancel_left]
  simpa only [V8Smz9CoherentMerkleGeometry.digestAt, Nat.zero_add] using
    congrFun (digest_at_ofFn_append digest tail) i

theorem node_parser_roundtrip (ns : Namespace) (depth : Nat) (left right : RawDigest) :
    globalOnlineNext ns (.tree (depth + 1)) (nodeInput left right) =
      some [(.tree depth, left), (.tree depth, right)] := by
  have parsed := global_nonleaf_frame ns .node (List.ofFn left ++ List.ofFn right)
    (by decide) (by simp [V8SmzaOracleParser.payloadBytes])
  have leftRead := digest_at_ofFn_append left (List.ofFn right)
  have rightRead := digest_at_prefix_ofFn (List.ofFn left) [] right
  simp only [List.append_nil, List.length_ofFn] at rightRead
  unfold globalOnlineNext
  rw [nodeInput, parsed]
  change some [(V8SmzaOracleParser.Stage.tree depth, V8Smz9CoherentMerkleGeometry.digestAt
      (List.ofFn left ++ List.ofFn right) 0),
    (V8SmzaOracleParser.Stage.tree depth, V8Smz9CoherentMerkleGeometry.digestAt
      (List.ofFn left ++ List.ofFn right) 64)] = _
  rw [leftRead, rightRead]

theorem root_parser_roundtrip (ns : Namespace) (salt binding : List Byte)
    (root : RawDigest) (saltLength : salt.length = 32)
    (bindingLength : binding.length = 1104) :
    globalOnlineNext ns .root (rootInput salt binding root) =
      some [(.tree 23, root)] := by
  have parsed := global_nonleaf_frame ns .root (salt ++ List.ofFn root ++ binding)
    (by decide) (by simp [V8SmzaOracleParser.payloadBytes, saltLength, bindingLength])
  have rootRead := digest_at_prefix_ofFn salt binding root
  rw [saltLength] at rootRead
  unfold globalOnlineNext
  rw [rootInput, parsed]
  change some [(V8SmzaOracleParser.Stage.tree 23, V8Smz9CoherentMerkleGeometry.digestAt
    ((salt ++ List.ofFn root) ++ binding) 32)] = _
  rw [List.append_assoc, rootRead]

theorem logRecords_mono (left right : Log) (included : left ⊆ right) :
    logRecords left ⊆ logRecords right := by
  intro call member
  exact List.mem_toFinset.mpr (included (List.mem_toFinset.mp member))

theorem initial_slot_recorded_path (ns : Namespace) (oracle : Oracle)
    (input : Input) (j : Fin 38) (result : Slot)
    (succeeded : (initialSlot ns input j).eval oracle = some result) :
    RecordedPath (globalOnlineNext ns)
      (logRecords ((initialSlot ns input j).record oracle).2)
      (.tree 0) result.hash [] (encodeLeaf input.binding (input.payloads j)) := by
  by_cases binding : ns.canonicalPreamble input.binding = true
  · by_cases payload : LegacyLeafCanonical input.salt (input.payloads j)
    · by_cases index : V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j
      · have same :
            (⟨input.indices j, oracle (encodeLeaf input.binding (input.payloads j)),
              input.paths j⟩ : Slot) = result := Option.some.inj (by
                simpa [initialSlot, binding, payload, index, ask, Program.bind, Program.eval]
                  using succeeded)
        rw [← same]
        let leaf : CurrentLeaf ns input.salt :=
          ⟨input.binding, input.payloads j, binding, payload⟩
        have parsed := global_normalized_leaf_roundtrip ns input.salt leaf
        dsimp only [leaf, CurrentLeaf.normalized] at parsed
        apply RecordedPath.here
        · simp [initialSlot, binding, payload, index, ask, Program.bind, Program.record,
            logRecords]
        · unfold globalOnlineNext
          rw [parsed]
          rfl
      · simp [initialSlot, binding, payload, index, Program.eval] at succeeded
    · simp [initialSlot, binding, payload, Program.eval] at succeeded
  · simp [initialSlot, binding, Program.eval] at succeeded

/-- One executing node extends its own ordinal's path. These are induction
invariants, not additional acceptance checks. The public endpoint below
constructs them from the leaf queries and sequential execution. -/
theorem next_slot_extends_path (ns : Namespace) (oracle : Oracle)
    (records : RawRecords) (state : State) (j : Fin 38) (result : Slot)
    (succeeded : (nextSlot state j).eval oracle = some result)
    (supported : logRecords ((nextSlot state j).record oracle).2 ⊆ records)
    (coordinate : SmzaQ38McaSourceBinding.Position) (depth : Nat) (leaf : RawInput)
    (index : (state j).index = coordinate.val / 2 ^ depth)
    (below : RecordedPath (globalOnlineNext ns) records (.tree depth) (state j).hash
      (SmzaRp05FilteredReadback.indexPath coordinate depth) leaf) :
    RecordedPath (globalOnlineNext ns) records (.tree (depth + 1)) result.hash
      (SmzaRp05FilteredReadback.indexPath coordinate (depth + 1)) leaf := by
  obtain ⟨sibling, remaining, _selected, output, recorded⟩ :=
    next_slot_query_recorded oracle state j result succeeded
  by_cases even : (state j).index % 2 = 0
  · have bit : coordinate.val.testBit depth = false := by
      rw [Nat.testBit_eq_decide_div_mod_eq, ← index, even]
      decide
    have member : (nodeInput (state j).hash sibling, result.hash) ∈ records := by
      apply supported
      simp only [if_pos even] at recorded
      simp [logRecords, recorded]
    rw [SmzaRp05FilteredReadback.indexPath, bit]
    exact RecordedPath.step _ _ _ _ 0 _ _ _ _ member
      (node_parser_roundtrip ns depth (state j).hash sibling) rfl below
  · have odd : (state j).index % 2 = 1 := by omega
    have bit : coordinate.val.testBit depth = true := by
      rw [Nat.testBit_eq_decide_div_mod_eq, ← index, odd]
      decide
    have member : (nodeInput sibling (state j).hash, result.hash) ∈ records := by
      apply supported
      simp only [if_neg even] at recorded
      simp [logRecords, recorded]
    rw [SmzaRp05FilteredReadback.indexPath, bit]
    exact RecordedPath.step _ _ _ _ 1 _ _ _ _ member
      (node_parser_roundtrip ns depth sibling (state j).hash) rfl below

theorem level_extends_paths (ns : Namespace) (oracle : Oracle)
    (records : RawRecords) (state result : State)
    (succeeded : (level state).eval oracle = some result)
    (supported : logRecords ((level state).record oracle).2 ⊆ records)
    (coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position)
    (depth : Nat) (leaves : Fin 38 → RawInput)
    (indices : ∀ j, (state j).index = (coordinates j).val / 2 ^ depth)
    (below : ∀ j, RecordedPath (globalOnlineNext ns) records (.tree depth) (state j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) depth) (leaves j)) :
    ∀ j, RecordedPath (globalOnlineNext ns) records (.tree (depth + 1)) (result j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) (depth + 1)) (leaves j) := by
  by_cases valid : duplicateConsistent state = true
  · have ran : (sequence 38 (nextSlot state)).eval oracle = some result := by
      simpa [level, valid] using succeeded
    intro j
    apply next_slot_extends_path ns oracle records state j (result j)
      (sequence_pointwise oracle 38 (nextSlot state) result ran j)
      _ (coordinates j) depth (leaves j) (indices j) (below j)
    exact (logRecords_mono _ _
      (sequence_log_subset oracle 38 (nextSlot state) result ran j)).trans
        (by simpa [level, valid] using supported)
  · simp [level, valid, Program.eval] at succeeded

theorem levels_extend_paths (ns : Namespace) (oracle : Oracle)
    (records : RawRecords) (steps : Nat) (state result : State)
    (succeeded : (levels steps state).eval oracle = some result)
    (supported : logRecords ((levels steps state).record oracle).2 ⊆ records)
    (coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position)
    (depth : Nat) (leaves : Fin 38 → RawInput)
    (indices : ∀ j, (state j).index = (coordinates j).val / 2 ^ depth)
    (below : ∀ j, RecordedPath (globalOnlineNext ns) records (.tree depth) (state j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) depth) (leaves j)) :
    ∀ j, RecordedPath (globalOnlineNext ns) records (.tree (depth + steps)) (result j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) (depth + steps)) (leaves j) := by
  induction steps generalizing state depth with
  | zero =>
      have equal : state = result := Option.some.inj succeeded
      simpa [equal] using below
  | succ steps ih =>
      have composed : ((level state).eval oracle).bind (fun middle =>
          (levels steps middle).eval oracle) = some result := by
        simpa only [levels, Program.eval_bind] using succeeded
      cases stepped : (level state).eval oracle with
      | none => simp [stepped] at composed
      | some middle =>
          have later : (levels steps middle).eval oracle = some result := by
            simpa only [stepped, Option.bind_some] using composed
          have firstSupport : logRecords ((level state).record oracle).2 ⊆ records :=
            (logRecords_mono _ _
              (Program.bind_log_left oracle (level state) (levels steps) middle stepped)).trans
              supported
          have laterSupport : logRecords ((levels steps middle).record oracle).2 ⊆ records :=
            (logRecords_mono _ _
              (Program.bind_log_right oracle (level state) (levels steps) middle stepped)).trans
              supported
          have nextIndices : ∀ j, (middle j).index = (coordinates j).val / 2 ^ (depth + 1) := by
            intro j
            rw [level_index oracle state middle stepped j, indices j,
              Nat.div_div_eq_div_mul, pow_succ]
          have nextPaths := level_extends_paths ns oracle records state middle stepped
            firstSupport coordinates depth leaves indices below
          have paths := ih (state := middle) (depth := depth + 1)
            later laterSupport nextIndices nextPaths
          simpa only [Nat.add_assoc, Nat.add_comm 1 steps] using paths

theorem accepted_shape_valid (ns : Namespace) (oracle : Oracle) (input : Input)
    (target : RawDigest) (accepted : acceptedResult ns oracle input = some target) :
    shapeValid ns input = true := by
  by_cases shape : shapeValid ns input = true
  · exact shape
  · simp [acceptedResult, merkleProgram, shape, Program.eval] at accepted

-- Do not normalize the concrete 38-by-23 execution while matching the
-- abstract bind/sequence lemmas below. This changes elaboration only.
attribute [local irreducible] merkleProgram sequence levels initialSlot finish

private theorem merkle_log_parts (ns : Namespace) (oracle : Oracle) (input : Input)
    (initial final : State) (shape : shapeValid ns input = true)
    (started : (sequence 38 (initialSlot ns input)).eval oracle = some initial)
    (reduced : (levels 23 initial).eval oracle = some final) :
    logRecords ((sequence 38 (initialSlot ns input)).record oracle).2 ⊆
        logRecords (recordedAttempt ns oracle input).2 ∧
      logRecords ((levels 23 initial).record oracle).2 ⊆
        logRecords (recordedAttempt ns oracle input).2 ∧
      logRecords ((finish input final).record oracle).2 ⊆
        logRecords (recordedAttempt ns oracle input).2 := by
  let continuation : State → Program RawDigest :=
    fun state => (levels 23 state).bind (finish input)
  have top : merkleProgram ns input =
      (sequence 38 (initialSlot ns input)).bind continuation := by
    simp [merkleProgram, shape, continuation]
  have first : logRecords ((sequence 38 (initialSlot ns input)).record oracle).2 ⊆
      logRecords (recordedAttempt ns oracle input).2 := by
    change _ ⊆ logRecords ((merkleProgram ns input).record oracle).2
    rw [top]
    exact logRecords_mono _ _ (Program.bind_log_left oracle
      (sequence 38 (initialSlot ns input)) continuation initial started)
  have rest : logRecords (((levels 23 initial).bind (finish input)).record oracle).2 ⊆
      logRecords (recordedAttempt ns oracle input).2 := by
    change _ ⊆ logRecords ((merkleProgram ns input).record oracle).2
    rw [top]
    exact logRecords_mono _ _ (Program.bind_log_right oracle
      (sequence 38 (initialSlot ns input)) continuation initial started)
  refine ⟨first, ?_, ?_⟩
  · exact (logRecords_mono _ _ (Program.bind_log_left oracle
      (levels 23 initial) (finish input) final reduced)).trans rest
  · exact (logRecords_mono _ _ (Program.bind_log_right oracle
      (levels 23 initial) (finish input) final reduced)).trans rest

/-- Rewrite the existing Boolean's own decision procedure, rather than
synthesizing and unifying a second finite-forall decision procedure. -/
private theorem shape_valid_data (ns : Namespace) (input : Input)
    (shape : shapeValid ns input = true) :
    ns.canonicalPreamble input.binding = true ∧ input.salt.length = 32 ∧
      ∀ j, input.indices j < 8388608 := by
  simp only [shapeValid, Bool.and_eq_true, decide_eq_true_eq] at shape
  exact ⟨shape.1, shape.2.1, shape.2.2.1⟩

private theorem finish_records_root (oracle : Oracle) (input : Input) (state : State)
    (complete : ∀ j : Fin 38, (state j).remaining = [] ∧ (state j).hash = (state 0).hash) :
    (rootInput input.salt input.binding (state 0).hash,
      oracle (rootInput input.salt input.binding (state 0).hash)) ∈
        logRecords ((finish input state).record oracle).2 := by
  have valid : finalValid state = true := by
    simp only [finalValid, decide_eq_true_eq]
    exact complete
  simp [finish, valid, ask, Program.record, logRecords]

-- Keep the public theorem's execution and record-relation wrappers opaque
-- during elaboration. Their explicit reductions above have already been
-- packaged into helper theorems; unfolding them here expands the full run.
attribute [local irreducible] recordedAttempt acceptedResult logRecords

private theorem executed_tree_paths (ns : Namespace) (oracle : Oracle)
    (input : Input) (records : RawRecords) (initial final : State)
    (started : (sequence 38 (initialSlot ns input)).eval oracle = some initial)
    (reduced : (levels 23 initial).eval oracle = some final)
    (firstSupport : logRecords ((sequence 38 (initialSlot ns input)).record oracle).2 ⊆ records)
    (levelSupport : logRecords ((levels 23 initial).record oracle).2 ⊆ records)
    (coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position)
    (coordinateEq : ∀ j, (coordinates j).val = input.indices j) :
    ∀ j, RecordedPath (globalOnlineNext ns) records (.tree 23) (final j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (encodeLeaf input.binding (input.payloads j)) := by
  let leaves : Fin 38 → RawInput := fun j => encodeLeaf input.binding (input.payloads j)
  have initialIndices : ∀ j, (initial j).index = (coordinates j).val / 2 ^ 0 := by
    intro j
    simpa [coordinateEq j] using initial_slot_index ns oracle input j (initial j)
      (sequence_pointwise oracle 38 (initialSlot ns input) initial started j)
  have initialPaths : ∀ j, RecordedPath (globalOnlineNext ns) records (.tree 0)
      (initial j).hash (SmzaRp05FilteredReadback.indexPath (coordinates j) 0) (leaves j) := by
    intro j
    apply recorded_path_mono (globalOnlineNext ns) _ records
      ((logRecords_mono _ _ (sequence_log_subset oracle 38
        (initialSlot ns input) initial started j)).trans firstSupport)
    exact initial_slot_recorded_path ns oracle input j (initial j)
      (sequence_pointwise oracle 38 (initialSlot ns input) initial started j)
  have treePaths := levels_extend_paths ns oracle records 23 initial final reduced
    levelSupport coordinates 0 leaves initialIndices initialPaths
  intro j
  simpa only [Nat.zero_add] using treePaths j

private theorem recorded_single_child
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (records : RawRecords) (stage : Stage) (target : RawDigest)
    (input : RawInput) (childStage : Stage) (childTarget : RawDigest)
    (rest : List Nat) (leaf : RawInput)
    (recorded : (input, target) ∈ records)
    (parsed : next stage input = some [(childStage, childTarget)])
    (below : RecordedPath next records childStage childTarget rest leaf) :
    RecordedPath next records stage target (0 :: rest) leaf := by
  exact RecordedPath.step stage target input [(childStage, childTarget)]
    0 childStage childTarget rest leaf recorded parsed rfl below

private theorem append_recorded_root (ns : Namespace) (input : Input)
    (records : RawRecords) (target : RawDigest) (final : State)
    (coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position) (j : Fin 38)
    (saltLength : input.salt.length = 32)
    (bindingLength : input.binding.length = 1104)
    (sameRoot : (final j).hash = (final 0).hash)
    (rootRecorded : (rootInput input.salt input.binding (final 0).hash, target) ∈ records)
    (below : RecordedPath (globalOnlineNext ns) records (.tree 23) (final j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (encodeLeaf input.binding (input.payloads j))) :
    RecordedPath (globalOnlineNext ns) records .root target
      (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (encodeLeaf input.binding (input.payloads j)) := by
  rw [sameRoot] at below
  have parsed : globalOnlineNext ns .root
      (rootInput input.salt input.binding (final 0).hash) =
      some [(.tree 23, (final 0).hash)] :=
    root_parser_roundtrip ns input.salt input.binding (final 0).hash
      saltLength bindingLength
  exact recorded_single_child (globalOnlineNext ns) records .root target
    (rootInput input.salt input.binding (final 0).hash) (.tree 23) (final 0).hash
    (SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
    (encodeLeaf input.binding (input.payloads j)) rootRecorded parsed below

/-- Public deterministic endpoint. Canonical paths are constructed from one
successful ordinary execution and that very execution's independently
instrumented log. No path, log-membership, collision-freedom, or extraction
certificate is an input. This is the Merkle phase, not the full verifier. -/
theorem accepted_recorded_paths (ns : Namespace) (oracle : Oracle) (input : Input)
    (target : RawDigest) (accepted : acceptedResult ns oracle input = some target) :
    ∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
      (∀ j, (coordinates j).val = input.indices j) ∧
      ∀ j, RecordedPath (globalOnlineNext ns)
        (logRecords (recordedAttempt ns oracle input).2) .root target
        (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (encodeLeaf input.binding (input.payloads j)) := by
  have shape := accepted_shape_valid ns oracle input target accepted
  obtain ⟨bindingCanonical, saltLength, indexBounds⟩ := shape_valid_data ns input shape
  let coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position :=
    fun j => ⟨input.indices j, indexBounds j⟩
  let records := logRecords (recordedAttempt ns oracle input).2
  obtain ⟨_, initial, final, started, reduced, complete, targetEq⟩ :=
    accepted_has_executed_common_root ns oracle input target accepted
  obtain ⟨firstSupport, levelSupport, finishSupport⟩ :=
    merkle_log_parts ns oracle input initial final shape started reduced
  have treePaths := executed_tree_paths ns oracle input records initial final
    started reduced firstSupport levelSupport coordinates (fun _ => rfl)
  have rootRecorded :
      (rootInput input.salt input.binding (final 0).hash, target) ∈ records := by
    apply finishSupport
    rw [targetEq]
    exact finish_records_root oracle input final complete
  refine ⟨coordinates, fun _ => rfl, ?_⟩
  intro j
  exact append_recorded_root ns input records target final coordinates j
    saltLength (ns.canonicalLength input.binding bindingCanonical)
    (complete j).2 rootRecorded (treePaths j)

/-- Each successful initial leaf read supplies the exact format and index
guards evaluated by the ordinary program, not a caller certificate. -/
theorem initial_slot_leaf_checks (ns : Namespace) (oracle : Oracle)
    (input : Input) (j : Fin 38) (result : Slot)
    (succeeded : (initialSlot ns input j).eval oracle = some result) :
    ns.canonicalPreamble input.binding = true ∧
      LegacyLeafCanonical input.salt (input.payloads j) ∧
      V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j := by
  by_cases binding : ns.canonicalPreamble input.binding = true
  · by_cases payload : LegacyLeafCanonical input.salt (input.payloads j)
    · by_cases index : V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j
      · exact ⟨binding, payload, index⟩
      · simp [initialSlot, binding, payload, index, Program.eval] at succeeded
    · simp [initialSlot, binding, payload, Program.eval] at succeeded
  · simp [initialSlot, binding, Program.eval] at succeeded

/-- Successful ordinary execution yields 38 canonical current leaves and
their recorded paths, including the opened-index equality. -/
theorem accepted_recorded_canonical_leaves (ns : Namespace) (oracle : Oracle)
    (input : Input) (target : RawDigest)
    (accepted : acceptedResult ns oracle input = some target) :
    ∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
      (∀ j, (coordinates j).val = input.indices j) ∧
      ∀ j, ∃ leaf : CurrentLeaf ns input.salt,
        leaf.preamble = input.binding ∧
        leaf.legacyPayload = input.payloads j ∧
        V8SmzaOracleParser.wordAt leaf.legacyPayload 4 = (coordinates j).val ∧
        RecordedPath (globalOnlineNext ns)
          (logRecords (recordedAttempt ns oracle input).2) .root target
          (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
          (encodeLeaf leaf.preamble leaf.legacyPayload) := by
  obtain ⟨coordinates, coordinateEq, paths⟩ :=
    accepted_recorded_paths ns oracle input target accepted
  obtain ⟨_, initial, _, started, _, _, _⟩ :=
    accepted_has_executed_common_root ns oracle input target accepted
  refine ⟨coordinates, coordinateEq, ?_⟩
  intro j
  obtain ⟨binding, payload, index⟩ := initial_slot_leaf_checks ns oracle input j
    (initial j) (sequence_pointwise oracle 38 (initialSlot ns input) initial started j)
  let leaf : CurrentLeaf ns input.salt :=
    ⟨input.binding, input.payloads j, binding, payload⟩
  refine ⟨leaf, rfl, rfl, ?_, ?_⟩
  · exact index.trans (coordinateEq j).symm
  · exact paths j

end HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier
