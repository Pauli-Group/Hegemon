import SmzaRp05ExecutableMerklePaths
import SmzaRp05GlobalOpeningReadback
import SmzaRp05MeasuredLogReadback

/-! Source-only same-measured-record bridge for the executable Merkle phase.
Acceptance constructs the ordered query, canonical leaves, and recorded
paths. Only physical parser-visible X retention is assumed. Collision
freedom is needed for the extraction corollary, not to construct readback.
This does not assert full verifier/Rust acceptance or physical retention. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleMeasured

open SmzaRp05ExecutableMerkleVerifier SmzaRp05LeafNamespace
open SmzaRp05FilteredDecoderInstability SmzaQ38McaSourceBinding
open SmzaRp05GlobalOpeningReadback
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

private theorem initial_canonical (ns : Namespace) (oracle : Oracle)
    (input : Input) (j : Fin 38) (result : Slot)
    (ran : (initialSlot ns input j).eval oracle = some result) :
    LegacyLeafCanonical input.salt (input.payloads j) ∧
      V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j := by
  by_cases binding : ns.canonicalPreamble input.binding = true
  · by_cases payload : LegacyLeafCanonical input.salt (input.payloads j)
    · by_cases index : V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j
      · exact ⟨payload, index⟩
      · simp [initialSlot, binding, payload, index, Program.eval] at ran
    · simp [initialSlot, binding, payload, Program.eval] at ran
  · simp [initialSlot, binding, Program.eval] at ran

/-- The query and readback are outputs, not caller-supplied certificates.
The support premise mentions the same accepted run's actual recorded log;
it permits additional adversary/history records in the measured relation. -/
theorem accepted_same_measured_readback
    (ns : Namespace) (oracle : Oracle) (input : Input)
    (target : V8SmzaOracleParser.RawDigest)
    (accepted : acceptedResult ns oracle input = some target)
    (measured : RawRecords)
    (supported : ∀ stage raw output,
      (raw, output) ∈ (recordedAttempt ns oracle input).2 →
      (globalOnlineNext ns stage raw).isSome → (raw, output) ∈ measured) :
    ∃ (coordinates : Fin 38 → Position) (query : Query)
      (claims : GlobalQueryReadback ns measured target query),
      (∀ j, (coordinates j).val = input.indices j) ∧
      StrictMono coordinates ∧ query.val = Finset.univ.image coordinates ∧
      (∀ j, claims.input (coordinates j) = encodeLeaf input.binding (input.payloads j)) ∧
      (∀ j, (claims.leaf (coordinates j)).bytes = input.payloads j) := by
  have shape := accepted_shape_valid ns oracle input target accepted
  simp only [shapeValid, Bool.and_eq_true, decide_eq_true_eq] at shape
  obtain ⟨coordinates, values, paths⟩ :=
    accepted_recorded_paths ns oracle input target accepted
  have ordered : StrictMono coordinates := by
    intro i j less
    change (coordinates i).val < (coordinates j).val
    rw [values i, values j]
    exact shape.2.2.2.1 i j less
  let query : Query := ⟨Finset.univ.image coordinates, by
    rw [Finset.card_image_of_injective _ ordered.injective]
    simp⟩
  obtain ⟨_, initial, _final, started, _reduced, _complete, _targetEq⟩ :=
    accepted_has_executed_common_root ns oracle input target accepted
  have canonical (j : Fin 38) := initial_canonical ns oracle input j (initial j)
    (sequence_pointwise oracle 38 (initialSlot ns input) initial started j)
  let ordinal : Position → Fin 38 := fun position =>
    if found : ∃ j, coordinates j = position then Classical.choose found else 0
  have ordinal_at (j : Fin 38) : ordinal (coordinates j) = j := by
    have found : ∃ k, coordinates k = coordinates j := ⟨j, rfl⟩
    simp only [ordinal, dif_pos found]
    exact ordered.injective (Classical.choose_spec found)
  let leaves : Position → CurrentLeaf ns input.salt := fun position =>
    ⟨input.binding, input.payloads (ordinal position), shape.1,
      (canonical (ordinal position)).1⟩
  have recorded : ∀ position ∈ query.val,
      SmzaRecordedTracePath.RecordedPath (globalOnlineNext ns) measured .root target
        (0 :: indexPath position 23)
        (encodeLeaf (leaves position).preamble (leaves position).legacyPayload) := by
    intro position member
    obtain ⟨j, _, rfl⟩ := Finset.mem_image.mp member
    simp only [leaves, ordinal_at]
    apply SmzaRp05MeasuredLogReadback.recorded_path_of_parser_supported_inputs
      (globalOnlineNext ns) ((recordedAttempt ns oracle input).2.toFinset) measured
      (fun stage raw output member valid =>
        supported stage raw output (List.mem_toFinset.mp member) valid)
      .root target (0 :: indexPath (coordinates j) 23)
      (encodeLeaf input.binding (input.payloads j))
    exact paths j
  have indexWord : ∀ position ∈ query.val,
      V8SmzaOracleParser.wordAt (leaves position).legacyPayload 4 = position.val := by
    intro position member
    obtain ⟨j, _, rfl⟩ := Finset.mem_image.mp member
    simp only [leaves, ordinal_at]
    exact (canonical j).2.trans (values j).symm
  let claims := canonicalQueryReadback ns measured target query input.salt
    leaves recorded indexWord
  refine ⟨coordinates, query, claims, values, ordered, rfl, ?_, ?_⟩
  · intro j
    change encodeLeaf input.binding (input.payloads (ordinal (coordinates j))) = _
    rw [ordinal_at]
  · intro j
    change input.payloads (ordinal (coordinates j)) = input.payloads j
    rw [ordinal_at]

/-- On a collision-free measured branch, every accepted payload cell is
read back from extraction on that very measured relation, at fuel at least
25 (one root wrapper, depth 23, and terminal leaf). -/
theorem accepted_same_measured_cells
    (ns : Namespace) (oracle : Oracle) (input : Input)
    (target : V8SmzaOracleParser.RawDigest)
    (accepted : acceptedResult ns oracle input = some target)
    (measured : RawRecords)
    (supported : ∀ stage raw output,
      (raw, output) ∈ (recordedAttempt ns oracle input).2 →
      (globalOnlineNext ns stage raw).isSome → (raw, output) ∈ measured)
    (collisionFree : SmzaRecordedTracePath.RecordsCollisionFree measured) :
    ∃ (coordinates : Fin 38 → Position) (query : Query),
      (∀ j, (coordinates j).val = input.indices j) ∧ StrictMono coordinates ∧
      query.val = Finset.univ.image coordinates ∧
      ∀ (fuel : Nat), 25 ≤ fuel → ∀ (j : Fin 38) (row : Fin 145),
        SmzaRp05TracePrefixes.rootOracle ns
          (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) measured fuel .root target)
          (coordinates j) row =
        SmzaRp05TracePrefixes.fieldWordAt (input.payloads j)
          (if row.val < 140 then 14 + row.val else 155 + (row.val - 140)) := by
  obtain ⟨coordinates, query, claims, values, ordered, image, _inputs, bytes⟩ :=
    accepted_same_measured_readback ns oracle input target accepted measured supported
  refine ⟨coordinates, query, values, ordered, image, ?_⟩
  intro fuel enough j row
  have member : coordinates j ∈ query.val := by
    rw [image]
    exact Finset.mem_image.mpr ⟨j, Finset.mem_univ _, rfl⟩
  have read := decoded_oracle_agrees_with_global_root claims collisionFree
    fuel enough (coordinates j) member row
  simpa only [decodedOracle, bytes] using read

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleMeasured
