import SmzaRp05AcceptedAllModeNullifierKeys
import SmzaRp05AuthorizationClosureTags

/-! Intra-transaction same-note nullifier binding. SingleKey and Final use
one common selected key for both inputs. Approval cannot have equal input
values when input1 is active, because its input0 is zero and input1 is
ordinary and nonzero. The exact four scalar-mode replication CSR equations
transport that exclusion from lane zero to all five key lanes. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureSameNote

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05AcceptedModeExhaustiveness
open HegemonCrypto.SmallWood.SmzaRp05AcceptedAllModeNullifierKeys
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

private theorem constant_trace_value {publicWords values : List Nat}
    (evaluated : evalExpressionNodes publicWords [] program.csrExpressions =
      some values) (node value : Nat)
    (found : program.csrExpressions[node]? = some (.constant value)) :
    (values.getD node 0 : Goldilocks) = (value : Goldilocks) := by
  have realizes : Realizes program.csrExpressions node (.constant value) :=
    Realizes.constant found
  have refined := fieldAt_refines_source
    ({ expressions := program.csrExpressions, roots := [] } : ExpressionProgram)
    publicWords [] values
    HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCanonical.csrCanonical
    evaluated node (List.getElem?_eq_some_iff.mp found).1
  rw [fieldAt_of_realizes realizes] at refined
  simpa [SourceTerm.eval] using refined.symm

def approvalReplicateAttempt (lane : Fin 4) : CsrExecutableAttempt :=
  { globalIndex := 5859 + lane.val
    family := 0
    localIndex := 5859 + lane.val
    emission := 0
    terms := [(5953 + lane.val, 1), (5952, 3)]
    targetRoot := 0 }

theorem approvalReplicateAttempt_member (lane : Fin 4) :
    approvalReplicateAttempt lane ∈ program.csrAttempts := by
  fin_cases lane <;> decide

private theorem accepted_approval_replication {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (lane : Fin 4) :
    packed.getD (5953 + lane.val) 0 = packed.getD 5952 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have zero := constant_trace_value evaluated 0 0 (by decide)
  have one := constant_trace_value evaluated 1 1 (by decide)
  have minusOne := constant_trace_value evaluated 3 18446744069414584320 (by decide)
  have negative : (values.getD 3 0 : Goldilocks) = -1 := by
    rw [minusOne]
    decide
  have equation := accepted_csr_attempt_field_equality
    (attempts (approvalReplicateAttempt lane) (approvalReplicateAttempt_member lane))
  simp only [approvalReplicateAttempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, zero, one, negative, neg_one_mul, add_zero] at equation
  apply canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (5953 + lane.val))
    (packed_word_canonical accepted.2.1 5952)
  simp only [packedWord]
  linear_combination equation

private theorem lane_row (packed : List Nat) (lane row : Nat)
    (bound : row < relationRowCount) :
    (packedWitnessLaneRows packed lane).getD row 0 =
      packed.getD (row * 64 + lane) 0 := by
  simp [packedWitnessLaneRows, List.getD_eq_getElem?_getD, bound, packingFactor]

/-- Approval's zero/ordinary roles exclude equal raw input values. -/
theorem accepted_equal_input_values_not_approval
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (rightActive : publicWords.getD 1 0 = 1)
    (sameValue : packed.getD 0 0 = packed.getD (34 * 64) 0) :
    ((packedWitnessLaneRows packed 0).getD approvalRow 0 : Goldilocks) = 0 := by
  have modes := (accepted_mode_selectors_exhaustive accepted 0).2
  rcases modes with single | approval | final
  · exact single.2.1
  · have semantic := packed_program_implies_local_semantics
      HegemonCrypto.SmallWood.SmzaRp05LocalCertificate.certificate accepted 0
    have singleZero :
        ((packedWitnessLaneRows packed 0).getD singleRow 0 : Goldilocks) = 0 := approval.1
    have approvalOne :
        ((packedWitnessLaneRows packed 0).getD approvalRow 0 : Goldilocks) = 1 := approval.2.1
    have zero := (local_approval_zero_native_roles semantic approvalOne).1
    have nonzero := (local_t1_selected_values_ne_zero semantic).2
    have gate : (publicWords.getD 1 0 : Goldilocks) *
        (((packedWitnessLaneRows packed 0).getD singleRow 0 : Goldilocks) +
          ((packedWitnessLaneRows packed 0).getD approvalRow 0 : Goldilocks)) = 1 := by
      rw [rightActive, singleZero, approvalOne]
      norm_num
    have bad := nonzero gate
    change ((packedWitnessLaneRows packed 0).getD (inputValueRow 0) 0 : Goldilocks) = 0
      at zero
    change ((packedWitnessLaneRows packed 0).getD (inputValueRow 1) 0 : Goldilocks) ≠ 0
      at bad
    rw [lane_row packed 0 (inputValueRow 0) (by decide)] at zero
    rw [lane_row packed 0 (inputValueRow 1) (by decide)] at bad
    have equalField :
        (packed.getD (inputValueRow 0 * 64 + 0) 0 : Goldilocks) =
          (packed.getD (inputValueRow 1 * 64 + 0) 0 : Goldilocks) := by
      simpa [inputValueRow] using congrArg (fun n : Nat => (n : Goldilocks)) sameValue
    exact (bad (equalField.symm.trans zero)).elim
  · exact final.2.1

theorem accepted_equal_input_values_same_key_words
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (rightActive : publicWords.getD 1 0 = 1)
    (sameValue : packed.getD 0 0 = packed.getD (34 * 64) 0)
    (limb : Fin 5) :
    (nullifierPreimage packed 0).getD limb.val 0 =
      (nullifierPreimage packed 1).getD limb.val 0 := by
  have modeZero := accepted_equal_input_values_not_approval accepted rightActive sameValue
  rw [lane_row packed 0 approvalRow (by decide)] at modeZero
  have replicate : packed.getD (93 * 64 + limb.val) 0 = packed.getD (93 * 64) 0 := by
    fin_cases limb
    · rfl
    · exact accepted_approval_replication accepted 0
    · exact accepted_approval_replication accepted 1
    · exact accepted_approval_replication accepted 2
    · exact accepted_approval_replication accepted 3
  have laneZero :
      ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 0 := by
    rw [lane_row packed limb.val approvalRow (by decide)]
    change (packed.getD (93 * 64 + limb.val) 0 : Goldilocks) = 0
    rw [replicate]
    simpa only [approvalRow, Nat.add_zero] using modeZero
  have left := accepted_all_mode_nullifier_preimage_key_word accepted
    HegemonCrypto.SmallWood.SmzaRp05NullifierMuxCertificate.certificate 0 limb
  have right := accepted_all_mode_nullifier_preimage_key_word accepted
    HegemonCrypto.SmallWood.SmzaRp05NullifierMuxCertificate.certificate 1 limb
  rw [laneZero] at left right
  simp only [zero_ne_one, if_false] at left right
  exact left.trans right.symm

/-- Exact source-value/rho equality and position equality force identical
twelve-word nullifier inputs inside one accepted transaction. -/
theorem accepted_same_note_position_nullifier_preimages_equal
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (rightActive : publicWords.getD 1 0 = 1)
    (sameValue : packed.getD 0 0 = packed.getD (34 * 64) 0)
    (sameRho : ∀ limb : Fin 4,
      spongeSourceWord packed 1 (6 + limb.val) =
        spongeSourceWord packed 38 (6 + limb.val))
    (samePosition : projectPosition packed 0 = projectPosition packed 1) :
    nullifierPreimage packed 0 = nullifierPreimage packed 1 := by
  have keys : ∀ limb : Fin 5,
      packed.getD (97 * 64 + limb.val) 0 = packed.getD (98 * 64 + limb.val) 0 := by
    intro limb
    have equal := accepted_equal_input_values_same_key_words
      accepted rightActive sameValue limb
    fin_cases limb <;> simpa [nullifierPreimage, inputNullifierKeyRow] using equal
  have keyMap :
      (List.range 5).map (fun limb =>
        packed.getD (inputNullifierKeyRow 0 * 64 + limb) 0) =
      (List.range 5).map (fun limb =>
        packed.getD (inputNullifierKeyRow 1 * 64 + limb) 0) := by
    apply List.map_congr_left
    intro limb member
    exact keys ⟨limb, List.mem_range.mp member⟩
  have rhoMap :
      (List.range 4).map (fun limb =>
        spongeSourceWord packed (inputNoteFirstCall 0) (6 + limb)) =
      (List.range 4).map (fun limb =>
        spongeSourceWord packed (inputNoteFirstCall 1) (6 + limb)) := by
    apply List.map_congr_left
    intro limb member
    exact sameRho ⟨limb, List.mem_range.mp member⟩
  unfold nullifierPreimage
  rw [keyMap, rhoMap]
  change _ ++ [0, 0, projectPosition packed 0] ++ _ =
    _ ++ [0, 0, projectPosition packed 1] ++ _
  rw [samePosition]

end HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureSameNote
