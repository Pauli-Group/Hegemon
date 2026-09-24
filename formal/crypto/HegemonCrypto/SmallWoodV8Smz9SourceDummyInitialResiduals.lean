import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

/-! Exactly family35, the 48 zero initial words for calls125..127.
The constructor still computes their real permutation outputs; this theorem
does not equate dummy final states with zero. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceDummyInitial
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option Elab.async false
set_option maxRecDepth 100000
set_option maxHeartbeats 2000000

def dummyInitialAttempt (offset : Nat) : CsrExecutableAttempt :=
  attempt (19120 + offset) 35 offset 0
    [(hashInitialIndex (125 + offset / 16) (offset % 16), 1)] 0

theorem exact_dummy_initial_family :
    exactCsrAttempts.filter (fun entry => entry.family == 35) =
      (List.range 48).map dummyInitialAttempt := by decide

theorem exact_dummy_initial_lookup (offset : Fin 48) :
    exactCsrAttempts[19120 + offset.val]? = some (dummyInitialAttempt offset.val) := by
  have member : dummyInitialAttempt offset.val ∈
      exactCsrAttempts.filter (fun entry => entry.family == 35) := by
    rw [exact_dummy_initial_family]
    exact List.mem_map.mpr ⟨offset.val, List.mem_range.mpr offset.isLt, rfl⟩
  exact exact_attempt_lookup _ (List.mem_filter.mp member).1

theorem full_candidate_dummy_initial_zero (statement : V8PublicStatement) (witness : V8Witness)
    (offset : Fin 48) :
    (fullTypedSourceCandidate statement witness).getD
      (hashInitialIndex (125 + offset.val / 16) (offset.val % 16)) 0 = 0 := by
  change (constructedAssignment statement witness _ _).getD _ 0 = 0
  rw [constructed_as_hash_placement]
  exact placed_dummy_initial_zero _ _ _ (before_hash_length statement witness _)
    _ _ (by omega) (by omega) (by omega)

theorem dummy_initial_address_bound (offset : Fin 48) :
    hashInitialIndex (125 + offset.val / 16) (offset.val % 16) < 43904 := by
  simp only [hashInitialIndex, hashRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, hashRowsPerGroup]
  omega

def dummyOnePacked : List Nat := List.replicate 43904 1

theorem dummy_one_packed_canonical : ExactWords 43904 dummyOnePacked := by
  constructor
  · exact List.length_replicate
  · intro value member
    have one : value = 1 := (List.mem_replicate.mp member).2
    rw [one]
    decide

noncomputable section

theorem actual_dummy_initial_residual (pub : Nat → F) (packed : List Nat) (offset : Nat) :
    actualCsrResidual pub packed (dummyInitialAttempt offset) =
      (packed.getD (hashInitialIndex (125 + offset / 16) (offset % 16)) 0 : F) := by
  simp only [actualCsrResidual, actualCsrTerms, dummyInitialAttempt, attempt,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    (actual_csr_zero_one pub).1, (actual_csr_zero_one pub).2,
    one_mul, add_zero, sub_zero]

theorem full_candidate_actual_dummy_all_48_zero (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 48) :
    ∃ entry, exactCsrAttempts[19120 + offset.val]? = some entry ∧ entry.family = 35 ∧
      entry.localIndex = offset.val ∧
      actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (fullTypedSourceCandidate statement witness) entry = 0 := by
  refine ⟨dummyInitialAttempt offset.val, exact_dummy_initial_lookup offset, rfl, rfl, ?_⟩
  rw [actual_dummy_initial_residual, full_candidate_dummy_initial_zero statement witness offset]
  rfl

theorem actual_dummy_all_48_one_control (pub : Nat → F) (offset : Fin 48) :
    actualCsrResidual pub dummyOnePacked (dummyInitialAttempt offset.val) = 1 := by
  rw [actual_dummy_initial_residual]
  have bound := dummy_initial_address_bound offset
  rw [show dummyOnePacked.getD (hashInitialIndex (125 + offset.val / 16) (offset.val % 16)) 0 = 1 by
    exact List.getD_replicate 1 bound]
  rfl

theorem actual_indexed_dummy_all_48_nonzero_control (pub : Nat → F) (offset : Fin 48) :
    ∃ entry, exactCsrAttempts[19120 + offset.val]? = some entry ∧
      actualCsrResidual pub dummyOnePacked entry ≠ 0 := by
  refine ⟨dummyInitialAttempt offset.val, exact_dummy_initial_lookup offset, ?_⟩
  rw [actual_dummy_all_48_one_control]
  decide

theorem dummy_initial_endpoint_metadata :
    dummyInitialAttempt 0 = attempt 19120 35 0 0 [(29821, 1)] 0 ∧
    dummyInitialAttempt 15 = attempt 19135 35 15 0 [(30781, 1)] 0 ∧
    dummyInitialAttempt 16 = attempt 19136 35 16 0 [(29822, 1)] 0 ∧
    dummyInitialAttempt 47 = attempt 19167 35 47 0 [(30783, 1)] 0 := by decide

end
end HegemonCrypto.SmallWood.V8Smz9SourceDummyInitial
