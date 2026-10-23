import HegemonCrypto.NativeLaunchDerivedDecsFailureCover
import HegemonCrypto.NativeLaunchGuardedPointGeometry

/-! The point function is constructed internally from the supplied shift.
Executable nonzero/canonical-shift and adjacent-index guards discharge both
point injection obligations of the checked DECS support/failure cover.
All acceptance, rebuilt FPP keys, responses, supports and decoder predicates
use that SAME constructed point function. All five concrete exceptions remain.
No supplied point equality/injectivity, desired binding or provenance premise.
Search/disjointness, Rust refinement, actual chronology, invalid-relation
acceptance-to-decoder-failure, QROM and all eight production gates remain open. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchGuardedDecsFailureCover
open NativeLaunchDerivedDecsFailureCover (Inputs)
open NativeLaunchGuardedPointGeometry (shiftGuard wireIndexGuard guarded_point_injective guarded_sampled_points_injective)
open SmallWood.NativeLaunchRelationModelResponse (Branch degree queryCount)
open SmallWood.V8Smz9McaDecoder (responseDecoder decoderFailureEvent)
open SmallWood.NativeHtlcUniversalMatrix (BadMatrix)
noncomputable section

/-- Discard the supplied generic point field and construct the native geometry
before formulating acceptance or any FPP/decoder expression. -/
def native {branch : Branch} (I : Inputs branch) (shift : Nat) : Inputs branch :=
  { I with point := NativeLaunchGuardedPointGeometry.point shift }

variable {branch : Branch} (I : Inputs branch) (shift : Nat)

theorem guarded_query_support
    (shiftAccepted : shiftGuard shift = true) (indicesAccepted : wireIndexGuard I.wire = true)
    (accepted : (native I shift).Accepted) (clean : ¬ (native I shift).Exceptional)
    (index : Fin (queryCount branch)) : I.wire.positions index ∈ (native I shift).support := by
  exact (native I shift).query_support accepted
    (guarded_sampled_points_injective I.wire shift shiftAccepted indicesAccepted) clean index

theorem guarded_failed_query_cover
    (shiftAccepted : shiftGuard shift = true) (indicesAccepted : wireIndexGuard I.wire = true)
    (accepted : (native I shift).Accepted)
    (index : Fin (queryCount branch)) (failed : I.wire.positions index ∉ (native I shift).support) :
    (native I shift).Exceptional := by
  exact (native I shift).failed_query_cover accepted
    (guarded_sampled_points_injective I.wire shift shiftAccepted indicesAccepted) index failed

theorem guarded_all_query_support_cover
    (shiftAccepted : shiftGuard shift = true) (indicesAccepted : wireIndexGuard I.wire = true)
    (accepted : (native I shift).Accepted) :
    (native I shift).Exceptional ∨ ∀ index, I.wire.positions index ∈ (native I shift).support := by
  exact (native I shift).all_query_support_cover accepted
    (guarded_sampled_points_injective I.wire shift shiftAccepted indicesAccepted)

theorem guarded_decoder_failure_cover
    (shiftAccepted : shiftGuard shift = true) (indicesAccepted : wireIndexGuard I.wire = true)
    (accepted : (native I shift).Accepted)
    (failed : responseDecoder (NativeLaunchGuardedPointGeometry.point shift) (degree branch)
      (native I shift).data (native I shift).masks (native I shift).response I.matrix = none) :
    (native I shift).Exceptional ∨
      (native I shift).sample (guarded_sampled_points_injective I.wire shift shiftAccepted indicesAccepted) ∈
        decoderFailureEvent (NativeLaunchGuardedPointGeometry.point shift) (degree branch) (queryCount branch)
          (native I shift).data (native I shift).masks (native I shift).response I.matrix := by
  exact (native I shift).decoder_failure_cover accepted
    (guarded_sampled_points_injective I.wire shift shiftAccepted indicesAccepted) failed

/-- Original computed decoder failure, with both injection premises discharged
by executable guards. This is generic in the branch and valid threshold. -/
theorem guarded_semantic_decoder_partition
    (shiftAccepted : shiftGuard shift = true) (indicesAccepted : wireIndexGuard I.wire = true)
    (accepted : (native I shift).Accepted) (threshold : Nat) (valid : degree branch < threshold)
    (failed : responseDecoder (NativeLaunchGuardedPointGeometry.point shift) (degree branch)
      (native I shift).data (native I shift).masks (native I shift).response I.matrix = none) :
    (native I shift).Exceptional ∨
      BadMatrix (NativeLaunchGuardedPointGeometry.point shift) (degree branch) threshold
        (native I shift).data (native I shift).masks I.matrix ∨
      ((native I shift).support.card < threshold ∧
        ((native I shift).sample (guarded_sampled_points_injective I.wire shift shiftAccepted indicesAccepted)).val ⊆
          (native I shift).support) := by
  exact (native I shift).semantic_decoder_partition accepted
    (guarded_sampled_points_injective I.wire shift shiftAccepted indicesAccepted)
    (guarded_point_injective shift shiftAccepted) threshold valid failed

end
end HegemonCrypto.NativeLaunchGuardedDecsFailureCover
