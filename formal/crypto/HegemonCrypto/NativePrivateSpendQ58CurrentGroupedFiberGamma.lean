import HegemonCrypto.NativePrivateSpendQ58CurrentConstructorGrouping
import HegemonCrypto.NativePrivateSpendQ58CurrentGammaFiber
import HegemonCrypto.NativePrivateSpendQ58ActiveEventProjection

/-! Exact current gamma label on the existing fixed-fiber completion.
Only ONE nonzero conditioned physical branch is used. An arbitrary sparse
basis is restored by the previously checked merge of its active database and
that same fixed table. It is not asserted equal to the original full basis,
and no independently nonzero standard physical view is a premise.
SOURCE ONLY: current G3 event inclusion/mass and kernel checks remain open. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGroupedFiberGamma

open HegemonCrypto.CmsCompressedOracle (Basis)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog physicalRun basisOracle)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open SmzaChallengeStageTargets (Role)
open scoped Classical
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (Counter RawInput RawDigest Key frame zero encode decode keyBytes key_bytes_injective
    recorded_current_base_parser stored_current_vector_answers_every_counter current_frame_address)
end G
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (RoleActive other_bounded_role_is_fixed)
end C
namespace P
export NativePrivateSpendQ58PartitionTransport
  (CmsState FixedTable conditioned nonzero_physical_fiber_fixed_answers)
end P
namespace A
export NativePrivateSpendQ58ActiveEventProjection
  (ActiveKey Memory restoreBasis merge_fixed)
end A
namespace F
export NativePrivateSpendQ58CurrentGammaFiber
  (currentRoleCaps fixedGamma gammaFromVector current_decs_base_vector_has_same_fiber_current_gamma)
end F
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (gammaAt gamma_at_congr_on_current_decs_keys)
end S
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (fieldKeys literal_request_counts)
end E
namespace RC
export NativePrivateSpendQ58CurrentRoleClassifier (canonicalCurrentQueryBytes)
end RC
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def live {Result : Type} (program : Program Result) (selected : Role) : G.Key program → Prop :=
  C.RoleActive selected F.currentRoleCaps (G.keyBytes program)

/-- Completion fills the exact current DECS group with the actual recorded
vector because that role is fixed in the same nonzero PIOP fiber. -/
theorem current_fiber_completion_stores_recorded_decs {Result Work : Type}
    [Fintype Work] [DecidableEq Work]
    (program : Program Result) (branch : Branches G.decode program)
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (fixed : P.FixedTable (Counter := G.Counter) (live program selected))
    (state : P.CmsState (Key := G.Key program) (Counter := G.Counter) (Work := Work))
    (fiberBasis : Basis (G.Key program) (VectorOutput G.Counter) (VectorOutput G.Counter) Work)
    (nonzero : P.conditioned (live program selected) fixed
      (physicalRun (G.encode program) G.decode program branch state) fiberBasis ≠ 0)
    (root : G.RawDigest) (vector : VectorOutput G.Counter)
    (recorded : (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero, vector) ∈
      answerLog G.decode program branch)
    (activeBasis : Basis (A.ActiveKey (live program selected))
      (VectorOutput G.Counter) (VectorOutput G.Counter)
      (A.Memory (Key := G.Key program) (Counter := G.Counter) (Work := Work))) :
    (A.restoreBasis (live program selected) fixed activeBasis).database
      (G.encode program (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero)) = some vector := by
  have parsed := G.recorded_current_base_parser program branch .decsMatrix root
    ⟨0, by decide⟩ G.zero vector recorded
  have different : Role.decsMatrix ≠ selected := by
    rcases piopSelected with matrix | opening
    · rw [matrix]; decide
    · rw [opening]; decide
  have inactive : ¬live program selected
      (G.encode program (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero)) :=
    C.other_bounded_role_is_fixed selected F.currentRoleCaps (G.keyBytes program) _
      ⟨.decsMatrix, root, 0, 0⟩ parsed different
      (by change 0 < F.currentRoleCaps .decsMatrix; decide)
  have same := P.nonzero_physical_fiber_fixed_answers (live program selected) fixed
    (G.encode program) G.decode program branch state fiberBasis nonzero _ recorded inactive
  have stored := A.merge_fixed (live program selected) fixed activeBasis.database
    ⟨G.encode program (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero), inactive⟩
  exact stored.trans (congrArg some same)

/-- Every restored sparse basis has the same current92-key gamma; the only
view construction is the retained restoreBasis/merge definition. -/
theorem current_gamma_on_every_restored_sparse_basis {Result Work : Type}
    [Fintype Work] [DecidableEq Work]
    (program : Program Result) (branch : Branches G.decode program)
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (fixed : P.FixedTable (Counter := G.Counter) (live program selected))
    (state : P.CmsState (Key := G.Key program) (Counter := G.Counter) (Work := Work))
    (fiberBasis : Basis (G.Key program) (VectorOutput G.Counter) (VectorOutput G.Counter) Work)
    (nonzero : P.conditioned (live program selected) fixed
      (physicalRun (G.encode program) G.decode program branch state) fiberBasis ≠ 0)
    (root : G.RawDigest) (vector : VectorOutput G.Counter)
    (recorded : (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero, vector) ∈
      answerLog G.decode program branch)
    (activeBasis : Basis (A.ActiveKey (live program selected))
      (VectorOutput G.Counter) (VectorOutput G.Counter)
      (A.Memory (Key := G.Key program) (Counter := G.Counter) (Work := Work)))
    (fallback : G.RawDigest) :
    S.gammaAt (basisOracle (G.encode program) G.decode
      (A.restoreBasis (live program selected) fixed activeBasis) fallback) root =
      F.gammaFromVector G.decode root vector := by
  have stored := current_fiber_completion_stores_recorded_decs program branch selected
    piopSelected fixed state fiberBasis nonzero root vector recorded activeBasis
  apply S.gamma_at_congr_on_current_decs_keys
  intro input member
  change input ∈ (List.range (SmzaRp05ExecutableChallengeStage.callCap 700)).map
    (fun counter => RC.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, counter⟩) at member
  rcases List.mem_map.mp member with ⟨counter, inRange, rfl⟩
  have bounded : counter < 840376 := by
    have small := List.mem_range.mp inRange
    rw [E.literal_request_counts.2.1] at small
    omega
  let c : G.Counter := ⟨counter, bounded⟩
  have literal : RC.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, counter⟩ =
      G.frame .decsMatrix root ⟨0, by decide⟩ c :=
    (NativePrivateSpendQ58CurrentConstructorGrouping.frame_is_literal_current
      .decsMatrix root ⟨0, by decide⟩ c).symm
  rw [literal]
  have answered := G.stored_current_vector_answers_every_counter program
    (A.restoreBasis (live program selected) fixed activeBasis) .decsMatrix root
    ⟨0, by decide⟩ vector stored c fallback
  have coord : NativePrivateSpendQ58CurrentConstructorGrouping.coordinate
      (G.frame .decsMatrix root ⟨0, by decide⟩ c) = c :=
    congrArg Prod.snd (G.current_frame_address _ _ _ _)
  simpa only [G.decode, coord, vectorOutputBytes] using answered

/-- Fixed gamma is literally the gamma of every current completed sparse
oracle in this SAME physical fiber, without a standard-view nonzero premise. -/
theorem current_same_fiber_fixed_gamma_is_completed_oracle_gamma {Result Work : Type}
    [Fintype Work] [DecidableEq Work]
    (program : Program Result) (branch : Branches G.decode program)
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (fixed : P.FixedTable (Counter := G.Counter) (live program selected))
    (state : P.CmsState (Key := G.Key program) (Counter := G.Counter) (Work := Work))
    (fiberBasis : Basis (G.Key program) (VectorOutput G.Counter) (VectorOutput G.Counter) Work)
    (nonzero : P.conditioned (live program selected) fixed
      (physicalRun (G.encode program) G.decode program branch state) fiberBasis ≠ 0)
    (root : G.RawDigest) (vector : VectorOutput G.Counter)
    (recorded : (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero, vector) ∈
      answerLog G.decode program branch)
    (activeBasis : Basis (A.ActiveKey (live program selected))
      (VectorOutput G.Counter) (VectorOutput G.Counter)
      (A.Memory (Key := G.Key program) (Counter := G.Counter) (Work := Work)))
    (fallback : G.RawDigest) :
    F.fixedGamma selected (G.keyBytes program) fixed G.decode root =
      some (S.gammaAt (basisOracle (G.encode program) G.decode
        (A.restoreBasis (live program selected) fixed activeBasis) fallback) root) := by
  have parsed := G.recorded_current_base_parser program branch .decsMatrix root
    ⟨0, by decide⟩ G.zero vector recorded
  have fixedSame := F.current_decs_base_vector_has_same_fiber_current_gamma selected
    piopSelected (G.keyBytes program) (G.key_bytes_injective program) fixed
    (G.encode program) G.decode program branch state fiberBasis nonzero
    (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero, vector) recorded root parsed
  have gammaSame := current_gamma_on_every_restored_sparse_basis program branch selected
    piopSelected fixed state fiberBasis nonzero root vector recorded activeBasis fallback
  exact fixedSame.trans (congrArg some gammaSame.symm)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGroupedFiberGamma
