import HegemonCrypto.SmallWoodV8Smz9SourceNullifierPosition

namespace HegemonCrypto.SmallWood.V8Smz9SourceNullifier32
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierFrames
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierScalarRho
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierPosition
open HegemonCrypto.SmallWood.V8Smz9NullifierSource
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def nullifierInitialAttempt (input lane : Nat) : CsrExecutableAttempt :=
  if lane = 0 then nullifierScalarAttempt input
  else if lane = 1 then nullifierPositionAttempt input
  else if lane < 6 then nullifierRhoAttempt input (lane - 2)
  else nullifierFrameAttempt input lane

theorem nullifier_initial_exact_lookup (input : Fin 2) (lane : Fin 16) :
    exactCsrAttempts[18300 + 16 * input.val + lane.val]? = some (nullifierInitialAttempt input.val lane.val) := by
  by_cases scalar : lane.val = 0
  · rw [nullifierInitialAttempt,if_pos scalar,scalar,Nat.add_zero,nullifier_scalar_exact_lookup]
  by_cases position : lane.val = 1
  · rw [nullifierInitialAttempt,if_neg scalar,if_pos position,position]
    convert nullifier_position_exact_lookup input using 1
    congr 1
    omega
  by_cases rho : lane.val < 6
  · rw [nullifierInitialAttempt,if_neg scalar,if_neg position,if_pos rho]
    have same : 18300 + 16 * input.val + lane.val = 18302 + 16 * input.val + (lane.val - 2) := by omega
    rw [same,nullifier_rho_exact_lookup input ⟨lane.val - 2,by omega⟩]
  · rw [nullifierInitialAttempt,if_neg scalar,if_neg position,if_neg rho,
      nullifier_frame_exact_lookup input lane (by omega)]

theorem full_candidate_nullifier_initial_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (input : Fin 2) (lane : Fin 16) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (nullifierInitialAttempt input.val lane.val) = 0 := by
  by_cases scalar : lane.val = 0
  · rw [nullifierInitialAttempt,if_pos scalar]
    exact full_candidate_nullifier_scalar_zero statement witness valid pub input
  by_cases position : lane.val = 1
  · rw [nullifierInitialAttempt,if_neg scalar,if_pos position]
    exact full_candidate_nullifier_position_zero statement witness valid pub input
  by_cases rho : lane.val < 6
  · rw [nullifierInitialAttempt,if_neg scalar,if_neg position,if_pos rho]
    exact full_candidate_nullifier_rho_zero statement witness valid pub input ⟨lane.val - 2,by omega⟩
  · rw [nullifierInitialAttempt,if_neg scalar,if_neg position,if_neg rho]
    exact full_candidate_nullifier_frame_zero statement witness valid pub input lane (by omega)

theorem nullifier_initial32_distinct_count :
    ((List.range 32).map (fun index => 18300 + index)).length = 32 ∧
      ((List.range 32).map (fun index => 18300 + index)).Nodup := by decide

theorem full_candidate_actual_nullifier_initial32_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (index : Fin 32) :
    (exactCsrAttempts[18300 + index.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  have address : 18300 + index.val = 18300 + 16 * (index.val / 16) + index.val % 16 := by omega
  rw [address,nullifier_initial_exact_lookup ⟨index.val / 16,by omega⟩ ⟨index.val % 16,by omega⟩,
    Option.map_some,full_candidate_nullifier_initial_zero statement witness valid pub]

end
end HegemonCrypto.SmallWood.V8Smz9SourceNullifier32
