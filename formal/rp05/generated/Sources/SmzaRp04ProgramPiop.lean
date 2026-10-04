import SmzaRp04NonlinearTransport
import HegemonCrypto.SmallWoodV8Smz9CurrentProgramPiop
namespace HegemonCrypto.SmallWood.SmzaRp04ProgramPiop
open Polynomial V8Smz9EagerPrivacy V8Smz9EagerSimulator
open V8Smz9PiopOpeningRecovery
noncomputable section
structure CurrentPublicParameters where
  publicValues : List Nat
  nonlinearGamma : Fin 5 → Fin 773 → Goldilocks
  linearWeights : Fin 5 → Fin 686 → Fin 64 → Goldilocks
  linearTargets : Fin 5 → Goldilocks

def publicWords (parameters : CurrentPublicParameters) : Nat → Goldilocks :=
  fun word => (parameters.publicValues.getD word 0 : Goldilocks)

def currentConstraints (parameters : CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) : Fin 773 → Goldilocks[X] :=
  SmzaRp04NonlinearTransport.constraintPolynomial (publicWords parameters)
    (witnessPolynomialAtNat witness)

def currentConstraintOpenings (parameters : CurrentPublicParameters)
    (opened : Fin 686 → Goldilocks) : Fin 773 → Goldilocks :=
  SmzaRp04NonlinearTransport.constraintScalar (publicWords parameters)
    (openedWitnessAtNat opened)

theorem witness_extension_degree (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69) :
    ∀ row, (witnessPolynomialAtNat witness row).natDegree ≤ 69 := by
  intro row
  by_cases bound : row < 686
  · simpa only [witnessPolynomialAtNat, dif_pos bound] using degreeBound ⟨row, bound⟩
  · simp [witnessPolynomialAtNat, bound]

theorem current_constraint_evaluation
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69)
    (constraint : Fin 773) (point : Goldilocks) :
    (currentConstraints parameters witness constraint).eval point =
      currentConstraintOpenings parameters (fun row => (witness row).eval point) constraint := by
  unfold currentConstraints currentConstraintOpenings
  rw [opened_witness_extension_matches_polynomial_evaluation]
  exact SmzaRp04NonlinearTransport.actual_constraint_evaluation _ _
    (witness_extension_degree witness degreeBound) constraint point

theorem current_constraint_degree
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69) (constraint : Fin 773) :
    (currentConstraints parameters witness constraint).natDegree ≤ 552 :=
  SmzaRp04NonlinearTransport.actual_constraint_degree _ _
    (witness_extension_degree witness degreeBound) constraint


end
end HegemonCrypto.SmallWood.SmzaRp04ProgramPiop
