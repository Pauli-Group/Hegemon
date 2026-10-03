import SmzaRp05ChunkedRootFinite
import SmzaRp05LocalCertificate
import SmzaRp05AccumulatorHashBridge

/-! Accepted RP05 witnesses induce the reference Poseidon hash recurrences,
using the bounded chunked DAG refinement. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ChunkedAcceptedRecurrence

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05ChunkedDagRefinement
open HegemonCrypto.SmallWood.SmzaRp05ChunkedRootFinite
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem accepted_root_recurrence {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {wireIndex lane : Nat} (wireBound : wireIndex < 332)
    (laneBound : lane < 64) :
    laneField packed lane (rootRow wireIndex) =
      fieldAt referenceExpressions
        (fun n => (publicWords.getD n 0 : Goldilocks))
        (laneField packed lane)
        (hashRootPair (wireIndex / 166) (wireIndex % 166)).2 := by
  obtain ⟨rootExpression, witnessExpression, member,
      witnessBefore, rhsBefore, rhsSupported, mappedRhs⟩ :=
    root_shape wireIndex wireBound
  obtain ⟨values, evaluated, zero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 lane laneBound) member
  let pub : Nat → Goldilocks := fun n => (publicWords.getD n 0 : Goldilocks)
  let rows : Nat → Goldilocks := laneField packed lane
  have source := fieldAt_refines_source program.nonlinearExecutable publicWords
    (packedWitnessLaneRows packed lane) values
    SmzaRp05LocalCertificate.certificate.canonical evaluated
    (currentRoot wireIndex)
    (SmzaRp05LocalCertificate.certificate.canonical.2 _ member)
  change fieldAt currentExpressions pub rows (currentRoot wireIndex) =
    (values.getD (currentRoot wireIndex) 0 : Goldilocks) at source
  have rootValue :
      fieldAt currentExpressions pub rows (currentRoot wireIndex) =
        fieldAt currentExpressions pub rows (124 + rootRow wireIndex) -
          fieldAt currentExpressions pub rows (currentRhs wireIndex) := by
    rw [fieldAt_eq currentExpressions pub rows (currentRoot wireIndex),
      rootExpression]
    simp only [expressionField, if_pos witnessBefore, if_pos rhsBefore]
  have witnessValue :
      fieldAt currentExpressions pub rows (124 + rootRow wireIndex) =
        rows (rootRow wireIndex) := by
    rw [fieldAt_eq currentExpressions pub rows (124 + rootRow wireIndex),
      witnessExpression]
    rfl
  have rhsZero : (values.getD (currentRoot wireIndex) 0 : Goldilocks) = 0 := by
    simp [List.getD_eq_getElem?_getD, zero]
  rw [rootValue, witnessValue, rhsZero] at source
  have currentRecurrence := sub_eq_zero.mp source
  have paired := paired_fieldAt pub rows (currentRhs wireIndex) rhsSupported
  rw [mappedRhs] at paired
  exact currentRecurrence.trans paired

theorem accepted_hash_recurrence {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {group wire lane : Nat} (groupBound : group < 2)
    (wireBound : wire < 166) (laneBound : lane < 64) :
    laneField packed lane (hashRow group wire) =
      fieldAt referenceExpressions
        (fun n => (publicWords.getD n 0 : Goldilocks))
        (laneField packed lane) (hashRootPair group wire).2 := by
  have indexBound : 166 * group + wire < 332 := by omega
  have quotient : (166 * group + wire) / 166 = group := by omega
  have remainder : (166 * group + wire) % 166 = wire := by omega
  simpa [rootRow, quotient, remainder] using
    (accepted_root_recurrence accepted indexBound laneBound)

end HegemonCrypto.SmallWood.SmzaRp05ChunkedAcceptedRecurrence
