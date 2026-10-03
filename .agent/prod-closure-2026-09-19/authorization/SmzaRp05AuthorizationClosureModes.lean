import SmzaRp05AuthorizationClosureSameNote

/-! Scalar mode replication from the actual first-family CSR equations. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureModes
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
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


def modeAttempt (mode : Fin 3) (lane : Fin 6) : CsrExecutableAttempt :=
  { globalIndex := 63 * (92 + mode.val) + lane.val
    family := 0
    localIndex := 63 * (92 + mode.val) + lane.val
    emission := 0
    terms := [((92 + mode.val) * 64 + lane.val + 1, 1),
      ((92 + mode.val) * 64, 3)]
    targetRoot := 0 }

private def modeChunk (mode : Fin 3) : List CsrExecutableAttempt :=
  if mode.val = 0 then exactCsrAttemptsChunk0181
  else if mode.val = 1 then exactCsrAttemptsChunk0183
  else exactCsrAttemptsChunk0185

private theorem modeAttempt_member (mode : Fin 3) (lane : Fin 6) :
    modeAttempt mode lane ∈ program.csrAttempts := by
  have member : modeAttempt mode lane ∈ modeChunk mode := by
    fin_cases mode <;> fin_cases lane <;> decide
  change modeAttempt mode lane ∈ exactCsrAttempts
  unfold exactCsrAttempts
  apply List.mem_flatten_of_mem (l := modeChunk mode) _ member
  fin_cases mode
  · exact List.getElem_mem (n := 181) (by decide)
  · exact List.getElem_mem (n := 183) (by decide)
  · exact List.getElem_mem (n := 185) (by decide)

theorem accepted_mode_replication {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (mode : Fin 3) (lane : Fin 6) :
    packed.getD ((92 + mode.val) * 64 + lane.val + 1) 0 =
      packed.getD ((92 + mode.val) * 64) 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have zero := constant_trace_value evaluated 0 0 (by decide)
  have one := constant_trace_value evaluated 1 1 (by decide)
  have minusOne := constant_trace_value evaluated 3 18446744069414584320 (by decide)
  have negative : (values.getD 3 0 : Goldilocks) = -1 := by
    rw [minusOne]
    decide
  have equation := accepted_csr_attempt_field_equality
    (attempts (modeAttempt mode lane) (modeAttempt_member mode lane))
  simp only [modeAttempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, zero, one, negative, neg_one_mul, add_zero] at equation
  apply canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _)
  simp only [packedWord]
  linear_combination equation

theorem lane_row (packed : List Nat) (lane row : Nat)
    (bound : row < relationRowCount) :
    (packedWitnessLaneRows packed lane).getD row 0 =
      packed.getD (row * 64 + lane) 0 := by
  simp [packedWitnessLaneRows, List.getD_eq_getElem?_getD, bound, packingFactor]

theorem accepted_lane_mode_eq {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (mode : Fin 3) (lane : Fin 7) :
    (packedWitnessLaneRows packed lane.val).getD (92 + mode.val) 0 =
      (packedWitnessLaneRows packed 0).getD (92 + mode.val) 0 := by
  rw [lane_row packed lane.val _ (by have := mode.isLt; change 92 + mode.val < 686; omega),
    lane_row packed 0 _ (by have := mode.isLt; change 92 + mode.val < 686; omega)]
  simp only [Nat.add_zero]
  fin_cases lane
  · rfl
  · exact accepted_mode_replication accepted mode 0
  · exact accepted_mode_replication accepted mode 1
  · exact accepted_mode_replication accepted mode 2
  · exact accepted_mode_replication accepted mode 3
  · exact accepted_mode_replication accepted mode 4
  · exact accepted_mode_replication accepted mode 5

end HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureModes
