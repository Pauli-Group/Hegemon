import HegemonCrypto.Goldilocks
import HegemonCrypto.SmallWoodRelation
import Mathlib.Algebra.Polynomial.Div

/-!
# SmallWood interactive polynomial algebra

This module isolates the algebra checked by the interactive SmallWood verifier before any
Fiat--Shamir or commitment argument is applied.  It proves honest completeness for the nonlinear
quotient check and the global linear-sum check over an arbitrary field and finite packing domain.

The final section exposes the exact contract that a production polynomial implementation must
meet at packing nodes.  That contract is intentionally separate from the algebraic theorem: it
prevents an interpolation theorem from being mistaken for Rust implementation refinement.
-/

namespace HegemonCrypto.SmallWood.Interactive

open Polynomial
open scoped BigOperators

section Algebra

variable {F Node Nonlinear Linear : Type*}
variable [Field F]

/-- Polynomial vanishing exactly on the finite packing domain. -/
noncomputable def packingVanishing (nodes : Finset Node) (point : Node -> F) : F[X] :=
  nodes.prod fun node => X - C (point node)

/-- Fiat--Shamir batching is a linear combination of the supplied polynomials. -/
noncomputable def batch
    (indices : Finset Nonlinear)
    (weight : Nonlinear -> F)
    (polynomial : Nonlinear -> F[X]) : F[X] :=
  indices.sum fun index => C (weight index) * polynomial index

/-- Sum of one polynomial's evaluations over all packing nodes. -/
def nodeSum
    (nodes : Finset Node)
    (point : Node -> F)
    (polynomial : F[X]) : F :=
  nodes.sum fun node => polynomial.eval (point node)

/-- A polynomial vanishing on distinct packing nodes contains the full packing vanishing factor. -/
theorem nodal_dvd_of_eval_zero
    (nodes : Finset Node)
    (point : Node -> F)
    (pointInjective : Set.InjOn point nodes)
    (polynomial : F[X])
    (vanishes : ∀ node ∈ nodes, polynomial.eval (point node) = 0) :
    packingVanishing nodes point ∣ polynomial := by
  classical
  induction nodes using Finset.induction_on generalizing polynomial with
  | empty =>
      simp [packingVanishing]
  | @insert node nodes nodeNotMem induction =>
      rw [packingVanishing, Finset.prod_insert nodeNotMem]
      have root : Polynomial.IsRoot polynomial (point node) :=
        vanishes node (Finset.mem_insert_self node nodes)
      rcases (Polynomial.dvd_iff_isRoot.mpr root) with ⟨quotient, quotientEquation⟩
      rw [quotientEquation]
      have restrictedInjective : Set.InjOn point nodes := by
        apply pointInjective.mono
        intro selected selectedMembership
        exact Finset.mem_insert_of_mem selectedMembership
      have quotientVanishes :
          ∀ selected ∈ nodes, quotient.eval (point selected) = 0 := by
        intro selected selectedMembership
        have productZero := vanishes selected (Finset.mem_insert_of_mem selectedMembership)
        rw [quotientEquation, Polynomial.eval_mul, Polynomial.eval_sub,
          Polynomial.eval_X, Polynomial.eval_C] at productZero
        have pointsDiffer : point selected - point node ≠ 0 := by
          apply sub_ne_zero.mpr
          intro pointsEqual
          have indicesEqual : selected = node := pointInjective
            (Finset.mem_insert_of_mem selectedMembership)
            (Finset.mem_insert_self node nodes)
            pointsEqual
          exact nodeNotMem (indicesEqual ▸ selectedMembership)
        exact (mul_eq_zero.mp productZero).resolve_left pointsDiffer
      exact mul_dvd_mul_left (X - C (point node))
        (induction (polynomial := quotient) restrictedInjective quotientVanishes)

/-- Batched honest constraints continue to vanish at every packing node. -/
theorem batch_eval_zero
    (indices : Finset Nonlinear)
    (nodes : Finset Node)
    (point : Node -> F)
    (weight : Nonlinear -> F)
    (polynomial : Nonlinear -> F[X])
    (vanishes : ∀ index ∈ indices, ∀ node ∈ nodes,
      (polynomial index).eval (point node) = 0) :
    ∀ node ∈ nodes,
      (batch indices weight polynomial).eval (point node) = 0 := by
  intro node nodeMembership
  simp only [batch, Polynomial.eval_finsetSum, Polynomial.eval_mul, Polynomial.eval_C]
  apply Finset.sum_eq_zero
  intro index indexMembership
  simp [vanishes index indexMembership node nodeMembership]

/-- Every honest nonlinear batch has a quotient by the packing-domain polynomial. -/
theorem honest_nonlinear_quotient_exists
    (indices : Finset Nonlinear)
    (nodes : Finset Node)
    (point : Node -> F)
    (pointInjective : Set.InjOn point nodes)
    (weight : Nonlinear -> F)
    (polynomial : Nonlinear -> F[X])
    (vanishes : ∀ index ∈ indices, ∀ node ∈ nodes,
      (polynomial index).eval (point node) = 0) :
    ∃ quotient : F[X],
      batch indices weight polynomial = packingVanishing nodes point * quotient := by
  have divisibility := nodal_dvd_of_eval_zero nodes point pointInjective
    (batch indices weight polynomial)
    (batch_eval_zero indices nodes point weight polynomial vanishes)
  rcases divisibility with ⟨quotient, equation⟩
  exact ⟨quotient, equation⟩

/-- The nonlinear verifier equation is exact away from the packing domain, including its mask. -/
theorem masked_quotient_eval
    (nodes : Finset Node)
    (point : Node -> F)
    (batched quotient mask : F[X])
    (quotientEquation : batched = packingVanishing nodes point * quotient)
    (evaluationPoint : F)
    (outsidePackingDomain :
      (packingVanishing nodes point).eval evaluationPoint ≠ 0) :
    (quotient + mask).eval evaluationPoint =
      batched.eval evaluationPoint /
          (packingVanishing nodes point).eval evaluationPoint +
        mask.eval evaluationPoint := by
  rw [quotientEquation]
  simp [Polynomial.eval_add, Polynomial.eval_mul, outsidePackingDomain]

/-- Batching commutes with summing evaluations over the packing domain. -/
theorem nodeSum_batch
    (indices : Finset Nonlinear)
    (nodes : Finset Node)
    (point : Node -> F)
    (weight : Nonlinear -> F)
    (polynomial : Nonlinear -> F[X]) :
    nodeSum nodes point (batch indices weight polynomial) =
      indices.sum fun index => weight index * nodeSum nodes point (polynomial index) := by
  simp only [nodeSum, batch, Polynomial.eval_finsetSum, Polynomial.eval_mul,
    Polynomial.eval_C]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro index indexMembership
  rw [Finset.mul_sum]

/-- Honest linear constraints retain their weighted targets after batching. -/
theorem nodeSum_batch_eq_targets
    (indices : Finset Nonlinear)
    (nodes : Finset Node)
    (point : Node -> F)
    (weight : Nonlinear -> F)
    (polynomial : Nonlinear -> F[X])
    (target : Nonlinear -> F)
    (targetEquation : ∀ index ∈ indices,
      nodeSum nodes point (polynomial index) = target index) :
    nodeSum nodes point (batch indices weight polynomial) =
      indices.sum fun index => weight index * target index := by
  rw [nodeSum_batch]
  apply Finset.sum_congr rfl
  intro index indexMembership
  rw [targetEquation index indexMembership]

/-- A zero-sum linear mask hides the batch without changing the verifier's target equation. -/
theorem masked_linear_node_sum
    (indices : Finset Nonlinear)
    (nodes : Finset Node)
    (point : Node -> F)
    (weight : Nonlinear -> F)
    (polynomial : Nonlinear -> F[X])
    (target : Nonlinear -> F)
    (mask : F[X])
    (targetEquation : ∀ index ∈ indices,
      nodeSum nodes point (polynomial index) = target index)
    (maskSum : nodeSum nodes point mask = 0) :
    nodeSum nodes point (batch indices weight polynomial + mask) =
      indices.sum fun index => weight index * target index := by
  rw [nodeSum]
  simp only [Polynomial.eval_add, Finset.sum_add_distrib]
  change
    nodeSum nodes point (batch indices weight polynomial) + nodeSum nodes point mask = _
  rw [nodeSum_batch_eq_targets indices nodes point weight polynomial target targetEquation,
    maskSum, add_zero]

/-- Complete algebraic input to one repeated SmallWood interactive check. -/
structure System where
  nodes : Finset Node
  point : Node -> F
  pointInjective : Set.InjOn point nodes
  nonlinearIndices : Finset Nonlinear
  nonlinearPolynomial : Nonlinear -> F[X]
  linearIndices : Finset Linear
  linearPolynomial : Linear -> F[X]
  linearTarget : Linear -> F

namespace System

/-- All nonlinear packing-node checks and all global linear target checks hold. -/
def Satisfied (system : System (F := F) (Node := Node)
    (Nonlinear := Nonlinear) (Linear := Linear)) : Prop :=
  (∀ index ∈ system.nonlinearIndices, ∀ node ∈ system.nodes,
      (system.nonlinearPolynomial index).eval (system.point node) = 0) ∧
    (∀ index ∈ system.linearIndices,
      nodeSum system.nodes system.point (system.linearPolynomial index) =
        system.linearTarget index)

/-- The exact equations reconstructed by an honest prover for one repetition. -/
structure HonestEquations
    (system : System (F := F) (Node := Node)
      (Nonlinear := Nonlinear) (Linear := Linear))
    (nonlinearWeight : Nonlinear -> F)
    (linearWeight : Linear -> F)
    (nonlinearMask linearMask : F[X]) where
  quotient : F[X]
  quotientEquation :
    batch system.nonlinearIndices nonlinearWeight system.nonlinearPolynomial =
      packingVanishing system.nodes system.point * quotient
  nonlinearEvaluationEquation : ∀ evaluationPoint : F,
    (packingVanishing system.nodes system.point).eval evaluationPoint ≠ 0 ->
      (quotient + nonlinearMask).eval evaluationPoint =
        (batch system.nonlinearIndices nonlinearWeight
            system.nonlinearPolynomial).eval evaluationPoint /
            (packingVanishing system.nodes system.point).eval evaluationPoint +
          nonlinearMask.eval evaluationPoint
  linearTargetEquation :
    nodeSum system.nodes system.point
        (batch system.linearIndices linearWeight system.linearPolynomial + linearMask) =
      system.linearIndices.sum fun index => linearWeight index * system.linearTarget index

/-- Honest PIOP completeness, before commitments or Fiat--Shamir are introduced. -/
theorem honest_completeness
    (system : System (F := F) (Node := Node)
      (Nonlinear := Nonlinear) (Linear := Linear))
    (satisfied : system.Satisfied)
    (nonlinearWeight : Nonlinear -> F)
    (linearWeight : Linear -> F)
    (nonlinearMask linearMask : F[X])
    (linearMaskSum : nodeSum system.nodes system.point linearMask = 0) :
    Nonempty (HonestEquations system nonlinearWeight linearWeight nonlinearMask linearMask) := by
  rcases honest_nonlinear_quotient_exists system.nonlinearIndices system.nodes system.point
    system.pointInjective nonlinearWeight system.nonlinearPolynomial satisfied.1 with
    ⟨quotient, quotientEquation⟩
  refine ⟨{
    quotient := quotient
    quotientEquation := quotientEquation
    nonlinearEvaluationEquation := ?_
    linearTargetEquation := ?_
  }⟩
  · intro evaluationPoint outsidePackingDomain
    exact masked_quotient_eval system.nodes system.point
      (batch system.nonlinearIndices nonlinearWeight system.nonlinearPolynomial)
      quotient nonlinearMask quotientEquation evaluationPoint outsidePackingDomain
  · exact masked_linear_node_sum system.linearIndices system.nodes system.point linearWeight
      system.linearPolynomial system.linearTarget linearMask satisfied.2 linearMaskSum

end System

end Algebra

section ProductionAdapter

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

variable {F : Type*} [Field F]

/-- Embedding boundary between deployed natural representatives and a protocol field. -/
structure ProductionFieldEncoding where
  encode : Goldilocks →+* F
  injective : Function.Injective encode

/-- Exact packing-node equations required from a production polynomial implementation. -/
structure ProductionOracleRefinement
    (statement : Statement)
    (witness : Witness)
    (encoding : ProductionFieldEncoding (F := F)) where
  point : Nat -> F
  pointInjective : Set.InjOn point (Finset.range statement.lppcPackingFactor)
  nonlinearPolynomial : Nat -> F[X]
  nonlinearAtPackingNode : ∀ constraint < statement.nonlinearConstraintCount,
    ∀ lane < statement.lppcPackingFactor,
      (nonlinearPolynomial constraint).eval (point lane) =
        encoding.encode (toGoldilocks
          (nonlinearConstraintValue statement witness lane constraint))
  linearPolynomial : Nat -> F[X]
  linearPackingSum : ∀ constraint < statement.linearConstraintCount,
    nodeSum (Finset.range statement.lppcPackingFactor) point (linearPolynomial constraint) =
      encoding.encode (toGoldilocks
        (linearConstraintValue statement witness constraint))

/-- Algebraic PIOP system induced by one checked production-oracle refinement. -/
noncomputable def ProductionOracleRefinement.system
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := F)}
    (oracles : ProductionOracleRefinement statement witness encoding) :
    System (F := F) (Node := Nat) (Nonlinear := Nat) (Linear := Nat) :=
  System.mk
    (Finset.range statement.lppcPackingFactor)
    oracles.point
    oracles.pointInjective
    (Finset.range statement.nonlinearConstraintCount)
    oracles.nonlinearPolynomial
    (Finset.range statement.linearConstraintCount)
    oracles.linearPolynomial
    (fun constraint => encoding.encode
      (toGoldilocks (fieldValue (statement.linearTargets.getD constraint 0))))

/-- Exact relation membership exposes every deployed nonlinear packing-node equation. -/
theorem relation_nonlinear_equation
    (statement : Statement)
    (witness : Witness)
    (membership : (statement, witness) ∈ Relation)
    (lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (constraint : Nat)
    (constraintBound : constraint < statement.nonlinearConstraintCount) :
    nonlinearConstraintValue statement witness lane constraint = 0 := by
  have exactEvaluation := membership.2
  unfold ExactProductionConstraintMapEvaluates exactProductionConstraintMapEvaluatesB at exactEvaluation
  simp only [Bool.and_eq_true] at exactEvaluation
  have nonlinearProgram := exactEvaluation.2
  unfold nonlinearProgramEvaluatesB at nonlinearProgram
  simp only [Bool.and_eq_true] at nonlinearProgram
  have laneChecked := (List.all_eq_true.mp nonlinearProgram.2) lane
    (List.mem_range.mpr laneBound)
  unfold nonlinearLaneEvaluatesB at laneChecked
  have constraintChecked := (List.all_eq_true.mp laneChecked) constraint
    (List.mem_range.mpr constraintBound)
  exact of_decide_eq_true constraintChecked

/-- Exact relation membership exposes every deployed global linear target equation. -/
theorem relation_linear_equation
    (statement : Statement)
    (witness : Witness)
    (membership : (statement, witness) ∈ Relation)
    (constraint : Nat)
    (constraintBound : constraint < statement.linearConstraintCount) :
    linearConstraintValue statement witness constraint =
      fieldValue (statement.linearTargets.getD constraint 0) := by
  have exactEvaluation := membership.2
  unfold ExactProductionConstraintMapEvaluates exactProductionConstraintMapEvaluatesB at exactEvaluation
  simp only [Bool.and_eq_true] at exactEvaluation
  have linearProgram := exactEvaluation.1.2
  unfold linearProgramEvaluatesB at linearProgram
  have constraintChecked := (List.all_eq_true.mp linearProgram) constraint
    (List.mem_range.mpr constraintBound)
  exact of_decide_eq_true constraintChecked

/-- A checked production oracle refinement turns exact relation membership into PIOP satisfaction. -/
theorem production_oracles_satisfied
    (statement : Statement)
    (witness : Witness)
    (encoding : ProductionFieldEncoding (F := F))
    (oracles : ProductionOracleRefinement statement witness encoding)
    (membership : (statement, witness) ∈ Relation) :
    oracles.system.Satisfied := by
  constructor
  · intro constraint constraintMembership lane laneMembership
    have constraintBound := List.mem_range.mp constraintMembership
    have laneBound := List.mem_range.mp laneMembership
    change (oracles.nonlinearPolynomial constraint).eval (oracles.point lane) = 0
    rw [oracles.nonlinearAtPackingNode constraint constraintBound lane laneBound,
      relation_nonlinear_equation statement witness membership lane laneBound constraint
        constraintBound]
    exact map_zero encoding.encode
  · intro constraint constraintMembership
    have constraintBound := List.mem_range.mp constraintMembership
    change
      nodeSum (Finset.range statement.lppcPackingFactor) oracles.point
          (oracles.linearPolynomial constraint) =
        encoding.encode
          (toGoldilocks (fieldValue (statement.linearTargets.getD constraint 0)))
    rw [oracles.linearPackingSum constraint constraintBound,
      relation_linear_equation statement witness membership constraint constraintBound]

/-- Exact production relation membership supplies the honest interactive PIOP equations. -/
theorem production_honest_completeness
    (statement : Statement)
    (witness : Witness)
    (encoding : ProductionFieldEncoding (F := F))
    (oracles : ProductionOracleRefinement statement witness encoding)
    (membership : (statement, witness) ∈ Relation)
    (nonlinearWeight linearWeight : Nat -> F)
    (nonlinearMask linearMask : F[X])
    (linearMaskSum : nodeSum oracles.system.nodes oracles.system.point linearMask = 0) :
    Nonempty (System.HonestEquations oracles.system nonlinearWeight linearWeight
      nonlinearMask linearMask) := by
  exact System.honest_completeness oracles.system
    (production_oracles_satisfied statement witness encoding oracles membership)
    nonlinearWeight linearWeight nonlinearMask linearMask linearMaskSum

end ProductionAdapter

end HegemonCrypto.SmallWood.Interactive
