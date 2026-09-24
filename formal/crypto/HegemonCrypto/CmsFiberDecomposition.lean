import HegemonCrypto.CmsKernelBounds

/-!
# CMS four-component database-fiber proof

For one fixed oracle input, phase, and private-workspace basis value, every database is either
absent at the queried input or is uniquely an insertion into an absent base database.  This file
uses that canonical fiber coordinate to reproduce the four orthogonal mass classes from CMS
Section 5.3.

The only probabilistic premise is `RealInstabilityBound`, which is already the exact finite
uniform-answer cardinality from `CmsClassicalDatabase`.
-/

namespace HegemonCrypto.CmsFiberDecomposition

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsKernelBounds
open HegemonCrypto.CmsLocalOperator

noncomputable section

variable {Input Output Phase : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]

noncomputable local instance complementDecidable
    (property : Property Input Output) :
    DecidablePred (complement property) :=
  Classical.decPred _

/--
Canonical coefficients on one query fiber.  `absent base` is the amplitude of an absent database;
`recorded base output` is the amplitude after inserting `output` into that absent base.
-/
structure FiberCoefficients (Input Output : Type*) where
  absent : Database Input Output -> ℂ
  recorded : Database Input Output -> Output -> ℂ

/-- Absent bases in `property` whose insertion remains strictly below the query cap. -/
def strictBases
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input) : Finset (Database Input Output) := by
  classical
  exact Finset.univ.filter fun database =>
    database input = none ∧
      property database ∧
      size database + 1 < queryBound

/-- Absent bases in `property` whose next insertion exactly reaches the query cap. -/
def edgeBases
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input) : Finset (Database Input Output) := by
  classical
  exact Finset.univ.filter fun database =>
    database input = none ∧
      property database ∧
      size database + 1 = queryBound

omit [DecidableEq Output] [AddCommGroup Output] in
theorem mem_strictBases_iff
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (database : Database Input Output) :
    database ∈ strictBases property queryBound input ↔
      database input = none ∧
        property database ∧
        size database + 1 < queryBound := by
  classical
  simp [strictBases]

omit [DecidableEq Output] [AddCommGroup Output] in
theorem mem_edgeBases_iff
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (database : Database Input Output) :
    database ∈ edgeBases property queryBound input ↔
      database input = none ∧
        property database ∧
        size database + 1 = queryBound := by
  classical
  simp [edgeBases]

/-- `s1`: recorded source mass whose erased base is in the target property. -/
def s1
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base ∈ strictBases property queryBound input,
    ∑ output ∈ insertionAnswers (complement property) base input,
      Complex.normSq (coefficient.recorded base output)

/-- `s2`: absent complement mass one insertion below the cap. -/
def s2
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base ∈ edgeBases (complement property) queryBound input,
    Complex.normSq (coefficient.absent base)

/-- `s3`: absent complement mass strictly below the cap boundary. -/
def s3
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base ∈ strictBases (complement property) queryBound input,
    Complex.normSq (coefficient.absent base)

/-- `s4`: recorded complement mass whose erased base also remains in the complement. -/
def s4
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base ∈ strictBases (complement property) queryBound input,
    ∑ output ∈ insertionAnswers (complement property) base input,
      Complex.normSq (coefficient.recorded base output)

/-- Total mass appearing in the four CMS crossing classes. -/
def crossingSourceMass
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  s1 property queryBound input coefficient +
    s2 property queryBound input coefficient +
    s3 property queryBound input coefficient +
    s4 property queryBound input coefficient

omit [DecidableEq Output] [AddCommGroup Output] in
theorem s1_nonnegative
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    0 <= s1 property queryBound input coefficient := by
  unfold s1
  apply Finset.sum_nonneg
  intro base _
  exact Finset.sum_nonneg fun output _ =>
    Complex.normSq_nonneg (coefficient.recorded base output)

omit [DecidableEq Output] [AddCommGroup Output] in
theorem s2_nonnegative
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    0 <= s2 property queryBound input coefficient := by
  unfold s2
  exact Finset.sum_nonneg fun base _ =>
    Complex.normSq_nonneg (coefficient.absent base)

omit [DecidableEq Output] [AddCommGroup Output] in
theorem s3_nonnegative
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    0 <= s3 property queryBound input coefficient := by
  unfold s3
  exact Finset.sum_nonneg fun base _ =>
    Complex.normSq_nonneg (coefficient.absent base)

omit [DecidableEq Output] [AddCommGroup Output] in
theorem s4_nonnegative
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    0 <= s4 property queryBound input coefficient := by
  unfold s4
  apply Finset.sum_nonneg
  intro base _
  exact Finset.sum_nonneg fun output _ =>
    Complex.normSq_nonneg (coefficient.recorded base output)

/-- `Psi_4`: erased target databases in the property. -/
def psi4Norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base ∈ strictBases property queryBound input,
    Complex.normSq
      (inverseSqrtOutputCard (Output := Output) *
        ∑ output ∈ insertionAnswers (complement property) base input,
          coefficient.recorded base output *
            system.character phaseValue output)

/-- `Xi_1`: cap-edge fresh insertions from the complement into the property. -/
def xi1Norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base ∈ edgeBases (complement property) queryBound input,
    ∑ output ∈ insertionAnswers property base input,
      Complex.normSq
        (inverseSqrtOutputCard (Output := Output) *
          (system.character phaseValue output * coefficient.absent base))

/-- `Xi_2`: replacements whose erased base is already in the property. -/
def xi2Norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base ∈ strictBases property queryBound input,
    ∑ targetOutput ∈ insertionAnswers property base input,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ insertionAnswers (complement property) base input,
            coefficient.recorded base sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))

/-- Direct part of `Xi_3`. -/
def xi3Direct
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output)
    (targetOutput : Output) : ℂ :=
  inverseSqrtOutputCard (Output := Output) *
    (system.character phaseValue targetOutput * coefficient.absent base)

/-- Replacement part of `Xi_3`. -/
def xi3Replacement
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output)
    (targetOutput : Output) : ℂ :=
  inverseOutputCard (Output := Output) *
    ∑ sourceOutput ∈ insertionAnswers (complement property) base input,
      coefficient.recorded base sourceOutput *
        (1 - system.character phaseValue sourceOutput -
          system.character phaseValue targetOutput)

/-- `Xi_3`: direct and replacement transitions from a complement base. -/
def xi3Norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base ∈ strictBases (complement property) queryBound input,
    ∑ targetOutput ∈ insertionAnswers property base input,
      Complex.normSq
        (xi3Direct system phaseValue coefficient base targetOutput +
          xi3Replacement system phaseValue property input coefficient base targetOutput)

omit [Fintype Phase] [DecidableEq Phase] in
theorem psi4_le
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    psi4Norm system phaseValue property queryBound input coefficient <=
      bound * s1 property queryBound input coefficient := by
  unfold psi4Norm s1
  calc
    (∑ base ∈ strictBases property queryBound input,
      Complex.normSq
        (inverseSqrtOutputCard (Output := Output) *
          ∑ output ∈ insertionAnswers (complement property) base input,
            coefficient.recorded base output *
              system.character phaseValue output)) <=
        ∑ base ∈ strictBases property queryBound input,
          bound *
            ∑ output ∈ insertionAnswers (complement property) base input,
              Complex.normSq (coefficient.recorded base output) := by
      apply Finset.sum_le_sum
      intro base baseMembership
      rw [mem_strictBases_iff] at baseMembership
      rcases baseMembership with ⟨absent, inProperty, strictSize⟩
      have sizeBound : size base < queryBound :=
        Nat.lt_trans (Nat.lt_succ_self _) strictSize
      have ratio :=
        insertion_answer_ratio_le_of_flip instability.2 base inProperty
          sizeBound input absent
      exact erasure_component_bound
        system phaseValue
        (insertionAnswers (complement property) base input)
        (coefficient.recorded base)
        ratio le_rfl instability.2.1
    _ = bound *
        ∑ base ∈ strictBases property queryBound input,
          ∑ output ∈ insertionAnswers (complement property) base input,
            Complex.normSq (coefficient.recorded base output) := by
      rw [Finset.mul_sum]

omit [DecidableEq Output] [Fintype Phase] [DecidableEq Phase] in
theorem xi1_le
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    xi1Norm system phaseValue property queryBound input coefficient <=
      bound * s2 property queryBound input coefficient := by
  unfold xi1Norm s2
  calc
    (∑ base ∈ edgeBases (complement property) queryBound input,
      ∑ output ∈ insertionAnswers property base input,
        Complex.normSq
          (inverseSqrtOutputCard (Output := Output) *
            (system.character phaseValue output * coefficient.absent base))) <=
        ∑ base ∈ edgeBases (complement property) queryBound input,
          bound * Complex.normSq (coefficient.absent base) := by
      apply Finset.sum_le_sum
      intro base baseMembership
      rw [mem_edgeBases_iff] at baseMembership
      rcases baseMembership with ⟨absent, inComplement, edgeSize⟩
      have sizeBound : size base < queryBound := by
        omega
      have ratio :=
        insertion_answer_ratio_le_of_flip instability.1 base inComplement
          sizeBound input absent
      exact insertion_component_bound
        system phaseValue (insertionAnswers property base input)
        (coefficient.absent base) ratio
    _ = bound *
        ∑ base ∈ edgeBases (complement property) queryBound input,
          Complex.normSq (coefficient.absent base) := by
      rw [Finset.mul_sum]

omit [Fintype Phase] [DecidableEq Phase] in
theorem xi2_le
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    xi2Norm system phaseValue property queryBound input coefficient <=
      5 * bound * s1 property queryBound input coefficient := by
  unfold xi2Norm s1
  calc
    (∑ base ∈ strictBases property queryBound input,
      ∑ targetOutput ∈ insertionAnswers property base input,
        Complex.normSq
          (inverseOutputCard (Output := Output) *
            ∑ sourceOutput ∈ insertionAnswers (complement property) base input,
              coefficient.recorded base sourceOutput *
                (1 - system.character phaseValue sourceOutput -
                  system.character phaseValue targetOutput))) <=
        ∑ base ∈ strictBases property queryBound input,
          5 * bound *
            ∑ sourceOutput ∈ insertionAnswers (complement property) base input,
              Complex.normSq (coefficient.recorded base sourceOutput) := by
      apply Finset.sum_le_sum
      intro base baseMembership
      rw [mem_strictBases_iff] at baseMembership
      rcases baseMembership with ⟨absent, inProperty, strictSize⟩
      have sizeBound : size base < queryBound :=
        Nat.lt_trans (Nat.lt_succ_self _) strictSize
      have ratio :=
        insertion_answer_ratio_le_of_flip instability.2 base inProperty
          sizeBound input absent
      exact replacement_component_bound
        system phaseValue nonzeroPhase
        (insertionAnswers (complement property) base input)
        (insertionAnswers property base input)
        (coefficient.recorded base)
        ratio le_rfl instability.2.1
    _ = 5 * bound *
        ∑ base ∈ strictBases property queryBound input,
          ∑ sourceOutput ∈ insertionAnswers (complement property) base input,
            Complex.normSq (coefficient.recorded base sourceOutput) := by
      rw [Finset.mul_sum]

omit [Fintype Phase] [DecidableEq Phase] in
theorem xi3_le
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    xi3Norm system phaseValue property queryBound input coefficient <=
      6 * bound *
        (s3 property queryBound input coefficient +
          s4 property queryBound input coefficient) := by
  unfold xi3Norm s3 s4
  calc
    (∑ base ∈ strictBases (complement property) queryBound input,
      ∑ targetOutput ∈ insertionAnswers property base input,
        Complex.normSq
          (xi3Direct system phaseValue coefficient base targetOutput +
            xi3Replacement system phaseValue property input coefficient
              base targetOutput)) <=
        ∑ base ∈ strictBases (complement property) queryBound input,
          6 * bound *
            (Complex.normSq (coefficient.absent base) +
              ∑ sourceOutput ∈ insertionAnswers (complement property) base input,
                Complex.normSq (coefficient.recorded base sourceOutput)) := by
      apply Finset.sum_le_sum
      intro base baseMembership
      rw [mem_strictBases_iff] at baseMembership
      rcases baseMembership with ⟨absent, inComplement, strictSize⟩
      have sizeBound : size base < queryBound :=
        Nat.lt_trans (Nat.lt_succ_self _) strictSize
      have targetRatio :=
        insertion_answer_ratio_le_of_flip instability.1 base inComplement
          sizeBound input absent
      apply combined_component_six_bound
      · exact insertion_component_bound
          system phaseValue (insertionAnswers property base input)
          (coefficient.absent base) targetRatio
      · exact replacement_component_target_bound
          system phaseValue nonzeroPhase
          (insertionAnswers (complement property) base input)
          (insertionAnswers property base input)
          (coefficient.recorded base)
          targetRatio le_rfl instability.1.1
    _ = 6 * bound *
        ((∑ base ∈ strictBases (complement property) queryBound input,
            Complex.normSq (coefficient.absent base)) +
          ∑ base ∈ strictBases (complement property) queryBound input,
            ∑ sourceOutput ∈ insertionAnswers (complement property) base input,
              Complex.normSq (coefficient.recorded base sourceOutput)) := by
      rw [mul_add, Finset.mul_sum, Finset.mul_sum, ← Finset.sum_add_distrib]
      apply Finset.sum_congr rfl
      intro base _
      ring

omit [Fintype Phase] [DecidableEq Phase] in
/--
The complete four-component local transition is bounded by `6 * instability` whenever the source
crossing classes have total mass at most one.
-/
theorem four_component_local_bound
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound)
    (normalized :
      crossingSourceMass property queryBound input coefficient <= 1) :
    psi4Norm system phaseValue property queryBound input coefficient +
        xi1Norm system phaseValue property queryBound input coefficient +
        xi2Norm system phaseValue property queryBound input coefficient +
        xi3Norm system phaseValue property queryBound input coefficient <=
      6 * bound := by
  let mass : SourceMasses :=
    { s1 := s1 property queryBound input coefficient
      s2 := s2 property queryBound input coefficient
      s3 := s3 property queryBound input coefficient
      s4 := s4 property queryBound input coefficient
      s1_nonnegative := s1_nonnegative property queryBound input coefficient
      s2_nonnegative := s2_nonnegative property queryBound input coefficient
      s3_nonnegative := s3_nonnegative property queryBound input coefficient
      s4_nonnegative := s4_nonnegative property queryBound input coefficient
      normalized := by
        simpa [crossingSourceMass] using normalized }
  let components : ProjectedComponentBounds mass :=
    { backwardFlip := bound
      forwardFlip := bound
      instability := bound
      psi4 := psi4Norm system phaseValue property queryBound input coefficient
      xi1 := xi1Norm system phaseValue property queryBound input coefficient
      xi2 := xi2Norm system phaseValue property queryBound input coefficient
      xi3 := xi3Norm system phaseValue property queryBound input coefficient
      backward_nonnegative := instability.2.1
      forward_nonnegative := instability.1.1
      instability_nonnegative := instability.1.1
      backward_le_instability := le_rfl
      forward_le_instability := le_rfl
      psi4_nonnegative := by
        unfold psi4Norm
        exact Finset.sum_nonneg fun base _ => Complex.normSq_nonneg _
      xi1_nonnegative := by
        unfold xi1Norm
        apply Finset.sum_nonneg
        intro base _
        exact Finset.sum_nonneg fun output _ => Complex.normSq_nonneg _
      xi2_nonnegative := by
        unfold xi2Norm
        apply Finset.sum_nonneg
        intro base _
        exact Finset.sum_nonneg fun output _ => Complex.normSq_nonneg _
      xi3_nonnegative := by
        unfold xi3Norm
        apply Finset.sum_nonneg
        intro base _
        exact Finset.sum_nonneg fun output _ => Complex.normSq_nonneg _
      psi4_le := by
        simpa [mass] using
          psi4_le system phaseValue property queryBound input coefficient instability
      xi1_le := by
        simpa [mass] using
          xi1_le system phaseValue property queryBound input coefficient instability
      xi2_le := by
        simpa [mass] using
          xi2_le system phaseValue nonzeroPhase property queryBound input coefficient instability
      xi3_le := by
        simpa [mass] using
          xi3_le system phaseValue nonzeroPhase property queryBound input coefficient instability }
  exact projected_component_sum_le_six_instability mass components

omit [Fintype Phase] [DecidableEq Phase] in
/--
Homogeneous four-component bound.  This is the direct-sum form: the projected mass is at most
`6 * instability` times the actual crossing source mass, without normalizing each block
independently.
-/
theorem four_component_local_bound_scaled
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    psi4Norm system phaseValue property queryBound input coefficient +
        xi1Norm system phaseValue property queryBound input coefficient +
        xi2Norm system phaseValue property queryBound input coefficient +
        xi3Norm system phaseValue property queryBound input coefficient <=
      6 * bound * crossingSourceMass property queryBound input coefficient := by
  have psiBound :=
    psi4_le system phaseValue property queryBound input coefficient instability
  have xi1Bound :=
    xi1_le system phaseValue property queryBound input coefficient instability
  have xi2Bound :=
    xi2_le system phaseValue nonzeroPhase property queryBound input coefficient instability
  have xi3Bound :=
    xi3_le system phaseValue nonzeroPhase property queryBound input coefficient instability
  have boundNonnegative : 0 <= bound := instability.1.1
  have s1Nonnegative := s1_nonnegative property queryBound input coefficient
  have s2Nonnegative := s2_nonnegative property queryBound input coefficient
  have s3Nonnegative := s3_nonnegative property queryBound input coefficient
  have s4Nonnegative := s4_nonnegative property queryBound input coefficient
  have firstAndThird :
      psi4Norm system phaseValue property queryBound input coefficient +
          xi2Norm system phaseValue property queryBound input coefficient <=
        6 * bound * s1 property queryBound input coefficient := by
    calc
      psi4Norm system phaseValue property queryBound input coefficient +
          xi2Norm system phaseValue property queryBound input coefficient <=
          bound * s1 property queryBound input coefficient +
            5 * bound * s1 property queryBound input coefficient :=
        add_le_add psiBound xi2Bound
      _ = 6 * bound * s1 property queryBound input coefficient := by ring
  have secondScaled :
      xi1Norm system phaseValue property queryBound input coefficient <=
        6 * bound * s2 property queryBound input coefficient := by
    calc
      xi1Norm system phaseValue property queryBound input coefficient <=
          bound * s2 property queryBound input coefficient := xi1Bound
      _ <= 6 * bound * s2 property queryBound input coefficient := by
        nlinarith
  calc
    psi4Norm system phaseValue property queryBound input coefficient +
        xi1Norm system phaseValue property queryBound input coefficient +
        xi2Norm system phaseValue property queryBound input coefficient +
        xi3Norm system phaseValue property queryBound input coefficient =
        (psi4Norm system phaseValue property queryBound input coefficient +
          xi2Norm system phaseValue property queryBound input coefficient) +
          xi1Norm system phaseValue property queryBound input coefficient +
          xi3Norm system phaseValue property queryBound input coefficient := by ring
    _ <=
        6 * bound * s1 property queryBound input coefficient +
          6 * bound * s2 property queryBound input coefficient +
          6 * bound *
            (s3 property queryBound input coefficient +
              s4 property queryBound input coefficient) :=
      add_le_add (add_le_add firstAndThird secondScaled) xi3Bound
    _ = 6 * bound *
        crossingSourceMass property queryBound input coefficient := by
      unfold crossingSourceMass
      ring

end

end HegemonCrypto.CmsFiberDecomposition
