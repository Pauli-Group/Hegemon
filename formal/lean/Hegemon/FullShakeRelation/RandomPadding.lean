import Std

namespace Hegemon
namespace FullShakeRelation
namespace RandomPadding

/-!
This file proves the exact algebraic hiding statement used by the proposed
random-high-tail PCS.  It deliberately works below probability theory:
uniform finite distributions are equal when one sampler is obtained from the
other by a permutation of the uniformly sampled seed space.

The proof only uses the additive part of a finite vector space, but the
interfaces below retain scalar multiplication and linearity so that a future
B128/E256 implementation cannot discharge the theorem with an arbitrary
nonlinear map.

Nothing here proves that an adaptive Fiat--Shamir query schedule is fixed,
that a Vandermonde matrix arising from concrete transcript queries has full
row rank, or that a BCS/QROM simulator exists.  Those remain explicit
certificate types at the end of the file.
-/

structure FiniteAbelianGroup (V : Type) where
  zero : V
  add : V → V → V
  neg : V → V
  addAssoc : ∀ a b c, add (add a b) c = add a (add b c)
  addComm : ∀ a b, add a b = add b a
  zeroAdd : ∀ a, add zero a = a
  negAdd : ∀ a, add (neg a) a = zero
  carrier : List V
  carrierComplete : ∀ a, a ∈ carrier
  carrierNodup : carrier.Nodup

structure FiniteField (K : Type) extends FiniteAbelianGroup K where
  one : K
  mul : K → K → K
  inv : K → K
  zeroNeOne : zero ≠ one
  mulAssoc : ∀ a b c, mul (mul a b) c = mul a (mul b c)
  mulComm : ∀ a b, mul a b = mul b a
  oneMul : ∀ a, mul one a = a
  leftDistrib : ∀ a b c, mul a (add b c) = add (mul a b) (mul a c)
  invMul : ∀ a, a ≠ zero → mul (inv a) a = one

structure FiniteVectorSpace (K V : Type) (field : FiniteField K)
    extends FiniteAbelianGroup V where
  smul : K → V → V
  oneSmul : ∀ v, smul field.one v = v
  mulSmul : ∀ a b v, smul (field.mul a b) v = smul a (smul b v)
  addSmul : ∀ a b v, smul (field.add a b) v = add (smul a v) (smul b v)
  smulAdd : ∀ a v w, smul a (add v w) = add (smul a v) (smul a w)
  zeroSmul : ∀ v, smul field.zero v = zero

structure LinearMap {K V W : Type} (field : FiniteField K)
    (domain : FiniteVectorSpace K V field)
    (codomain : FiniteVectorSpace K W field) where
  toFun : V → W
  mapZero : toFun domain.zero = codomain.zero
  mapAdd : ∀ v w, toFun (domain.add v w) = codomain.add (toFun v) (toFun w)
  mapSmul : ∀ a v, toFun (domain.smul a v) = codomain.smul a (toFun v)

theorem FiniteAbelianGroup.addZero {V : Type} (space : FiniteAbelianGroup V) (v : V) :
    space.add v space.zero = v := by
  calc
    space.add v space.zero = space.add space.zero v := space.addComm _ _
    _ = v := space.zeroAdd _

theorem FiniteAbelianGroup.addNeg {V : Type} (space : FiniteAbelianGroup V) (v : V) :
    space.add v (space.neg v) = space.zero := by
  calc
    space.add v (space.neg v) = space.add (space.neg v) v := space.addComm _ _
    _ = space.zero := space.negAdd _

theorem FiniteAbelianGroup.addLeftComm {V : Type} (space : FiniteAbelianGroup V)
    (a b c : V) : space.add a (space.add b c) = space.add b (space.add a c) := by
  calc
    space.add a (space.add b c) = space.add (space.add a b) c := (space.addAssoc _ _ _).symm
    _ = space.add (space.add b a) c := congrArg (fun x => space.add x c) (space.addComm _ _)
    _ = space.add b (space.add a c) := space.addAssoc _ _ _

def FiniteAbelianGroup.translate {V : Type} (space : FiniteAbelianGroup V)
    (shift value : V) : V :=
  space.add shift value

structure SeedPermutation (Seed : Type) where
  forward : Seed → Seed
  backward : Seed → Seed
  backwardForward : ∀ seed, backward (forward seed) = seed
  forwardBackward : ∀ seed, forward (backward seed) = seed

def SeedPermutation.identity (Seed : Type) : SeedPermutation Seed where
  forward := id
  backward := id
  backwardForward := by intro seed; rfl
  forwardBackward := by intro seed; rfl

def FiniteAbelianGroup.translationPermutation {V : Type}
    (space : FiniteAbelianGroup V) (shift : V) : SeedPermutation V where
  forward := space.translate shift
  backward := space.translate (space.neg shift)
  backwardForward := by
    intro value
    unfold FiniteAbelianGroup.translate
    calc
      space.add (space.neg shift) (space.add shift value) =
          space.add (space.add (space.neg shift) shift) value :=
        (space.addAssoc _ _ _).symm
      _ = space.add space.zero value := congrArg (fun x => space.add x value) (space.negAdd shift)
      _ = value := space.zeroAdd value
  forwardBackward := by
    intro value
    unfold FiniteAbelianGroup.translate
    calc
      space.add shift (space.add (space.neg shift) value) =
          space.add (space.add shift (space.neg shift)) value :=
        (space.addAssoc _ _ _).symm
      _ = space.add space.zero value := congrArg (fun x => space.add x value) (space.addNeg shift)
      _ = value := space.zeroAdd value

/-- Exact equality of two samplers driven by the same uniform finite seed.
The permutation is the measure-preserving coupling. -/
def SameUniformDistribution {Seed Output : Type}
    (left right : Seed → Output) : Prop :=
  ∃ reindex : SeedPermutation Seed,
    ∀ seed, left seed = right (reindex.forward seed)

theorem sameUniformDistribution_refl {Seed Output : Type} (sample : Seed → Output) :
    SameUniformDistribution sample sample := by
  exact ⟨SeedPermutation.identity Seed, by intro seed; rfl⟩

variable {K Active Randomness Observation : Type}
variable (field : FiniteField K)
variable (activeSpace : FiniteVectorSpace K Active field)
variable (randomnessSpace : FiniteVectorSpace K Randomness field)
variable (observationSpace : FiniteVectorSpace K Observation field)

def transcript
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace)
    (witness : Active) (randomness : Randomness) : Observation :=
  observationSpace.add (activeMap.toFun witness) (paddingMap.toFun randomness)

def ActiveShiftCovered
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace)
    (left right : Active) : Prop :=
  ∃ delta, activeMap.toFun left =
    observationSpace.add (activeMap.toFun right) (paddingMap.toFun delta)

def WitnessIndependent
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace) : Prop :=
  ∀ left right, SameUniformDistribution
    (transcript field activeSpace randomnessSpace observationSpace activeMap paddingMap left)
    (transcript field activeSpace randomnessSpace observationSpace activeMap paddingMap right)

def AllActiveShiftsCovered
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace) : Prop :=
  ∀ left right, ActiveShiftCovered field activeSpace randomnessSpace observationSpace
    activeMap paddingMap left right

theorem same_distribution_iff_active_shift_in_padding_range
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace)
    (left right : Active) :
    SameUniformDistribution
        (transcript field activeSpace randomnessSpace observationSpace activeMap paddingMap left)
        (transcript field activeSpace randomnessSpace observationSpace activeMap paddingMap right) ↔
      ActiveShiftCovered field activeSpace randomnessSpace observationSpace
        activeMap paddingMap left right := by
  constructor
  · intro same
    rcases same with ⟨reindex, pointwise⟩
    refine ⟨reindex.forward randomnessSpace.zero, ?_⟩
    have atZero := pointwise randomnessSpace.zero
    unfold transcript at atZero
    calc
      activeMap.toFun left =
          observationSpace.add (activeMap.toFun left) observationSpace.zero :=
        (observationSpace.addZero _).symm
      _ = observationSpace.add (activeMap.toFun left)
          (paddingMap.toFun randomnessSpace.zero) :=
        congrArg (observationSpace.add (activeMap.toFun left)) paddingMap.mapZero.symm
      _ = observationSpace.add (activeMap.toFun right)
          (paddingMap.toFun (reindex.forward randomnessSpace.zero)) := atZero
  · rintro ⟨delta, shiftEquation⟩
    refine ⟨randomnessSpace.translationPermutation delta, ?_⟩
    intro randomness
    change
      observationSpace.add (activeMap.toFun left) (paddingMap.toFun randomness) =
        observationSpace.add (activeMap.toFun right)
          (paddingMap.toFun (randomnessSpace.add delta randomness))
    calc
      observationSpace.add (activeMap.toFun left) (paddingMap.toFun randomness) =
          observationSpace.add
            (observationSpace.add (activeMap.toFun right) (paddingMap.toFun delta))
            (paddingMap.toFun randomness) :=
        congrArg (fun x => observationSpace.add x (paddingMap.toFun randomness)) shiftEquation
      _ = observationSpace.add (activeMap.toFun right)
          (observationSpace.add (paddingMap.toFun delta) (paddingMap.toFun randomness)) :=
        observationSpace.addAssoc _ _ _
      _ = observationSpace.add (activeMap.toFun right)
          (paddingMap.toFun (randomnessSpace.add delta randomness)) :=
        congrArg (observationSpace.add (activeMap.toFun right)) (paddingMap.mapAdd _ _).symm

theorem witness_independent_iff_all_active_shifts_in_padding_range
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace) :
    WitnessIndependent field activeSpace randomnessSpace observationSpace activeMap paddingMap ↔
      AllActiveShiftsCovered field activeSpace randomnessSpace observationSpace
        activeMap paddingMap := by
  constructor
  · intro independent left right
    exact (same_distribution_iff_active_shift_in_padding_range
      field activeSpace randomnessSpace observationSpace activeMap paddingMap left right).mp
      (independent left right)
  · intro covered left right
    exact (same_distribution_iff_active_shift_in_padding_range
      field activeSpace randomnessSpace observationSpace activeMap paddingMap left right).mpr
      (covered left right)

/-- Translation invariance is an exact finite-space formulation of a uniform
output distribution. -/
def FullyUniform
    (sample : Randomness → Observation) : Prop :=
  ∀ shift, SameUniformDistribution
    (fun randomness => observationSpace.add shift (sample randomness)) sample

def FullRowRank
    (paddingMap : LinearMap field randomnessSpace observationSpace) : Prop :=
  Function.Surjective paddingMap.toFun

theorem full_row_rank_padding_gives_full_uniform_output
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace)
    (fullRowRank : FullRowRank field randomnessSpace observationSpace paddingMap)
    (witness : Active) :
    FullyUniform field observationSpace
      (transcript field activeSpace randomnessSpace observationSpace activeMap paddingMap witness) := by
  intro shift
  rcases fullRowRank shift with ⟨delta, mapsToShift⟩
  refine ⟨randomnessSpace.translationPermutation delta, ?_⟩
  intro randomness
  change
    observationSpace.add shift
        (observationSpace.add (activeMap.toFun witness) (paddingMap.toFun randomness)) =
      observationSpace.add (activeMap.toFun witness)
        (paddingMap.toFun (randomnessSpace.add delta randomness))
  calc
    observationSpace.add shift
        (observationSpace.add (activeMap.toFun witness) (paddingMap.toFun randomness)) =
      observationSpace.add (activeMap.toFun witness)
        (observationSpace.add shift (paddingMap.toFun randomness)) :=
      observationSpace.addLeftComm _ _ _
    _ = observationSpace.add (activeMap.toFun witness)
        (observationSpace.add (paddingMap.toFun delta) (paddingMap.toFun randomness)) :=
      congrArg
        (fun x => observationSpace.add (activeMap.toFun witness)
          (observationSpace.add x (paddingMap.toFun randomness))) mapsToShift.symm
    _ = observationSpace.add (activeMap.toFun witness)
        (paddingMap.toFun (randomnessSpace.add delta randomness)) :=
      congrArg (observationSpace.add (activeMap.toFun witness)) (paddingMap.mapAdd _ _).symm

theorem full_row_rank_padding_is_witness_independent
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace)
    (fullRowRank : FullRowRank field randomnessSpace observationSpace paddingMap) :
    WitnessIndependent field activeSpace randomnessSpace observationSpace
      activeMap paddingMap := by
  intro left right
  apply (same_distribution_iff_active_shift_in_padding_range
    field activeSpace randomnessSpace observationSpace activeMap paddingMap left right).mpr
  rcases fullRowRank
      (observationSpace.add
        (observationSpace.neg (activeMap.toFun right))
        (activeMap.toFun left)) with ⟨delta, mapsToDifference⟩
  refine ⟨delta, ?_⟩
  calc
    activeMap.toFun left = observationSpace.add observationSpace.zero
        (activeMap.toFun left) := (observationSpace.zeroAdd _).symm
    _ = observationSpace.add
        (observationSpace.add
          (activeMap.toFun right)
          (observationSpace.neg (activeMap.toFun right)))
        (activeMap.toFun left) :=
      congrArg (fun value => observationSpace.add value (activeMap.toFun left))
        (observationSpace.addNeg (activeMap.toFun right)).symm
    _ = observationSpace.add (activeMap.toFun right)
        (observationSpace.add
          (observationSpace.neg (activeMap.toFun right))
          (activeMap.toFun left)) := observationSpace.addAssoc _ _ _
    _ = observationSpace.add (activeMap.toFun right)
        (paddingMap.toFun delta) :=
      congrArg (observationSpace.add (activeMap.toFun right)) mapsToDifference.symm

theorem zero_padding_rank_hides_iff_active_observations_equal
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace)
    (zeroRank : ∀ randomness, paddingMap.toFun randomness = observationSpace.zero)
    (left right : Active) :
    SameUniformDistribution
        (transcript field activeSpace randomnessSpace observationSpace activeMap paddingMap left)
        (transcript field activeSpace randomnessSpace observationSpace activeMap paddingMap right) ↔
      activeMap.toFun left = activeMap.toFun right := by
  constructor
  · intro same
    rcases same with ⟨reindex, pointwise⟩
    have atZero := pointwise randomnessSpace.zero
    unfold transcript at atZero
    rw [zeroRank, zeroRank, observationSpace.addZero, observationSpace.addZero] at atZero
    exact atZero
  · intro equal
    refine ⟨SeedPermutation.identity Randomness, ?_⟩
    intro randomness
    change
      observationSpace.add (activeMap.toFun left) (paddingMap.toFun randomness) =
        observationSpace.add (activeMap.toFun right) (paddingMap.toFun randomness)
    exact congrArg (fun x => observationSpace.add x (paddingMap.toFun randomness)) equal

/-- In characteristic two, reusing one padding sample in two observations
exposes the sum of the two active observations: the padding cancels exactly. -/
theorem reused_padding_exposes_binary_active_difference
    (activeMap : LinearMap field activeSpace observationSpace)
    (paddingMap : LinearMap field randomnessSpace observationSpace)
    (characteristicTwo : ∀ value,
      observationSpace.add value value = observationSpace.zero)
    (left right : Active) (randomness : Randomness) :
    observationSpace.add
        (transcript field activeSpace randomnessSpace observationSpace
          activeMap paddingMap left randomness)
        (transcript field activeSpace randomnessSpace observationSpace
          activeMap paddingMap right randomness) =
      observationSpace.add (activeMap.toFun left) (activeMap.toFun right) := by
  unfold transcript
  calc
    observationSpace.add
        (observationSpace.add (activeMap.toFun left) (paddingMap.toFun randomness))
        (observationSpace.add (activeMap.toFun right) (paddingMap.toFun randomness)) =
      observationSpace.add
        (observationSpace.add (activeMap.toFun left) (activeMap.toFun right))
        (observationSpace.add (paddingMap.toFun randomness) (paddingMap.toFun randomness)) := by
          rw [observationSpace.addAssoc]
          rw [observationSpace.addLeftComm (paddingMap.toFun randomness)]
          rw [← observationSpace.addAssoc]
    _ = observationSpace.add
        (observationSpace.add (activeMap.toFun left) (activeMap.toFun right))
        observationSpace.zero :=
      congrArg (observationSpace.add
        (observationSpace.add (activeMap.toFun left) (activeMap.toFun right)))
        (characteristicTwo _)
    _ = observationSpace.add (activeMap.toFun left) (activeMap.toFun right) :=
      observationSpace.addZero _

def ScheduleIndependent {Witness Transcript Query : Type}
    (schedule : Witness → Transcript → List Query) : Prop :=
  ∀ left right transcriptPrefix,
    schedule left transcriptPrefix = schedule right transcriptPrefix

/-- A concrete high-tail implementation must supply this proposition.  It is
not a global assumption and this file provides no inhabitant. -/
structure HighTailVandermondeCertificate
    (paddingMap : LinearMap field randomnessSpace observationSpace)
    (queryPointsNonzero queryPointsPairwiseDistinct monomialRowsMatchPaddingMap : Prop) : Prop where
  provesQueryPointsNonzero : queryPointsNonzero
  provesQueryPointsPairwiseDistinct : queryPointsPairwiseDistinct
  provesMonomialRowsMatchPaddingMap : monomialRowsMatchPaddingMap
  fullRowRank : FullRowRank field randomnessSpace observationSpace paddingMap

/-- This is the missing bridge from the fixed-matrix theorem above to an
adaptive Fiat--Shamir transcript.  No theorem in this file constructs it. -/
structure AdaptiveFiatShamirZkCertificate
    {Witness Transcript Query : Type}
    (schedule : Witness → Transcript → List Query)
    (terminalAndFriRowsIncluded bcsQromSimulatorExists
      qromProgrammingBoundAtLeast128Bits shake512TranscriptSaltBinding : Prop) : Prop where
  scheduleIndependent : ScheduleIndependent schedule
  provesTerminalAndFriRowsIncluded : terminalAndFriRowsIncluded
  provesBcsQromSimulatorExists : bcsQromSimulatorExists
  provesQromProgrammingBoundAtLeast128Bits : qromProgrammingBoundAtLeast128Bits
  provesShake512TranscriptSaltBinding : shake512TranscriptSaltBinding

end RandomPadding
end FullShakeRelation
end Hegemon
