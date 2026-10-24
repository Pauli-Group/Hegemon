import HegemonCrypto.NativePrivateSpendQ58CurrentExecutableVerifier
import HegemonCrypto.SmallWoodV8Smz9AdmissibleRootProbability

/-! Current opening-domain root count. The old stronger domain is used only
as an injective subset to lower-bound the current domain cardinality. It is
NOT added as a current verifier guard. There is no physical/QROM mass claim. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOpeningDensity
open Polynomial
open V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdaptiveFiniteAccounting.Historical
open NativePrivateSpendQ58CurrentExecutableVerifier (Opening points)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false

instance : Fintype Opening := Fintype.ofFinite _

/-- Historical restrictions are sufficient for, but not required by, current
SMZD acceptance. Forgetting them preserves the exact six points. -/
def historicalToCurrent (old : FullAdmissibleOpeningTuple) : Opening :=
  let valid := full_admissible_linear_piop_exact old
  ⟨baseOpeningPoints old.1, valid.pointsInjective, valid.pointsNonzero,
    valid.pointsOutsidePacking, valid.correctionFactorNonzero⟩

def historicalToCurrentEmbedding : FullAdmissibleOpeningTuple ↪ Opening where
  toFun := historicalToCurrent
  inj' := by
    intro left right same
    apply Subtype.ext
    apply DFunLike.ext _ _
    intro coordinate
    apply Subtype.ext
    exact congrArg (fun current : Opening => points current coordinate) same

/-- The conservative already-checked denominator remains a lower bound,
although the current verifier accepts a larger domain. -/
theorem current_opening_card_lower_bound :
    correctionAwareOpeningTupleLowerBound ≤ Fintype.card Opening :=
  full_admissible_opening_tuple_card_lower_bound.trans
    (Fintype.card_le_of_embedding historicalToCurrentEmbedding)

abbrev CurrentRootTuple (polynomial : Goldilocks[X]) :=
  { opening : Opening // ∀ coordinate, polynomial.eval (points opening coordinate) = 0 }
instance (polynomial : Goldilocks[X]) : Fintype (CurrentRootTuple polynomial) :=
  Fintype.ofFinite _

def currentRootTupleEmbedding (polynomial : Goldilocks[X]) :
    CurrentRootTuple polynomial ↪
      (Fin 6 ↪ { point // point ∈ FiniteFieldSampling.rootSet polynomial }) where
  toFun accepted :=
    { toFun := fun coordinate =>
        ⟨points accepted.1 coordinate,
          (FiniteFieldSampling.mem_root_set_iff polynomial _).mpr (accepted.2 coordinate)⟩
      inj' := by
        intro left right same
        apply accepted.1.2.1
        exact congrArg
          (fun point : { point // point ∈ FiniteFieldSampling.rootSet polynomial } => point.val)
          same }
  inj' := by
    intro left right same
    apply Subtype.ext
    apply Subtype.ext
    funext coordinate
    exact congrArg (fun tuple => (tuple coordinate).val) same

/-- Count actual current distinct root tuples, with no legacy PCS restriction
and no supplied event density. -/
theorem current_root_tuple_card_le
    {polynomial : Goldilocks[X]} (nonzero : polynomial ≠ 0) :
    Fintype.card (CurrentRootTuple polynomial) ≤
      fallingProduct polynomial.natDegree piopOpenings := by
  calc
    Fintype.card (CurrentRootTuple polynomial) ≤
        Fintype.card (Fin 6 ↪ { point // point ∈ FiniteFieldSampling.rootSet polynomial }) :=
      Fintype.card_le_of_embedding (currentRootTupleEmbedding polynomial)
    _ = (FiniteFieldSampling.rootSet polynomial).card.descFactorial piopOpenings := by
      rw [Fintype.card_embedding_eq]
      simp [piopOpenings, V8Smz9QromAccounting.piopOpenings]
    _ ≤ polynomial.natDegree.descFactorial piopOpenings :=
      Nat.descFactorial_le _ (FiniteFieldSampling.root_set_card_le_nat_degree nonzero)
    _ = fallingProduct polynomial.natDegree piopOpenings := by
      exact (UniformSubsetSampling.falling_product_eq_desc_factorial _ _).symm

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOpeningDensity
