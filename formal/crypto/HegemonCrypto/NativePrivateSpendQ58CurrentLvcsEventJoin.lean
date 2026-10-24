import HegemonCrypto.NativePrivateSpendQ58CurrentOrdinaryRecovery
import HegemonCrypto.NativePrivateSpendQ58CurrentDecodedRelation
import SmzaRp05ExecutablePcsClosureLvcsAlgebraInterpolation

/-! Current literal 13115-head/58-tail LVCS polynomial bridge.
The twelve checks below are DERIVED from the executed reconstruction, not a
TwelveChecks input. A nonzero current discrepancy remains an explicit all58
root event. Decoder and raw path facts in intermediate lemmas are calculated
readback arms, not the final acceptance theorem's premises.
SOURCE ONLY: no compiler, physical mass or gate qualification asserted. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLvcsEventJoin

open Polynomial
open NativePrivateSpendQ58CurrentExecutableVerifier
open SmzaRp05LvcsWireProjection SmzaRp05PcsWireProjection
open SmzaRp05ExecutablePcsClosureLvcsAlgebra
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (readPath)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9McaDecoder V8Smz9McaRecovery
open scoped Classical BigOperators
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport
  (currentPoint priorData priorMasks actualCoefficients
   prior_tables_match_actual_rows pcs_points_match_actual_indices)
end L
namespace O
export NativePrivateSpendQ58CurrentOrdinaryRecovery
  (Position actualView actualSample pcs_current_point_injective)
end O
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded columnPolynomial)
end D
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace encodeLeaf)
end M
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext)
end F

theorem current_reconstruct_rows_full_dot
    (fields : DecodedPcsFields) (points decsPoints : List F)
    (pointCount : points.length = 6) (rowScalars : List (List FieldWord))
    (widths deltas : List Nat) (rows : FMatrix)
    (success : reconstructRowsFromPcsFields fields points decsPoints rowScalars
      64 widths deltas 2 13115 140 58 = some rows) :
    ∃ heads inverse,
      reconstructAllHeads fields points rowScalars 64 widths deltas 2 13115 = some heads ∧
      gaussInverse 12
        (splitCoefficientMatrix pivotColumns (pcsBuildCoefficients points 2 64 140)).1 =
          some inverse ∧
      rows.length = decsPoints.length ∧
      ∀ j, j < decsPoints.length → ∀ k, k < 12 →
        dot ((pcsBuildCoefficients points 2 64 140).getD k []) (rows.getD j []) =
          evaluateConsecutive
            (rotateLeft ((heads.getD k []) ++
              ((fields.rcombiTails.map fieldWordsToGoldilocks).getD k [])) 13115)
            (decsPoints.getD j 0) := by
  exact NativePrivateSpendQ58CurrentAcceptedPcsFacts.reconstruct_rows_current_full_dot
    fields points decsPoints pointCount rowScalars widths deltas rows success


/-- Current specialization of the actual two-block residual equations. -/
theorem current_executed_block_equations
    (fields : DecodedPcsFields) (points decsPoints : List Goldilocks)
    (pointCount : points.length = 6) (rowScalars : List (List FieldWord))
    (widths deltas : List Nat) (rows : FMatrix)
    (success : reconstructRowsFromPcsFields fields points decsPoints rowScalars
      64 widths deltas 2 13115 140 58 = some rows) :
    ∃ heads,
      reconstructAllHeads fields points rowScalars 64 widths deltas 2 13115 = some heads ∧
      rows.length = decsPoints.length ∧
      ∀ j, j < decsPoints.length → ∀ opening : Fin 6, ∀ block : Fin 2,
        evaluateConsecutive
          (rotateLeft ((heads.getD (2 * opening.val + block.val) []) ++
            ((fields.rcombiTails.map fieldWordsToGoldilocks).getD
              (2 * opening.val + block.val) [])) 13115) (decsPoints.getD j 0) =
        ∑ coefficient : Fin 70, (points.getD opening.val 0) ^ coefficient.val *
          (rows.getD j []).getD (70 * block.val + coefficient.val) 0 := by
  exact NativePrivateSpendQ58CurrentAcceptedPcsFacts.reconstructed_rows_current_twelve_block_equations
    fields points decsPoints pointCount rowScalars widths deltas rows success

abbrev Combination := Fin 6 × Fin 2

def blockRow (block : Fin 2) (coefficient : Fin 70) : Fin 140 :=
  ⟨70 * block.val + coefficient.val, by have := block.isLt; have := coefficient.isLt; omega⟩

def combinationPolynomial (source : D.Decoded) (opening : Opening)
    (combination : Combination) : Goldilocks[X] :=
  ∑ coefficient : Fin 70,
    C (NativePrivateSpendQ58CurrentExecutableVerifier.points opening combination.1 ^ coefficient.val) *
      source.data (blockRow combination.2 coefficient)

def actualCombinationPolynomial (fields : DecodedPcsFields)
    (heads : FMatrix) (combination : Combination) : Goldilocks[X] :=
  consecutivePolynomial (rotateLeft
    ((heads.getD (2 * combination.1.val + combination.2.val) []) ++
      ((fields.rcombiTails.map fieldWordsToGoldilocks).getD
        (2 * combination.1.val + combination.2.val) [])) 13115)

def discrepancy (source : D.Decoded) (opening : Opening)
    (fields : DecodedPcsFields) (heads : FMatrix) (combination : Combination) : Goldilocks[X] :=
  actualCombinationPolynomial fields heads combination - combinationPolynomial source opening combination

/-- Literal current LVCS failure, retaining its nonzero polynomial and all
actual58 sampled positions. It is not a success/failure certificate field. -/
def CurrentLvcsRootEvent (source : D.Decoded) (opening : Opening)
    (fields : DecodedPcsFields) (heads : FMatrix) (coordinates : Fin 58 → O.Position) : Prop :=
  ∃ combination,
    discrepancy source opening fields heads combination ≠ 0 ∧
    ∀ j, (discrepancy source opening fields heads combination).eval (L.currentPoint (coordinates j)) = 0

/-- Successful current source recovery, literal leaf cells and the executable
LVCS residual jointly DERIVE every sampled discrepancy zero. No TwelveChecks
or sampled scalar-agreement callback occurs in the signature. -/
theorem executed_recovered_current_discrepancy_roots
    (ns : M.Namespace) (pending : Bool) (wire : Wire) (decoded : DecodedFields)
    (opening : Opening) (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (prior : RawRecords) (source : D.Decoded)
    (calculated : NativePrivateSpendQ58CurrentRecovery.decoded L.currentPoint
      (O.actualView prior output) = some source)
    (coordinates : Fin 58 → O.Position)
    (indicesEq : ∀ j, (coordinates j).val = output.indexes.getD j.val 0)
    (supported : Finset.univ.image coordinates ⊆
      NativePrivateSpendQ58CurrentRecovery.support L.currentPoint (O.actualView prior output))
    (readbacks : ∀ j, readPath (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (extract F.rawNext prior 25 .root output.root) =
        some (M.encodeLeaf output.input.binding (output.input.payloads j))) :
    ∃ heads,
      reconstructAllHeads decoded.pcs (List.ofFn (points opening)) decoded.rowScalars
        64 NativePrivateSpendQ58CurrentExecutableVerifier.widths
        NativePrivateSpendQ58CurrentExecutableVerifier.deltas 2 13115 = some heads ∧
      ∀ combination j,
        (discrepancy source opening decoded.pcs heads combination).eval (L.currentPoint (coordinates j)) = 0 := by
  obtain ⟨_, sampledPending, _, _, _, _, pointsEq, rowsEq, inputEq, _⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
      ns pending wire decoded opening oracle output executed
  have pointAt := L.pcs_points_match_actual_indices ns pending wire decoded opening
    oracle output executed coordinates indicesEq
  have tables := L.prior_tables_match_actual_rows ns pending wire decoded opening
    oracle output executed prior coordinates readbacks
  have pointInjective := O.pcs_current_point_injective ns pending wire decoded opening
    oracle output executed coordinates indicesEq
  have recovered := decoded_source_agrees_and_has_bounded_degree L.currentPoint
    pointInjective 13172
    (NativePrivateSpendQ58CurrentRecovery.support L.currentPoint (O.actualView prior output))
    (L.priorData prior output.root) (L.priorMasks prior output.root) source calculated
  have fields := NativePrivateSpendQ58CurrentAcceptedLeafSupport.merkle_input_actual_fields
    wire.salt ns.binding sampledPending output.indexes output.rows decoded.decs.maskingEvals
    wire.tapes wire.paths output.input inputEq
  obtain ⟨pointLength, _⟩ := mapM_success_entry output.indexes
    (SmzaRp05DecsPointProjection.fieldPoint 13173) output.decsPoints 0 0 pointsEq
  have currentLength : output.decsPoints.length = 58 := pointLength.trans fields.2.2.1
  obtain ⟨heads, headsBuilt, _, checks⟩ := current_executed_block_equations
    decoded.pcs (List.ofFn (points opening)) output.decsPoints (by simp)
    decoded.rowScalars NativePrivateSpendQ58CurrentExecutableVerifier.widths
    NativePrivateSpendQ58CurrentExecutableVerifier.deltas output.rows rowsEq
  refine ⟨heads, headsBuilt, ?_⟩
  intro combination j
  have checked := checks j.val (by rw [currentLength]; exact j.isLt)
    combination.1 combination.2
  rw [pointAt j] at checked
  have agree : ∀ column : Fin 140,
      (source.data column).eval (L.currentPoint (coordinates j)) =
        (output.rows.getD j.val []).getD column.val 0 := by
    intro column
    exact (recovered.2.1.2 column (coordinates j)
      (supported (Finset.mem_image.mpr ⟨j, Finset.mem_univ j, rfl⟩))).trans
        (tables.1 j column)
  simp only [discrepancy, eval_sub, actualCombinationPolynomial,
    ← evaluate_consecutive_eq_polynomial, combinationPolynomial,
    eval_finsetSum, eval_mul, eval_C]
  rw [checked]
  apply sub_eq_zero.mpr
  apply Finset.sum_congr rfl
  intro coefficient _
  rw [agree]
  have pointEq :
      (List.ofFn (NativePrivateSpendQ58CurrentExecutableVerifier.points opening)).getD
        combination.1.val 0 =
      NativePrivateSpendQ58CurrentExecutableVerifier.points opening combination.1 := by
    simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn,
      dif_pos combination.1.isLt, Option.getD_some]
  exact congrArg (fun point : Goldilocks =>
    point ^ coefficient.val * (output.rows.getD j.val []).getD
      (70 * combination.2.val + coefficient.val) 0) pointEq

/-- Pointwise completeness of the named LVCS failure arm. There is no
assumed detection predicate: failure of a polynomial identity constructs the
exact nonzero polynomial which vanished on the actual sampled coordinates. -/
theorem current_combinations_equal_or_literal_root_event
    (source : D.Decoded) (opening : Opening) (fields : DecodedPcsFields)
    (heads : FMatrix) (coordinates : Fin 58 → O.Position)
    (derivedRoots : ∀ combination j,
      (discrepancy source opening fields heads combination).eval (L.currentPoint (coordinates j)) = 0) :
    (∀ combination, actualCombinationPolynomial fields heads combination =
      combinationPolynomial source opening combination) ∨
    CurrentLvcsRootEvent source opening fields heads coordinates := by
  by_cases equal : ∀ combination, actualCombinationPolynomial fields heads combination =
      combinationPolynomial source opening combination
  · exact Or.inl equal
  · apply Or.inr
    push Not at equal
    obtain ⟨combination, different⟩ := equal
    exact ⟨combination, sub_ne_zero.mpr different, derivedRoots combination⟩

/-- The inverse current row-major maps yield the real unstacked column
opening from a current combination evaluated at head node58+column. -/
theorem combination_head_is_current_column_opening
    (source : D.Decoded) (opening : Opening) (coordinate : Fin 6)
    (block : Fin 2) (head : Fin 13115) :
    (combinationPolynomial source opening (coordinate, block)).eval ((58 + head.val : Nat) : Goldilocks) =
      (D.columnPolynomial source (finProdFinEquiv (block, head))).eval (points opening coordinate) := by
  simp only [combinationPolynomial, D.columnPolynomial, eval_finsetSum,
    eval_mul, eval_C, eval_pow, eval_X,
    NativePrivateSpendQ58CurrentDecodedRelation.unstackedCell,
    NativePrivateSpendQ58CurrentDecodedRelation.rowHead, Equiv.symm_apply_apply]
  apply Finset.sum_congr rfl
  intro coefficient _
  have index : blockRow block coefficient = finProdFinEquiv (block, coefficient) := by
    apply Fin.ext
    change 70 * block.val + coefficient.val = coefficient.val + 70 * block.val
    omega
  rw [index]
  ring

/-- Current positions, not the old fixed-shift domain. -/
def currentRootIndices (point : O.Position → Goldilocks) (polynomial : Goldilocks[X]) : Finset O.Position :=
  Finset.univ.filter fun index => polynomial.eval (point index) = 0

theorem current_root_indices_card
    (point : O.Position → Goldilocks) (injective : Function.Injective point)
    (polynomial : Goldilocks[X]) (nonzero : polynomial ≠ 0) :
    (currentRootIndices point polynomial).card ≤ polynomial.natDegree := by
  let embedding : { index // index ∈ currentRootIndices point polynomial } ↪
      { value // value ∈ FiniteFieldSampling.rootSet polynomial } :=
    { toFun := fun index => ⟨point index.val,
        (FiniteFieldSampling.mem_root_set_iff polynomial _).mpr
          ((Finset.mem_filter.mp index.property).2)⟩
      inj' := by
        intro left right same
        apply Subtype.ext
        exact injective (congrArg (fun value : { value // value ∈ FiniteFieldSampling.rootSet polynomial } => value.val) same) }
  have count : (currentRootIndices point polynomial).card ≤
      (FiniteFieldSampling.rootSet polynomial).card := by
    simpa only [Fintype.card_coe] using Fintype.card_le_of_embedding embedding
  exact count.trans (FiniteFieldSampling.root_set_card_le_nat_degree nonzero)

/-- No sampled equality or density is supplied: this counts exactly the
current58 subsets contained in one fixed nonzero polynomial's root set. -/
abbrev RootQuery (point : O.Position → Goldilocks) (polynomial : Goldilocks[X]) :=
  { query : QuerySample O.Position 58 // query.val ⊆ currentRootIndices point polynomial }
instance (point : O.Position → Goldilocks) (polynomial : Goldilocks[X]) :
    Fintype (RootQuery point polynomial) := Fintype.ofFinite _

def rootQueryEmbedding (point : O.Position → Goldilocks) (polynomial : Goldilocks[X]) :
    RootQuery point polynomial ↪
      { subset // subset ∈ (currentRootIndices point polynomial).powersetCard 58 } where
  toFun query := ⟨query.val.val, Finset.mem_powersetCard.mpr ⟨query.property, query.val.property⟩⟩
  inj' := by
    intro left right same
    apply Subtype.ext
    apply Subtype.ext
    exact congrArg
      (fun subset : { subset : Finset O.Position //
          subset ∈ (currentRootIndices point polynomial).powersetCard 58 } => subset.val) same

theorem current58_root_query_card
    (point : O.Position → Goldilocks) (injective : Function.Injective point)
    (polynomial : Goldilocks[X]) (nonzero : polynomial ≠ 0) :
    Fintype.card (RootQuery point polynomial) ≤ Nat.choose polynomial.natDegree 58 := by
  calc
    _ ≤ Fintype.card { subset // subset ∈ (currentRootIndices point polynomial).powersetCard 58 } :=
      Fintype.card_le_of_embedding (rootQueryEmbedding point polynomial)
    _ = Nat.choose (currentRootIndices point polynomial).card 58 := by
      rw [Fintype.card_coe, Finset.card_powersetCard]
    _ ≤ Nat.choose polynomial.natDegree 58 :=
      Nat.choose_le_choose 58 (current_root_indices_card point injective polynomial nonzero)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLvcsEventJoin
