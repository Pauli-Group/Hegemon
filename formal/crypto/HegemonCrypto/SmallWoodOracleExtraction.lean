import HegemonCrypto.SmallWoodDecsExtraction
import HegemonCrypto.SmallWoodRoundByRound
import Mathlib.Data.List.OfFn
import Mathlib.GroupTheory.OrderOfElement

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Deterministic extraction from the active SmallWood oracle

The interactive SmallWood prover exposes the complete DECS evaluation oracle.  This module
implements the inverse of the active production encoding:

1. interpolate each committed DECS column over the `2^20` Goldilocks subgroup;
2. undo the LVCS left rotation by evaluating at the 375 data points `23 .. 397`;
3. undo the fixed two-way stacking into the `69 x 749` matrix;
4. recover the first 699 degree-68 witness polynomials; and
5. evaluate those polynomials at the 64 packing points.

No witness is selected by choice.  `extractWitness` is one deterministic function of the full
interactive oracle.
-/

namespace HegemonCrypto.SmallWood.OracleExtraction

open Polynomial
open scoped BigOperators
open HegemonCrypto.SmallWood.DecsExtraction
open HegemonCrypto.SmallWood.Extraction
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWood.PiopExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

noncomputable section

/-- The production Goldilocks two-adic root, shared with the Rust evaluator. -/
def goldilocksTwoAdicRoot : Goldilocks :=
  (0x185629dcda58878c : Nat)

/-- Generator of the active `2^20` evaluation subgroup. -/
def activeRadix2Root : Goldilocks :=
  goldilocksTwoAdicRoot ^ (2 ^ 12)

theorem active_radix2_root_pow_domain :
    activeRadix2Root ^ (2 ^ 20) = 1 := by
  change
    ((1753635133440165772 : ZMod 18446744069414584321) ^ (2 ^ 12)) ^
        (2 ^ 20) = 1
  calc
    _ =
        (1753635133440165772 : ZMod 18446744069414584321) ^
          ((2 ^ 12) * (2 ^ 20)) :=
      (pow_mul (1753635133440165772 : ZMod 18446744069414584321)
        (2 ^ 12) (2 ^ 20)).symm
    _ = 1 := by
      reduce_mod_char

theorem active_radix2_root_pow_half_ne_one :
    activeRadix2Root ^ (2 ^ 19) ≠ 1 := by
  change
    ((1753635133440165772 : ZMod 18446744069414584321) ^ (2 ^ 12)) ^
        (2 ^ 19) ≠ 1
  intro equality
  have combined :
      (1753635133440165772 : ZMod 18446744069414584321) ^
          ((2 ^ 12) * (2 ^ 19)) = 1 := by
    calc
      _ =
          ((1753635133440165772 : ZMod 18446744069414584321) ^ (2 ^ 12)) ^
            (2 ^ 19) :=
        pow_mul (1753635133440165772 : ZMod 18446744069414584321)
          (2 ^ 12) (2 ^ 19)
      _ = 1 := equality
  reduce_mod_char at combined
  have representativeEquality := congrArg ZMod.val combined
  change 18446744069414584320 = 1 at representativeEquality
  omega

theorem active_radix2_root_order :
    orderOf activeRadix2Root = 2 ^ 20 := by
  simpa using
    (orderOf_eq_prime_pow
      (p := 2)
      (n := 19)
      (x := activeRadix2Root)
      active_radix2_root_pow_half_ne_one
      active_radix2_root_pow_domain)

/-- Exact point used by the active Rust radix-2 DECS evaluator. -/
def activeEvaluationPoint (index : Fin decsEvaluationCount) : Goldilocks :=
  activeRadix2Root ^ index.val

theorem active_evaluation_point_injective :
    Function.Injective activeEvaluationPoint := by
  intro left right equalPowers
  have finiteOrder : IsOfFinOrder activeRadix2Root :=
    isOfFinOrder_iff_pow_eq_one.mpr
      ⟨2 ^ 20, by positivity, active_radix2_root_pow_domain⟩
  have equalRemainders :=
    (finiteOrder.pow_inj_mod (n := left.val) (m := right.val)).mp equalPowers
  rw [active_radix2_root_order] at equalRemainders
  have leftReduced : left.val % 2 ^ 20 = left.val :=
    Nat.mod_eq_of_lt left.isLt
  have rightReduced : right.val % 2 ^ 20 = right.val :=
    Nat.mod_eq_of_lt right.isLt
  rw [leftReduced, rightReduced] at equalRemainders
  exact Fin.ext equalRemainders

/-- Canonical embedding of one stored Goldilocks word into the proof field. -/
def wordToGoldilocks (word : FieldWord) : Goldilocks :=
  toGoldilocks word.val

/-- Canonical equivalence between stored field words and the Goldilocks proof field. -/
def fieldWordGoldilocksEquiv : FieldWord ≃ Goldilocks where
  toFun := wordToGoldilocks
  invFun := fun value => ⟨fromGoldilocks value, fromGoldilocks_lt value⟩
  left_inv := by
    intro word
    apply Fin.ext
    change fromGoldilocks (toGoldilocks word.val) = word.val
    rw [fromGoldilocks_toGoldilocks]
    exact Nat.mod_eq_of_lt word.isLt
  right_inv := by
    intro value
    exact toGoldilocks_fromGoldilocks value

/-- Entrywise conversion of the first uniform DECS challenge. -/
def decsChallengeToGoldilocks
    (challenge : Matrix decsEta lvcsRowCount) :
    HegemonCrypto.SmallWoodPowerBatching.CoefficientMatrix
      (F := Goldilocks) lvcsRowCount decsEta :=
  fun repetition row => wordToGoldilocks (challenge repetition row)

/-- Entrywise conversion of the statement-specific PIOP batching challenge. -/
def piopChallengeToGoldilocks
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement) :
    HegemonCrypto.SmallWoodPowerBatching.CoefficientMatrix
      (F := Goldilocks)
      (productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount)
  rho :=
  fun repetition column => wordToGoldilocks (challenge repetition column)

/-- The first verifier challenge is uniformly equivalent to a Goldilocks coefficient matrix. -/
def decsChallengeEquiv :
    Matrix decsEta lvcsRowCount ≃
      HegemonCrypto.SmallWoodPowerBatching.CoefficientMatrix
        (F := Goldilocks) lvcsRowCount decsEta :=
  Equiv.piCongrRight fun _ =>
    Equiv.piCongrRight fun _ => fieldWordGoldilocksEquiv

theorem decs_challenge_equiv_apply
    (challenge : Matrix decsEta lvcsRowCount) :
    decsChallengeEquiv challenge = decsChallengeToGoldilocks challenge := by
  rfl

/-- The second verifier challenge is uniformly equivalent to its Goldilocks matrix. -/
def piopChallengeEquiv (statement : Statement) :
    PiopBatchingChallenge statement ≃
      HegemonCrypto.SmallWoodPowerBatching.CoefficientMatrix
        (F := Goldilocks)
        (productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount)
        rho :=
  Equiv.piCongrRight fun _ =>
    Equiv.piCongrRight fun _ => fieldWordGoldilocksEquiv

theorem piop_challenge_equiv_apply
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement) :
    piopChallengeEquiv statement challenge =
      piopChallengeToGoldilocks statement challenge := by
  rfl

/-- Concrete finite event set, with classical decidability isolated behind one name. -/
noncomputable def uniformEventSet
    {Sample : Type}
    [Fintype Sample]
    [DecidableEq Sample]
    (event : Sample -> Prop) : Finset Sample := by
  classical
  exact Finset.univ.filter event

/-- Uniform finite event probability, used at each public-coin verifier turn. -/
noncomputable def uniformEventProbability
    {Sample : Type}
    [Fintype Sample]
    [DecidableEq Sample]
  (event : Sample -> Prop) : Rat :=
  (uniformEventSet event).card / Fintype.card Sample

/-- The finite probability is the cardinality of the filtered uniform sample space. -/
theorem uniform_event_probability_eq_filter
    {Sample : Type}
    [Fintype Sample]
    [DecidableEq Sample]
    (event : Sample -> Prop)
    [DecidablePred event] :
    uniformEventProbability event =
      ((Finset.univ.filter event).card : Rat) / Fintype.card Sample := by
  classical
  unfold uniformEventProbability
  have eventSetEquation :
      uniformEventSet event = Finset.univ.filter event := by
    ext sample
    simp [uniformEventSet]
  rw [eventSetEquation]

/-- Every finite uniform event has nonnegative probability. -/
theorem uniform_event_probability_nonnegative
    {Sample : Type}
    [Fintype Sample]
    [DecidableEq Sample]
    (event : Sample -> Prop) :
    0 ≤ uniformEventProbability event := by
  unfold uniformEventProbability
  positivity

/-- Every finite uniform event has probability at most one, including an empty sample type. -/
theorem uniform_event_probability_at_most_one
    {Sample : Type}
    [Fintype Sample]
    [DecidableEq Sample]
    (event : Sample -> Prop) :
    uniformEventProbability event ≤ 1 := by
  have eventCardLe :
      (uniformEventSet event).card ≤ Fintype.card Sample := by
    rw [← Finset.card_univ]
    exact Finset.card_le_card (by
      intro sample membership
      exact Finset.mem_univ sample)
  unfold uniformEventProbability
  by_cases cardZero : Fintype.card Sample = 0
  · have eventCardZero : (uniformEventSet event).card = 0 :=
      Nat.eq_zero_of_le_zero (cardZero ▸ eventCardLe)
    simp [cardZero, eventCardZero]
  · have cardPositive : (0 : Rat) < Fintype.card Sample := by
      exact_mod_cast Nat.pos_of_ne_zero cardZero
    rw [div_le_iff₀ cardPositive]
    simpa only [one_mul] using (show
      ((uniformEventSet event).card : Rat) ≤ (Fintype.card Sample : Rat) by
        exact_mod_cast eventCardLe)

/-- The impossible event has exact probability zero. -/
theorem uniform_event_probability_false
    {Sample : Type}
    [Fintype Sample]
    [DecidableEq Sample] :
    uniformEventProbability (fun _ : Sample => False) = 0 := by
  unfold uniformEventProbability
  have emptySet :
      uniformEventSet (fun _ : Sample => False) = ∅ := by
    ext sample
    simp [uniformEventSet]
  rw [emptySet]
  simp

/-- Entrywise equivalences preserve exact uniform finite-event probabilities. -/
theorem uniform_event_probability_equiv
    {Left Right : Type}
    [Fintype Left] [DecidableEq Left]
    [Fintype Right] [DecidableEq Right]
    (equivalence : Left ≃ Right)
    (event : Right -> Prop) :
    uniformEventProbability (fun sample => event (equivalence sample)) =
      uniformEventProbability event := by
  classical
  have filteredCard :
      (uniformEventSet fun sample : Left =>
          event (equivalence sample)).card =
        (uniformEventSet event).card := by
    calc
      (uniformEventSet fun sample : Left =>
          event (equivalence sample)).card =
          ((uniformEventSet fun sample : Left =>
            event (equivalence sample)).map equivalence.toEmbedding).card := by
            rw [Finset.card_map]
      _ = (uniformEventSet event).card := by
        congr 1
        ext sample
        simp [uniformEventSet]
  unfold uniformEventProbability
  rw [filteredCard, Fintype.card_congr equivalence]

theorem uniform_event_probability_membership
    {Sample : Type}
    [Fintype Sample]
    [DecidableEq Sample]
    (eventSet : Finset Sample) :
    uniformEventProbability (fun sample => sample ∈ eventSet) =
      eventSet.card / Fintype.card Sample := by
  classical
  have eventSetEquation :
      uniformEventSet (fun sample : Sample => sample ∈ eventSet) =
        eventSet := by
    ext sample
    simp [uniformEventSet]
  unfold uniformEventProbability
  rw [eventSetEquation]

/-- Inclusion of finite events preserves their uniform probabilities. -/
theorem uniform_event_probability_mono
    {Sample : Type}
    [Fintype Sample]
    [DecidableEq Sample]
    {left right : Sample -> Prop}
    (subset : ∀ sample, left sample -> right sample) :
    uniformEventProbability left ≤ uniformEventProbability right := by
  classical
  unfold uniformEventProbability
  apply div_le_div_of_nonneg_right
  · exact_mod_cast Finset.card_le_card (by
      intro sample membership
      exact Finset.mem_filter.mpr
        ⟨Finset.mem_univ _, subset sample (Finset.mem_filter.mp membership).2⟩ :
      uniformEventSet left ⊆ uniformEventSet right)
  · positivity

/-- One of the first 138, non-masking columns of the committed oracle. -/
def committedColumnValue
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount)
    (index : Fin decsEvaluationCount) : Goldilocks :=
  wordToGoldilocks
    (oracle index ⟨row.val, by
      have := row.isLt
      omega⟩)

/-- One of the final five independently sampled DECS masking columns. -/
def maskingColumnValue
    (oracle : CommittedOracle)
    (repetition : Fin decsEta)
    (index : Fin decsEvaluationCount) : Goldilocks :=
  wordToGoldilocks
    (oracle index ⟨lvcsRowCount + repetition.val, by
      have repetitionBound := repetition.isLt
      change repetition.val < 5 at repetitionBound
      change 138 + repetition.val < 138 + 5
      omega⟩)

/-- Semantic first-round acceptance event over the ideal uniform DECS challenge. -/
def DecsChallengePasses
    (oracle : CommittedOracle)
    (challenge : Matrix decsEta lvcsRowCount) : Prop :=
  decsChallengeToGoldilocks challenge ∈
    degreeEnforcementFailureSet
      (degreeBound := decsPolynomialDegree)
      activeEvaluationPoint
      (committedColumnValue oracle)
      (maskingColumnValue oracle)

/-- The exact low-degree condition enforced on every committed LVCS row. -/
def CommittedRowsDegreeBounded (oracle : CommittedOracle) : Prop :=
  ∀ row : Fin lvcsRowCount,
    IsDegreeBoundedWord
      (Finset.univ : Finset (Fin decsEvaluationCount))
      activeEvaluationPoint
      (committedColumnValue oracle row)
      decsPolynomialDegree

/-- Canonical interpolation of one committed LVCS row from the complete interactive oracle. -/
def interpolatedCommittedRow
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount) : Goldilocks[X] :=
  Lagrange.interpolate
    (Finset.univ : Finset (Fin decsEvaluationCount))
    activeEvaluationPoint
    (committedColumnValue oracle row)

theorem interpolated_committed_row_eval
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount)
    (index : Fin decsEvaluationCount) :
    (interpolatedCommittedRow oracle row).eval (activeEvaluationPoint index) =
      committedColumnValue oracle row index := by
  apply Lagrange.eval_interpolate_at_node
  · exact active_evaluation_point_injective.injOn
  · simp

theorem interpolated_committed_row_degree_le
    (oracle : CommittedOracle)
    (degreeBounded : CommittedRowsDegreeBounded oracle)
    (row : Fin lvcsRowCount) :
    (interpolatedCommittedRow oracle row).natDegree ≤ decsPolynomialDegree := by
  obtain ⟨polynomial, polynomialDegree, agrees⟩ := degreeBounded row
  obtain ⟨_, _, _, _, _, _, _, _, _, _, degreeValue⟩ := active_geometry
  have domainCard :
      (Finset.univ : Finset (Fin decsEvaluationCount)).card = 1048576 := by
    rw [Finset.card_univ, Fintype.card_fin]
    rfl
  have polynomialDegreeLt :
      polynomial.degree <
        (Finset.univ : Finset (Fin decsEvaluationCount)).card := by
    refine lt_of_le_of_lt (degree_le_of_natDegree_le polynomialDegree) ?_
    rw [degreeValue, domainCard]
    exact_mod_cast (by decide : 397 < 1048576)
  have interpolationEquation :
      polynomial = interpolatedCommittedRow oracle row := by
    apply Lagrange.eq_interpolate_of_eval_eq
    · exact active_evaluation_point_injective.injOn
    · exact polynomialDegreeLt
    · exact agrees
  rw [← interpolationEquation]
  exact polynomialDegree

/--
If any committed LVCS row is outside the active degree-397 code, all five independently masked
combinations are degree bounded only within the exact first SmallWood failure term.
-/
theorem invalid_committed_rows_degree_failure_probability_le
    (oracle : CommittedOracle)
    (notDegreeBounded : ¬ CommittedRowsDegreeBounded oracle) :
    degreeEnforcementFailureProbability
        (degreeBound := decsPolynomialDegree)
        activeEvaluationPoint
        (committedColumnValue oracle)
        (maskingColumnValue oracle) ≤
      (epsilon1Numerator : Rat) / epsilon1Denominator := by
  have badRow :
      ∃ row : Fin lvcsRowCount,
        ¬ IsDegreeBoundedWord
          (Finset.univ : Finset (Fin decsEvaluationCount))
          activeEvaluationPoint
          (committedColumnValue oracle row)
          decsPolynomialDegree := by
    simpa [CommittedRowsDegreeBounded] using notDegreeBounded
  exact active_degree_enforcement_failure_probability_le
    activeEvaluationPoint
    active_evaluation_point_injective
    (committedColumnValue oracle)
    (maskingColumnValue oracle)
    badRow

theorem decs_challenge_pass_probability_eq
    (oracle : CommittedOracle) :
    uniformEventProbability (DecsChallengePasses oracle) =
      degreeEnforcementFailureProbability
        (degreeBound := decsPolynomialDegree)
        activeEvaluationPoint
        (committedColumnValue oracle)
        (maskingColumnValue oracle) := by
  calc
    uniformEventProbability (DecsChallengePasses oracle) =
        uniformEventProbability
          (fun matrix :
            HegemonCrypto.SmallWoodPowerBatching.CoefficientMatrix
              (F := Goldilocks) lvcsRowCount decsEta =>
            matrix ∈
              degreeEnforcementFailureSet
                (degreeBound := decsPolynomialDegree)
                activeEvaluationPoint
                (committedColumnValue oracle)
                (maskingColumnValue oracle)) := by
      exact uniform_event_probability_equiv decsChallengeEquiv _
    _ = degreeEnforcementFailureProbability
          (degreeBound := decsPolynomialDegree)
          activeEvaluationPoint
          (committedColumnValue oracle)
          (maskingColumnValue oracle) := by
      rw [uniform_event_probability_membership]
      rfl

theorem invalid_committed_rows_decs_challenge_probability_le
    (oracle : CommittedOracle)
    (notDegreeBounded : ¬ CommittedRowsDegreeBounded oracle) :
    uniformEventProbability (DecsChallengePasses oracle) ≤
      (epsilon1Numerator : Rat) / epsilon1Denominator := by
  rw [decs_challenge_pass_probability_eq]
  exact invalid_committed_rows_degree_failure_probability_le
    oracle notDegreeBounded

/--
The active LVCS encoder appends 23 hiding values to one 375-cell stacked row, rotates the
398-value vector left by 375, and interpolates those rotated values at the consecutive points
`0 .. 397`. The original stacked row is therefore recovered by evaluating the committed
polynomial at points `23 .. 397`; these are values, not polynomial coefficients.
-/
def lvcsDataPoint (column : Fin lvcsColumnCount) : Goldilocks :=
  toGoldilocks (decsOpenedEvaluations + column.val)

def stackedHeadCell
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount)
    (column : Fin lvcsColumnCount) : Goldilocks :=
  (interpolatedCommittedRow oracle row).eval (lvcsDataPoint column)

/-- Stacked row containing one unstacked matrix cell. -/
def stackedRowIndex
    (row : Fin unstackedRowCount)
    (column : Fin unstackedColumnCount) : Fin lvcsRowCount :=
  ⟨(column.val / lvcsColumnCount) * unstackedRowCount + row.val, by
    have rowBound := row.isLt
    have columnBound := column.isLt
    change row.val < 69 at rowBound
    change column.val < 749 at columnBound
    change (column.val / 375) * 69 + row.val < 138
    have blockBound : column.val / 375 < 2 := by omega
    omega⟩

/-- Column inside the 375-cell stacked row containing one unstacked matrix cell. -/
def stackedColumnIndex
    (column : Fin unstackedColumnCount) : Fin lvcsColumnCount :=
  ⟨column.val % lvcsColumnCount, by
    exact Nat.mod_lt _ (by decide)⟩

/-- Exact inverse of the fixed two-way SmallWood stacking map. -/
def unstackedCell
    (oracle : CommittedOracle)
    (row : Fin unstackedRowCount)
    (column : Fin unstackedColumnCount) : Goldilocks :=
  stackedHeadCell oracle
    (stackedRowIndex row column)
    (stackedColumnIndex column)

/-- Embed one of the 699 witness-polynomial columns in the 749-column unstacked matrix. -/
def witnessColumnIndex (column : Fin rowCount) : Fin unstackedColumnCount :=
  ⟨column.val, by
    have columnBound := column.isLt
    change column.val < 699 at columnBound
    change column.val < 749
    omega⟩

/-- The exact degree-68 polynomial recovered for one packed witness row. -/
def witnessPolynomial
    (oracle : CommittedOracle)
    (column : Fin rowCount) : Goldilocks[X] :=
  ∑ coefficient : Fin unstackedRowCount,
    C (unstackedCell oracle coefficient (witnessColumnIndex column)) *
      X ^ coefficient.val

/-- Packed-row index represented by one flattened witness cell. -/
def witnessRowIndex
    (index : Fin (rowCount * packingFactor)) : Fin rowCount :=
  ⟨index.val / packingFactor, by
    have indexBound := index.isLt
    change index.val < 699 * 64 at indexBound
    change index.val / 64 < 699
    omega⟩

/-- Packing-point index represented by one flattened witness cell. -/
def witnessLaneIndex
    (index : Fin (rowCount * packingFactor)) : Fin packingFactor :=
  ⟨index.val % packingFactor, Nat.mod_lt _ (by decide)⟩

/-- Exact production packing point for one witness lane. -/
def witnessPackingPoint
    (lane : Fin packingFactor) : Goldilocks :=
  toGoldilocks lane.val

/--
One deterministic active witness cell. Flattening is row-major, matching Rust:
`flat = packed_row * 64 + lane`.
-/
def extractWitnessCell
    (oracle : CommittedOracle)
    (index : Fin (rowCount * packingFactor)) : Nat :=
  fromGoldilocks
    ((witnessPolynomial oracle (witnessRowIndex index)).eval
      (witnessPackingPoint (witnessLaneIndex index)))

theorem extract_witness_cell_canonical
    (oracle : CommittedOracle)
    (index : Fin (rowCount * packingFactor)) :
    toGoldilocks (extractWitnessCell oracle index) =
      (witnessPolynomial oracle (witnessRowIndex index)).eval
        (witnessPackingPoint (witnessLaneIndex index)) := by
  exact toGoldilocks_fromGoldilocks _

/--
Generic list materialization carrying its own index theorem. Keeping this definition generic in
`n` prevents elaboration from normalizing the active 44,736-cell witness.
-/
structure IndexedList {α : Type} {n : Nat} (function : Fin n -> α) where
  values : List α
  length_eq : values.length = n
  get_eq :
    ∀ index : Fin n,
      values.get (Fin.cast length_eq.symm index) = function index

def indexedListOfFn
    {α : Type}
    {n : Nat}
    (function : Fin n -> α) : IndexedList function where
  values := List.ofFn function
  length_eq := List.length_ofFn
  get_eq := by
    intro index
    rw [List.get_ofFn]
    rfl

/-- Materialized active witness together with its exact cell equation. -/
def extractedWitnessBundle
    (oracle : CommittedOracle) : IndexedList (extractWitnessCell oracle) :=
  indexedListOfFn (extractWitnessCell oracle)

/-- Exact `Witness` consumed by the Hegemon relation. -/
def extractWitness (oracle : CommittedOracle) : Witness :=
  (extractedWitnessBundle oracle).values

theorem extract_witness_length (oracle : CommittedOracle) :
    (extractWitness oracle).length = rowCount * packingFactor := by
  exact (extractedWitnessBundle oracle).length_eq

theorem extract_witness_active_length (oracle : CommittedOracle) :
    (extractWitness oracle).length = 699 * 64 := by
  rw [extract_witness_length]
  rfl

theorem extract_witness_get
    (oracle : CommittedOracle)
    (index : Fin (rowCount * packingFactor)) :
    (extractWitness oracle).get
        (Fin.cast (extract_witness_length oracle).symm index) =
      extractWitnessCell oracle index := by
  exact (extractedWitnessBundle oracle).get_eq index

theorem extracted_witness_value_canonical
    (oracle : CommittedOracle)
    (index : Fin (rowCount * packingFactor)) :
    toGoldilocks
        ((extractWitness oracle).get
          (Fin.cast (extract_witness_length oracle).symm index)) =
      (witnessPolynomial oracle (witnessRowIndex index)).eval
        (witnessPackingPoint (witnessLaneIndex index)) := by
  rw [extract_witness_get]
  exact extract_witness_cell_canonical oracle index

/-- Exact statement that a list is the row-major witness encoded by one committed oracle. -/
def OracleEncodesWitness
    (oracle : CommittedOracle)
    (witness : Witness) : Prop :=
  ∃ lengthEquation : witness.length = rowCount * packingFactor,
    ∀ index : Fin (rowCount * packingFactor),
      toGoldilocks
          (witness.get (Fin.cast lengthEquation.symm index)) =
        (witnessPolynomial oracle (witnessRowIndex index)).eval
          (witnessPackingPoint (witnessLaneIndex index))

/-- The deterministic extractor satisfies the exact oracle-to-witness encoding relation. -/
theorem oracle_encodes_extracted_witness
    (oracle : CommittedOracle) :
    OracleEncodesWitness oracle (extractWitness oracle) := by
  refine ⟨extract_witness_length oracle, ?_⟩
  intro index
  exact extracted_witness_value_canonical oracle index

/-- Every recovered witness polynomial has the exact production degree bound. -/
theorem witness_polynomial_degree_le
    (oracle : CommittedOracle)
    (column : Fin rowCount) :
    (witnessPolynomial oracle column).natDegree ≤ witnessPolynomialDegree := by
  unfold witnessPolynomial
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  refine natDegree_mul_le.trans ?_
  have coefficientBound := coefficient.isLt
  change coefficient.val < 69 at coefficientBound
  change
    (C (unstackedCell oracle coefficient (witnessColumnIndex column))).natDegree +
        (X ^ coefficient.val).natDegree ≤ 68
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  omega

/-! ## Constraint polynomials induced by the extracted witness -/

/-- Exact packing-node embedding used by the production prover. -/
def packingNodePoint (lane : Nat) : Goldilocks :=
  toGoldilocks lane

theorem packing_node_point_injective :
    Set.InjOn packingNodePoint (Finset.range packingFactor) := by
  intro left leftMembership right rightMembership samePoint
  have leftBound := Finset.mem_range.mp leftMembership
  have rightBound := Finset.mem_range.mp rightMembership
  change left < 64 at leftBound
  change right < 64 at rightBound
  have modularEquality :
      left % goldilocksModulus = right % goldilocksModulus := by
    exact
      (ZMod.natCast_eq_natCast_iff' left right goldilocksModulus).mp
        samePoint
  have leftBelowModulus : left < goldilocksModulus := by
    exact leftBound.trans (by decide)
  have rightBelowModulus : right < goldilocksModulus := by
    exact rightBound.trans (by decide)
  simpa [Nat.mod_eq_of_lt leftBelowModulus,
    Nat.mod_eq_of_lt rightBelowModulus] using modularEquality

/-- Identity field embedding used by the active Goldilocks PIOP. -/
def goldilocksIdentityEncoding :
    ProductionFieldEncoding (F := Goldilocks) where
  encode := RingHom.id Goldilocks
  injective := Function.injective_id

/-- Canonical nonlinear constraint polynomial for a concrete extracted witness. -/
def nonlinearConstraintPolynomial
    (statement : Statement)
    (witness : Witness)
    (constraint : Nat) : Goldilocks[X] :=
  Lagrange.interpolate
    (Finset.range statement.lppcPackingFactor)
    packingNodePoint
    (fun lane =>
      toGoldilocks
        (nonlinearConstraintValue statement witness lane constraint))

/--
Canonical linear constraint polynomial.  Only its packing-node sum is protocol-visible before the
off-domain evaluation check, so placing the exact global value at lane zero and zero elsewhere
gives a minimal semantic representative.
-/
def linearConstraintPolynomial
    (statement : Statement)
    (witness : Witness)
    (constraint : Nat) : Goldilocks[X] :=
  Lagrange.interpolate
    (Finset.range statement.lppcPackingFactor)
    packingNodePoint
    (fun lane =>
      if lane = 0 then
        toGoldilocks (linearConstraintValue statement witness constraint)
      else
        0)

theorem active_packing_node_point_injective
    (statement : Statement)
    (active : ActiveStatement statement) :
    Set.InjOn packingNodePoint
      (Finset.range statement.lppcPackingFactor) := by
  rw [active.2.1]
  exact packing_node_point_injective

theorem nonlinear_constraint_polynomial_at_packing_node
    (statement : Statement)
    (witness : Witness)
    (active : ActiveStatement statement)
    (constraint lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor) :
    (nonlinearConstraintPolynomial statement witness constraint).eval
        (packingNodePoint lane) =
      toGoldilocks
        (nonlinearConstraintValue statement witness lane constraint) := by
  apply Lagrange.eval_interpolate_at_node
  · exact active_packing_node_point_injective statement active
  · exact Finset.mem_range.mpr laneBound

theorem linear_constraint_polynomial_packing_sum
    (statement : Statement)
    (witness : Witness)
    (active : ActiveStatement statement)
    (constraint : Nat) :
    nodeSum
        (Finset.range statement.lppcPackingFactor)
        packingNodePoint
        (linearConstraintPolynomial statement witness constraint) =
      toGoldilocks (linearConstraintValue statement witness constraint) := by
  unfold nodeSum linearConstraintPolynomial
  rw [Finset.sum_congr rfl fun lane laneMembership =>
    Lagrange.eval_interpolate_at_node
      (fun selected =>
        if selected = 0 then
          toGoldilocks (linearConstraintValue statement witness constraint)
        else
          0)
      (active_packing_node_point_injective statement active)
      laneMembership]
  rw [active.2.1]
  simp [packingFactor]

/--
Concrete PIOP semantic adapter induced by the deterministic oracle witness.  This contains no
cryptographic assumption and no caller-supplied equation.
-/
def extractedProductionOracles
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement) :
    ProductionOracleRefinement
      statement
      (extractWitness oracle)
      goldilocksIdentityEncoding where
  point := packingNodePoint
  pointInjective := active_packing_node_point_injective statement active
  nonlinearPolynomial :=
    nonlinearConstraintPolynomial statement (extractWitness oracle)
  nonlinearAtPackingNode := by
    intro constraint _ lane laneBound
    exact nonlinear_constraint_polynomial_at_packing_node
      statement (extractWitness oracle) active constraint lane laneBound
  linearPolynomial :=
    linearConstraintPolynomial statement (extractWitness oracle)
  linearPackingSum := by
    intro constraint _
    exact linear_constraint_polynomial_packing_sum
      statement (extractWitness oracle) active constraint

/-- Exact equivalence between the extracted PIOP system and the Hegemon transaction relation. -/
theorem extracted_production_oracles_satisfied_iff_relation
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement) :
    (extractedProductionOracles statement oracle active).system.Satisfied ↔
      (statement, extractWitness oracle) ∈ Relation := by
  constructor
  · intro satisfied
    apply production_oracles_sound
      statement
      (extractWitness oracle)
      goldilocksIdentityEncoding
      (extractedProductionOracles statement oracle active)
      active.2.2.2.2.2
    · rw [extract_witness_length, active.1, active.2.1]
    · exact satisfied
  · intro relation
    exact production_oracles_satisfied
      statement
      (extractWitness oracle)
      goldilocksIdentityEncoding
      (extractedProductionOracles statement oracle active)
      relation

/-- Concrete statement-specific padded PIOP system recovered from the committed oracle. -/
def extractedPaddedSystem
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement) :=
  paddedProductionSystem
    (extractedProductionOracles statement oracle active)

/--
If the deterministic oracle witness is invalid, all five uniform PIOP batching rows can pass only
inside the exact second SmallWood failure term.
-/
theorem invalid_extracted_witness_batch_failure_probability_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (notRelation :
      (statement, extractWitness oracle) ∉ Relation) :
    batchFailureProbability
        (repetitions := activePiopRepetitions)
        (extractedPaddedSystem statement oracle active) ≤
      (epsilon2Numerator : Rat) / epsilon2Denominator := by
  exact invalid_production_oracle_batch_failure_probability_le
    statement
    (extractWitness oracle)
    goldilocksIdentityEncoding
    (extractedProductionOracles statement oracle active)
    active.2.2.2.2.2
    (by rw [extract_witness_length, active.1, active.2.1])
    notRelation

/--
Semantic second-verifier acceptance event over the exact statement-sized uniform challenge.
The event is not an abstract caller predicate: it is membership in the concrete PIOP batching
failure set induced by the witness deterministically extracted from the committed oracle.
-/
noncomputable def PiopChallengePasses
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement) : Prop :=
  piopChallengeToGoldilocks statement challenge ∈
    batchFailureSet
      (repetitions := rho)
      (extractedPaddedSystem statement oracle active)

/--
Production-accurate second-verifier event. Linear-mask sums are committed before this challenge,
so they are arbitrary fixed affine offsets rather than an honest-prover zero-sum assumption.
-/
noncomputable def PiopAffineChallengePasses
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (linearMaskSum : Fin rho -> Goldilocks)
    (challenge : PiopBatchingChallenge statement) : Prop :=
  piopChallengeToGoldilocks statement challenge ∈
    affineBatchFailureSet
      (extractedPaddedSystem statement oracle active)
      linearMaskSum

/-- The field-word challenge has exactly the same failure probability as the Goldilocks matrix. -/
theorem piop_challenge_pass_probability_eq
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement) :
    uniformEventProbability (PiopChallengePasses statement oracle active) =
      batchFailureProbability
        (repetitions := rho)
        (extractedPaddedSystem statement oracle active) := by
  calc
    uniformEventProbability (PiopChallengePasses statement oracle active) =
        uniformEventProbability
          (fun matrix :
            HegemonCrypto.SmallWoodPowerBatching.CoefficientMatrix
              (F := Goldilocks)
              (productionPiopRowWidth
                statement.nonlinearConstraintCount statement.linearConstraintCount)
              rho =>
            matrix ∈
              batchFailureSet
                (repetitions := rho)
                (extractedPaddedSystem statement oracle active)) := by
      exact uniform_event_probability_equiv (piopChallengeEquiv statement) _
    _ = batchFailureProbability
          (repetitions := rho)
          (extractedPaddedSystem statement oracle active) := by
      rw [uniform_event_probability_membership]
      rfl

/-- Field-word and Goldilocks challenge matrices preserve the exact affine failure probability. -/
theorem piop_affine_challenge_pass_probability_eq
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (linearMaskSum : Fin rho -> Goldilocks) :
    uniformEventProbability
        (PiopAffineChallengePasses statement oracle active linearMaskSum) =
      affineBatchFailureProbability
        (extractedPaddedSystem statement oracle active)
        linearMaskSum := by
  calc
    uniformEventProbability
        (PiopAffineChallengePasses statement oracle active linearMaskSum) =
      uniformEventProbability
        (fun matrix :
          HegemonCrypto.SmallWoodPowerBatching.CoefficientMatrix
            (F := Goldilocks)
            (productionPiopRowWidth
              statement.nonlinearConstraintCount statement.linearConstraintCount)
            rho =>
          matrix ∈
            affineBatchFailureSet
              (extractedPaddedSystem statement oracle active)
              linearMaskSum) := by
      exact uniform_event_probability_equiv (piopChallengeEquiv statement) _
    _ = affineBatchFailureProbability
          (extractedPaddedSystem statement oracle active)
          linearMaskSum := by
      rw [uniform_event_probability_membership]
      rfl

/--
If the deterministic oracle witness does not satisfy the production relation, the exact second
verifier challenge accepts with probability at most the active five-row SmallWood term.
-/
theorem invalid_extracted_witness_piop_challenge_probability_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (notRelation :
      (statement, extractWitness oracle) ∉ Relation) :
    uniformEventProbability (PiopChallengePasses statement oracle active) ≤
      (epsilon2Numerator : Rat) / epsilon2Denominator := by
  rw [piop_challenge_pass_probability_eq]
  simpa [rho, activePiopRepetitions, activeParameters] using
    invalid_extracted_witness_batch_failure_probability_le
      statement oracle active notRelation

/--
The exact production affine challenge event retains the active second-term bound for every
precommitted linear mask.
-/
theorem invalid_extracted_witness_piop_affine_challenge_probability_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (linearMaskSum : Fin rho -> Goldilocks)
    (notRelation :
      (statement, extractWitness oracle) ∉ Relation) :
    uniformEventProbability
        (PiopAffineChallengePasses
          statement oracle active linearMaskSum) ≤
      (epsilon2Numerator : Rat) / epsilon2Denominator := by
  rw [piop_affine_challenge_pass_probability_eq]
  have systemUnsatisfied :
      ¬ FullySatisfied (extractedPaddedSystem statement oracle active) := by
    intro satisfied
    exact notRelation <|
      (extracted_production_oracles_satisfied_iff_relation
        statement oracle active).mp <|
        (padded_production_fully_satisfied_iff
          (extractedProductionOracles statement oracle active)).mp satisfied
  calc
    affineBatchFailureProbability
        (extractedPaddedSystem statement oracle active)
        linearMaskSum ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ rho :=
        unsatisfied_affine_batch_failure_probability_le
          (extractedPaddedSystem statement oracle active)
          linearMaskSum systemUnsatisfied
    _ = (epsilon2Numerator : Rat) / epsilon2Denominator := by
      rw [HegemonCrypto.SmallWoodPowerBatching.active_epsilon2_is_uniform_matrix_bound]
      simp [Goldilocks, ZMod.card, goldilocksOrder, rho,
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus,
        Hegemon.Transaction.SmallWoodTranscriptBinding.activeProfile, activeParameters]

end

end HegemonCrypto.SmallWood.OracleExtraction
