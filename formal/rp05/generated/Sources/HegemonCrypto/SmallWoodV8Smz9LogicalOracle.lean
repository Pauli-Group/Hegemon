import HegemonCrypto.SmallWoodHeterogeneousCmsQrom
import HegemonCrypto.SmallWoodSmz9ProofWire
import HegemonCrypto.SmallWoodPiopOpeningSampling
import Mathlib.Data.Fintype.CardEmbedding
import Mathlib.Data.Finset.Powerset

/-!
# Exact SMZ9 statement-indexed ideal logical oracle

This module replaces the historical logical-oracle dimensions `5 / 23 / 138` with the exact
HGV8RP03/SMZ9 dimensions `6 / 20 / 140`.  A local logical response contains one uniform DECS
batching matrix, one statement-dependent PIOP batching challenge, six distinct PIOP openings
outside the 64 packing points, and one uniform twenty-element subset of the `2^23` DECS domain.
Every DECS subset has a canonical `Fin 20` selector whose range is exactly that subset.

For a finite statement family, one ideal oracle output is the dependent product of all local
responses.  The selected statement coordinate of a uniform product output is proved exactly
uniform.  A singleton adaptive selector is then lifted through the implemented CMS database and
oracle bridge under one global query list and one explicit real-instability premise.

The active round-by-round source syntax is still hard-coded to `5 / 23 / 138`, so this file does
not claim an exact SMZ9 verifier transition, extraction-failure selector, or CMS-instability proof.
Those three missing refinements are named separately and remain constructor-free.  In particular,
the ideal theorem below is not a SHA-512 product-oracle reduction, a Poseidon2 theorem, a native
verifier refinement, or production authority.
-/

namespace HegemonCrypto.SmallWood.V8Smz9LogicalOracle

open scoped BigOperators

open HegemonCrypto.SecurityAuthority
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsFinitePhaseSystem
open HegemonCrypto.CmsLifting
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.OracleExtraction

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option linter.unusedSectionVars false

noncomputable section

local instance classicalPropDecidable (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

abbrev Statement := HegemonCrypto.SmallWood.Statement
abbrev FieldWord := HegemonCrypto.SmallWoodTranscript.FieldWord

def fieldCardinality : Nat :=
  Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus
def packingFactor : Nat := 64
def piopRepetitionCount : Nat := 5
def piopOpeningCount : Nat := 6
def decsEta : Nat := 5
def decsDomainSize : Nat := 2 ^ 23
def decsOpeningCount : Nat := 20
def decsRowCount : Nat := 140
def nonlinearHighCoefficientCount : Nat := 483
def linearHighCoefficientCount : Nat := 126
def openedCombinationCount : Nat := 12
def proofGeometryColumnCount : Nat := 368
def decsPolynomialCoefficientCount : Nat :=
  proofGeometryColumnCount + decsOpeningCount

theorem exact_smz9_logical_oracle_profile :
    fieldCardinality = 18446744069414584321 ∧
      packingFactor = 64 ∧ piopRepetitionCount = 5 ∧ piopOpeningCount = 6 ∧
      decsEta = 5 ∧ decsDomainSize = 8388608 ∧ decsOpeningCount = 20 ∧
      decsRowCount = 140 ∧ nonlinearHighCoefficientCount = 483 ∧
      linearHighCoefficientCount = 126 ∧ openedCombinationCount = 12 ∧
      proofGeometryColumnCount = 368 ∧ decsPolynomialCoefficientCount = 388 ∧
      HegemonCrypto.SmallWoodSmz9ProofWire.openedLeafCount = decsOpeningCount := by
  decide

abbrev Matrix (rows columns : Nat) :=
  Fin rows → Fin columns → FieldWord

theorem matrix_card (rows columns : Nat) :
    Fintype.card (Matrix rows columns) = fieldCardinality ^ (rows * columns) := by
  simp only [Matrix, Fintype.card_fun, Fintype.card_fin]
  change (fieldCardinality ^ columns) ^ rows = fieldCardinality ^ (rows * columns)
  rw [← pow_mul, Nat.mul_comm]

/-! ## Exact local challenge domains -/

def packingEmbedding : Fin packingFactor ↪ FieldWord where
  toFun lane := ⟨lane.val, lt_trans lane.isLt (by decide)⟩
  inj' := by
    intro left right equal
    apply Fin.ext
    exact congrArg (fun value : FieldWord => value.val) equal

def packingDomain : Finset FieldWord :=
  Finset.univ.map packingEmbedding

theorem packing_domain_card : packingDomain.card = packingFactor := by
  simp [packingDomain]

theorem mem_packing_domain_iff (point : FieldWord) :
    point ∈ packingDomain ↔ point.val < packingFactor := by
  constructor
  · intro membership
    rcases Finset.mem_map.mp membership with ⟨lane, _laneMembership, equal⟩
    have values : lane.val = point.val :=
      congrArg (fun value : FieldWord => value.val) equal
    have laneBound := lane.isLt
    omega
  · intro bound
    let lane : Fin packingFactor := ⟨point.val, bound⟩
    apply Finset.mem_map.mpr
    refine ⟨lane, Finset.mem_univ lane, ?_⟩
    apply Fin.ext
    rfl

abbrev PiopOpeningChallenge :=
  HegemonCrypto.SmallWood.PiopOpeningSampling.ValidTuple
    packingDomain piopOpeningCount

def canonicalPiopOpeningChallenge : PiopOpeningChallenge := by
  refine ⟨(fun index => ⟨packingFactor + index.val, ?_⟩), ?_⟩
  · have bound := index.isLt
    change index.val < 6 at bound
    change 64 + index.val < 18446744069414584321
    omega
  · constructor
    · intro left right equal
      apply Fin.ext
      have values := congrArg (fun value : FieldWord => value.val) equal
      change 64 + left.val = 64 + right.val at values
      omega
    · intro index membership
      have pointBound := (mem_packing_domain_iff _).mp membership
      change 64 + index.val < 64 at pointBound
      omega

noncomputable instance piopOpeningChallengeDecidableEq :
    DecidableEq PiopOpeningChallenge :=
  Classical.decEq _

noncomputable instance piopOpeningChallengeNonempty :
    Nonempty PiopOpeningChallenge :=
  ⟨canonicalPiopOpeningChallenge⟩

theorem outside_packing_card :
    Fintype.card
        (HegemonCrypto.SmallWood.PiopOpeningSampling.Outside packingDomain) =
      fieldCardinality - packingFactor := by
  rw [HegemonCrypto.SmallWood.PiopOpeningSampling.outside_card,
    packing_domain_card]
  simp [FieldWord, fieldCardinality]

theorem piop_opening_challenge_card :
    Fintype.card PiopOpeningChallenge =
      (fieldCardinality - packingFactor).descFactorial piopOpeningCount := by
  rw [HegemonCrypto.SmallWood.PiopOpeningSampling.valid_tuple_card,
    outside_packing_card]

abbrev DecsOpeningChallenge :=
  { sample : Finset (Fin decsDomainSize) // sample.card = decsOpeningCount }

def initialDecsOpeningEmbedding : Fin decsOpeningCount ↪ Fin decsDomainSize where
  toFun index := ⟨index.val, lt_trans index.isLt (by decide)⟩
  inj' := by
    intro left right equal
    apply Fin.ext
    exact congrArg (fun value : Fin decsDomainSize => value.val) equal

def canonicalDecsOpeningChallenge : DecsOpeningChallenge :=
  ⟨Finset.univ.map initialDecsOpeningEmbedding, by simp⟩

noncomputable instance decsOpeningChallengeFintype :
    Fintype DecsOpeningChallenge :=
  Fintype.ofFinite _

noncomputable instance decsOpeningChallengeDecidableEq :
    DecidableEq DecsOpeningChallenge :=
  Classical.decEq _

noncomputable instance decsOpeningChallengeNonempty :
    Nonempty DecsOpeningChallenge :=
  ⟨canonicalDecsOpeningChallenge⟩

def decsOpeningChallengeEquivPowerset :
    DecsOpeningChallenge ≃
      { sample : Finset (Fin decsDomainSize) //
        sample ∈
          (Finset.univ : Finset (Fin decsDomainSize)).powersetCard decsOpeningCount } where
  toFun sample :=
    ⟨sample.val,
      Finset.mem_powersetCard.mpr ⟨Finset.subset_univ _, sample.property⟩⟩
  invFun sample :=
    ⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩
  left_inv _ := Subtype.ext rfl
  right_inv _ := Subtype.ext rfl

theorem decs_opening_challenge_card :
    Fintype.card DecsOpeningChallenge =
      Nat.choose decsDomainSize decsOpeningCount := by
  rw [Fintype.card_congr decsOpeningChallengeEquivPowerset]
  change
    Fintype.card
        (↥((Finset.univ : Finset (Fin decsDomainSize)).powersetCard
          decsOpeningCount)) =
      Nat.choose decsDomainSize decsOpeningCount
  rw [Fintype.card_coe, Finset.card_powersetCard, Finset.card_univ,
    Fintype.card_fin]

/-- Canonical enumeration of the exact twenty positions in one uniform DECS subset. -/
noncomputable def decsOpeningSelector
    (challenge : DecsOpeningChallenge) :
    Fin decsOpeningCount ↪ Fin decsDomainSize where
  toFun index :=
    ((challenge.val.equivFinOfCardEq challenge.property).symm index).val
  inj' := by
    intro left right equal
    apply (challenge.val.equivFinOfCardEq challenge.property).symm.injective
    exact Subtype.ext equal

theorem decs_opening_selector_range
    (challenge : DecsOpeningChallenge) :
    Finset.univ.map (decsOpeningSelector challenge) = challenge.val := by
  ext value
  constructor
  · intro membership
    rcases Finset.mem_map.mp membership with ⟨index, _indexMembership, equal⟩
    have selectedMembership :
        ((challenge.val.equivFinOfCardEq challenge.property).symm index).val ∈
          challenge.val :=
      ((challenge.val.equivFinOfCardEq challenge.property).symm index).property
    simpa [decsOpeningSelector] using equal ▸ selectedMembership
  · intro membership
    obtain ⟨index, equal⟩ :=
      (challenge.val.equivFinOfCardEq challenge.property).symm.surjective
        ⟨value, membership⟩
    apply Finset.mem_map.mpr
    refine ⟨index, Finset.mem_univ index, ?_⟩
    exact congrArg Subtype.val equal

theorem decs_opening_selector_card
    (challenge : DecsOpeningChallenge) :
    (Finset.univ.map (decsOpeningSelector challenge)).card = decsOpeningCount := by
  rw [decs_opening_selector_range]
  exact challenge.property

/-! ## Exact local response and statement-dependent query grammar -/

abbrev PiopBatchingChallenge (statement : Statement) :=
  HegemonCrypto.SmallWood.RoundByRound.PiopBatchingChallenge statement

abbrev CommittedOracle :=
  Matrix decsDomainSize (decsRowCount + decsEta)

abbrev DecsPolynomialMessage :=
  Matrix decsEta decsPolynomialCoefficientCount

structure PiopPolynomialMessage where
  nonlinear : Matrix piopRepetitionCount nonlinearHighCoefficientCount
  linear : Matrix piopRepetitionCount linearHighCoefficientCount

def piopPolynomialMessageEquivProduct :
    (Matrix piopRepetitionCount nonlinearHighCoefficientCount ×
      Matrix piopRepetitionCount linearHighCoefficientCount) ≃
      PiopPolynomialMessage where
  toFun components :=
    { nonlinear := components.1, linear := components.2 }
  invFun message := (message.nonlinear, message.linear)
  left_inv components := by cases components; rfl
  right_inv message := by cases message; rfl

noncomputable instance piopPolynomialMessageFintype :
    Fintype PiopPolynomialMessage :=
  Fintype.ofEquiv _ piopPolynomialMessageEquivProduct

noncomputable instance piopPolynomialMessageDecidableEq :
    DecidableEq PiopPolynomialMessage :=
  Classical.decEq _

noncomputable instance piopPolynomialMessageNonempty :
    Nonempty PiopPolynomialMessage :=
  ⟨{ nonlinear := fun _ _ => 0, linear := fun _ _ => 0 }⟩

abbrev PcsCombinationMessage :=
  Matrix openedCombinationCount decsPolynomialCoefficientCount

structure LogicalOutput (statement : Statement) where
  decsChallenge : Matrix decsEta decsRowCount
  piopChallenge : PiopBatchingChallenge statement
  piopOpening : PiopOpeningChallenge
  decsOpening : DecsOpeningChallenge
  deriving Fintype

noncomputable instance logicalOutputDecidableEq (statement : Statement) :
    DecidableEq (LogicalOutput statement) :=
  Classical.decEq _

noncomputable instance logicalOutputNonempty (statement : Statement) :
    Nonempty (LogicalOutput statement) :=
  ⟨{ decsChallenge := fun _ _ => 0
     piopChallenge := fun _ _ => 0
     piopOpening := canonicalPiopOpeningChallenge
     decsOpening := canonicalDecsOpeningChallenge }⟩

noncomputable instance logicalOutputInhabited (statement : Statement) :
    Inhabited (LogicalOutput statement) :=
  ⟨Classical.choice (logicalOutputNonempty statement)⟩

def logicalOutputEquivProduct (statement : Statement) :
    LogicalOutput statement ≃
      Matrix decsEta decsRowCount ×
        (PiopBatchingChallenge statement ×
          (PiopOpeningChallenge × DecsOpeningChallenge)) where
  toFun output :=
    (output.decsChallenge,
      (output.piopChallenge, (output.piopOpening, output.decsOpening)))
  invFun output :=
    { decsChallenge := output.1
      piopChallenge := output.2.1
      piopOpening := output.2.2.1
      decsOpening := output.2.2.2 }
  left_inv output := by cases output; rfl
  right_inv output := by rcases output with ⟨_, _, _, _⟩; rfl

theorem logical_output_card (statement : Statement) :
    Fintype.card (LogicalOutput statement) =
      Fintype.card (Matrix decsEta decsRowCount) *
        (Fintype.card (PiopBatchingChallenge statement) *
          (Fintype.card PiopOpeningChallenge *
            Fintype.card DecsOpeningChallenge)) := by
  rw [Fintype.card_congr (logicalOutputEquivProduct statement)]
  simp only [Fintype.card_prod]

structure SecondQuery where
  oracle : CommittedOracle
  decsChallenge : Matrix decsEta decsRowCount
  decsMessage : DecsPolynomialMessage
  deriving Fintype

structure ThirdQuery (statement : Statement) where
  oracle : CommittedOracle
  decsChallenge : Matrix decsEta decsRowCount
  decsMessage : DecsPolynomialMessage
  piopChallenge : PiopBatchingChallenge statement
  piopMessage : PiopPolynomialMessage

structure FourthQuery (statement : Statement) where
  oracle : CommittedOracle
  decsChallenge : Matrix decsEta decsRowCount
  decsMessage : DecsPolynomialMessage
  piopChallenge : PiopBatchingChallenge statement
  piopMessage : PiopPolynomialMessage
  piopOpening : PiopOpeningChallenge
  pcsMessage : PcsCombinationMessage

inductive VerifierQuery (statement : Statement) where
  | first (oracle : CommittedOracle)
  | second (query : SecondQuery)
  | third (query : ThirdQuery statement)
  | fourth (query : FourthQuery statement)

def thirdQueryEquivProduct (statement : Statement) :
    (CommittedOracle ×
      Matrix decsEta decsRowCount ×
        DecsPolynomialMessage ×
          PiopBatchingChallenge statement ×
            PiopPolynomialMessage) ≃
      ThirdQuery statement where
  toFun data :=
    { oracle := data.1
      decsChallenge := data.2.1
      decsMessage := data.2.2.1
      piopChallenge := data.2.2.2.1
      piopMessage := data.2.2.2.2 }
  invFun query :=
    (query.oracle, query.decsChallenge, query.decsMessage,
      query.piopChallenge, query.piopMessage)
  left_inv data := by rcases data with ⟨_, _, _, _, _⟩; rfl
  right_inv query := by cases query; rfl

noncomputable instance thirdQueryFintype (statement : Statement) :
    Fintype (ThirdQuery statement) :=
  Fintype.ofEquiv _ (thirdQueryEquivProduct statement)

def fourthQueryEquivProduct (statement : Statement) :
    (CommittedOracle ×
      Matrix decsEta decsRowCount ×
        DecsPolynomialMessage ×
          PiopBatchingChallenge statement ×
            PiopPolynomialMessage ×
              PiopOpeningChallenge ×
                PcsCombinationMessage) ≃
      FourthQuery statement where
  toFun data :=
    { oracle := data.1
      decsChallenge := data.2.1
      decsMessage := data.2.2.1
      piopChallenge := data.2.2.2.1
      piopMessage := data.2.2.2.2.1
      piopOpening := data.2.2.2.2.2.1
      pcsMessage := data.2.2.2.2.2.2 }
  invFun query :=
    (query.oracle, query.decsChallenge, query.decsMessage,
      query.piopChallenge, query.piopMessage, query.piopOpening, query.pcsMessage)
  left_inv data := by rcases data with ⟨_, _, _, _, _, _, _⟩; rfl
  right_inv query := by cases query; rfl

noncomputable instance fourthQueryFintype (statement : Statement) :
    Fintype (FourthQuery statement) :=
  Fintype.ofEquiv _ (fourthQueryEquivProduct statement)

def verifierQueryEquivSum (statement : Statement) :
    (CommittedOracle ⊕
      SecondQuery ⊕ ThirdQuery statement ⊕ FourthQuery statement) ≃
      VerifierQuery statement where
  toFun
    | .inl oracle => .first oracle
    | .inr (.inl query) => .second query
    | .inr (.inr (.inl query)) => .third query
    | .inr (.inr (.inr query)) => .fourth query
  invFun
    | .first oracle => .inl oracle
    | .second query => .inr (.inl query)
    | .third query => .inr (.inr (.inl query))
    | .fourth query => .inr (.inr (.inr query))
  left_inv query := by rcases query with _ | _ | _ | _ <;> rfl
  right_inv query := by cases query <;> rfl

noncomputable instance verifierQueryFintype (statement : Statement) :
    Fintype (VerifierQuery statement) :=
  Fintype.ofEquiv _ (verifierQueryEquivSum statement)

noncomputable instance verifierQueryDecidableEq (statement : Statement) :
    DecidableEq (VerifierQuery statement) :=
  Classical.decEq _

theorem verifier_query_card (statement : Statement) :
    Fintype.card (VerifierQuery statement) =
      Fintype.card CommittedOracle + Fintype.card SecondQuery +
        Fintype.card (ThirdQuery statement) + Fintype.card (FourthQuery statement) := by
  rw [Fintype.card_congr (verifierQueryEquivSum statement).symm]
  simp only [Fintype.card_sum]
  omega

/-! ## One common statement-indexed ideal output -/

abbrev IndexedVerifierQuery
    (Index : Type)
    (statement : Index → Statement) :=
  Sigma fun index => VerifierQuery (statement index)

abbrev IndexedLogicalResponse
    (Index : Type)
    (statement : Index → Statement) :=
  (index : Index) → LogicalOutput (statement index)

abbrev IndexedLogicalOutput
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :=
  Fin (Fintype.card (IndexedLogicalResponse Index statement))

noncomputable instance indexedVerifierQueryFintype
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :
    Fintype (IndexedVerifierQuery Index statement) :=
  inferInstance

noncomputable instance indexedVerifierQueryDecidableEq
    (Index : Type)
    (statement : Index → Statement) :
    DecidableEq (IndexedVerifierQuery Index statement) :=
  Classical.decEq _

noncomputable instance indexedLogicalOutputFintype
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :
    Fintype (IndexedLogicalOutput Index statement) :=
  inferInstance

noncomputable instance indexedLogicalOutputDecidableEq
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :
    DecidableEq (IndexedLogicalOutput Index statement) :=
  Classical.decEq _

noncomputable instance indexedLogicalResponseNonempty
    (Index : Type)
    (statement : Index → Statement) :
    Nonempty (IndexedLogicalResponse Index statement) :=
  inferInstance

noncomputable instance indexedLogicalResponseInhabited
    (Index : Type)
    (statement : Index → Statement) :
    Inhabited (IndexedLogicalResponse Index statement) :=
  ⟨Classical.choice (indexedLogicalResponseNonempty Index statement)⟩

noncomputable instance indexedLogicalOutputCardNeZero
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :
    NeZero (Fintype.card (IndexedLogicalResponse Index statement)) :=
  ⟨Fintype.card_ne_zero⟩

noncomputable def indexedLogicalResponseEquivOutput
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :
    IndexedLogicalResponse Index statement ≃ IndexedLogicalOutput Index statement :=
  Fintype.equivFin (IndexedLogicalResponse Index statement)

noncomputable def indexedLogicalOutputAddEquivZMod
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :
    IndexedLogicalOutput Index statement ≃+
      ZMod (Fintype.card (IndexedLogicalResponse Index statement)) :=
  (ZMod.finEquiv
    (Fintype.card (IndexedLogicalResponse Index statement))).toAddEquiv

noncomputable def indexedLogicalOutputCoordinate
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    (output : IndexedLogicalOutput Index statement)
    (index : Index) : LogicalOutput (statement index) :=
  (indexedLogicalResponseEquivOutput Index statement).symm output index

abbrev IndexedLogicalPhase
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :=
  ZMod (Fintype.card (IndexedLogicalResponse Index statement))

noncomputable def indexedCompletePhaseSystem
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :
    CompletePhaseSystem
      (IndexedLogicalOutput Index statement)
      (IndexedLogicalPhase Index statement) :=
  cyclicCompletePhaseSystem (indexedLogicalOutputAddEquivZMod Index statement)

/-- Uniformity of a selected statement coordinate in the exact dependent-product response. -/
theorem indexed_logical_output_coordinate_uniform
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    (statement : Index → Statement)
    (index : Index)
    (event : LogicalOutput (statement index) → Prop) :
    uniformEventProbability
        (fun output : IndexedLogicalOutput Index statement =>
          event (indexedLogicalOutputCoordinate output index)) =
      uniformEventProbability event := by
  let decode := (indexedLogicalResponseEquivOutput Index statement).symm
  let split := Equiv.piSplitAt index (fun selected => LogicalOutput (statement selected))
  calc
    _ = uniformEventProbability
          (fun response : IndexedLogicalResponse Index statement =>
            event (response index)) := by
      simpa [indexedLogicalOutputCoordinate, decode] using
        uniform_event_probability_equiv decode
          (fun response : IndexedLogicalResponse Index statement =>
            event (response index))
    _ = uniformEventProbability
          (fun output :
            LogicalOutput (statement index) ×
              ((selected : { selected // selected ≠ index }) →
                LogicalOutput (statement selected)) => event output.1) := by
      simpa [split] using
        uniform_event_probability_equiv split
          (fun output :
            LogicalOutput (statement index) ×
              ((selected : { selected // selected ≠ index }) →
                LogicalOutput (statement selected)) => event output.1)
    _ = uniformEventProbability event :=
      HegemonCrypto.SmallWood.LogicalOracle.uniform_probability_first event

/-! ## Exact singleton selector and conditional ideal-QROM lift -/

abbrev IndexedLogicalDatabase
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) :=
  Database
    (IndexedVerifierQuery Index statement)
    (IndexedLogicalOutput Index statement)

abbrev LocalFailure
    {Index : Type}
    (statement : Index → Statement) :=
  (index : Index) →
    VerifierQuery (statement index) → LogicalOutput (statement index) → Prop

def IndexedRecordedFailure
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    (localFailure : LocalFailure statement) :
    Property
      (IndexedVerifierQuery Index statement)
      (IndexedLogicalOutput Index statement) :=
  fun database =>
    ∃ (query : IndexedVerifierQuery Index statement)
      (output : IndexedLogicalOutput Index statement),
      database query = some output ∧
        localFailure query.1 query.2
          (indexedLogicalOutputCoordinate output query.1)

def IndexedKnowledgeFailureProperty
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    (localFailure : LocalFailure statement) :
    Property
      (IndexedVerifierQuery Index statement)
      (IndexedLogicalOutput Index statement) :=
  union
    (HasCollision :
      Property
        (IndexedVerifierQuery Index statement)
        (IndexedLogicalOutput Index statement))
    (IndexedRecordedFailure localFailure)

structure IndexedIdealFailureSelector
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    (localFailure : LocalFailure statement)
    (Workspace : Type*) where
  enabled : Workspace → Prop
  selectedIndex : Workspace → Index
  query : (workspace : Workspace) →
    VerifierQuery (statement (selectedIndex workspace))
  output : Workspace → IndexedLogicalOutput Index statement
  failure : ∀ workspace, enabled workspace →
    localFailure (selectedIndex workspace) (query workspace)
      (indexedLogicalOutputCoordinate
        (output workspace) (selectedIndex workspace))

def indexedFailureClaims
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    {localFailure : LocalFailure statement}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector localFailure Workspace)
    (workspace : Workspace) :
    List
      (IndexedVerifierQuery Index statement ×
        IndexedLogicalOutput Index statement) :=
  [(⟨selector.selectedIndex workspace, selector.query workspace⟩,
    selector.output workspace)]

def IndexedIdealFailureEvent
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    {localFailure : LocalFailure statement}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector localFailure Workspace) :
    Workspace → IndexedLogicalDatabase Index statement → Prop :=
  AdaptiveClaimsEvent selector.enabled (indexedFailureClaims selector)

theorem indexed_failure_claim_inputs_nodup
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    {localFailure : LocalFailure statement}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector localFailure Workspace)
    (workspace : Workspace) :
    ((indexedFailureClaims selector workspace).map Prod.fst).Nodup := by
  simp [indexedFailureClaims]

theorem indexed_failure_claim_length
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    {localFailure : LocalFailure statement}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector localFailure Workspace)
    (workspace : Workspace) :
    (indexedFailureClaims selector workspace).length = 1 := by
  simp [indexedFailureClaims]

/-- The selected singleton claim is recorded as the exact selected local failure. -/
theorem indexed_failure_event_implies_knowledge_failure
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    {localFailure : LocalFailure statement}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector localFailure Workspace)
    (workspace : Workspace)
    (database : IndexedLogicalDatabase Index statement)
    (failure : IndexedIdealFailureEvent selector workspace database) :
    IndexedKnowledgeFailureProperty localFailure database := by
  rcases failure with ⟨enabled, records⟩
  apply Or.inr
  refine
    ⟨⟨selector.selectedIndex workspace, selector.query workspace⟩,
      selector.output workspace, ?_, selector.failure workspace enabled⟩
  exact records
    (⟨selector.selectedIndex workspace, selector.query workspace⟩,
      selector.output workspace)
    (by simp [indexedFailureClaims])

theorem indexed_knowledge_failure_empty_false
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    (localFailure : LocalFailure statement) :
    ¬IndexedKnowledgeFailureProperty localFailure
      (empty : IndexedLogicalDatabase Index statement) := by
  intro failure
  rcases failure with collision | recordedFailure
  · rcases collision with
      ⟨left, right, output, different, leftRecorded, _rightRecorded⟩
    simp at leftRecorded
  · rcases recordedFailure with ⟨query, output, recorded, _failure⟩
    simp at recorded

theorem indexed_initial_knowledge_failure_project_eq_zero
    {Index : Type}
    [Fintype Index]
    {statement : Index → Statement}
    {Phase : Type*}
    [Fintype Phase] [DecidableEq Phase]
    {Workspace : Type*}
    [Fintype Workspace] [DecidableEq Workspace]
    (localFailure : LocalFailure statement)
    (queryBound : Nat)
    (initialRegisters :
      RegisterBasis
        (Input := IndexedVerifierQuery Index statement)
        (Phase := Phase)
        (Workspace := Workspace) → ℂ) :
    project (IndexedKnowledgeFailureProperty localFailure) queryBound
        (partialRandomOracleState
          (Output := IndexedLogicalOutput Index statement) ∅ initialRegisters) =
      0 := by
  funext basis
  by_cases records :
      RecordsExactly (Output := IndexedLogicalOutput Index statement)
        ∅ basis.database
  · have databaseEmpty :
        basis.database = (empty : IndexedLogicalDatabase Index statement) :=
      (records_exactly_empty_iff basis.database).mp records
    simp [project, databaseEmpty, size_empty,
      indexed_knowledge_failure_empty_false localFailure]
  · simp [project, partialRandomOracleState, records]

def exactSmz9IndexedIdealLogicalBridgeLoss
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement) : ℝ :=
  1 / (Fintype.card (IndexedLogicalOutput Index statement) : ℝ)

def exactSmz9IndexedIdealLogicalQromFailureBound
    (Index : Type)
    [Fintype Index]
    (statement : Index → Statement)
    (queries : Nat)
    (instability : ℝ) : ℝ :=
  oracleLoss
    (databaseLoss queries instability)
    (exactSmz9IndexedIdealLogicalBridgeLoss Index statement)

/--
Exact `6 / 20 / 140` statement-indexed ideal logical-QROM lifting theorem.

`steps` is one global query list for the common tagged oracle.  The theorem is conditional on a
real CMS-instability bound for the exact selected local-failure property; it does not obtain that
bound from the historical `5 / 23 / 138` round transition and does not instantiate SHA-512.
-/
theorem exact_smz9_indexed_ideal_logical_qrom_failure_probability_le
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index → Statement}
    {Phase : Type*}
    [Fintype Phase] [DecidableEq Phase]
    {Workspace : Type*}
    [Fintype Workspace] [DecidableEq Workspace]
    (localFailure : LocalFailure statement)
    (completePhaseSystem :
      CompletePhaseSystem (IndexedLogicalOutput Index statement) Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := IndexedVerifierQuery Index statement)
      (Output := IndexedLogicalOutput Index statement)
      (Phase := Phase)
      (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis
        (Input := IndexedVerifierQuery Index statement)
        (Phase := Phase)
        (Workspace := Workspace) → ℂ)
    (initialSubnormalized :
      Subnormalized
        (partialRandomOracleState
          (Output := IndexedLogicalOutput Index statement) ∅ initialRegisters))
    (selector : IndexedIdealFailureSelector localFailure Workspace)
    (instabilityBound : ℝ)
    (instability :
      RealInstabilityBound
        (IndexedKnowledgeFailureProperty localFailure)
        steps.length instabilityBound) :
    ScopedSecurityClaim .idealLogicalQrom
      (normSquared
          (workspaceEventProjection (IndexedIdealFailureEvent selector)
            (totalOracleFamilyState
              (oracleFamilyRun completePhaseSystem.system steps
                (fun _oracle => initialRegisters)))) ≤
        exactSmz9IndexedIdealLogicalQromFailureBound
          Index statement steps.length instabilityBound) := by
  apply ScopedSecurityClaim.ofIdealLogicalQrom
  let system := completePhaseSystem.system
  let blindSteps :=
    steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let initialState :=
    partialRandomOracleState
      (Output := IndexedLogicalOutput Index statement) ∅ initialRegisters
  let compressedState :=
    rawRun system steps.length blindSteps initialState
  let family :=
    oracleFamilyRun system steps (fun _oracle => initialRegisters)
  have initialBounded : BoundedState 0 initialState := by
    exact partial_random_oracle_empty_bounded initialRegisters
  have capacity : blindSteps.length ≤ steps.length := by
    simp [blindSteps]
  have simulation :
      globalDecompress compressedState = totalOracleFamilyState family := by
    exact compressed_run_is_uniform_random_oracle_purification
      system steps.length steps initialRegisters (by simp)
  have compressedBounded :
      BoundedState steps.length compressedState := by
    exact raw_run_bounded_of_bounded
      system steps.length blindSteps initialState 0
        (by simpa using capacity) initialBounded
  have compressedSubnormalized :
      Subnormalized compressedState := by
    exact raw_run_subnormalized_of_bounded
      system steps.length blindSteps initialState 0
        (by simpa using capacity) initialBounded initialSubnormalized
  have databaseGame :
      normSquared
          (project (IndexedKnowledgeFailureProperty localFailure) steps.length
            compressedState) ≤
        databaseLoss steps.length instabilityBound := by
    have lifted :=
      implemented_raw_database_game_le_database_loss
        system
        (IndexedKnowledgeFailureProperty localFailure)
        steps.length
        blindSteps
        initialState
        instability
        capacity
        initialBounded
        initialSubnormalized
        (indexed_initial_knowledge_failure_project_eq_zero
          localFailure steps.length initialRegisters)
    have blindLength : blindSteps.length = steps.length := by
      simp [blindSteps]
    rw [blindLength] at lifted
    exact lifted
  have transferred :=
    adaptive_claims_probability_le
      compressedState
      family
      simulation
      selector.enabled
      (indexedFailureClaims selector)
      (indexed_failure_claim_inputs_nodup selector)
      1
      (by
        intro workspace
        rw [indexed_failure_claim_length selector workspace])
      (IndexedKnowledgeFailureProperty localFailure)
      (indexed_failure_event_implies_knowledge_failure selector)
      steps.length
      compressedBounded
      compressedSubnormalized
      (databaseLoss steps.length instabilityBound)
      databaseGame
  have bridgeEq :
      ((1 : Nat) : ℝ) ^ 2 *
          (1 /
            (Fintype.card
              (IndexedLogicalOutput Index statement) : ℝ)) =
        exactSmz9IndexedIdealLogicalBridgeLoss Index statement := by
    unfold exactSmz9IndexedIdealLogicalBridgeLoss
    rw [Nat.cast_one, one_pow, one_mul]
  change
    normSquared
        (workspaceEventProjection
          (AdaptiveClaimsEvent selector.enabled (indexedFailureClaims selector))
          (totalOracleFamilyState family)) ≤
      oracleLoss
        (databaseLoss steps.length instabilityBound)
        (exactSmz9IndexedIdealLogicalBridgeLoss Index statement)
  rw [← bridgeEq]
  exact transferred

/-! ## Exact historical mismatch and deliberately unavailable source bridges -/

theorem fin_five_not_equiv_fin_six :
    ¬Nonempty (Fin 5 ≃ Fin 6) := by
  intro equivalence
  have cards := Fintype.card_congr (Classical.choice equivalence)
  norm_num at cards

theorem fin_twenty_three_not_equiv_fin_twenty :
    ¬Nonempty (Fin 23 ≃ Fin 20) := by
  intro equivalence
  have cards := Fintype.card_congr (Classical.choice equivalence)
  norm_num at cards

theorem fin_one_hundred_thirty_eight_not_equiv_fin_one_hundred_forty :
    ¬Nonempty (Fin 138 ≃ Fin 140) := by
  intro equivalence
  have cards := Fintype.card_congr (Classical.choice equivalence)
  norm_num at cards

/-!
The identifiers below pin each missing bridge to the concrete source surface it must refine.
They are audit metadata, not proofs that Lean executes or verifies the Rust implementation.  The
wire and executable-ROM vectors are useful regression witnesses, but neither is a universal
transition/refinement theorem.
-/

def exactSmz9RoundTransitionVerifierSource : String :=
  "transaction_circuit::smallwood_engine::verify_statement_with_transcript_backend_profile_and_domain"
def exactSmz9RoundTransitionTraceSource : String :=
  "transaction_circuit::smallwood_engine::build_smallwood_poseidon2_v8_smz9_verifier_trace_v1"
def exactSmz9RoundTransitionProfileSource : String :=
  "POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE"
def exactSmz9RoundTransitionBackendSource : String :=
  "SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9"
def exactSmz9RoundTransitionDecsDomainSource : String :=
  "SmallwoodDecsEvaluationDomain::Radix2DisjointCoset"
def exactSmz9WireVectorSource : String :=
  "testdata/formal_crypto_vectors/smallwood_smz9_proof_wire.json"

/-- An exact deterministic transition refinement contributes no additive probability loss. -/
def exactSmz9RoundTransitionRefinementLoss : ℝ := 0

def exactSmz9FailureSelectorSource : String :=
  "transaction_circuit::smallwood_poseidon2_v8_zk_refinement::validate_accepted_smallwood_poseidon2_v8_smz9_refinement_v1"
def exactSmz9FailureSelectorTraceField : String :=
  "SmallwoodVerifierTraceV1::accept"
def exactSmz9ExecutableRefinementVectorSource : String :=
  "docs/crypto/smallwood_poseidon2_v8_smz9_executable_zk_refinement.json"

/-- Exact event/selector preservation also contributes no additive probability loss. -/
def exactSmz9FailureSelectorRefinementLoss : ℝ := 0

def exactSmz9CmsInstabilitySource : String :=
  "HegemonCrypto.CmsClassicalDatabase.RealInstabilityBound"
def exactSmz9CmsDatabaseLiftSource : String :=
  "HegemonCrypto.CmsLifting.databaseLoss"
def exactSmz9CmsExposureDomain : String :=
  "one-global-step-list-E-equals-adversarial-Q-plus-honest-H"

/-- The exact database loss controlled by the missing SMZ9 instability theorem. -/
def exactSmz9CmsControlledDatabaseLoss
    (totalOracleExposures : Nat) (instability : ℝ) : ℝ :=
  databaseLoss totalOracleExposures instability

/--
Accounting target after splitting interactive instability and full-output collision terms.  The
logical-oracle bridge must justify this decomposition at the exact common-output cardinality; the
definition alone does not do so.
-/
def exactSmz9CmsInteractiveAndCollisionLoss
    (totalOracleExposures : Nat)
    (interactiveFailure outputCardinality : ℝ) : ℝ :=
  12 * (totalOracleExposures : ℝ) ^ 2 * interactiveFailure +
    48 * (totalOracleExposures : ℝ) ^ 3 / outputCardinality

theorem exact_smz9_missing_bridge_source_inventory :
    exactSmz9RoundTransitionProfileSource =
        "POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE" ∧
      exactSmz9RoundTransitionBackendSource =
        "SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9" ∧
      exactSmz9RoundTransitionDecsDomainSource =
        "SmallwoodDecsEvaluationDomain::Radix2DisjointCoset" ∧
      exactSmz9RoundTransitionRefinementLoss = 0 ∧
      exactSmz9FailureSelectorTraceField = "SmallwoodVerifierTraceV1::accept" ∧
      exactSmz9FailureSelectorRefinementLoss = 0 ∧
      exactSmz9CmsExposureDomain =
        "one-global-step-list-E-equals-adversarial-Q-plus-honest-H" := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Exact SMZ9 source verifier transition, absent while RoundByRound remains `5 / 23 / 138`. -/
inductive ExactSmz9RoundTransitionRefinement : Prop

/-- Exact native/extractor failure event to `IndexedIdealFailureSelector` refinement. -/
inductive ExactSmz9FailureSelectorRefinement : Prop

/-- Exact CMS instability theorem for the SMZ9 transition and extraction-failure property. -/
inductive ExactSmz9CmsInstability : Prop

theorem exact_smz9_round_transition_refinement_is_unavailable :
    ¬ExactSmz9RoundTransitionRefinement := by
  intro refinement
  exact nomatch refinement

theorem exact_smz9_failure_selector_refinement_is_unavailable :
    ¬ExactSmz9FailureSelectorRefinement := by
  intro refinement
  exact nomatch refinement

theorem exact_smz9_cms_instability_is_unavailable :
    ¬ExactSmz9CmsInstability := by
  intro instability
  exact nomatch instability

end

end HegemonCrypto.SmallWood.V8Smz9LogicalOracle
