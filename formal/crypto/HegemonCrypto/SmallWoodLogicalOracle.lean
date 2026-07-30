import HegemonCrypto.CmsClassicalDatabase
import HegemonCrypto.SmallWoodProductionBcsInstantiation
import Mathlib.Data.Finset.Prod
import Mathlib.Data.Fintype.Prod
import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic.FieldSimp
import Mathlib.Tactic.Push

/-!
# Logical random-oracle interface for the active SmallWood transcript

The deployed SHA-512 counter-mode sampler emits many physical digest blocks.  Those blocks are
not independent public-coin rounds: one complete sampler invocation realizes one typed verifier
message.  This module therefore gives the CMS transform one finite logical response containing
all four active challenge types.  A domain-separated verifier query selects exactly one
coordinate.

The coordinate lemmas below prove that a uniform logical response induces the exact uniform
challenge distribution used by the interactive round-by-round theorem.  Connecting this logical
oracle to the deployed counter-mode SHA-512 implementation is intentionally a separate,
cryptographic random-oracle/XOF assumption.
-/

namespace HegemonCrypto.SmallWood.LogicalOracle

open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.RoundByRound.Interactive
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionBcsInstantiation

set_option maxHeartbeats 0
set_option maxRecDepth 100000

noncomputable section

set_option linter.unusedSectionVars false

local instance classicalPropDecidable (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

abbrev ActiveStatementType := HegemonCrypto.SmallWood.Statement

/-! ## Nonempty active challenge spaces -/

def canonicalPiopOpeningChallenge : PiopOpeningChallenge := by
  refine ⟨(fun index => ⟨packingFactor + index.val, ?_⟩), ?_⟩
  · change packingFactor + index.val < 18446744069414584321
    have indexBound := index.isLt
    change index.val < 5 at indexBound
    simp [packingFactor]
    omega
  · constructor
    · intro left right equal
      apply Fin.ext
      have values := congrArg Fin.val equal
      simp at values
      omega
    · intro index
      simp [packingPoints, packingFactor]

def canonicalDecsOpeningChallenge : DecsOpeningChallenge := by
  let embedding : Fin decsOpenedEvaluations ↪ Fin decsEvaluationCount :=
    { toFun := fun index => ⟨index.val, by
        have bound := index.isLt
        change index.val < 1048576
        change index.val < 20 at bound
        omega⟩
      inj' := fun left right equal =>
        Fin.ext
          (congrArg
            (fun value : Fin decsEvaluationCount => value.val)
            equal) }
  refine ⟨Finset.univ.map embedding, ?_⟩
  simp

noncomputable instance piopPolynomialMessageNonempty :
    Nonempty PiopPolynomialMessage :=
  ⟨{ nonlinear := fun _ _ => 0, linear := fun _ _ => 0 }⟩

noncomputable instance piopOpeningChallengeNonempty :
    Nonempty PiopOpeningChallenge :=
  ⟨canonicalPiopOpeningChallenge⟩

noncomputable instance decsOpeningChallengeNonempty :
    Nonempty DecsOpeningChallenge :=
  ⟨canonicalDecsOpeningChallenge⟩

/-! ## One finite output carrying all four typed verifier messages -/

structure LogicalOutput (statement : ActiveStatementType) where
  decsChallenge : Matrix decsEta lvcsRowCount
  piopChallenge : PiopBatchingChallenge statement
  piopOpening : PiopOpeningChallenge
  decsOpening : DecsOpeningChallenge
  deriving Fintype

noncomputable instance logicalOutputDecidableEq (statement : ActiveStatementType) :
    DecidableEq (LogicalOutput statement) :=
  Classical.decEq _

noncomputable instance logicalOutputNonempty (statement : ActiveStatementType) :
    Nonempty (LogicalOutput statement) :=
  ⟨{ decsChallenge := fun _ _ => 0
     piopChallenge := fun _ _ => 0
     piopOpening := canonicalPiopOpeningChallenge
     decsOpening := canonicalDecsOpeningChallenge }⟩

noncomputable instance logicalOutputInhabited (statement : ActiveStatementType) :
    Inhabited (LogicalOutput statement) :=
  ⟨Classical.choice (logicalOutputNonempty statement)⟩

def logicalOutputEquivProduct (statement : ActiveStatementType) :
    LogicalOutput statement ≃
      Matrix decsEta lvcsRowCount ×
        (PiopBatchingChallenge statement ×
          (PiopOpeningChallenge × DecsOpeningChallenge)) where
  toFun := fun output =>
    (output.decsChallenge,
      (output.piopChallenge, (output.piopOpening, output.decsOpening)))
  invFun := fun output =>
    { decsChallenge := output.1
      piopChallenge := output.2.1
      piopOpening := output.2.2.1
      decsOpening := output.2.2.2 }
  left_inv := by intro output; cases output; rfl
  right_inv := by intro output; rcases output with ⟨_, _, _, _⟩; rfl

def logicalOutputPiopEquivProduct (statement : ActiveStatementType) :
    LogicalOutput statement ≃
      PiopBatchingChallenge statement ×
        (Matrix decsEta lvcsRowCount ×
          (PiopOpeningChallenge × DecsOpeningChallenge)) where
  toFun := fun output =>
    (output.piopChallenge,
      (output.decsChallenge, (output.piopOpening, output.decsOpening)))
  invFun := fun output =>
    { decsChallenge := output.2.1
      piopChallenge := output.1
      piopOpening := output.2.2.1
      decsOpening := output.2.2.2 }
  left_inv := by intro output; cases output; rfl
  right_inv := by intro output; rcases output with ⟨_, _, _, _⟩; rfl

def logicalOutputPiopOpeningEquivProduct (statement : ActiveStatementType) :
    LogicalOutput statement ≃
      PiopOpeningChallenge ×
        (Matrix decsEta lvcsRowCount ×
          (PiopBatchingChallenge statement × DecsOpeningChallenge)) where
  toFun := fun output =>
    (output.piopOpening,
      (output.decsChallenge, (output.piopChallenge, output.decsOpening)))
  invFun := fun output =>
    { decsChallenge := output.2.1
      piopChallenge := output.2.2.1
      piopOpening := output.1
      decsOpening := output.2.2.2 }
  left_inv := by intro output; cases output; rfl
  right_inv := by intro output; rcases output with ⟨_, _, _, _⟩; rfl

def logicalOutputDecsOpeningEquivProduct (statement : ActiveStatementType) :
    LogicalOutput statement ≃
      DecsOpeningChallenge ×
        (Matrix decsEta lvcsRowCount ×
          (PiopBatchingChallenge statement × PiopOpeningChallenge)) where
  toFun := fun output =>
    (output.decsOpening,
      (output.decsChallenge, (output.piopChallenge, output.piopOpening)))
  invFun := fun output =>
    { decsChallenge := output.2.1
      piopChallenge := output.2.2.1
      piopOpening := output.2.2.2
      decsOpening := output.1 }
  left_inv := by intro output; cases output; rfl
  right_inv := by intro output; rcases output with ⟨_, _, _, _⟩; rfl

/--
CMS implements its finite phase oracle over an additive output register.  The additive structure
here is only a coordinate representation transported from the cyclic group with the same finite
cardinality; none of the SmallWood verifier semantics depends on that representation.
-/
noncomputable instance logicalOutputAddCommGroup (statement : ActiveStatementType) :
    AddCommGroup (LogicalOutput statement) := by
  letI : NeZero (Fintype.card (LogicalOutput statement)) :=
    ⟨Fintype.card_ne_zero⟩
  exact Equiv.addCommGroup (Fintype.equivFin (LogicalOutput statement))

/-- The additive representation used by the CMS phase oracle is explicitly cyclic. -/
noncomputable def logicalOutputAddEquivFin (statement : ActiveStatementType) :
    LogicalOutput statement ≃+
      Fin (Fintype.card (LogicalOutput statement)) where
  toEquiv := Fintype.equivFin (LogicalOutput statement)
  map_add' := by
    intro left right
    change
      (Fintype.equivFin (LogicalOutput statement))
          ((Fintype.equivFin (LogicalOutput statement)).symm
            ((Fintype.equivFin (LogicalOutput statement)) left +
              (Fintype.equivFin (LogicalOutput statement)) right)) =
        (Fintype.equivFin (LogicalOutput statement)) left +
          (Fintype.equivFin (LogicalOutput statement)) right
    exact (Fintype.equivFin (LogicalOutput statement)).apply_symm_apply _

/-- Canonical cyclic target used by the concrete Fourier phase system. -/
noncomputable def logicalOutputAddEquivZMod (statement : ActiveStatementType) :
    LogicalOutput statement ≃+
      ZMod (Fintype.card (LogicalOutput statement)) :=
  (logicalOutputAddEquivFin statement).trans
    (ZMod.finEquiv (Fintype.card (LogicalOutput statement))).toAddEquiv

/-! ## Exact coordinate-uniformity arithmetic -/

theorem filter_first_card
    {Left Right : Type}
    [Fintype Left] [Fintype Right]
    (event : Left -> Prop) :
    ((Finset.univ : Finset (Left × Right)).filter
        (fun sample => event sample.1)).card =
      (Finset.univ.filter event).card * Fintype.card Right := by
  classical
  have filtered := Finset.filter_product_left
    (s := (Finset.univ : Finset Left))
    (t := (Finset.univ : Finset Right))
    event
  have cards := congrArg Finset.card filtered
  simpa [Finset.univ_product_univ, Finset.card_product] using cards

theorem filter_second_card
    {Left Right : Type}
    [Fintype Left] [Fintype Right]
    (event : Right -> Prop) :
    ((Finset.univ : Finset (Left × Right)).filter
        (fun sample => event sample.2)).card =
      Fintype.card Left * (Finset.univ.filter event).card := by
  classical
  have filtered := Finset.filter_product_right
    (s := (Finset.univ : Finset Left))
    (t := (Finset.univ : Finset Right))
    event
  have cards := congrArg Finset.card filtered
  simpa [Finset.univ_product_univ, Finset.card_product] using cards

theorem uniform_probability_first
    {Left Right : Type}
    [Fintype Left] [Fintype Right]
    [DecidableEq Left] [DecidableEq Right]
    [Nonempty Left] [Nonempty Right]
    (event : Left -> Prop) :
    uniformEventProbability (fun sample : Left × Right => event sample.1) =
      uniformEventProbability event := by
  rw [uniform_event_probability_eq_filter, uniform_event_probability_eq_filter,
    filter_first_card, Fintype.card_prod]
  have rightNonzero : (Fintype.card Right : Rat) ≠ 0 := by
    exact_mod_cast Fintype.card_ne_zero
  push_cast
  field_simp

theorem uniform_probability_second
    {Left Right : Type}
    [Fintype Left] [Fintype Right]
    [DecidableEq Left] [DecidableEq Right]
    [Nonempty Left] [Nonempty Right]
    (event : Right -> Prop) :
    uniformEventProbability (fun sample : Left × Right => event sample.2) =
      uniformEventProbability event := by
  rw [uniform_event_probability_eq_filter, uniform_event_probability_eq_filter,
    filter_second_card, Fintype.card_prod]
  have leftNonzero : (Fintype.card Left : Rat) ≠ 0 := by
    exact_mod_cast Fintype.card_ne_zero
  push_cast
  field_simp

theorem logical_output_decs_uniform
    (statement : ActiveStatementType)
    (event : Matrix decsEta lvcsRowCount -> Prop) :
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          event output.decsChallenge) =
      uniformEventProbability event := by
  calc
    _ =
        uniformEventProbability
          (fun output :
              Matrix decsEta lvcsRowCount ×
                (PiopBatchingChallenge statement ×
                  (PiopOpeningChallenge × DecsOpeningChallenge)) =>
            event output.1) := by
      simpa [logicalOutputEquivProduct] using
        uniform_event_probability_equiv
          (logicalOutputEquivProduct statement)
          (fun output => event output.1)
    _ = uniformEventProbability event :=
      uniform_probability_first event

theorem logical_output_piop_uniform
    (statement : ActiveStatementType)
    (event : PiopBatchingChallenge statement -> Prop) :
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          event output.piopChallenge) =
      uniformEventProbability event := by
  calc
    _ =
        uniformEventProbability
          (fun output :
              PiopBatchingChallenge statement ×
                (Matrix decsEta lvcsRowCount ×
                  (PiopOpeningChallenge × DecsOpeningChallenge)) =>
            event output.1) := by
      simpa [logicalOutputPiopEquivProduct] using
        uniform_event_probability_equiv
          (logicalOutputPiopEquivProduct statement)
          (fun output => event output.1)
    _ = uniformEventProbability event :=
      uniform_probability_first event

theorem logical_output_piop_opening_uniform
    (statement : ActiveStatementType)
    (event : PiopOpeningChallenge -> Prop) :
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          event output.piopOpening) =
      uniformEventProbability event := by
  calc
    _ =
        uniformEventProbability
          (fun output :
              PiopOpeningChallenge ×
                (Matrix decsEta lvcsRowCount ×
                  (PiopBatchingChallenge statement × DecsOpeningChallenge)) =>
            event output.1) := by
      simpa [logicalOutputPiopOpeningEquivProduct] using
        uniform_event_probability_equiv
          (logicalOutputPiopOpeningEquivProduct statement)
          (fun output => event output.1)
    _ = uniformEventProbability event :=
      uniform_probability_first event

theorem logical_output_decs_opening_uniform
    (statement : ActiveStatementType)
    (event : DecsOpeningChallenge -> Prop) :
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          event output.decsOpening) =
      uniformEventProbability event := by
  calc
    _ =
        uniformEventProbability
          (fun output :
              DecsOpeningChallenge ×
                (Matrix decsEta lvcsRowCount ×
                  (PiopBatchingChallenge statement × PiopOpeningChallenge)) =>
            event output.1) := by
      simpa [logicalOutputDecsOpeningEquivProduct] using
        uniform_event_probability_equiv
          (logicalOutputDecsOpeningEquivProduct statement)
          (fun output => event output.1)
    _ = uniformEventProbability event :=
      uniform_probability_first event

/-! ## Exact fixed-statement verifier-query grammar -/

structure SecondQuery where
  oracle : CommittedOracle
  decsChallenge : Matrix decsEta lvcsRowCount
  decsMessage : DecsPolynomialMessage
  deriving Fintype

structure ThirdQuery (statement : ActiveStatementType) where
  oracle : CommittedOracle
  decsChallenge : Matrix decsEta lvcsRowCount
  decsMessage : DecsPolynomialMessage
  piopChallenge : PiopBatchingChallenge statement
  piopMessage : PiopPolynomialMessage

structure FourthQuery (statement : ActiveStatementType) where
  oracle : CommittedOracle
  decsChallenge : Matrix decsEta lvcsRowCount
  decsMessage : DecsPolynomialMessage
  piopChallenge : PiopBatchingChallenge statement
  piopMessage : PiopPolynomialMessage
  piopOpening : PiopOpeningChallenge
  pcsMessage : PcsCombinationMessage

inductive VerifierQuery (statement : ActiveStatementType) where
  | first (oracle : CommittedOracle)
  | second (query : SecondQuery)
  | third (query : ThirdQuery statement)
  | fourth (query : FourthQuery statement)

def thirdQueryEquivProduct (statement : ActiveStatementType) :
    (CommittedOracle ×
      Matrix decsEta lvcsRowCount ×
        DecsPolynomialMessage ×
          PiopBatchingChallenge statement ×
            PiopPolynomialMessage) ≃
      ThirdQuery statement where
  toFun := fun data =>
    { oracle := data.1
      decsChallenge := data.2.1
      decsMessage := data.2.2.1
      piopChallenge := data.2.2.2.1
      piopMessage := data.2.2.2.2 }
  invFun := fun query =>
    (query.oracle, query.decsChallenge, query.decsMessage,
      query.piopChallenge, query.piopMessage)
  left_inv := by intro data; rcases data with ⟨_, _, _, _, _⟩; rfl
  right_inv := by intro query; cases query; rfl

noncomputable instance thirdQueryFintype (statement : ActiveStatementType) :
    Fintype (ThirdQuery statement) :=
  Fintype.ofEquiv _ (thirdQueryEquivProduct statement)

def fourthQueryEquivProduct (statement : ActiveStatementType) :
    (CommittedOracle ×
      Matrix decsEta lvcsRowCount ×
        DecsPolynomialMessage ×
          PiopBatchingChallenge statement ×
            PiopPolynomialMessage ×
              PiopOpeningChallenge ×
                PcsCombinationMessage) ≃
      FourthQuery statement where
  toFun := fun data =>
    { oracle := data.1
      decsChallenge := data.2.1
      decsMessage := data.2.2.1
      piopChallenge := data.2.2.2.1
      piopMessage := data.2.2.2.2.1
      piopOpening := data.2.2.2.2.2.1
      pcsMessage := data.2.2.2.2.2.2 }
  invFun := fun query =>
    (query.oracle, query.decsChallenge, query.decsMessage,
      query.piopChallenge, query.piopMessage, query.piopOpening, query.pcsMessage)
  left_inv := by intro data; rcases data with ⟨_, _, _, _, _, _, _⟩; rfl
  right_inv := by intro query; cases query; rfl

noncomputable instance fourthQueryFintype (statement : ActiveStatementType) :
    Fintype (FourthQuery statement) :=
  Fintype.ofEquiv _ (fourthQueryEquivProduct statement)

def verifierQueryEquivSum (statement : ActiveStatementType) :
    (CommittedOracle ⊕
      SecondQuery ⊕
        ThirdQuery statement ⊕
          FourthQuery statement) ≃
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
  left_inv := by intro query; rcases query with _ | _ | _ | _ <;> rfl
  right_inv := by intro query; cases query <;> rfl

noncomputable instance verifierQueryFintype (statement : ActiveStatementType) :
    Fintype (VerifierQuery statement) :=
  Fintype.ofEquiv _ (verifierQueryEquivSum statement)

noncomputable instance verifierQueryDecidableEq (statement : ActiveStatementType) :
    DecidableEq (VerifierQuery statement) :=
  Classical.decEq _

def queryPrefix
    {statement : ActiveStatementType}
    (active : ActiveStatement statement) :
    VerifierQuery statement -> Prefix
  | .first oracle =>
      .oracle statement active oracle
  | .second query =>
      .decsPolynomials statement active
        query.oracle query.decsChallenge query.decsMessage
  | .third query =>
      .piopPolynomials statement active
        query.oracle query.decsChallenge query.decsMessage
        query.piopChallenge query.piopMessage
  | .fourth query =>
      .pcsCombination statement active
        query.oracle query.decsChallenge query.decsMessage
        query.piopChallenge query.piopMessage query.piopOpening query.pcsMessage

noncomputable def queryChallenge
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (query : VerifierQuery statement)
    (output : LogicalOutput statement) :
    Challenge (queryPrefix active query) := by
  cases query with
  | first => exact output.decsChallenge
  | second => exact output.piopChallenge
  | third => exact output.piopOpening
  | fourth => exact output.decsOpening

theorem query_prefix_is_verifier_turn
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (query : VerifierQuery statement) :
    Prefix.verifierTurn (queryPrefix active query) := by
  cases query <;> trivial

theorem query_prefix_statement
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (query : VerifierQuery statement) :
    (queryPrefix active query).statement = statement := by
  cases query <;> rfl

theorem first_query_output_probability_eq_next_semantic_good
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (oracle : CommittedOracle) :
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active (.first oracle))
                (queryChallenge active (.first oracle) output)) =
            true) =
      nextSemanticGoodProbability
        (queryPrefix active (.first oracle)) := by
  unfold nextSemanticGoodProbability
  change
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active (.first oracle))
                output.decsChallenge) =
            true) =
      uniformEventProbability
        (fun challenge =>
          semanticState
              (verifierExtension
                (queryPrefix active (.first oracle))
                challenge) =
            true)
  exact
    logical_output_decs_uniform statement
      (fun challenge =>
        semanticState
            (verifierExtension
              (queryPrefix active (.first oracle))
              challenge) =
          true)

theorem second_query_output_probability_eq_next_semantic_good
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (query : SecondQuery) :
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active (.second query))
                (queryChallenge active (.second query) output)) =
            true) =
      nextSemanticGoodProbability
        (queryPrefix active (.second query)) := by
  unfold nextSemanticGoodProbability
  change
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active (.second query))
                output.piopChallenge) =
            true) =
      uniformEventProbability
        (fun challenge =>
          semanticState
              (verifierExtension
                (queryPrefix active (.second query))
                challenge) =
            true)
  exact
    logical_output_piop_uniform statement
      (fun challenge =>
        semanticState
            (verifierExtension
              (queryPrefix active (.second query))
              challenge) =
          true)

theorem third_query_output_probability_eq_next_semantic_good
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (query : ThirdQuery statement) :
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active (.third query))
                (queryChallenge active (.third query) output)) =
            true) =
      nextSemanticGoodProbability
        (queryPrefix active (.third query)) := by
  unfold nextSemanticGoodProbability
  change
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active (.third query))
                output.piopOpening) =
            true) =
      uniformEventProbability
        (fun challenge =>
          semanticState
              (verifierExtension
                (queryPrefix active (.third query))
                challenge) =
            true)
  exact
    logical_output_piop_opening_uniform statement
      (fun challenge =>
        semanticState
            (verifierExtension
              (queryPrefix active (.third query))
              challenge) =
          true)

theorem fourth_query_output_probability_eq_next_semantic_good
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (query : FourthQuery statement) :
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active (.fourth query))
                (queryChallenge active (.fourth query) output)) =
            true) =
      nextSemanticGoodProbability
        (queryPrefix active (.fourth query)) := by
  unfold nextSemanticGoodProbability
  change
    uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active (.fourth query))
                output.decsOpening) =
            true) =
      uniformEventProbability
        (fun challenge =>
          semanticState
              (verifierExtension
                (queryPrefix active (.fourth query))
                challenge) =
            true)
  exact
    logical_output_decs_opening_uniform statement
      (fun challenge =>
        semanticState
            (verifierExtension
              (queryPrefix active (.fourth query))
              challenge) =
          true)

end

end HegemonCrypto.SmallWood.LogicalOracle
