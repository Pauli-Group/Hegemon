import SmzaRp04PrefixLabels
import SmzaRawStageGeometry
import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewFinalInput

/-! Source-ordered labels from the raw VC extraction trace.

Only strictly earlier challenge tables are available to a role's decoder.
In particular, the current selected output cannot be hidden in a common
"fixed advice" argument. Missing records and failed prior samplers stay absent.
The finite table-conditioning theorem must supply these earlier tables from
the other domains of the same oracle, and accepted readback must identify
the resulting labels with the accepted transcript.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04TracePrefixes

open Polynomial SmzaChallengeStageTargets SmzaRp04CompleteRawRoleCells
open SmzaRp04RoleBadCells SmzaRp04PublicContext SmzaRp04ChronologicalAlgebra
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction
open V8Smz9PiopSoundness V8Smz9McaRecovery V8Smz9EagerPrivacy
open V8Smz9AdaptiveFiniteAccounting
open V8Smz9HonestWholeViewFinalInput
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev Digest := V8SmzaOracleParser.RawDigest
abbrev Trace := V8Smz9CoherentMerkleGeometry.ExtractionTrace RawInput
abbrev Payload := V8SmzaOracleParser.Payload

def child (trace : Trace) (index : Nat) : Trace :=
  match trace with
  | .record _ children => children[index]?.getD .missing
  | _ => .missing

def payload (kind : V8SmzaOracleParser.Kind) (trace : Trace) : Option Payload := do
  let input ← match trace with
    | .record input _ => some input
    | _ => none
  let parsed ← V8SmzaOracleParser.rawPayload input
  if parsed.kind = kind then some parsed else none

/-- Follow the actual root-to-leaf bit path; never search for a same-index
leaf in an unrelated branch of a malicious tree. -/
def descend (coordinate : Position) : Nat → Trace → Trace
  | 0, trace => trace
  | depth + 1, trace =>
      descend coordinate depth (child trace (if coordinate.val.testBit depth then 1 else 0))

def fieldWordAt (bytes : RawInput) (word : Nat) : V8Smz9LogicalOracle.FieldWord :=
  ⟨V8SmzaOracleParser.wordAt bytes word % goldilocksModulus,
    Nat.mod_lt _ (by norm_num [goldilocksModulus])⟩

def rootOracle (root : Trace) : CommittedOracle :=
  fun coordinate row =>
    match payload .leaf (descend coordinate 23 (child root 0)) with
    | none => 0
    | some leaf =>
        if V8SmzaOracleParser.wordAt leaf.bytes 4 = coordinate.val ∧
            V8SmzaOracleParser.wordAt leaf.bytes 13 = 140 ∧
            V8SmzaOracleParser.wordAt leaf.bytes 154 = 5 then
          fieldWordAt leaf.bytes
            (if row.val < 140 then 14 + row.val else 155 + (row.val - 140))
        else 0

def sourceCoefficients (fpp : Payload) : Fin 5 → Fin 406 → Goldilocks :=
  fun row coefficient => toGoldilocks
    (V8SmzaOracleParser.wordAt fpp.bytes (8 + row.val * 406 + coefficient.val))

def sourceResponse (fpp : Payload) : ResponseStrategy :=
  fun _ row => (Polynomial.degreeLTEquiv Goldilocks 406).symm (sourceCoefficients fpp row)

def piopCoefficients (piop : Payload) : PiopCoefficients Goldilocks :=
  alternatingCoefficientEquiv fun index => toGoldilocks
    (V8SmzaOracleParser.wordAt piop.bytes (8 + index.val))

def piopResponse (piop : Payload) : ClaimedTranscript where
  nonlinear row := coefficientPolynomial ((piopCoefficients piop).1 row)
  nonlinearDegree row := by
    simpa only [Nat.reduceSub] using
      coefficient_polynomial_nat_degree_le ((piopCoefficients piop).1 row)
  linearHigh := (piopCoefficients piop).2

/-- The DECS hash contains heads followed by tails, NOT polynomial
coefficients. The verifier rotates the 368 heads behind the 38 tails and
interpolates at consecutive points. -/
def queryEvaluations (decs : Payload) (combination : SmzaQ38LvcsOpening.Combination)
    (index : Fin 406) : Goldilocks :=
  toGoldilocks (V8SmzaOracleParser.wordAt decs.bytes
    (8 + (combination.1.val * 2 + combination.2.val) * 406 + (index.val + 368) % 406))

def queryPolynomial (decs : Payload) (combination : SmzaQ38LvcsOpening.Combination) :
    Goldilocks[X] :=
  Lagrange.interpolate (Finset.univ : Finset (Fin 406))
    (fun index => toGoldilocks index.val) (queryEvaluations decs combination)

def queryCoefficients (decs : Payload) : Fixed406Coefficients :=
  fun combination coefficient => (queryPolynomial decs combination).coeff coefficient.val

theorem consecutive_point_injective :
    Function.Injective (fun index : Fin 406 => toGoldilocks index.val) := by
  intro left right same
  apply Fin.ext
  have leftBound : left.val < goldilocksModulus := left.isLt.trans (by decide)
  have rightBound : right.val < goldilocksModulus := right.isLt.trans (by decide)
  have values := congrArg fromGoldilocks same
  simpa only [fromGoldilocks_toGoldilocks, fieldValue,
    Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] using values

theorem query_polynomial_degree (decs : Payload)
    (combination : SmzaQ38LvcsOpening.Combination) :
    (queryPolynomial decs combination).natDegree ≤ 405 := by
  apply natDegree_le_of_degree_le
  have bounded := Lagrange.degree_interpolate_le (queryEvaluations decs combination)
    consecutive_point_injective.injOn (s := (Finset.univ : Finset (Fin 406)))
  simpa only [queryPolynomial, Finset.card_univ, Fintype.card_fin, Nat.reduceSub] using bounded

theorem query_coefficients_reconstruct_interpolation (decs : Payload)
    (combination : SmzaQ38LvcsOpening.Combination) :
    claimedPolynomials (queryCoefficients decs) combination = queryPolynomial decs combination := by
  exact coefficient_polynomial_of_coefficients _
    (Nat.lt_succ_of_le (query_polynomial_degree decs combination))

theorem query_polynomial_reads_rotated_heads_and_tails (decs : Payload)
    (combination : SmzaQ38LvcsOpening.Combination) (index : Fin 406) :
    (claimedPolynomials (queryCoefficients decs) combination).eval (toGoldilocks index.val) =
      queryEvaluations decs combination index := by
  rw [query_coefficients_reconstruct_interpolation]
  exact Lagrange.eval_interpolate_at_node (queryEvaluations decs combination)
    consecutive_point_injective.injOn (Finset.mem_univ index)

def roleOrder : Role → Nat
  | .decsMatrix => 0
  | .piopMatrix => 1
  | .piopOpening => 2
  | .decsSample => 3

def RoleOutput (publicWords : List Nat) : Role → Type
  | .decsMatrix => Coefficients
  | .piopMatrix => Matrix (batchingWidth publicWords)
  | .piopOpening => Opening
  | .decsSample => Query

/-- A role cannot inspect itself or a later challenge through this interface.
The opening lookup includes the canonical nonce search in the fixed table. -/
abbrev EarlierTables (publicWords : List Nat) (role : Role) :=
  (earlier : Role) → roleOrder earlier < roleOrder role →
    Digest → Option (RoleOutput publicWords earlier)

def emptyLabels (publicWords : List Nat) : PrefixLabels publicWords :=
  ⟨none, none, none, none, none⟩

def matrixLabel (publicWords : List Nat)
    (advice : EarlierTables publicWords .piopMatrix) (trace : Trace) :
    Option (PiopMatrixLabel publicWords) := do
  let fpp ← payload .fpp trace
  let coefficients ← advice .decsMatrix (by decide)
    (V8SmzaOracleParser.digestAt fpp.bytes 0)
  matrixPrefix publicWords (rootOracle (child trace 0)) (sourceResponse fpp) coefficients

def openingLabel (publicWords : List Nat)
    (advice : EarlierTables publicWords .piopOpening) (trace : Trace) :
    Option (PiopOpeningLabel publicWords) := do
  let piop ← payload .piop trace
  let fpp ← payload .fpp (child trace 0)
  let coefficients ← advice .decsMatrix (by decide)
    (V8SmzaOracleParser.digestAt fpp.bytes 0)
  let matrix ← advice .piopMatrix (by decide)
    (V8SmzaOracleParser.digestAt piop.bytes 0)
  openingPrefix publicWords (rootOracle (child (child trace 0) 0))
    (sourceResponse fpp) coefficients matrix (piopResponse piop)

def queryLabels (publicWords : List Nat)
    (advice : EarlierTables publicWords .decsSample) (trace : Trace) :
    Option (Option SmzaRp04McaRoleCells.SmallSupportLabel × Option DecsSampleLabel) := do
  let decs ← payload .decs trace
  let _ ← payload .piop (child trace 0)
  let fpp ← payload .fpp (child (child trace 0) 0)
  let coefficients ← advice .decsMatrix (by decide)
    (V8SmzaOracleParser.digestAt fpp.bytes 0)
  let opening ← advice .piopOpening (by decide)
    (V8SmzaOracleParser.digestAt decs.bytes 0)
  let oracle := rootOracle (child (child (child trace 0) 0) 0)
  let response := sourceResponse fpp
  let support := supportPrefix oracle response coefficients
  let lvcs := match recovered : recoverSource oracle response coefficients with
    | none => none
    | some source => some
        { rows := source.data
          rowsDegree := (recovered_source_degree_and_agreement oracle response coefficients
            source recovered).2.2.2
          points := baseOpeningPoints opening.1
          claimedCoefficients := queryCoefficients decs : DecsSampleLabel }
  pure (support, lvcs)

def roleLabels (publicWords : List Nat) (role : Role)
    (advice : EarlierTables publicWords role) (trace : Trace) : PrefixLabels publicWords :=
  match role with
  | .decsMatrix => { emptyLabels publicWords with decsMatrix := some (rootOracle trace) }
  | .piopMatrix => { emptyLabels publicWords with piopMatrix := matrixLabel publicWords advice trace }
  | .piopOpening => { emptyLabels publicWords with piopOpening := openingLabel publicWords advice trace }
  | .decsSample =>
      match queryLabels publicWords advice trace with
      | none => emptyLabels publicWords
      | some (support, lvcs) =>
          { emptyLabels publicWords with smallSupport := support, lvcs := lvcs }

theorem selected_role_not_in_earlier_tables (role : Role) :
    ¬ roleOrder role < roleOrder role := Nat.lt_irrefl _

end
end HegemonCrypto.SmallWood.SmzaRp04TracePrefixes
