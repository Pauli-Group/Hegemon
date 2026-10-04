import SmzaRp05FilteredDecoderInstability
import SmzaRp05PublicWords
import SmzaRp05RelationModelCore
import SmzaRp04CompleteRawRoleDensityCore

/-!
# RP05 trace prefixes

This is the byte-level bridge from the strict-leaf-v2 record relation to the
typed four-role prefix labels.  Every raw payload in this file is obtained
through `globalNormalizedPayload`: current leaves lose their 1,104-byte
preamble before the historical leaf coordinates are read, historical v1
leaves are rejected, and the preserved nonleaf roles are normalized without
fixing one salt for the whole database.

The label *shapes* and their pointwise density lemmas are relation-neutral.
The old `SmzaRp04TracePrefixes.matrixLabel` is not: its `matrixPrefix` closes
over `SmzaRp04Components.program`.  Consequently this file takes the
recovered-candidate constructor as explicit relation data.  Instantiating it
with the generated RP05 818-constraint program is a later literal-generation
obligation; using the RP04 constructor is not an admissible default.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05TracePrefixes

open HegemonCrypto.CmsClassicalDatabase
open Polynomial SmzaChallengeStageTargets SmzaRp04CompleteRawRoleCells
open SmzaRp04RoleBadCells SmzaRp04McaRoleCells
open SmzaRp04PublicContext SmzaRp04ChronologicalAlgebra
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction
open V8Smz9PiopSoundness V8Smz9McaRecovery V8Smz9EagerPrivacy
open V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdmissibleRootProbability
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open SmzaRp05LeafNamespace SmzaRp05FilteredReadback
open SmzaRp05FilteredDecoderInstability SmzaRp05StatementNamespace
open SmzaRp04RawRoleSampling SmzaRp04RawMcaSampling
open V8Smz9CappedRawSampler V8Smz9CoherentVectorMerkle
open V8Smz9RawCounterCompiler V8Smz9RuntimeFieldLayout
open V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
noncomputable local instance traceOpeningNonempty : Nonempty Opening :=
  Fintype.card_pos_iff.mp full_admissible_opening_tuple_card_positive

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

/-- Current payload parsing.  In particular, this is not
`V8SmzaOracleParser.rawPayload`, which is v1-only at the leaf role. -/
def payload (ns : Namespace) (kind : V8SmzaOracleParser.Kind)
    (trace : Trace) : Option Payload := do
  let input ← match trace with
    | .record input _ => some input
    | _ => none
  let parsed ← globalNormalizedPayload ns input
  if parsed.kind = kind then some parsed else none

def descend (coordinate : Position) : Nat → Trace → Trace
  | 0, trace => trace
  | depth + 1, trace =>
      descend coordinate depth
        (child trace (if coordinate.val.testBit depth then 1 else 0))

def fieldWordAt (bytes : RawInput) (word : Nat) :
    V8Smz9LogicalOracle.FieldWord :=
  ⟨V8SmzaOracleParser.wordAt bytes word % goldilocksModulus,
    Nat.mod_lt _ (by norm_num [goldilocksModulus])⟩

/-- The old 23-level Merkle geometry and 140-by-5 row layout are unchanged,
but the terminal leaf is read only after global v2 normalization. -/
def rootOracle (ns : Namespace) (root : Trace) : CommittedOracle :=
  fun coordinate row =>
    match payload ns .leaf (descend coordinate 23 (child root 0)) with
    | none => 0
    | some leaf =>
        if V8SmzaOracleParser.wordAt leaf.bytes 4 = coordinate.val ∧
            V8SmzaOracleParser.wordAt leaf.bytes 13 = 140 ∧
            V8SmzaOracleParser.wordAt leaf.bytes 154 = 5 then
          fieldWordAt leaf.bytes
            (if row.val < 140 then 14 + row.val else 155 + (row.val - 140))
        else 0

/-- Convert a length-checked canonical preamble into the finite statement
carrier. -/
def statementOfBytes (bytes : List Byte) (length : bytes.length = preambleBytes) :
    Statement :=
  fun index => bytes.get ⟨index.val, by
    simp only [length]
    exact index.isLt⟩

def statementOfBytes? (bytes : List Byte) : Option Statement :=
  if length : bytes.length = preambleBytes then
    some (statementOfBytes bytes length)
  else none

theorem statement_of_bytes_roundtrip (bytes : List Byte)
    (length : bytes.length = preambleBytes) :
    (statementOfBytes bytes length).toBytes = bytes := by
  apply List.ext_getElem
  · simp [Statement.toBytes, length]
  · intro index leftBound rightBound
    simp [Statement.toBytes, statementOfBytes]

theorem public_words_of_current_preamble (bytes : List Byte)
    (length : bytes.length = preambleBytes) :
    publicWords (statementOfBytes bytes length) =
      (List.range 120).map fun word =>
        V8SmzaOracleParser.wordAt (bytes.drop 84) word := by
  simp [publicWords, statement_of_bytes_roundtrip bytes length]

/-- Map the global list-valued parser into the finite statement namespace.
Failure is retained explicitly rather than assigning malformed bytes a
statement. -/
def typedLeafStatement (ns : Namespace) (input : RawInput) :
    Option Statement := do
  let bytes ← globalLeafStatement ns input
  statementOfBytes? bytes

theorem typed_leaf_statement_of_global (ns : Namespace) (input : RawInput)
    (bytes : List Byte) (parsed : globalLeafStatement ns input = some bytes)
    (length : bytes.length = preambleBytes) :
    typedLeafStatement ns input = some (statementOfBytes bytes length) := by
  simp [typedLeafStatement, parsed, statementOfBytes?, length]

/-- Relation-neutral chronological labels.  Unlike the RP04 aliases, their
matrix dimension is the width supplied by the current relation model. -/
structure MatrixLabel (width : Nat) where
  candidate : Candidate width
  invalid : ¬ PiopExtraction.FullySatisfied candidate.system

structure MatrixPrefixKey (width : Nat) where
  candidate : Candidate width

structure OpeningLabel (width : Nat) where
  candidate : Candidate width
  matrix : Matrix width
  response : ClaimedTranscript

structure Prefix (width : Nat) where
  decsMatrix : Option CommittedOracle
  piopMatrix : Option (MatrixPrefixKey width)
  piopOpening : Option (OpeningLabel width)
  smallSupport : Option SmallSupportLabel
  lvcs : Option DecsSamplePrefixKey

/-- Data-only LVCS prefix; the recovered degree bound stays in the event. -/
def recoveredDecsSampleKey (source : RecoveredSource)
    (points : Fin 6 → Goldilocks) (claimed : Fixed406Coefficients) :
    DecsSamplePrefixKey :=
  { rows := source.data, points := points, claimedCoefficients := claimed }

theorem recovered_decs_sample_key_bad
    (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) (source : RecoveredSource)
    (recovered : recoverSource oracle response coefficients = some source)
    (points : Fin 6 → Goldilocks) (claimed : Fixed406Coefficients)
    (query : Query)
    (bad : query ∈ lvcsBadQueryEvent source.data points
      (claimedPolynomials claimed)) :
    decsSamplePrefixBad (recoveredDecsSampleKey source points claimed) query := by
  exact ⟨(recovered_source_degree_and_agreement oracle response coefficients
    source recovered).2.2.2, bad⟩

def sourceResponse : Payload → ResponseStrategy :=
  SmzaRp04TracePrefixes.sourceResponse

def piopResponse : Payload → ClaimedTranscript :=
  SmzaRp04TracePrefixes.piopResponse

def queryCoefficients : Payload → Fixed406Coefficients :=
  SmzaRp04TracePrefixes.queryCoefficients

/-- Source recovery uses the current decoded Merkle tree. -/
def recoveredSource (ns : Namespace) (root : Trace) (fpp : Payload)
    (coefficients : Coefficients) : Option RecoveredSource :=
  recoverSource (rootOracle ns root) (sourceResponse fpp) coefficients

def matrixPrefix (model : RelationModel) (ns : Namespace)
    (statement : Statement) (root : Trace) (fpp : Payload)
    (coefficients : Coefficients) : Option (MatrixPrefixKey (model.width statement)) :=
  (recoveredSource ns root fpp coefficients).map fun source =>
    ⟨model.recoveredCandidate statement source.data⟩

def openingPrefix (model : RelationModel) (ns : Namespace)
    (statement : Statement) (root : Trace) (fpp : Payload)
    (coefficients : Coefficients) (matrix : Matrix (model.width statement))
    (claimed : ClaimedTranscript) : Option (OpeningLabel (model.width statement)) :=
  (recoveredSource ns root fpp coefficients).map fun source =>
    ⟨model.recoveredCandidate statement source.data, matrix, claimed⟩

def roleOrder : Role → Nat := SmzaRp04TracePrefixes.roleOrder

def RoleOutput (model : RelationModel) (statement : Statement) : Role → Type
  | .decsMatrix => Coefficients
  | .piopMatrix => Matrix (model.width statement)
  | .piopOpening => Opening
  | .decsSample => Query

/-- Advice is indexed by the complete current statement.  Its order proof
prevents a selected table (and every later table) from entering its own
label. -/
abbrev EarlierTables (model : RelationModel) (statement : Statement) (role : Role) :=
  (earlier : Role) → roleOrder earlier < roleOrder role →
    Digest → Option (RoleOutput model statement earlier)

abbrev AllEarlierTables (model : RelationModel) (role : Role) :=
  (statement : Statement) → EarlierTables model statement role

theorem selected_role_not_in_earlier_tables (role : Role) :
    ¬ roleOrder role < roleOrder role := Nat.lt_irrefl _

def emptyLabels (width : Nat) : Prefix width :=
  ⟨none, none, none, none, none⟩

def matrixLabel (model : RelationModel) (ns : Namespace)
    (statement : Statement) (advice : EarlierTables model statement .piopMatrix)
    (trace : Trace) : Option (MatrixPrefixKey (model.width statement)) := do
  let fpp ← payload ns .fpp trace
  let coefficients ← advice .decsMatrix (by decide)
    (V8SmzaOracleParser.digestAt fpp.bytes 0)
  matrixPrefix model ns statement (child trace 0) fpp coefficients

def openingLabel (model : RelationModel) (ns : Namespace)
    (statement : Statement) (advice : EarlierTables model statement .piopOpening)
    (trace : Trace) : Option (OpeningLabel (model.width statement)) := do
  let piop ← payload ns .piop trace
  let fpp ← payload ns .fpp (child trace 0)
  let coefficients ← advice .decsMatrix (by decide)
    (V8SmzaOracleParser.digestAt fpp.bytes 0)
  let matrix ← advice .piopMatrix (by decide)
    (V8SmzaOracleParser.digestAt piop.bytes 0)
  openingPrefix model ns statement
    (child (child trace 0) 0) fpp coefficients matrix (piopResponse piop)

def queryLabels (ns : Namespace) (statement : Statement)
    (model : RelationModel) (advice : EarlierTables model statement .decsSample)
    (trace : Trace) :
    Option (Option SmallSupportLabel × Option DecsSamplePrefixKey) := do
  let decs ← payload ns .decs trace
  let _ ← payload ns .piop (child trace 0)
  let fpp ← payload ns .fpp (child (child trace 0) 0)
  let coefficients ← advice .decsMatrix (by decide)
    (V8SmzaOracleParser.digestAt fpp.bytes 0)
  let opening ← advice .piopOpening (by decide)
    (V8SmzaOracleParser.digestAt decs.bytes 0)
  let oracle := rootOracle ns (child (child (child trace 0) 0) 0)
  let response := sourceResponse fpp
  let support := supportPrefix oracle response coefficients
  let lvcs := (recoveredSource ns
      (child (child (child trace 0) 0) 0) fpp coefficients).map fun source =>
    recoveredDecsSampleKey source
      (baseOpeningPoints opening.1) (queryCoefficients decs)
  pure (support, lvcs)

def prefixLabels (model : RelationModel) (ns : Namespace)
    (statement : Statement) (role : Role)
    (advice : EarlierTables model statement role) (trace : Trace) :
    Prefix (model.width statement) :=
  match role with
  | .decsMatrix =>
      { emptyLabels (model.width statement) with
        decsMatrix := some (rootOracle ns trace) }
  | .piopMatrix =>
      { emptyLabels (model.width statement) with
        piopMatrix := matrixLabel model ns statement advice trace }
  | .piopOpening =>
      { emptyLabels (model.width statement) with
        piopOpening := openingLabel model ns statement advice trace }
  | .decsSample =>
      match queryLabels ns statement model advice trace with
      | none => emptyLabels (model.width statement)
      | some (support, lvcs) =>
          { emptyLabels (model.width statement) with
            smallSupport := support, lvcs := lvcs }

/-- Fixed label type for the dynamic/indexed database arguments.  The
statement is carried with its dependent typed prefix.  `unavailable` is the
fail-closed result for a malformed or wrong-length outer statement. -/
inductive TypedPrefixLabel (width : Statement → Nat) where
  | unavailable
  | decoded (statement : Statement) (labels : Prefix (width statement))

def roleLabels (model : RelationModel) (ns : Namespace)
    (statement : Statement) (role : Role)
    (advice : EarlierTables model statement role)
    (trace : Trace) : TypedPrefixLabel model.width :=
  .decoded statement (prefixLabels model ns statement role advice trace)

/-- Total postprocessing used after the outer statement selector. -/
def roleLabelsFromBytes (model : RelationModel) (ns : Namespace)
    (role : Role) (advice : AllEarlierTables model role)
    (statementBytes : List Byte) (trace : Trace) : TypedPrefixLabel model.width :=
  match statementOfBytes? statementBytes with
  | none => .unavailable
  | some statement => roleLabels model ns statement role (advice statement) trace

/-- Exact physical counter selectors, parameterized only by the current
relation width.  These are the same capped raw decoders used by RP04; no
abstract uniform sampler replaces them. -/
structure Routes (Counter : Type*) (width : Nat) where
  decsMatrix : Fin (digestCallCap (140 * 5)) ↪ Counter
  piopMatrix : Fin (digestCallCap (5 * width)) ↪ Counter
  piopOpening : Fin (digestCallCap V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings) ↪ Counter
  decsSample : Fin (digestCallCap q38CandidateCount) ↪ Counter

abbrev TypedRoutes (model : RelationModel) (Counter : Type*) :=
  (statement : Statement) → Routes Counter (model.width statement)

def matrixCellBadOld {width : Nat} (label : MatrixLabel width)
    (output : Matrix width) : Prop :=
  output ∈ piopMatrixBadEvent label.candidate

def matrixCellBad {width : Nat} (key : MatrixPrefixKey width)
    (output : Matrix width) : Prop :=
  ¬ PiopExtraction.FullySatisfied key.candidate.system ∧
    output ∈ piopMatrixBadEvent key.candidate

def openingCellBad {width : Nat} (label : OpeningLabel width)
    (output : Opening) : Prop :=
  output ∈ piopOpeningBadEvent label.candidate label.matrix label.response

theorem actual_matrix_cell_density_old
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {width : Nat} (select : Fin (digestCallCap (5 * width)) ↪ Counter)
    (label : MatrixLabel width) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ output, actualPiopMatrixOutput select vector = some output ∧
        matrixCellBadOld label output) ≤ roleLoss .piopMatrix := by
  change outputEventProbability (fun vector : VectorOutput Counter =>
    (fun raw : Fin (digestCallCap (5 * width)) → RawByteBlock =>
      ∃ output, rawPiopMatrixOutput width raw = some output ∧
        matrixCellBadOld label output) (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ output, rawPiopMatrixOutput width raw = some output ∧
      matrixCellBadOld label output)]
  let bad := piopMatrixBadEvent label.candidate
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap (5 * width)) (5 * width)
    (totalEquivDecoder (matrixFieldEquiv width))
    (total_equiv_decoder_fibers_equal (matrixFieldEquiv width)) bad
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability bad := by
      simpa only [rawPiopMatrixOutput, matrixCellBadOld, bad] using sampled
    _ = outputEventProbability (matrixCellBadOld label) := by
      change V8Smz9RobustQueryMismatch.FiniteEvents.probability bad =
        outputEventProbability (fun output : Matrix width =>
          output ∈ piopMatrixBadEvent label.candidate)
      exact (output_event_probability_membership
        (piopMatrixBadEvent label.candidate)).symm
    _ ≤ roleLoss .piopMatrix := by
      change outputEventProbability (fun output : Matrix width =>
        output ∈ piopMatrixBadEvent label.candidate) ≤ _
      rw [output_event_probability_membership]
      exact piop_matrix_bad_probability_le label.candidate label.invalid

theorem actual_matrix_cell_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {width : Nat} (select : Fin (digestCallCap (5 * width)) ↪ Counter)
    (key : MatrixPrefixKey width) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ output, actualPiopMatrixOutput select vector = some output ∧
        matrixCellBad key output) ≤ roleLoss .piopMatrix := by
  by_cases invalid : ¬ PiopExtraction.FullySatisfied key.candidate.system
  · let label : MatrixLabel width := ⟨key.candidate, invalid⟩
    have same : (fun vector : VectorOutput Counter =>
        ∃ output, actualPiopMatrixOutput select vector = some output ∧
          matrixCellBad key output) =
        (fun vector : VectorOutput Counter =>
          ∃ output, actualPiopMatrixOutput select vector = some output ∧
            matrixCellBadOld label output) := by
      funext vector
      simp [matrixCellBad, matrixCellBadOld, invalid, label]
    rw [same]
    exact actual_matrix_cell_density_old select label
  · have same : (fun vector : VectorOutput Counter =>
        ∃ output, actualPiopMatrixOutput select vector = some output ∧
          matrixCellBad key output) = (fun _ => False) := by
      funext vector
      simp [matrixCellBad, invalid]
    rw [same]
    have nonnegative : 0 ≤ roleLoss .piopMatrix := by
      unfold roleLoss
      positivity
    simpa [outputEventProbability] using nonnegative

theorem actual_opening_cell_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {width : Nat}
    (select : Fin (digestCallCap V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings) ↪ Counter)
    (label : OpeningLabel width) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ output, actualPiopOpeningOutput select vector = some output ∧
        openingCellBad label output) ≤ roleLoss .piopOpening := by
  change outputEventProbability (fun vector : VectorOutput Counter =>
    (fun raw : Fin (digestCallCap V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings) →
        RawByteBlock =>
      ∃ output, rawPiopOpeningOutput raw = some output ∧
        openingCellBad label output) (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ output, rawPiopOpeningOutput raw = some output ∧
      openingCellBad label output)]
  let bad := piopOpeningBadEvent label.candidate label.matrix label.response
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings)
    V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings openingDecoder
    opening_decoder_fibers_equal bad
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability bad := by
      simpa only [rawPiopOpeningOutput, openingCellBad, bad] using sampled
    _ = outputEventProbability (openingCellBad label) := by
      change V8Smz9RobustQueryMismatch.FiniteEvents.probability bad =
        outputEventProbability (fun output : Opening =>
          output ∈ piopOpeningBadEvent label.candidate label.matrix label.response)
      exact (output_event_probability_membership
        (piopOpeningBadEvent label.candidate label.matrix label.response)).symm
    _ ≤ roleLoss .piopOpening := by
      change outputEventProbability (fun output : Opening =>
        output ∈ piopOpeningBadEvent label.candidate label.matrix label.response) ≤ _
      rw [output_event_probability_membership]
      exact piop_opening_bad_probability_le
        label.candidate label.matrix label.response

def completeBad {Counter : Type*} {width : Nat}
    (routes : Routes Counter width) (role : Role) (label : Prefix width)
    (vector : VectorOutput Counter) : Prop :=
  match role with
  | .decsMatrix => optionalEvent
      (fun oracle vector => ∃ output,
        actualDecsMatrixOutput routes.decsMatrix vector = some output ∧
          matrixBad oracle output) label.decsMatrix vector
  | .piopMatrix => optionalEvent
      (fun cellLabel vector => ∃ output,
        actualPiopMatrixOutput routes.piopMatrix vector = some output ∧
          matrixCellBad cellLabel output) label.piopMatrix vector
  | .piopOpening => optionalEvent
      (fun cellLabel vector => ∃ output,
        actualPiopOpeningOutput routes.piopOpening vector = some output ∧
          openingCellBad cellLabel output) label.piopOpening vector
  | .decsSample =>
      optionalEvent
        (fun cellLabel vector => ∃ output,
          actualDecsSampleOutput routes.decsSample vector = some output ∧
            smallSupportBad cellLabel output) label.smallSupport vector ∨
      optionalEvent
        (fun cellLabel vector => ∃ output,
          actualDecsSampleOutput routes.decsSample vector = some output ∧
            decsSamplePrefixBad cellLabel output) label.lvcs vector

theorem complete_bad_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {width : Nat} (routes : Routes Counter width) (role : Role)
    (label : Prefix width) :
    outputEventProbability (completeBad routes role label) ≤
      completeRoleLoss role := by
  cases role with
  | decsMatrix =>
      exact optional_event_probability_le _ matrixLoss
        (complete_role_loss_nonnegative .decsMatrix)
        (actual_matrix_bad_and_success_le routes.decsMatrix) label.decsMatrix
  | piopMatrix =>
      exact optional_event_probability_le _ (roleLoss .piopMatrix)
        (complete_role_loss_nonnegative .piopMatrix)
        (actual_matrix_cell_density routes.piopMatrix) label.piopMatrix
  | piopOpening =>
      exact optional_event_probability_le _ (roleLoss .piopOpening)
        (complete_role_loss_nonnegative .piopOpening)
        (actual_opening_cell_density routes.piopOpening) label.piopOpening
  | decsSample =>
      have supportBound := optional_event_probability_le _ smallSupportLoss
        (by unfold smallSupportLoss; positivity)
        (actual_small_support_bad_and_success_le routes.decsSample)
        label.smallSupport
      have lvcsBound := optional_event_probability_le _ (roleLoss .decsSample)
        (by
          unfold roleLoss q38LvcsLoss q38SingleRootLoss
          exact mul_nonneg (by norm_num)
            (div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)))
        (actual_decs_sample_prefix_bad_and_success_le routes.decsSample) label.lvcs
      exact (output_event_union_le _ _).trans (add_le_add supportBound lvcsBound)

/-- Genuine fixed-type bridge to the physical bad event. -/
def typedCompleteRawBad {Counter : Type*} (model : RelationModel)
    (routes : TypedRoutes model Counter) (role : Role)
    (label : TypedPrefixLabel model.width) (vector : VectorOutput Counter) : Prop :=
  match label with
  | .unavailable => False
  | .decoded statement labels => completeBad (routes statement) role labels vector

/-- Pointwise density for the exact capped raw samplers at the model-supplied
width.  This is relation-generic, but does not classify RP05 accepted failure;
that still requires the generated current relation and its acceptance proof. -/
theorem typed_complete_raw_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (routes : TypedRoutes model Counter)
    (role : Role) (label : TypedPrefixLabel model.width) :
    outputEventProbability (typedCompleteRawBad model routes role label) ≤
      completeRoleLoss role := by
  cases label with
  | unavailable =>
      simpa [typedCompleteRawBad, outputEventProbability] using
        complete_role_loss_nonnegative role
  | decoded statement labels =>
      exact complete_bad_density (routes statement) role labels

end
end HegemonCrypto.SmallWood.SmzaRp05TracePrefixes
