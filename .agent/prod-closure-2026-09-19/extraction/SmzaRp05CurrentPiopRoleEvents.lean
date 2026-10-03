import SmzaRp05CurrentCausalSourceLabel

/-! The PIOP bad events use the candidate decoded by the current 406-point
source decoder. Their fixed-label counts are the relation-generic PIOP
counts; their labels are not the historical 388-point source labels. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPiopRoleEvents

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsClassicalDatabase HegemonCrypto.FiniteOracleDatabase
open SmzaChallengeStageTargets
open SmzaRp05TracePrefixes SmzaRp05CurrentTracePrefixes406
open SmzaRp05CurrentRoleLabels SmzaRp05AcceptedRoleLabels
open SmzaRp05CurrentCausalSourceLabel SmzaRp05AdaptiveDynamicBad
open SmzaRp05FilteredDecoderInstability SmzaRp05FilteredReadback
open SmzaRp04RoleBadCells SmzaRp04McaRoleCells
open SmzaRp04RawRoleSampling SmzaRp04RawMcaSampling
open SmzaRp04ChronologicalAlgebra SmzaRp04CompleteRawRoleCells
open V8Smz9CoherentVectorMerkle V8Smz9PiopSoundness

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Trace" => SmzaRp05TracePrefixes.Trace

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  (inferInstance : LinearOrder V8SmzaOracleParser.RawInput).toDecidableEq

/-- Only the two PIOP roles use this event. Current MCA and q38 have their
own separately counted events. -/
inductive PiopRole where
  | matrix
  | opening

def PiopRole.toRole : PiopRole → Role
  | .matrix => .piopMatrix
  | .opening => .piopOpening

def currentPiopRoleEvent406 {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : PiopRole)
    (advice : AllEarlierTables model role.toRole) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte)) :
    Database Key (VectorOutput Counter) → Prop :=
  roleEvent keyBytes (vectorOutputBytes counter)
    (globalLeafStatement ns)
    (currentOuter ns keyBytes role.toRole outerFuel)
    (statementTraceDecoder (globalOnlineNext ns)
      (fun _ key => targetOfRaw role.toRole (keyBytes key))
      (fun statement _ trace => currentRoleLabelsFromBytes406 model ns
        role.toRole advice statement trace) innerFuel)
    (fun key => InRoleDomain role.toRole (keyBytes key))
    (fun _ label output => typedCompleteRawBad model routes role.toRole label output)
    authorized

/-- The two-pass dynamic-label bound applies to the exact current decoder
labels. No probability bound or event-inclusion premise is supplied. -/
theorem current_piop_role_instability406 {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : PiopRole)
    (advice : AllEarlierTables model role.toRole) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte)) (cap : Nat) :
    InstabilityBound
      (currentPiopRoleEvent406 model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized)
      cap ((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role.toRole) := by
  simpa only [currentPiopRoleEvent406, currentOuter] using
    (rp05_role_instability ns keyBytes counter
      (fun key => targetOfRaw role.toRole (keyBytes key))
      (fun _ trace => preambleFromTrace ns role.toRole trace)
      (fun _ key => targetOfRaw role.toRole (keyBytes key))
      (fun statement _ trace => currentRoleLabelsFromBytes406 model ns
        role.toRole advice statement trace)
      outerFuel innerFuel authorized cap
      (fun key => InRoleDomain role.toRole (keyBytes key))
      (fun _ label output => typedCompleteRawBad model routes role.toRole label output)
      (completeRoleLoss role.toRole) (complete_role_loss_nonnegative role.toRole)
      (fun _ label => typed_complete_raw_density model routes role.toRole label))

/-- An invalid current decoded candidate's actual bad matrix is charged to
the current matrix label on its causal subtrace. -/
theorem current_causal_matrix_failure_is_label_bad
    {Counter : Type*} (model : RelationModel)
    (ns : SmzaRp05LeafNamespace.Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads ns trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (coefficients : CurrentCoefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages coefficients matrix opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : currentSourceDecoder406 (causalOracle ns trace) messages.fpp
      coefficients = some source)
    (routes : Routes Counter (model.width statement))
    (vector : VectorOutput Counter)
    (sampled : actualPiopMatrixOutput routes.piopMatrix vector = some matrix)
    (invalid : ¬ PiopExtraction.FullySatisfied
      (model.recoveredCandidate statement source.data).system)
    (bad : matrix ∈ piopMatrixBadEvent (model.recoveredCandidate statement source.data)) :
    completeBad routes .piopMatrix
      (currentPrefixLabels406 model ns statement .piopMatrix (advice .piopMatrix)
        (causalTrace trace .piopMatrix)) vector := by
  simp only [completeBad, currentPrefixLabels406]
  rw [current_causal_matrix_label_readback model ns statement trace messages
    advice coefficients matrix opening earlier source recovered]
  exact ⟨_, rfl, matrix, sampled, invalid, bad⟩

/-- The current opening label retains the same candidate, prior matrix, and
serialized PIOP response as the accepted causal chain. -/
theorem current_causal_opening_failure_is_label_bad
    {Counter : Type*} (model : RelationModel)
    (ns : SmzaRp05LeafNamespace.Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads ns trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (coefficients : CurrentCoefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages coefficients matrix opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : currentSourceDecoder406 (causalOracle ns trace) messages.fpp
      coefficients = some source)
    (routes : Routes Counter (model.width statement))
    (vector : VectorOutput Counter)
    (sampled : actualPiopOpeningOutput routes.piopOpening vector = some opening)
    (bad : opening ∈ piopOpeningBadEvent (model.recoveredCandidate statement source.data)
      matrix (SmzaRp05TracePrefixes.piopResponse messages.piop)) :
    completeBad routes .piopOpening
      (currentPrefixLabels406 model ns statement .piopOpening (advice .piopOpening)
        (causalTrace trace .piopOpening)) vector := by
  simp only [completeBad, currentPrefixLabels406]
  rw [current_causal_opening_label_readback model ns statement trace messages
    advice coefficients matrix opening earlier source recovered]
  exact ⟨_, rfl, opening, sampled, bad⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentPiopRoleEvents
