import SmzaRp05AdaptiveRetainedAdviceFixedReadback
import SmzaRp05CurrentExecutedEarlierAdvice
import SmzaRp05CurrentDecsMatrixSampling
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentExecutedMatrixReadback

/-! The fixed-complement table is decoded with the current role decoders. In
particular, DECS matrix entries use the current row-major 5-by-140 map rather
than the historical `decsMatrixFieldEquiv`. The readback lemma below connects
that decoder to an actual retained branch answer on a nonzero physical fiber.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFixedEarlierAdvice

open scoped Classical
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables RoleOutput)
open SmzaChallengeStageTargets (Role)
open SmzaRp05ConditionedExecution
  (FixedTable fixedVectorAtNonce fixedCanonicalOpeningAt fixedFiberToActive
    otherRoleTransform ActiveMemory)
open SmzaRp05CurrentAdaptiveExecution (Context CmsState)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleDecodedAt)
open SmzaRp05CurrentDecsMatrixSampling (currentActualDecsMatrixOutput)
open SmzaRp05CurrentDecsMatrixSampling (currentRawDecsMatrixOutput)
open SmzaRp05CurrentExecutedMatrixReadback
  (currentDecsMatrixRawBlocks currentDecsMatrixVector)
open SmzaRp05CurrentGroupedOracleVector
  (finiteGroupedDatabaseOracle stored_group_vector_answers_every_counter)
open SmzaRp05CurrentFiniteGroupedProgram (Key included)
open SmzaRp05GroupedSuffix (CanonicalRolePrefix GroupCounter groupEncode)
open SmzaRp04RawRoleSampling
  (actualPiopMatrixOutput actualPiopOpeningOutput actualDecsSampleOutput)
open SmzaRp05ConditionedExecution (firstSome canonicalOpeningNonceOrder)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open SmzaChallengeStageTargets (StageQuery)
open SmzaChallengeStageTargets (parseStageQuery)
open SmzaRoleDomainConditioning (ActiveKey)
open HegemonCrypto.CmsCompressedOracle (Basis)
open SmzaRp05AdaptiveRetainedAdviceFixedReadback
  (nonzero_physical_branch_fixed_vector_readback grouped_representative_injective)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp04RawRoleSampling (selectedRawBlocks)
open V8Smz9RawCounterCompiler (digestCallCap)
open HegemonCrypto.FiniteOracleDatabase (Database)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

variable {Key Counter BaseWork Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

abbrev CurrentOutput := VectorOutput Counter

/-- A retained full grouped cell determines the literal source-oracle bytes
at every DECS-matrix counter, hence its current decoder result. `counterInput`
identity is the structural route proof supplied by the concrete canonical
prefix and value-preserving embedding; the stored vector is the actual finite
grouped database cell, not an advice-equality assumption. -/
theorem current_decs_matrix_decoder_from_stored_group_cell
    {Result : Type} (program : Program Result)
    (database : Database
      (SmzaRp05CurrentFiniteGroupedProgram.Key program)
      (VectorOutput GroupCounter))
    (fallback : RawDigest)
    (key : SmzaRp05CurrentFiniteGroupedProgram.Key program)
    (rolePrefix : CanonicalRolePrefix)
    (keyIdentity : included program key = Sum.inl rolePrefix)
    (vector : VectorOutput GroupCounter) (stored : database key = some vector)
    (model : RelationModel) (statement : SmzaRp05StatementNamespace.Statement)
    (target : RawDigest)
    (route : Fin (digestCallCap 700) ↪ GroupCounter)
    (counterAddress : ∀ index,
      counterInput decsCoefficientDomain target index.val =
        groupEncode (rolePrefix, route index)) :
    currentActualDecsMatrixOutput route vector =
      currentOracleDecodedAt model
        (finiteGroupedDatabaseOracle program database fallback)
        statement .decsMatrix target := by
  let oracle := finiteGroupedDatabaseOracle program database fallback
  have fixedBlocks : selectedRawBlocks route vector =
      currentDecsMatrixRawBlocks oracle target := by
    funext index
    change rawDigestBits.symm (vector (route index)) =
      oracle (counterInput decsCoefficientDomain target index.val)
    rw [counterAddress index]
    symm
    exact stored_group_vector_answers_every_counter program database fallback key
      rolePrefix keyIdentity vector stored (route index)
  have oracleBlocks : selectedRawBlocks
      (Equiv.refl (Fin (digestCallCap 700)))
      (currentDecsMatrixVector oracle target) = currentDecsMatrixRawBlocks oracle target := by
    funext index
    change rawDigestBits.symm
        (rawDigestBits (oracle
          (counterInput decsCoefficientDomain target index.val))) =
      oracle (counterInput decsCoefficientDomain target index.val)
    exact rawDigestBits.symm_apply_apply _
  unfold currentOracleDecodedAt
  change currentActualDecsMatrixOutput route vector =
    currentActualDecsMatrixOutput (Equiv.refl (Fin (digestCallCap 700)))
      (currentDecsMatrixVector oracle target)
  unfold currentActualDecsMatrixOutput currentRawDecsMatrixOutput
  rw [fixedBlocks, oracleBlocks]

/-- Decode one fixed full-vector cell using the current decoder family. -/
def currentFixedVectorDecodedAt
    (ctx : Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (statement : SmzaRp05StatementNamespace.Statement) (role : Role)
    (target : RawDigest) (nonce : Nat) : Option (RoleOutput ctx.model statement role) :=
  (fixedVectorAtNonce ctx blockCap fixed role target nonce).bind fun vector =>
    match role with
    | .decsMatrix => currentActualDecsMatrixOutput (ctx.routes statement).decsMatrix vector
    | .piopMatrix => actualPiopMatrixOutput (ctx.routes statement).piopMatrix vector
    | .piopOpening => actualPiopOpeningOutput (ctx.routes statement).piopOpening vector
    | .decsSample => actualDecsSampleOutput (ctx.routes statement).decsSample vector

/-- Current fixed advice preserves the literal first-success opening scan,
while every selected cell is decoded by the current matrix/sample functions. -/
def currentFixedDecodedAt
    (ctx : Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (statement : SmzaRp05StatementNamespace.Statement) (role : Role)
    (target : RawDigest) : Option (RoleOutput ctx.model statement role) :=
  match role with
  | .piopOpening => fixedCanonicalOpeningAt ctx blockCap fixed statement target
  | .decsMatrix => currentFixedVectorDecodedAt ctx blockCap fixed statement
      .decsMatrix target 0
  | .piopMatrix => currentFixedVectorDecodedAt ctx blockCap fixed statement
      .piopMatrix target 0
  | .decsSample => currentFixedVectorDecodedAt ctx blockCap fixed statement
      .decsSample target 0

def currentFixedAdvice
    (ctx : Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    AllEarlierTables ctx.model ctx.role :=
  fun statement earlier _ target =>
    currentFixedDecodedAt ctx blockCap fixed statement earlier target

/-- A retained actual answer fixes the complete vector selected by the
current fixed decoder on every nonzero branch. Parser-field uniqueness and
the grouped representative's injectivity rule out selecting a different
fixed key with the same challenge fields. -/
theorem current_fixed_vector_decoded_from_actual_branch
    (ctx : Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (keyInjection : Function.Injective ctx.keyBytes)
    (blockCap : Role → Nat) (dummy : SmzaRoleDomainConditioning.ActiveKey
      ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → CurrentOutput → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (basis : Basis
      (SmzaRoleDomainConditioning.ActiveKey ctx.role blockCap ctx.keyBytes)
      CurrentOutput CurrentOutput (ActiveMemory ctx))
    (nonzero : fixedFiberToActive ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap
        (SmzaRp05PhysicalAcceptedReplayLite.physicalRun encode decode program branch state))
      basis ≠ 0)
    (call : V8SmzaOracleParser.RawInput × CurrentOutput)
    (recorded : call ∈ answerLog decode program branch)
    (query : StageQuery)
    (parsed : parseStageQuery (ctx.keyBytes (encode call.1)) = some query)
    (different : query.role ≠ ctx.role)
    (bounded : query.counter < blockCap query.role)
    (base : query.counter = 0)
    (statement : SmzaRp05StatementNamespace.Statement) :
    currentFixedVectorDecodedAt ctx blockCap fixed statement
      query.role query.target query.nonce =
      (match query.role with
       | .decsMatrix => currentActualDecsMatrixOutput
           (ctx.routes statement).decsMatrix call.2
       | .piopMatrix => actualPiopMatrixOutput
           (ctx.routes statement).piopMatrix call.2
       | .piopOpening => actualPiopOpeningOutput
           (ctx.routes statement).piopOpening call.2
       | .decsSample => actualDecsSampleOutput
           (ctx.routes statement).decsSample call.2) := by
  unfold currentFixedVectorDecodedAt
  rw [nonzero_physical_branch_fixed_vector_readback ctx keyInjection blockCap dummy
    fixed encode decode program branch state basis nonzero call recorded query parsed
    different bounded base]
  simp only [Option.bind_some]

/-- `groupRepresentative` is injective for the concrete grouped physical
key space. Callers may use this directly for the fixed-context key embedding. -/
theorem current_grouped_representative_injective :
    Function.Injective SmzaRp05GroupedSuffix.groupRepresentative :=
  grouped_representative_injective

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFixedEarlierAdvice
