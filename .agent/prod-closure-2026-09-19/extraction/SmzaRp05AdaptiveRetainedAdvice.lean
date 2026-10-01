import SmzaRp05OracleDerivedAdvice
import SmzaRp05DependentAdviceEvent

/-!
# Same-execution sparse advice

Only the earlier challenge addresses named by the recovered causal trace
are compared. Full advice-table equality is neither required nor inferred.
Successful raw reads, including the literal first-success opening scan,
construct the agreement consumed by the existing accepted-failure theorem.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdvice

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets SmzaRp05TracePrefixes
open SmzaRp05AcceptedRoleLabels SmzaRp05RetainedAdvice
open SmzaRp05TerminalExtraction SmzaRp05OracleDerivedAdvice
open SmzaRp05ConditionedExecution SmzaRp05CurrentRoleLabels
open SmzaRp05DependentAdviceEvent
open SmzaRp05LeafNamespace SmzaRp05FilteredReadback
open SmzaRp05FilteredDecoderInstability SmzaRp04AuthorizedLabelTransport
open SmzaRp04RawMcaSampling SmzaRp04RawRoleSampling
open SmzaRp04StatementRecordFilter V8SmzaOnlineParser
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentVectorMerkle
open V8Smz9CoherentMerkleInstrument
open V8Smz9HiddenLeafQrom V8Smz9PiopSoundness
open SmzaQ38McaSourceBinding SmzaRp05GroupedSuffix

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Trace" => SmzaRp05TracePrefixes.Trace

local instance : DecidableEq V8SmzaOracleParser.RawInput := currentRawInputDecidableEq

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

/-- Two successful readings of the same three challenge values agree at
every lookup used by the four causal prefixes. No other address is used. -/
theorem trace_read_agreement_of_earlier_readback
    (model : RelationModel) (ns : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads ns trace)
    (left right : (role : Role) → EarlierTables model statement role)
    (coefficients : Coefficients) (matrix : Matrix (model.width statement))
    (opening : Opening)
    (leftReads : EarlierReadback model statement left messages coefficients matrix opening)
    (rightReads : EarlierReadback model statement right messages coefficients matrix opening)
    (role : Role) :
    TraceReadAgreement model ns statement role (left role) (right role)
      (causalTrace trace role) := by
  cases role with
  | decsMatrix => trivial
  | piopMatrix =>
      intro fpp parsed
      have same : fpp = messages.fpp := Option.some.inj
        (parsed.symm.trans messages.fppRead)
      subst fpp
      exact leftReads.matrixCoefficients.trans rightReads.matrixCoefficients.symm
  | piopOpening =>
      constructor
      · intro fpp parsed
        have same : fpp = messages.fpp := Option.some.inj
          (parsed.symm.trans messages.fppRead)
        subst fpp
        exact leftReads.openingCoefficients.trans rightReads.openingCoefficients.symm
      · intro piop parsed
        have same : piop = messages.piop := Option.some.inj
          (parsed.symm.trans messages.piopRead)
        subst piop
        exact leftReads.openingMatrix.trans rightReads.openingMatrix.symm
  | decsSample =>
      constructor
      · intro fpp parsed
        have same : fpp = messages.fpp := Option.some.inj
          (parsed.symm.trans messages.fppRead)
        subst fpp
        exact leftReads.sampleCoefficients.trans rightReads.sampleCoefficients.symm
      · intro decs parsed
        have same : decs = messages.decs := Option.some.inj
          (parsed.symm.trans messages.decsRead)
        subst decs
        exact leftReads.sampleOpening.trans rightReads.sampleOpening.symm

/-- Three actual successful sparse decodings construct all five readback
fields; the duplication reflects reuse of the same answer by later roles. -/
theorem retained_decodings_supply_earlier_readback
    (model : RelationModel) (ns : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads ns trace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (routes : TypedRoutes model Counter)
    (claims : Database Key (VectorOutput Counter))
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (coefficients : Coefficients) (matrix : Matrix (model.width statement))
    (opening : Opening)
    (decsRead : retainedDecodedAt model keyBytes routes claims lookup statement .decsMatrix
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) = some coefficients)
    (matrixRead : retainedDecodedAt model keyBytes routes claims lookup statement .piopMatrix
      (V8SmzaOracleParser.digestAt messages.piop.bytes 0) = some matrix)
    (openingRead : retainedDecodedAt model keyBytes routes claims lookup statement .piopOpening
      (V8SmzaOracleParser.digestAt messages.decs.bytes 0) = some opening) :
    EarlierReadback model statement
      (retainedAdviceOfClaims model keyBytes routes claims lookup statement)
      messages coefficients matrix opening :=
  ⟨decsRead, decsRead, matrixRead, decsRead, openingRead⟩

/-- The sparse canonical opening scan needs only failed attempts before the
successful nonce and that successful read. Later nonces may remain absent. -/
theorem retained_opening_of_actual_prefix
    (model : RelationModel) (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (routes : TypedRoutes model Counter)
    (claims : Database Key (VectorOutput Counter))
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (statement : Statement) (target : V8SmzaOracleParser.RawDigest)
    (before after : List (Fin 16)) (selected : Fin 16)
    (opening : Opening)
    (order : canonicalOpeningNonceOrder = before ++ selected :: after)
    (prior : ∀ nonce ∈ before,
      (retainedVectorAtNonce keyBytes claims lookup .piopOpening target nonce).bind
        (actualPiopOpeningOutput (routes statement).piopOpening) = none)
    (success :
      (retainedVectorAtNonce keyBytes claims lookup .piopOpening target selected).bind
        (actualPiopOpeningOutput (routes statement).piopOpening) = some opening) :
    retainedDecodedAt model keyBytes routes claims lookup statement .piopOpening target =
      some opening := by
  simp only [retainedDecodedAt]
  rw [order]
  exact firstSome_append_selected _ before after selected opening prior success

/-- A successful fixed-table selection and a literal retained read of that
selected base key determine the same vector. Parser aliases are handled by
requiring the actual selected key's receipt, not by asserting injectivity. -/
theorem retained_vector_eq_fixed_of_actual_receipt
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (claims : Database Key (VectorOutput Counter))
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (role : Role) (target : V8SmzaOracleParser.RawDigest) (nonce : LookupNonce)
    (vector : VectorOutput Counter)
    (fixedRead : fixedVectorAtNonce ctx blockCap fixed role target nonce.val = some vector)
    (receipt : ∀ key : SmzaRoleDomainConditioning.FixedOtherKey
        ctx.role blockCap ctx.keyBytes, ∀ parsed,
      parseStageQuery (ctx.keyBytes key.val) = some parsed →
      parsed.role = role → parsed.target = target → parsed.nonce = nonce.val →
      parsed.counter = 0 →
      lookup role target nonce = some key.val ∧ claims key.val = some (fixed key)) :
    retainedVectorAtNonce ctx.keyBytes claims lookup role target nonce = some vector := by
  obtain ⟨key, parsed, parsedRead, sameRole, sameTarget, sameNonce, base, value⟩ :=
    fixed_vector_at_nonce_has_base_key ctx blockCap fixed role target nonce.val vector fixedRead
  obtain ⟨found, recorded⟩ := receipt key parsed parsedRead sameRole sameTarget sameNonce base
  exact retained_vector_at_nonce_of_lookup ctx.keyBytes claims lookup role target nonce
    key.val parsed vector found parsedRead sameRole sameTarget sameNonce (by simpa [value] using recorded)

/-- Sparse terminal inclusion requires trace-local read agreement, not the
false equation equating a partial retained map with an entire advice table. -/
theorem sparse_role_event_implies_current_of_trace_agreement
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List HegemonCrypto.CanonicalBytes.Byte))
    (workspace : SparseTerminalWorkspace Key Counter BaseWork) (role : Role)
    (allAdvice : AllEarlierTables model role)
    (database : Database Key (VectorOutput Counter))
    (sameDatabase : database = mergedSparse workspace)
    (agreement : TraceReadAgreement model ns (statementOf workspace.2) role
      (retainedAdviceOfClaims model keyBytes routes workspace.1.roleClaims
        workspace.1.roleLookup (statementOf workspace.2) role)
      (allAdvice (statementOf workspace.2)) (causalTrace (traceOf workspace.2) role))
    (selected : sparseWorkspaceRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role workspace) :
    currentRoleEvent model ns keyBytes counter routes role allAdvice
      outerFuel innerFuel (authorizedOf workspace.2) database := by
  rcases selected with ⟨vector, recorded, fresh, inRole, outerReadback, innerReadback, bad⟩
  refine ⟨roleKeyOf workspace.2 role, vector, ?_, inRole, ?_⟩
  · rw [sameDatabase]
    exact merged_sparse_role_claim workspace _ vector recorded
  · unfold completeFilteredLabel currentOuter
    rw [sameDatabase]
    dsimp only
    rw [outerReadback]
    simp only [fresh, if_false, AuthorizedBad]
    change typedCompleteRawBad model routes role
      (roleLabelsFromBytes model ns role allAdvice (statementOf workspace.2).toBytes
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) (statementOf workspace.2).toBytes
            (rawRecords keyBytes (vectorOutputBytes counter) (mergedSparse workspace))) innerFuel
          (targetOfRaw role (keyBytes (roleKeyOf workspace.2 role))).1
          (targetOfRaw role (keyBytes (roleKeyOf workspace.2 role))).2)) vector
    rw [innerReadback, role_labels_from_statement_bytes]
    have labels := prefix_labels_eq_of_retained_reads model ns (statementOf workspace.2)
      role _ _ (causalTrace (traceOf workspace.2) role) agreement
    change typedCompleteRawBad model routes role
      (.decoded (statementOf workspace.2)
        (prefixLabels model ns (statementOf workspace.2) role
          (allAdvice (statementOf workspace.2)) (causalTrace (traceOf workspace.2) role))) vector
    rw [← labels]
    exact bad

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdvice
