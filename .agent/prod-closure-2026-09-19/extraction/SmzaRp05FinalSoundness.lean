import SmzaRp05TerminalExtraction

/-!
# Accepted RP05 extraction failure on the certified common execution

The witness below is semantic data, not a probability premise.  Its event
inclusion is derived by the accepted-failure classifier and targets the exact
fixed-advice union bounded on the single proof-erased physical execution.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05FinalSoundness

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open SmzaChallengeStageTargets SmzaRp04CompleteRawRoleCells
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05AcceptedRoleLabels SmzaRp05AcceptedExtraction
open SmzaRp05TerminalExtraction SmzaRp05TracePrefixes SmzaRp05PartialReadout
open SmzaRp05SuffixReadout
open SmzaRp05SecurityLedger
open SmzaRp05AdaptiveFilteredCollision
open V8Smz9CoherentVectorMerkle V8Smz9PiopSoundness
open SmzaQ38OracleExtraction SmzaQ38McaSourceBinding
open SmzaRp05CurrentRoleLabels SmzaRp04RawMcaSampling SmzaRp04RawRoleSampling

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Output := VectorOutput Counter
abbrev Statement := SmzaRp05StatementNamespace.Statement
abbrev Trace := SmzaRp05TracePrefixes.Trace
abbrev Work {Counter BaseWork : Type} :=
  SmzaRp05CurrentAdaptiveExecution.Work
    (Counter := Counter) (BaseWork := BaseWork)
abbrev CmsState {Key Counter BaseWork : Type} :=
  SmzaRp05CurrentAdaptiveExecution.CmsState
    (Key := Key) (Counter := Counter) (BaseWork := BaseWork)

/-- All semantic data asserting that one basis is an accepted transcript for
which extraction fails.  Every oracle/readback field is evaluated on the
basis database and every authorization field on the basis workspace. -/
structure AcceptedFailureWitness
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (workspace : Work (Counter := Counter) (BaseWork := BaseWork))
    (database : Database Key (Output (Counter := Counter)))
    (claims : List (Key × Output (Counter := Counter))) where
  statement : Statement
  trace : Trace
  messages : CausalPayloads ns trace
  advice : (role : Role) → EarlierTables model statement role
  strategy : Strategy model statement
  coefficients : Coefficients
  matrix : Matrix (model.width statement)
  opening : Opening
  query : Query
  keys : Role → Key
  vectors : Role → Output (Counter := Counter)
  fresh : statement.toBytes ∉ authorizedOf workspace.2
  earlier : EarlierReadback model statement advice messages coefficients matrix opening
  piopResponseRead : strategy.piopResponse coefficients matrix =
    piopResponse messages.piop
  claimedCoefficientsRead :
    (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
      queryCoefficients messages.decs
  claimsContainRoles : ∀ role, (keys role, vectors role) ∈ claims
  adviceAtStatement : ∀ role, allAdvice role statement = advice role
  roleQueries : ∀ role, ∃ parsed,
    parseStageQuery (keyBytes (keys role)) = some parsed ∧ parsed.role = role
  outerReadback : ∀ role,
    SmzaRp05FilteredDecoderInstability.rawTraceDecoder
      (SmzaRp05FilteredDecoderInstability.globalOnlineNext ns)
      (fun key => targetOfRaw role (keyBytes key))
      (fun _ decoded => SmzaRp05CurrentRoleLabels.preambleFromTrace ns role decoded)
      outerFuel
      (SmzaRp04StatementRecordFilter.nonleafFilter
        (SmzaRp05FilteredReadback.globalLeafStatement ns)
        (V8Smz9CoherentMerkleInstrument.rawRecords keyBytes
          (vectorOutputBytes counter) database))
      (keys role) = some statement.toBytes
  innerReadback : ∀ role,
    V8Smz9CoherentMerkleGeometry.extract
      (SmzaRp05FilteredDecoderInstability.globalOnlineNext ns)
      (SmzaRp04StatementRecordFilter.oneStatementFilter
        (SmzaRp05FilteredReadback.globalLeafStatement ns)
        statement.toBytes
        (V8Smz9CoherentMerkleInstrument.rawRecords keyBytes
          (vectorOutputBytes counter) database))
      innerFuel (targetOfRaw role (keyBytes (keys role))).1
        (targetOfRaw role (keyBytes (keys role))).2 = causalTrace trace role
  decsRead : actualDecsMatrixOutput (routes statement).decsMatrix
    (vectors .decsMatrix) = some coefficients
  matrixRead : actualPiopMatrixOutput (routes statement).piopMatrix
    (vectors .piopMatrix) = some matrix
  openingRead : actualPiopOpeningOutput (routes statement).piopOpening
    (vectors .piopOpening) = some opening
  queryRead : actualDecsSampleOutput (routes statement).decsSample
    (vectors .decsSample) = some query
  checks : AcceptedChecks refinement statement (causalOracle ns trace)
    (sourceResponse messages.fpp) strategy coefficients matrix opening query
  failed : ExtractionFailure refinement statement (causalOracle ns trace)
    (sourceResponse messages.fpp) coefficients

def acceptedFailureEvent
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (claims : List (Key × Output (Counter := Counter))) :
    AdaptiveEvent Key (Output (Counter := Counter))
      (Work (Counter := Counter) (BaseWork := BaseWork)) :=
  fun workspace database => Nonempty
    (AcceptedFailureWitness model refinement ns keyBytes counter routes
      allAdvice outerFuel innerFuel authorizedOf workspace database claims)

def claimFailureEvent
    (claims : List (Key × Output (Counter := Counter))) :
    AdaptiveEvent Key (Output (Counter := Counter))
      (Work (Counter := Counter) (BaseWork := BaseWork)) :=
  fun _ database => ¬ClaimsDatabaseEvent claims database

/-- Accepted semantic failure is pointwise contained in the exact fixed-advice
role union or in literal failure of the retained full-vector claims. -/
theorem accepted_failure_event_inclusion
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (claims : List (Key × Output (Counter := Counter)))
    (workspace : Work (Counter := Counter) (BaseWork := BaseWork))
    (database : Database Key (Output (Counter := Counter)))
    (accepted : acceptedFailureEvent model refinement ns keyBytes counter
      routes allAdvice outerFuel innerFuel authorizedOf claims workspace database) :
    CertifiedFor.anyContextRoleEvent
        (CertifiedFor.roleContexts model ns keyBytes counter routes allAdvice
          outerFuel innerFuel authorizedOf) workspace database ∨
      claimFailureEvent claims workspace database := by
  rcases accepted with ⟨witness⟩
  have classified := accepted_failure_implies_any_current_role_or_claim_failure
    model refinement ns keyBytes counter routes (authorizedOf workspace.2)
    witness.statement witness.fresh outerFuel innerFuel witness.keys witness.vectors
    claims witness.claimsContainRoles database witness.trace witness.messages
    witness.advice allAdvice witness.adviceAtStatement witness.strategy
    witness.coefficients witness.matrix witness.opening witness.query witness.earlier
    witness.piopResponseRead witness.claimedCoefficientsRead witness.roleQueries
    witness.outerReadback witness.innerReadback witness.decsRead witness.matrixRead
    witness.openingRead witness.queryRead witness.checks witness.failed
  rcases classified with current | claim
  · left
    rcases current with ⟨role, roleEvent⟩
    exact ⟨role, roleEvent⟩
  · exact Or.inr claim

/-- Diagonal mass monotonicity for the derived accepted-failure event.  This
is the semantic inclusion step; it introduces no probability assumption. -/
theorem accepted_failure_event_mass_le_role_or_claim
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (claims : List (Key × Output (Counter := Counter)))
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared
        (adaptiveProject
          (acceptedFailureEvent model refinement ns keyBytes counter routes
            allAdvice outerFuel innerFuel authorizedOf claims) cap state) ≤
      normSquared
          (adaptiveProject
            (CertifiedFor.anyContextRoleEvent
              (CertifiedFor.roleContexts model ns keyBytes counter routes
                allAdvice outerFuel innerFuel authorizedOf)) cap state) +
        normSquared (adaptiveProject (claimFailureEvent claims) cap state) := by
  unfold normSquared adaptiveProject
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro basis _
  by_cases bounded : size basis.database ≤ cap
  · by_cases accepted : acceptedFailureEvent model refinement ns keyBytes
        counter routes allAdvice outerFuel innerFuel authorizedOf claims
        basis.workspace basis.database
    · rcases accepted_failure_event_inclusion model refinement ns keyBytes
          counter routes allAdvice outerFuel innerFuel authorizedOf claims
          basis.workspace basis.database accepted with roleBad | claimBad
      · simp [bounded, accepted, roleBad, Complex.normSq_nonneg]
      · simp [bounded, accepted, claimBad, Complex.normSq_nonneg]
    · simp [bounded, accepted]
      exact add_nonneg (Complex.normSq_nonneg _) (Complex.normSq_nonneg _)
  · simp [bounded]

/-- If every retained claim is literally supported by a state, the adaptive
claim-failure projector is zero.  This is a support statement about the
actual terminal read branch, not a probabilistic premise. -/
theorem adaptive_claim_failure_eq_zero_of_known
    (claims : List (Key × Output (Counter := Counter)))
    (cap : Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (known : ∀ claim ∈ claims, KnownAt claim.1 claim.2 state) :
    adaptiveProject (claimFailureEvent claims) cap state = 0 := by
  funext basis
  unfold adaptiveProject claimFailureEvent
  by_cases selected : size basis.database ≤ cap ∧
      ¬ClaimsDatabaseEvent claims basis.database
  · have stateZero : state basis = 0 := by
      by_contra nonzero
      apply selected.2
      intro claim member
      by_contra missing
      have supported := congrFun (known claim member) basis
      unfold KnownAt coordinateEventProjection at supported
      rw [if_neg missing] at supported
      exact nonzero supported.symm
    simp [selected, stateZero]
  · simp [selected]

/-- The accepted-witness mass before the terminal decompression.  This is an
intermediate event, not the final accepted-transcript failure probability. -/
def acceptedPreDecompressionFailureMass
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (baseAuthorized : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork))
    (xReads roleReads : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key) : ℝ :=
  ∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
    ∑ roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads,
      normSquared
        (adaptiveProject
          (acceptedFailureEvent model refinement ns keyBytes counter routes
            allAdvice outerFuel innerFuel
              (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
                baseAuthorized workspace.2)
            (branchClaims roleReads roleAnswers)) cap
          (terminalMeasurementBranch xReads roleReads lookup
            xAnswers roleAnswers state))

/-- Only the pre-decompression witness event is bounded here.  The physical
terminal decompression changes database coordinates on which the current role
event depends, so this theorem must not be read as final accepted soundness. -/
theorem accepted_pre_decompression_failure_event_mass_below_130_bits
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (baseAuthorized : BaseWork → Finset (List Byte))
    {cap finish queries : Nat}
    (skeleton : PhysicalProgramSkeleton
      (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork)
      cap 0 finish queries)
    (certified : CertifiedFor
      (CertifiedFor.roleContexts model ns keyBytes counter routes
        allAdvice outerFuel innerFuel
        (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
          baseAuthorized workspace.2)) skeleton)
    (queriesLe : queries ≤ cap) (capLe : cap ≤ 3 * 2^64)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := PostVerifierTerminalWork Key Counter BaseWork) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers))
    (xReads roleReads compression : List Key)
    (roleReadNodup : roleReads.Nodup)
    (compressionNodup : compression.Nodup)
    (included : ∀ key ∈ roleReads, key ∈ compression)
    (readCountLe : roleReads.length ≤ cap)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xTotal : TotalOn xReads
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers)))
    (roleTotal : TotalOn roleReads
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers))) :
    acceptedPreDecompressionFailureMass model refinement ns keyBytes counter
      routes allAdvice outerFuel innerFuel cap baseAuthorized
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers))
      xReads roleReads lookup < 1 / (2 : ℝ)^130 := by
  let contexts := CertifiedFor.roleContexts model ns keyBytes counter
    routes allAdvice outerFuel innerFuel
      (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
        baseAuthorized workspace.2)
  let commonState := PhysicalProgramSkeleton.run skeleton
    (partialRandomOracleState
      (Output := Output (Counter := Counter)) ∅ registers)
  have terminalBound := certified_common_state_terminal_failure_below_130_bits
    contexts (fun role => by simp [contexts]) skeleton certified queriesLe capLe
    registers subnormalized xReads roleReads compression roleReadNodup
    compressionNodup included readCountLe lookup xTotal roleTotal
  have branchBound :
      acceptedPreDecompressionFailureMass model refinement ns keyBytes counter
          routes allAdvice outerFuel innerFuel cap baseAuthorized commonState
          xReads roleReads lookup ≤
        ∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
          ∑ roleAnswers : ReadAnswers (Input := Key)
              (Output (Counter := Counter)) roleReads,
            normSquared
              (adaptiveProject
                (CertifiedFor.anyContextRoleEvent contexts) cap
                (terminalMeasurementBranch xReads roleReads lookup
                  xAnswers roleAnswers commonState)) := by
    unfold acceptedPreDecompressionFailureMass
    apply Finset.sum_le_sum
    intro xAnswers _
    apply Finset.sum_le_sum
    intro roleAnswers _
    let branchState := terminalMeasurementBranch xReads roleReads lookup
      xAnswers roleAnswers commonState
    have known : ∀ claim ∈ branchClaims roleReads roleAnswers,
        KnownAt claim.1 claim.2 branchState := by
      intro claim member
      apply known_at_record_terminal_snapshot
      exact branch_claim_known_at roleReads roleReadNodup roleAnswers
        (retainedReadBranch xReads xAnswers commonState) claim member
    have claimZero := adaptive_claim_failure_eq_zero_of_known
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork)
      (branchClaims roleReads roleAnswers) cap branchState known
    have classified := accepted_failure_event_mass_le_role_or_claim
      model refinement ns keyBytes counter routes allAdvice outerFuel
      innerFuel cap
      (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
        baseAuthorized workspace.2)
      (branchClaims roleReads roleAnswers) branchState
    rw [claimZero] at classified
    simpa [normSquared, contexts, branchState] using classified
  have measuredRoleMass :
      (∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
        ∑ roleAnswers : ReadAnswers (Input := Key)
            (Output (Counter := Counter)) roleReads,
          normSquared
            (adaptiveProject
              (CertifiedFor.anyContextRoleEvent contexts) cap
              (terminalMeasurementBranch xReads roleReads lookup
                xAnswers roleAnswers commonState))) =
        normSquared
          (adaptiveProject (CertifiedFor.anyContextRoleEvent contexts)
            cap commonState) := by
    simpa [contexts] using
      (sum_terminal_measurement_branch_common_role_event_norm_squared
        model ns keyBytes counter routes allAdvice outerFuel innerFuel
        baseAuthorized cap xReads roleReads lookup commonState xTotal roleTotal)
  rw [measuredRoleMass] at branchBound
  have claimMassNonnegative :
      0 ≤
        ∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
          ∑ roleAnswers : ReadAnswers (Input := Key)
              (Output (Counter := Counter)) roleReads,
            normSquared
              (claimFailureProjection (branchClaims roleReads roleAnswers)
                (decompressList compression
                  (terminalMeasurementBranch xReads roleReads lookup
                    xAnswers roleAnswers commonState))) := by
    apply Finset.sum_nonneg
    intro xAnswers _
    apply Finset.sum_nonneg
    intro roleAnswers _
    unfold normSquared
    exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)
  exact lt_of_le_of_lt
    (branchBound.trans (le_add_of_nonneg_right claimMassNonnegative))
    (by simpa [contexts, commonState] using terminalBound)

/-- The semantic accepted-failure event on the actual *final*, partially
decompressed terminal state.  In particular the witness database argument is
the database basis of that final state, not the retained-read state. -/
def acceptedFinalTerminalFailureMass
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (baseAuthorized : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork))
    (xReads roleReads compression : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key) : ℝ :=
  ∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
    ∑ roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads,
      normSquared
        (adaptiveProject
          (acceptedFailureEvent model refinement ns keyBytes counter routes
            allAdvice outerFuel innerFuel
              (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
                baseAuthorized workspace.2)
            (branchClaims roleReads roleAnswers)) cap
          (decompressList compression
            (terminalMeasurementBranch xReads roleReads lookup
              xAnswers roleAnswers state)))

/-- A size-capped claim failure is bounded by the literal, uncapped terminal
claim-failure projector on exactly the same final state. -/
theorem adaptive_claim_failure_mass_le_terminal_claim_failure
    (claims : List (Key × Output (Counter := Counter)))
    (cap : Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (adaptiveProject (claimFailureEvent claims) cap state) ≤
      normSquared (claimFailureProjection claims state) := by
  unfold normSquared adaptiveProject claimFailureEvent claimFailureProjection
    databaseEventProjection
  apply Finset.sum_le_sum
  intro basis _
  by_cases within : size basis.database ≤ cap <;>
    by_cases failed : ¬ClaimsDatabaseEvent claims basis.database <;>
      simp [within, failed, Complex.normSq_nonneg]

/-- True final-state event inclusion.  The accepted witness is classified on
the decompressed database; its role alternative is therefore also evaluated
on that decompressed database.  The second term is precisely the existing
post-decompression claim-loss projector.  No transport of the first term to
the pre-decompression common state is asserted. -/
theorem accepted_final_terminal_failure_mass_le_role_and_claim
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (baseAuthorized : BaseWork → Finset (List Byte))
    (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork))
    (xReads roleReads compression : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key) :
    acceptedFinalTerminalFailureMass model refinement ns keyBytes counter
        routes allAdvice outerFuel innerFuel cap baseAuthorized state xReads
        roleReads compression lookup ≤
      (∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
        ∑ roleAnswers : ReadAnswers (Input := Key)
            (Output (Counter := Counter)) roleReads,
          normSquared
            (adaptiveProject
              (CertifiedFor.anyContextRoleEvent
                (CertifiedFor.roleContexts model ns keyBytes counter
                  routes allAdvice outerFuel innerFuel
                  (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
                    baseAuthorized workspace.2))) cap
              (decompressList compression
                (terminalMeasurementBranch xReads roleReads lookup
                  xAnswers roleAnswers state)))) +
      (∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
        ∑ roleAnswers : ReadAnswers (Input := Key)
            (Output (Counter := Counter)) roleReads,
          normSquared
            (claimFailureProjection (branchClaims roleReads roleAnswers)
              (decompressList compression
                (terminalMeasurementBranch xReads roleReads lookup
                  xAnswers roleAnswers state)))) := by
  unfold acceptedFinalTerminalFailureMass
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro xAnswers _
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro roleAnswers _
  let finalState := decompressList compression
    (terminalMeasurementBranch xReads roleReads lookup
      xAnswers roleAnswers state)
  exact (accepted_failure_event_mass_le_role_or_claim model refinement
    ns keyBytes counter routes allAdvice outerFuel innerFuel cap
    (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
      baseAuthorized workspace.2)
    (branchClaims roleReads roleAnswers) finalState).trans
      (add_le_add_right
        (adaptive_claim_failure_mass_le_terminal_claim_failure
          (BaseWork := SparseTerminalWorkspace Key Counter BaseWork)
          (branchClaims roleReads roleAnswers) cap finalState) _)

end
end HegemonCrypto.SmallWood.SmzaRp05FinalSoundness
