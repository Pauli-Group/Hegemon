import SmzaRp05PartialReadout
import SmzaRp05SuffixReadout
import SmzaRp05CurrentAdaptiveExecution
import SmzaRp05ConditionedExecution
import SmzaRp05AcceptedRoleLabels
import SmzaRp05RetainedAdvice
import SmzaRp05VectorRetention
import SmzaRp05SecurityLedger

/-!
# RP05 terminal extraction on one common compressed state

This module defines the common sparse terminal workspace, the literal
workspace-only role events, their deterministic accepted-failure inclusion,
and the common-state union bound.  It also exposes the actual adaptive-program
bound for each selected-role right state.

The conditioned source now proves the whole certified physical interaction,
including marks, writes, copies, retained writes, and charged queries. This
module still needs the accepted-extraction dependency and its selected-role
connection before a terminal accepted-failure bound is established.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05TerminalExtraction

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsLifting
open V8Smz9CoherentVectorMerkle
open SmzaChallengeStageTargets
open SmzaRp04CompleteRawRoleCells
open SmzaRp05CurrentRoleLabels
open SmzaRp05PartialReadout
open SmzaRp05VectorRetention
open SmzaRp05SecurityLedger
open SmzaRp04FourRoleLedger
open SmzaRp05SuffixReadout
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05AdaptiveKernelInstantiation
open SmzaRp05ConditionedExecution
open SmzaRp05RetainedAdvice
open SmzaRp05AdaptiveFilteredCollision
open SmzaRp05AcceptedRoleLabels SmzaRp05AcceptedExtraction
open SmzaRp05LeafNamespace SmzaRp05FilteredReadback
open SmzaRp05FilteredDecoderInstability SmzaRp05TracePrefixes
open SmzaRp04AuthorizedLabelTransport
open SmzaRp04RawMcaSampling SmzaRp04RawRoleSampling
open SmzaRp04StatementRecordFilter
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open V8Smz9McaRecovery V8Smz9McaDecoder V8Smz9PiopSoundness
open SmzaQ38OracleExtraction SmzaQ38McaSourceBinding
open V8SmzaOnlineParser

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  currentRawInputDecidableEq
set_option linter.unusedSectionVars false

variable {Key Counter Phase Workspace BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]
variable [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Output := VectorOutput Counter
abbrev Statement := SmzaRp05StatementNamespace.Statement
abbrev Trace := SmzaRp05TracePrefixes.Trace


/-! ## Sparse common terminal event -/

/-- The common terminal classical workspace contains only the measured raw/X
records and the full-vector cells actually read by the extraction suffix.
Absent keys stay absent. -/
abbrev LookupNonce := Fin 16

/-- The finite retained data copied out of the post-verifier database.  The
nonce register is the source verifier's literal `0,...,15` opening scan; using
`Nat` here would make the alleged classical workspace infinite and therefore
would not define a `CmsCompressedOracle.State`. -/
structure SparseTerminalRegisters (Key Counter : Type*) where
  measuredX : Database Key (VectorOutput Counter)
  roleClaims : Database Key (VectorOutput Counter)
  roleLookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key
deriving DecidableEq

noncomputable instance sparseTerminalRegistersFintype
    (Key Counter : Type*) [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter] :
    Fintype (SparseTerminalRegisters Key Counter) := by
  letI : Fintype (Database Key (VectorOutput Counter)) := inferInstance
  letI : Fintype
      (Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key) := inferInstance
  exact
  Fintype.ofEquiv
    (Database Key (VectorOutput Counter) ×
      Database Key (VectorOutput Counter) ×
      (Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key))
    { toFun := fun x => ⟨x.1, x.2.1, x.2.2⟩
      invFun := fun x => (x.measuredX, x.roleClaims, x.roleLookup)
      left_inv := by intro x; rcases x with ⟨a, b, c⟩; rfl
      right_inv := by intro x; cases x; rfl }

/-- A real terminal state coordinate: the finite recorded registers together
with the unchanged finite trace/authorization workspace carried by the
verifier. -/
abbrev SparseTerminalWorkspace (Key Counter BaseWork : Type*) :=
  SparseTerminalRegisters Key Counter × BaseWork

/-- The finite base coordinate used by the concrete post-verifier
instrument. `authorization` is a finite register whose interpretation as a
set is supplied by `authorizedValue`; `accepted` retains the trace and
accepted-verifier data.  In particular no unbounded `Finset (List Byte)` is
placed directly in the quantum basis. -/
structure TraceAuthWorkspace (Authorization Accepted : Type*) where
  authorization : Authorization
  accepted : Accepted
deriving DecidableEq, Fintype

abbrev TerminalMemory (Key Counter Authorization Accepted : Type*) :=
  SparseTerminalWorkspace Key Counter
    (TraceAuthWorkspace Authorization Accepted)

/-- Retained role reads override X only at the explicitly read key.  No
unqueried oracle coordinate is materialized. -/
def mergedSparse
    (workspace : SparseTerminalWorkspace Key Counter BaseWork) :
    Database Key (Output (Counter := Counter)) :=
  fun key => match workspace.1.roleClaims key with
    | some vector => some vector
    | none => workspace.1.measuredX key

theorem merged_sparse_role_claim
    (workspace : SparseTerminalWorkspace Key Counter BaseWork)
    (key : Key) (vector : Output (Counter := Counter))
    (read : workspace.1.roleClaims key = some vector) :
    mergedSparse workspace key = some vector := by
  simp [mergedSparse, read]

/-! ## Literal terminal measurement and copy instrument -/

/-- Keep exactly the scheduled coordinates of a database.  This is a sparse
copy; values outside the supplied finite schedule are not materialized. -/
def restrictDatabaseTo (keys : Finset Key)
    (database : Database Key (Output (Counter := Counter))) :
    Database Key (Output (Counter := Counter)) :=
  fun key => if key ∈ keys then database key else none

/-- The finite, ex-ante description of the two terminal read schedules and
the deterministic retained-role lookup. -/
structure TerminalReadSpec (Key : Type*) where
  xKeys : Finset Key
  roleKeys : Finset Key
  roleLookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key
deriving DecidableEq

noncomputable instance terminalReadSpecFintype
    (Key : Type*) [Fintype Key] : Fintype (TerminalReadSpec Key) :=
  Fintype.ofEquiv
    (Finset Key × Finset Key ×
      (Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key))
    { toFun := fun x => ⟨x.1, x.2.1, x.2.2⟩
      invFun := fun x => (x.xKeys, x.roleKeys, x.roleLookup)
      left_inv := by intro x; rcases x with ⟨a, b, c⟩; rfl
      right_inv := by intro x; cases x; rfl }

def emptyTerminalRegisters (Key Counter : Type*) :
    SparseTerminalRegisters Key Counter where
  measuredX := empty
  roleClaims := empty
  roleLookup := fun _ _ _ => none

/-- Exact terminal registers copied from one post-verifier database basis.
Only the two scheduled finite key sets are copied. -/
def recordedTerminalRegisters
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter))) :
    SparseTerminalRegisters Key Counter where
  measuredX := restrictDatabaseTo spec.xKeys database
  roleClaims := restrictDatabaseTo spec.roleKeys database
  roleLookup := spec.roleLookup

/-- Reversible blank/snapshot exchange.  This is the literal private copy
gate: the controlling database is retained and the prior blank register is
recoverable. -/
def terminalRegisterCopyEquiv
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter))) :
    SparseTerminalRegisters Key Counter ≃ SparseTerminalRegisters Key Counter :=
  Equiv.swap (emptyTerminalRegisters Key Counter)
    (recordedTerminalRegisters spec database)

def terminalMemoryCopyEquiv
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter))) :
    SparseTerminalWorkspace Key Counter BaseWork ≃
      SparseTerminalWorkspace Key Counter BaseWork :=
  Equiv.prodCongr (terminalRegisterCopyEquiv spec database) (Equiv.refl BaseWork)

/-- Exact workspace shape of `CurrentAdaptiveExecution` after its corrected
physical program: the retained-old slot is outermost and the terminal memory
is its `BaseWork`. -/
abbrev PostVerifierTerminalWork (Key Counter BaseWork : Type) :=
  SmzaRp05CurrentAdaptiveExecution.Work
    (Counter := Counter)
    (BaseWork := SparseTerminalWorkspace Key Counter BaseWork)

def postVerifierTerminalCopyEquiv
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter))) :
    PostVerifierTerminalWork Key Counter BaseWork ≃
      PostVerifierTerminalWork Key Counter BaseWork :=
  Equiv.prodCongr (Equiv.refl (Option (Output (Counter := Counter))))
    (terminalMemoryCopyEquiv (Counter := Counter) (BaseWork := BaseWork)
      spec database)

@[simp]
theorem terminal_memory_copy_preserves_base
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter)))
    (workspace : SparseTerminalWorkspace Key Counter BaseWork) :
    (terminalMemoryCopyEquiv spec database workspace).2 = workspace.2 := by
  rfl

@[simp]
theorem terminal_memory_copy_empty
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter)))
    (base : BaseWork) :
    terminalMemoryCopyEquiv spec database
        (emptyTerminalRegisters Key Counter, base) =
      (recordedTerminalRegisters spec database, base) := by
  simp [terminalMemoryCopyEquiv, terminalRegisterCopyEquiv]

/-- The private copy following the physical reads.  It acts on the exact
post-verifier state type: the database and phase are unchanged and the finite
terminal registers occupy `BaseWork`; the outer retained-old slot is preserved
as the first workspace factor. -/
def recordTerminalSnapshot
    (spec : TerminalReadSpec Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork) :=
  databaseControlledWorkspaceUpdate
    (postVerifierTerminalCopyEquiv (Counter := Counter) (BaseWork := BaseWork) spec) state

theorem record_terminal_snapshot_norm_squared
    (spec : TerminalReadSpec Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    normSquared (recordTerminalSnapshot spec state) = normSquared state := by
  exact database_controlled_workspace_update_norm_squared _ state

def withTerminalRegisters
    (registers : SparseTerminalRegisters Key Counter)
    (basis : Basis Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    Basis Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork) :=
  { basis with workspace := (basis.workspace.1, (registers, basis.workspace.2.2)) }

/-- At the populated terminal basis, the copy amplitude is definitionally the
amplitude of the corresponding blank post-verifier basis.  This is the exact
bridge from the certified physical execution to the recorded terminal state. -/
theorem record_terminal_snapshot_apply_recorded
    (spec : TerminalReadSpec Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork))
    (basis : Basis Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    recordTerminalSnapshot spec state
        (withTerminalRegisters
          (recordedTerminalRegisters (Counter := Counter) spec basis.database) basis) =
      state
        (withTerminalRegisters (emptyTerminalRegisters Key Counter) basis) := by
  simp [recordTerminalSnapshot, databaseControlledWorkspaceUpdate,
    withTerminalRegisters, postVerifierTerminalCopyEquiv,
    terminalMemoryCopyEquiv, terminalRegisterCopyEquiv]

/-- Authorization and accepted-trace data are the unchanged second factor of
the copy.  Thus every base-only event, in particular the verifier's accepted
and authorization predicates, commutes with the instrument exactly. -/
theorem base_event_record_terminal_snapshot
    (spec : TerminalReadSpec Key) (enabled : BaseWork → Prop)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    workspaceOnlyProjection (fun workspace => enabled workspace.2.2)
        (recordTerminalSnapshot spec state) =
      recordTerminalSnapshot spec
        (workspaceOnlyProjection (fun workspace => enabled workspace.2.2) state) := by
  funext target
  simp only [workspaceOnlyProjection, workspaceEventProjection,
    recordTerminalSnapshot, databaseControlledWorkspaceUpdate]
  rfl

/-- One literal two-stage terminal branch: first measure the scheduled X
coordinates, then the scheduled role coordinates, and finally copy the two
sparse views and the finite lookup into private workspace. -/
def terminalMeasurementBranch
    (xReads roleReads : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads)
    (roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork) :=
  let spec : TerminalReadSpec Key :=
    ⟨xReads.toFinset, roleReads.toFinset, lookup⟩
  recordTerminalSnapshot spec
    (retainedReadBranch roleReads roleAnswers
      (retainedReadBranch xReads xAnswers state))

theorem terminal_measurement_branch_norm_squared
    (xReads roleReads : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads)
    (roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    normSquared
        (terminalMeasurementBranch xReads roleReads lookup xAnswers roleAnswers state) =
      normSquared
        (retainedReadBranch roleReads roleAnswers
          (retainedReadBranch xReads xAnswers state)) := by
  exact record_terminal_snapshot_norm_squared _ _

/-- A prior read branch only removes basis amplitudes, so totality of every
later scheduled coordinate is retained. -/
theorem total_on_retained_read_branch
    (earlier : List Key)
    (answers : ReadAnswers (Input := Key) (Output (Counter := Counter)) earlier)
    (later : List Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork))
    (total : TotalOn later state) :
    TotalOn later (retainedReadBranch earlier answers state) := by
  intro key member
  induction earlier generalizing state with
  | nil => exact total key member
  | cons input remaining inductionHypothesis =>
      rcases answers with ⟨answer, answers⟩
      apply inductionHypothesis answers
      intro selected selectedMem
      exact total_at_coordinate_event_projection selected input answer state
        (total selected selectedMem)

/-- All X/read outcomes are retained with their original weights.  The copy
is norm preserving on every branch, so there is no postselection denominator
and no branch-probability premise. -/
theorem sum_terminal_measurement_branch_norm_squared
    (xReads roleReads : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork))
    (xTotal : TotalOn xReads state) (roleTotal : TotalOn roleReads state) :
    (∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
      ∑ roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads,
        normSquared
          (terminalMeasurementBranch xReads roleReads lookup
            xAnswers roleAnswers state)) = normSquared state := by
  calc
    _ = ∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
        normSquared (retainedReadBranch xReads xAnswers state) := by
      apply Finset.sum_congr rfl
      intro xAnswers _
      simp_rw [terminal_measurement_branch_norm_squared]
      exact sum_retained_read_branch_norm_squared roleReads
        (retainedReadBranch xReads xAnswers state)
        (total_on_retained_read_branch xReads xAnswers roleReads state roleTotal)
    _ = normSquared state :=
      sum_retained_read_branch_norm_squared xReads state xTotal

/-- A diagonal read branch commutes with every adaptive diagonal event
projector.  Both operators only discard basis amplitudes and inspect the same
unchanged database/workspace basis. -/
theorem retained_read_branch_adaptive_project
    (event : AdaptiveEvent Key (Output (Counter := Counter))
      (PostVerifierTerminalWork Key Counter BaseWork))
    (cap : Nat) (reads : List Key)
    (answers : ReadAnswers (Input := Key) (Output (Counter := Counter)) reads)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    retainedReadBranch reads answers (adaptiveProject event cap state) =
      adaptiveProject event cap (retainedReadBranch reads answers state) := by
  induction reads generalizing state with
  | nil => rfl
  | cons key reads inductionHypothesis =>
      rcases answers with ⟨answer, answers⟩
      simp only [retainedReadBranch]
      rw [← inductionHypothesis]
      congr 1
      funext basis
      unfold coordinateEventProjection adaptiveProject
      by_cases read : basis.database key = some answer <;>
        by_cases selected :
          size basis.database ≤ cap ∧ event basis.workspace basis.database <;>
        simp [read, selected]

/-- Adaptive diagonal projection only removes amplitudes, so it preserves
totality at every scheduled read coordinate. -/
theorem total_on_adaptive_project
    (event : AdaptiveEvent Key (Output (Counter := Counter))
      (PostVerifierTerminalWork Key Counter BaseWork))
    (cap : Nat) (reads : List Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork))
    (total : TotalOn reads state) :
    TotalOn reads (adaptiveProject event cap state) := by
  intro key member basis absent
  unfold adaptiveProject
  by_cases selected :
      size basis.database ≤ cap ∧ event basis.workspace basis.database
  · simp [selected, total key member basis absent]
  · simp [selected]

/-- The snapshot copy commutes with the fixed-advice role union when
authorization is read only from the unchanged underlying verifier base.  This
is the concrete authorization shape used by the terminal instrument; allowing
authorization to inspect the newly populated terminal registers would make a
generic commute statement false. -/
theorem record_terminal_snapshot_adaptive_project_base_authorization
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (baseAuthorized : BaseWork → Finset (List Byte))
    (cap : Nat) (spec : TerminalReadSpec Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    let contexts :=
      SmzaRp05ConditionedExecution.CertifiedFor.roleContexts model ns
        keyBytes counter routes allAdvice outerFuel innerFuel
        (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
          baseAuthorized workspace.2)
    recordTerminalSnapshot spec
        (adaptiveProject
          (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
          cap state) =
      adaptiveProject
        (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
        cap (recordTerminalSnapshot spec state) := by
  dsimp only
  funext basis
  unfold recordTerminalSnapshot databaseControlledWorkspaceUpdate adaptiveProject
  simp only [SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent,
    SmzaRp05ConditionedExecution.CertifiedFor.roleContexts,
    SmzaRp05CurrentAdaptiveExecution.event,
    SmzaRp05CurrentAdaptiveExecution.baseEvent, ignoreRetained,
    postVerifierTerminalCopyEquiv, terminalMemoryCopyEquiv,
    terminalRegisterCopyEquiv]
  rfl

/-- The complete literal read/copy instrument commutes with the common fixed-
advice role projector under the same base-only authorization discipline. -/
theorem terminal_measurement_branch_adaptive_project_base_authorization
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (baseAuthorized : BaseWork → Finset (List Byte))
    (cap : Nat) (xReads roleReads : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads)
    (roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    let contexts :=
      SmzaRp05ConditionedExecution.CertifiedFor.roleContexts model ns
        keyBytes counter routes allAdvice outerFuel innerFuel
        (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
          baseAuthorized workspace.2)
    terminalMeasurementBranch xReads roleReads lookup xAnswers roleAnswers
        (adaptiveProject
          (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
          cap state) =
      adaptiveProject
        (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
        cap (terminalMeasurementBranch xReads roleReads lookup
          xAnswers roleAnswers state) := by
  dsimp only
  unfold terminalMeasurementBranch
  rw [retained_read_branch_adaptive_project,
    retained_read_branch_adaptive_project,
    record_terminal_snapshot_adaptive_project_base_authorization]

/-- Summing the common role-event mass over every terminal measurement
outcome gives exactly its pre-instrument mass.  In particular the four-role
union is not multiplied by the number of X/role answer branches. -/
theorem sum_terminal_measurement_branch_common_role_event_norm_squared
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (baseAuthorized : BaseWork → Finset (List Byte))
    (cap : Nat) (xReads roleReads : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork))
    (xTotal : TotalOn xReads state) (roleTotal : TotalOn roleReads state) :
    let contexts :=
      SmzaRp05ConditionedExecution.CertifiedFor.roleContexts model ns
        keyBytes counter routes allAdvice outerFuel innerFuel
        (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
          baseAuthorized workspace.2)
    (∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
      ∑ roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads,
        normSquared
          (adaptiveProject
            (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
            cap (terminalMeasurementBranch xReads roleReads lookup
              xAnswers roleAnswers state))) =
      normSquared
        (adaptiveProject
          (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
          cap state) := by
  dsimp only
  let contexts :=
    SmzaRp05ConditionedExecution.CertifiedFor.roleContexts model ns
      keyBytes counter routes allAdvice outerFuel innerFuel
      (fun workspace : SparseTerminalWorkspace Key Counter BaseWork =>
        baseAuthorized workspace.2)
  simp_rw [← terminal_measurement_branch_adaptive_project_base_authorization
    model ns keyBytes counter routes allAdvice outerFuel innerFuel
      baseAuthorized cap]
  exact sum_terminal_measurement_branch_norm_squared xReads roleReads lookup
    (adaptiveProject
      (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
      cap state)
    (total_on_adaptive_project _ cap xReads state xTotal)
    (total_on_adaptive_project _ cap roleReads state roleTotal)

@[simp]
theorem recorded_terminal_x_read
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter)))
    (key : Key) (member : key ∈ spec.xKeys) :
    (recordedTerminalRegisters (Counter := Counter) spec database).measuredX key =
      database key := by
  simp [recordedTerminalRegisters, restrictDatabaseTo, member]

@[simp]
theorem recorded_terminal_role_read
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter)))
    (key : Key) (member : key ∈ spec.roleKeys) :
    (recordedTerminalRegisters (Counter := Counter) spec database).roleClaims key =
      database key := by
  simp [recordedTerminalRegisters, restrictDatabaseTo, member]

/-- Lookup one actually retained challenge vector.  The parser receipt,
target, nonce, and populated sparse claim are all checked before selection. -/
def retainedVectorAtNonce
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (claims : Database Key (Output (Counter := Counter)))
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (role : Role) (target : V8SmzaOracleParser.RawDigest) (nonce : LookupNonce) :
    Option (Output (Counter := Counter)) := do
  let key ← lookup role target nonce
  let parsed ← parseStageQuery (keyBytes key)
  if parsed.role = role ∧ parsed.target = target ∧ parsed.nonce = nonce.val then
    claims key
  else none

theorem retained_vector_at_nonce_of_lookup
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (claims : Database Key (Output (Counter := Counter)))
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (role : Role) (target : V8SmzaOracleParser.RawDigest) (nonce : LookupNonce)
    (key : Key) (parsed : StageQuery)
    (vector : Output (Counter := Counter))
    (found : lookup role target nonce = some key)
    (parsedRead : parseStageQuery (keyBytes key) = some parsed)
    (sameRole : parsed.role = role) (sameTarget : parsed.target = target)
    (sameNonce : parsed.nonce = nonce.val)
    (read : claims key = some vector) :
    retainedVectorAtNonce keyBytes claims lookup role target nonce =
      some vector := by
  simp [retainedVectorAtNonce, found, parsedRead, sameRole, sameTarget,
    sameNonce, read]

def retainedDecodedAt
    (model : RelationModel) (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (counterRoutes : TypedRoutes model Counter)
    (claims : Database Key (Output (Counter := Counter)))
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (statement : Statement) (role : Role)
    (target : V8SmzaOracleParser.RawDigest) :
    Option (RoleOutput model statement role) :=
  match role with
  | .decsMatrix =>
      (retainedVectorAtNonce keyBytes claims lookup .decsMatrix target 0).bind
        (actualDecsMatrixOutput (counterRoutes statement).decsMatrix)
  | .piopMatrix =>
      (retainedVectorAtNonce keyBytes claims lookup .piopMatrix target 0).bind
        (actualPiopMatrixOutput (counterRoutes statement).piopMatrix)
  | .piopOpening =>
      firstSome (fun nonce : Fin 16 =>
        (retainedVectorAtNonce keyBytes claims lookup .piopOpening target nonce).bind
          (actualPiopOpeningOutput (counterRoutes statement).piopOpening))
        canonicalOpeningNonceOrder
  | .decsSample =>
      (retainedVectorAtNonce keyBytes claims lookup .decsSample target 0).bind
        (actualDecsSampleOutput (counterRoutes statement).decsSample)

/-- Earlier values on the left event are a deterministic partial lookup in
the retained claim map.  Missing reads return `none`; the opening case uses
the source's literal first-success nonce order. -/
def retainedAdviceOfClaims
    (model : RelationModel) (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (routes : TypedRoutes model Counter)
    (claims : Database Key (Output (Counter := Counter)))
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (statement : Statement) (selected : Role) :
    EarlierTables model statement selected :=
  fun earlier _ target =>
    retainedDecodedAt model keyBytes routes claims lookup statement earlier target

/-- Pointwise sparse-left/fixed-right bridge.  Only trace-selected earlier
lookups are required to agree; unqueried fixed-table cells are irrelevant. -/
theorem retained_prefix_eq_fixed_advice
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (fixed : SmzaRp05ConditionedExecution.FixedTable ctx blockCap)
    (claims : Database Key (Output (Counter := Counter)))
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (statement : Statement) (trace : Trace)
    (agreement : TraceReadAgreement ctx.model ctx.leafNamespace statement ctx.role
      (retainedAdviceOfClaims ctx.model ctx.keyBytes ctx.routes claims lookup
        statement ctx.role)
      (fixedAdvice ctx blockCap fixed statement) trace) :
    prefixLabels ctx.model ctx.leafNamespace statement ctx.role
        (retainedAdviceOfClaims ctx.model ctx.keyBytes ctx.routes claims lookup
          statement ctx.role) trace =
      prefixLabels ctx.model ctx.leafNamespace statement ctx.role
        (fixedAdvice ctx blockCap fixed statement) trace := by
  exact prefix_labels_eq_of_retained_reads ctx.model ctx.leafNamespace statement
    ctx.role _ _ trace agreement

/-- Literal sparse left event `E_r`.  Its inputs are only measured X records,
actually retained role vectors, and accepted-transcript values already in the
classical base workspace.  The outer/inner decoder equalities are evaluated
on `mergedSparse`; no full random-oracle table or external role advice appears. -/
def sparseWorkspaceRoleEvent
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte)) (role : Role) :
    SparseTerminalWorkspace Key Counter BaseWork → Prop :=
  fun workspace =>
    let statement := statementOf workspace.2
    let trace := traceOf workspace.2
    let key := roleKeyOf workspace.2 role
    ∃ vector,
      workspace.1.roleClaims key = some vector ∧
      statement.toBytes ∉ authorizedOf workspace.2 ∧
      InRoleDomain role (keyBytes key) ∧
      rawTraceDecoder (globalOnlineNext ns)
        (fun selected => targetOfRaw role (keyBytes selected))
        (fun _ decoded => preambleFromTrace ns role decoded) outerFuel
        (nonleafFilter (globalLeafStatement ns)
          (rawRecords keyBytes (vectorOutputBytes counter)
            (mergedSparse workspace))) key = some statement.toBytes ∧
      extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (rawRecords keyBytes (vectorOutputBytes counter)
            (mergedSparse workspace))) innerFuel
        (targetOfRaw role (keyBytes key)).1
        (targetOfRaw role (keyBytes key)).2 = causalTrace trace role ∧
      typedCompleteRawBad model routes role
        (.decoded statement
          (prefixLabels model ns statement role
            (retainedAdviceOfClaims model keyBytes routes workspace.1.roleClaims
              workspace.1.roleLookup statement role)
            (causalTrace trace role))) vector

/-- The common failure event is a union on one sparse workspace.  This is the
left event used before four different selected-role partial compressions. -/
def anySparseWorkspaceRoleEvent
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte)) :
    SparseTerminalWorkspace Key Counter BaseWork → Prop :=
  fun workspace => ∃ role, sparseWorkspaceRoleEvent model ns keyBytes
    counter routes outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf
    role workspace

theorem any_sparse_workspace_role_event_mass_le_sum
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : State Key (Output (Counter := Counter)) Phase
      (SparseTerminalWorkspace Key Counter BaseWork)) :
    normSquared
        (workspaceOnlyProjection
          (anySparseWorkspaceRoleEvent model ns keyBytes counter routes
            outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf) state) ≤
      ∑ role : Role,
        normSquared
          (workspaceOnlyProjection
            (sparseWorkspaceRoleEvent model ns keyBytes counter routes
              outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role)
            state) := by
  unfold normSquared workspaceOnlyProjection workspaceEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  let selectedRole : Role → Prop := fun role =>
    sparseWorkspaceRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role
      basis.workspace
  by_cases anyRole : anySparseWorkspaceRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf basis.workspace
  · have witness : ∃ role, selectedRole role := anyRole
    obtain ⟨role, selected⟩ := witness
    have witness' : ∃ role, selectedRole role := ⟨role, selected⟩
    have lower := Finset.single_le_sum
      (f := fun chosen : Role =>
        Complex.normSq (if selectedRole chosen then state basis else 0))
      (fun chosen _ => Complex.normSq_nonneg _)
      (Finset.mem_univ role)
    simpa [selectedRole, selected, anySparseWorkspaceRoleEvent, witness'] using lower
  · simp only [if_neg anyRole, Complex.normSq_zero]
    exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)

/-! ## The four events and readout loss on one post-verifier state -/

def postVerifierSparseRoleEvent
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte)) (role : Role) :
    PostVerifierTerminalWork Key Counter BaseWork → Prop :=
  fun work => sparseWorkspaceRoleEvent model ns keyBytes counter routes
    outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role work.2

def postVerifierAnySparseRoleEvent
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte)) :
    PostVerifierTerminalWork Key Counter BaseWork → Prop :=
  fun work => ∃ role, postVerifierSparseRoleEvent model ns keyBytes
    counter routes outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf
    role work

/-- Exact four-way union bound on the single corrected post-verifier state.
The outer retained-old coordinate and all terminal registers are shared; no
role-conditioned state is substituted. -/
theorem post_verifier_any_sparse_role_event_mass_le_sum
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    normSquared
        (workspaceOnlyProjection
          (postVerifierAnySparseRoleEvent model ns keyBytes counter routes
            outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf) state) ≤
      ∑ role : Role,
        normSquared
          (workspaceOnlyProjection
            (postVerifierSparseRoleEvent model ns keyBytes counter routes
              outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role)
            state) := by
  unfold normSquared workspaceOnlyProjection workspaceEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  let selectedRole : Role → Prop := fun role =>
    postVerifierSparseRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role
      basis.workspace
  by_cases anyRole : postVerifierAnySparseRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf basis.workspace
  · have witness : ∃ role, selectedRole role := anyRole
    obtain ⟨role, selected⟩ := witness
    have witness' : ∃ role, selectedRole role := ⟨role, selected⟩
    have lower := Finset.single_le_sum
      (f := fun chosen : Role =>
        Complex.normSq (if selectedRole chosen then state basis else 0))
      (fun chosen _ => Complex.normSq_nonneg _)
      (Finset.mem_univ role)
    simpa [selectedRole, selected, postVerifierAnySparseRoleEvent, witness'] using lower
  · simp only [if_neg anyRole, Complex.normSq_zero]
    exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)

theorem coordinate_event_projection_record_terminal_snapshot
    (spec : TerminalReadSpec Key) (key : Key)
    (value : Output (Counter := Counter))
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    coordinateEventProjection key value (recordTerminalSnapshot spec state) =
      recordTerminalSnapshot spec (coordinateEventProjection key value state) := by
  rfl

theorem known_at_record_terminal_snapshot
    (spec : TerminalReadSpec Key) (key : Key)
    (value : Output (Counter := Counter))
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork))
    (known : KnownAt key value state) :
    KnownAt key value (recordTerminalSnapshot spec state) := by
  unfold KnownAt at known ⊢
  rw [coordinate_event_projection_record_terminal_snapshot, known]

/-- The exact claim-loss bound after the literal X/read/copy branch and one
selected-coordinate decompression schedule.  Its known-cell premise is
derived from `retainedReadBranch`; the copy does not alter the database. -/
theorem terminal_measurement_branch_claim_failure_le
    (xReads roleReads compression : List Key)
    (roleReadNodup : roleReads.Nodup) (compressionNodup : compression.Nodup)
    (included : ∀ key ∈ roleReads, key ∈ compression)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads)
    (roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    let knownState := terminalMeasurementBranch xReads roleReads lookup
      xAnswers roleAnswers state
    let finalState := decompressList compression knownState
    normSquared
        (claimFailureProjection (branchClaims roleReads roleAnswers) finalState) ≤
      ((2 * (branchClaims roleReads roleAnswers).toFinset.card : Nat) : ℝ) /
          Fintype.card (Output (Counter := Counter)) * normSquared knownState := by
  dsimp only
  apply known_claims_partial_decompress_failure_le
  · intro claim member
    apply known_at_record_terminal_snapshot
    exact branch_claim_known_at roleReads roleReadNodup roleAnswers
      (retainedReadBranch xReads xAnswers state) claim member
  · intro claim member
    obtain ⟨other, outside, factor⟩ :=
      nodup_decompress_list_selected_factorization claim.1 compression
        (terminalMeasurementBranch xReads roleReads lookup
          xAnswers roleAnswers state)
        (included claim.1 (branch_claim_key_mem roleReads roleAnswers claim member))
        compressionNodup
    exact ⟨other, outside, factor⟩

/-- Complete all-outcome claim-loss bound.  Each branch keeps its original
weight, and the common state norm occurs only once after summing the
orthogonal X and role answer registers. -/
theorem sum_terminal_measurement_claim_failure_le
    (xReads roleReads compression : List Key)
    (roleReadNodup : roleReads.Nodup) (compressionNodup : compression.Nodup)
    (included : ∀ key ∈ roleReads, key ∈ compression)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork))
    (xTotal : TotalOn xReads state) (roleTotal : TotalOn roleReads state) :
    (∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
      ∑ roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads,
        normSquared
          (claimFailureProjection (branchClaims roleReads roleAnswers)
            (decompressList compression
              (terminalMeasurementBranch xReads roleReads lookup
                xAnswers roleAnswers state)))) ≤
      ((2 * roleReads.length : Nat) : ℝ) /
          Fintype.card (Output (Counter := Counter)) * normSquared state := by
  calc
    _ ≤ ∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
        ∑ roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads,
          (((2 * roleReads.length : Nat) : ℝ) /
            Fintype.card (Output (Counter := Counter))) *
              normSquared (terminalMeasurementBranch xReads roleReads lookup
                xAnswers roleAnswers state) := by
      apply Finset.sum_le_sum
      intro xAnswers _
      apply Finset.sum_le_sum
      intro roleAnswers _
      refine (terminal_measurement_branch_claim_failure_le
        xReads roleReads compression roleReadNodup compressionNodup included
        lookup xAnswers roleAnswers state).trans ?_
      apply mul_le_mul_of_nonneg_right
      · apply div_le_div_of_nonneg_right
        · have bound := Nat.mul_le_mul_left 2
            (List.toFinset_card_le (branchClaims roleReads roleAnswers))
          rw [branch_claims_length roleReads roleAnswers] at bound
          exact_mod_cast bound
        · positivity
      · unfold normSquared
        exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
    _ = ((2 * roleReads.length : Nat) : ℝ) /
          Fintype.card (Output (Counter := Counter)) * normSquared state := by
      simp_rw [← Finset.mul_sum]
      rw [sum_terminal_measurement_branch_norm_squared xReads roleReads lookup
        state xTotal roleTotal]

/-- Final same-common-state probability endpoint for the terminal lane.  The
four workspace events and the claim-failure projector are evaluated on the
same decompressed branch.  The right readout term is the literal retained
full-vector loss of that branch, not an asserted terminal-memory view. -/
theorem terminal_common_state_four_roles_and_claim_failure_le
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte))
    (xReads roleReads compression : List Key)
    (roleReadNodup : roleReads.Nodup) (compressionNodup : compression.Nodup)
    (included : ∀ key ∈ roleReads, key ∈ compression)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads)
    (roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads)
    (state : State Key (Output (Counter := Counter)) Phase
      (PostVerifierTerminalWork Key Counter BaseWork)) :
    let knownState := terminalMeasurementBranch xReads roleReads lookup
      xAnswers roleAnswers state
    let finalState := decompressList compression knownState
    normSquared
        (workspaceOnlyProjection
          (postVerifierAnySparseRoleEvent model ns keyBytes counter routes
            outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf)
          finalState) +
      normSquared
        (claimFailureProjection (branchClaims roleReads roleAnswers) finalState) ≤
      (∑ role : Role,
        normSquared
          (workspaceOnlyProjection
            (postVerifierSparseRoleEvent model ns keyBytes counter routes
              outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role)
            finalState)) +
        ((2 * (branchClaims roleReads roleAnswers).toFinset.card : Nat) : ℝ) /
            Fintype.card (Output (Counter := Counter)) * normSquared knownState := by
  dsimp only
  exact add_le_add
    (post_verifier_any_sparse_role_event_mass_le_sum model ns keyBytes
      counter routes outerFuel innerFuel statementOf traceOf roleKeyOf
      authorizedOf _)
    (terminal_measurement_branch_claim_failure_le xReads roleReads compression
      roleReadNodup compressionNodup included lookup xAnswers roleAnswers state)

/-- Deterministic accepted-failure classification on the sparse common
workspace.  `TraceReadAgreement` asks only for the at-most-two earlier values
actually used by the recovered prefix.  It does not assume equality of whole
advice tables or populate any unqueried oracle coordinate. -/
theorem accepted_failure_has_sparse_workspace_role_event
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : Namespace) (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte))
    (workspace : SparseTerminalWorkspace Key Counter BaseWork)
    (messages : CausalPayloads ns (traceOf workspace.2))
    (advice : (role : Role) →
      EarlierTables model (statementOf workspace.2) role)
    (strategy : Strategy model (statementOf workspace.2))
    (coefficients : Coefficients)
    (matrix : Matrix (model.width (statementOf workspace.2)))
    (opening : Opening) (query : Query)
    (vectors : Role → Output (Counter := Counter))
    (fresh : (statementOf workspace.2).toBytes ∉
      authorizedOf workspace.2)
    (earlier : EarlierReadback model (statementOf workspace.2) advice messages
      coefficients matrix opening)
    (piopResponseRead : strategy.piopResponse coefficients matrix =
      piopResponse messages.piop)
    (claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs)
    (roleClaimsRead : ∀ role,
      workspace.1.roleClaims (roleKeyOf workspace.2 role) = some (vectors role))
    (roleQueries : ∀ role, ∃ parsed,
      parseStageQuery (keyBytes (roleKeyOf workspace.2 role)) = some parsed ∧
        parsed.role = role)
    (outerReadback : ∀ role,
      rawTraceDecoder (globalOnlineNext ns)
        (fun key => targetOfRaw role (keyBytes key))
        (fun _ decoded => preambleFromTrace ns role decoded) outerFuel
        (nonleafFilter (globalLeafStatement ns)
          (rawRecords keyBytes (vectorOutputBytes counter)
            (mergedSparse workspace)))
        (roleKeyOf workspace.2 role) =
          some (statementOf workspace.2).toBytes)
    (innerReadback : ∀ role,
      extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns)
          (statementOf workspace.2).toBytes
          (rawRecords keyBytes (vectorOutputBytes counter)
            (mergedSparse workspace))) innerFuel
        (targetOfRaw role (keyBytes (roleKeyOf workspace.2 role))).1
        (targetOfRaw role (keyBytes (roleKeyOf workspace.2 role))).2 =
          causalTrace (traceOf workspace.2) role)
    (agreement : ∀ role,
      TraceReadAgreement model ns (statementOf workspace.2) role
        (advice role)
        (retainedAdviceOfClaims model keyBytes routes workspace.1.roleClaims
          workspace.1.roleLookup (statementOf workspace.2) role)
        (causalTrace (traceOf workspace.2) role))
    (decsRead : actualDecsMatrixOutput
      (routes (statementOf workspace.2)).decsMatrix (vectors .decsMatrix) =
        some coefficients)
    (matrixRead : actualPiopMatrixOutput
      (routes (statementOf workspace.2)).piopMatrix (vectors .piopMatrix) =
        some matrix)
    (openingRead : actualPiopOpeningOutput
      (routes (statementOf workspace.2)).piopOpening (vectors .piopOpening) =
        some opening)
    (queryRead : actualDecsSampleOutput
      (routes (statementOf workspace.2)).decsSample (vectors .decsSample) =
        some query)
    (checks : AcceptedChecks refinement (statementOf workspace.2)
      (causalOracle ns (traceOf workspace.2))
      (sourceResponse messages.fpp) strategy coefficients matrix opening query)
    (failed : ExtractionFailure refinement (statementOf workspace.2)
      (causalOracle ns (traceOf workspace.2))
      (sourceResponse messages.fpp) coefficients) :
    anySparseWorkspaceRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf workspace := by
  obtain ⟨role, calculatedBad⟩ :=
    accepted_failure_has_typed_complete_raw_bad_role refinement
      (statementOf workspace.2) routes
      (causalOracle ns (traceOf workspace.2))
      (sourceResponse messages.fpp) strategy coefficients matrix opening query
      vectors decsRead matrixRead openingRead queryRead checks failed
  have chronological := causal_role_prefix_matches_calculated model ns
    (statementOf workspace.2) (traceOf workspace.2) messages advice strategy
    coefficients matrix opening earlier piopResponseRead claimedCoefficientsRead role
  have retainedPrefix := prefix_labels_eq_of_retained_reads model ns
    (statementOf workspace.2) role (advice role)
    (retainedAdviceOfClaims model keyBytes routes workspace.1.roleClaims
      workspace.1.roleLookup (statementOf workspace.2) role)
    (causalTrace (traceOf workspace.2) role) (agreement role)
  have retainedToCalculated : SameRolePrefix role
      (prefixLabels model ns (statementOf workspace.2) role
        (retainedAdviceOfClaims model keyBytes routes workspace.1.roleClaims
          workspace.1.roleLookup (statementOf workspace.2) role)
        (causalTrace (traceOf workspace.2) role))
      (calculatedLabels (statementOf workspace.2)
        (causalOracle ns (traceOf workspace.2))
        (sourceResponse messages.fpp) strategy coefficients matrix opening) := by
    rw [← retainedPrefix]
    exact chronological
  have retainedBad :=
    (typed_complete_bad_congr_role_prefix model routes
      (statementOf workspace.2) role _ _ (vectors role)
      retainedToCalculated).mpr calculatedBad
  refine ⟨role, vectors role, roleClaimsRead role, fresh, ?_,
    outerReadback role, innerReadback role, retainedBad⟩
  obtain ⟨parsed, parsedRead, parsedRole⟩ := roleQueries role
  exact ⟨parsed, parsedRead, parsedRole⟩

/-- The deterministic extraction theorem on the exact output of the terminal
copy instrument.  The four role cells are read from `database` at scheduled
keys; `roleClaimsRead` is therefore derived below rather than supplied as a
view premise.  The X/role maps in the conclusion are precisely the two sparse
restrictions made by `recordTerminalSnapshot`. -/
theorem accepted_failure_has_recorded_terminal_role_event
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : Namespace) (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte))
    (spec : TerminalReadSpec Key)
    (database : Database Key (Output (Counter := Counter))) (base : BaseWork)
    (messages : CausalPayloads ns (traceOf base))
    (advice : (role : Role) → EarlierTables model (statementOf base) role)
    (strategy : Strategy model (statementOf base))
    (coefficients : Coefficients) (matrix : Matrix (model.width (statementOf base)))
    (opening : Opening) (query : Query)
    (vectors : Role → Output (Counter := Counter))
    (fresh : (statementOf base).toBytes ∉ authorizedOf base)
    (earlier : EarlierReadback model (statementOf base) advice messages
      coefficients matrix opening)
    (piopResponseRead : strategy.piopResponse coefficients matrix =
      piopResponse messages.piop)
    (claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs)
    (roleKeyScheduled : ∀ role, roleKeyOf base role ∈ spec.roleKeys)
    (roleDatabaseRead : ∀ role,
      database (roleKeyOf base role) = some (vectors role))
    (roleQueries : ∀ role, ∃ parsed,
      parseStageQuery (keyBytes (roleKeyOf base role)) = some parsed ∧
        parsed.role = role)
    (outerReadback : ∀ role,
      rawTraceDecoder (globalOnlineNext ns)
        (fun selected => targetOfRaw role (keyBytes selected))
        (fun _ decoded => preambleFromTrace ns role decoded) outerFuel
        (nonleafFilter (globalLeafStatement ns)
          (rawRecords keyBytes (vectorOutputBytes counter)
            (mergedSparse
              (recordedTerminalRegisters (Counter := Counter) spec database, base))))
        (roleKeyOf base role) = some (statementOf base).toBytes)
    (innerReadback : ∀ role,
      extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns)
          (statementOf base).toBytes
          (rawRecords keyBytes (vectorOutputBytes counter)
            (mergedSparse
              (recordedTerminalRegisters (Counter := Counter) spec database, base))))
        innerFuel (targetOfRaw role (keyBytes (roleKeyOf base role))).1
          (targetOfRaw role (keyBytes (roleKeyOf base role))).2 =
            causalTrace (traceOf base) role)
    (agreement : ∀ role,
      TraceReadAgreement model ns (statementOf base) role (advice role)
        (retainedAdviceOfClaims model keyBytes routes
          (recordedTerminalRegisters (Counter := Counter) spec database).roleClaims
          spec.roleLookup (statementOf base) role)
        (causalTrace (traceOf base) role))
    (decsRead : actualDecsMatrixOutput (routes (statementOf base)).decsMatrix
      (vectors .decsMatrix) = some coefficients)
    (matrixRead : actualPiopMatrixOutput (routes (statementOf base)).piopMatrix
      (vectors .piopMatrix) = some matrix)
    (openingRead : actualPiopOpeningOutput (routes (statementOf base)).piopOpening
      (vectors .piopOpening) = some opening)
    (queryRead : actualDecsSampleOutput (routes (statementOf base)).decsSample
      (vectors .decsSample) = some query)
    (checks : AcceptedChecks refinement (statementOf base)
      (causalOracle ns (traceOf base)) (sourceResponse messages.fpp)
      strategy coefficients matrix opening query)
    (failed : ExtractionFailure refinement (statementOf base)
      (causalOracle ns (traceOf base)) (sourceResponse messages.fpp)
      coefficients) :
    anySparseWorkspaceRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf
      (recordedTerminalRegisters (Counter := Counter) spec database, base) := by
  apply accepted_failure_has_sparse_workspace_role_event model refinement ns
    keyBytes counter routes outerFuel innerFuel statementOf traceOf roleKeyOf
    authorizedOf
    (recordedTerminalRegisters (Counter := Counter) spec database, base)
    messages advice strategy coefficients matrix opening query vectors fresh
    earlier piopResponseRead claimedCoefficientsRead
  · intro role
    exact (recorded_terminal_role_read spec database (roleKeyOf base role)
      (roleKeyScheduled role)).trans (roleDatabaseRead role)
  · exact roleQueries
  · exact outerReadback
  · exact innerReadback
  · simpa [recordedTerminalRegisters] using agreement
  · exact decsRead
  · exact matrixRead
  · exact openingRead
  · exact queryRead
  · exact checks
  · exact failed

/-- A populated sparse event is the actual adaptive `currentRoleEvent` when
the concrete schedules cover the reachable post-verifier database and the
retained earlier reads decode to the context advice.  These are execution
invariants, not an arbitrary terminal view: the database equality is about
the two literal sparse copies made by the instrument. -/
theorem sparse_workspace_role_event_implies_current_role_event
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte))
    (workspace : SparseTerminalWorkspace Key Counter BaseWork) (role : Role)
    (allAdvice : AllEarlierTables model role)
    (database : Database Key (Output (Counter := Counter)))
    (sameDatabase : database = mergedSparse workspace)
    (adviceAtStatement : allAdvice (statementOf workspace.2) =
      retainedAdviceOfClaims model keyBytes routes workspace.1.roleClaims
        workspace.1.roleLookup (statementOf workspace.2) role)
    (event : sparseWorkspaceRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role workspace) :
    currentRoleEvent model ns keyBytes counter routes role allAdvice
      outerFuel innerFuel (authorizedOf workspace.2) database := by
  rcases event with
    ⟨vector, recorded, fresh, inRole, outerReadback, innerReadback, bad⟩
  refine ⟨roleKeyOf workspace.2 role, vector, ?_, inRole, ?_⟩
  · rw [sameDatabase]
    exact merged_sparse_role_claim workspace _ vector recorded
  · unfold completeFilteredLabel
    unfold currentOuter
    rw [sameDatabase]
    dsimp only
    rw [outerReadback]
    simp only [fresh, if_false, AuthorizedBad]
    change typedCompleteRawBad model routes role
      (roleLabelsFromBytes model ns role allAdvice
        (statementOf workspace.2).toBytes
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns)
            (statementOf workspace.2).toBytes
            (rawRecords keyBytes (vectorOutputBytes counter)
              (mergedSparse workspace))) innerFuel
          (targetOfRaw role (keyBytes (roleKeyOf workspace.2 role))).1
          (targetOfRaw role (keyBytes (roleKeyOf workspace.2 role))).2)) vector
    rw [innerReadback, role_labels_from_statement_bytes, adviceAtStatement]
    exact bad

/-- Pointwise bridge on the exact `Option Output × BaseWork` terminal
coordinate consumed by `CertifiedFor.common_terminal_role_mass_le`. -/
theorem post_verifier_sparse_role_event_implies_current
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (statementOf : BaseWork → Statement) (traceOf : BaseWork → Trace)
    (roleKeyOf : BaseWork → Role → Key)
    (authorizedOf : BaseWork → Finset (List Byte))
    (role : Role) (allAdvice : AllEarlierTables model role)
    (work : PostVerifierTerminalWork Key Counter BaseWork)
    (database : Database Key (Output (Counter := Counter)))
    (sameDatabase : database = mergedSparse work.2)
    (adviceAtStatement : allAdvice (statementOf work.2.2) =
      retainedAdviceOfClaims model keyBytes routes work.2.1.roleClaims
        work.2.1.roleLookup (statementOf work.2.2) role)
    (event : postVerifierSparseRoleEvent model ns keyBytes counter routes
      outerFuel innerFuel statementOf traceOf roleKeyOf authorizedOf role work) :
    currentRoleEvent model ns keyBytes counter routes role allAdvice
      outerFuel innerFuel (authorizedOf work.2.2) database := by
  exact sparse_workspace_role_event_implies_current_role_event model ns
    keyBytes counter routes outerFuel innerFuel statementOf traceOf roleKeyOf
    authorizedOf work.2 role allAdvice database sameDatabase adviceAtStatement event

/-- Actual adaptive-program endpoint.  Ordinary queries, authorization marks,
private kernels, reversible copies, marked leaf writes, and retained
full-vector writes are compiled by `ActualProgram.compile`; none is omitted
from the terminal state. -/
theorem current_adaptive_terminal_role_mass_le
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (T finish queries : Nat)
    (program : SmzaRp05CurrentAdaptiveExecution.ActualProgram ctx T 0 finish queries)
    (queriesLe : queries ≤ T)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers)) :
    normSquared
        (adaptiveProject (SmzaRp05CurrentAdaptiveExecution.event ctx) T
          (AdaptiveProgram.run
            (SmzaRp05CurrentAdaptiveExecution.ActualProgram.compile ctx T program)
            (partialRandomOracleState
              (Output := Output (Counter := Counter)) ∅ registers))) ≤
      6 * (T : ℝ) ^ 2 * (((completeRoleLoss ctx.role : Rat)) : ℝ) +
        36 * (T : ℝ) ^ 3 / (2^512 : ℝ) := by
  exact current_adaptive_role_bad_mass_le ctx T finish queries program queriesLe
    registers subnormalized

/-! ## Direct endpoint from the single certified physical execution -/

/-- Run the literal terminal measurement/read/copy branch directly on the
single proof-erased post-verifier state.  There is no caller-supplied final
state or equality to a role-specific execution. -/
def certifiedTerminalMeasurementBranch
    {cap finish queries : Nat}
    (skeleton : SmzaRp05ConditionedExecution.PhysicalProgramSkeleton
      (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork)
      cap 0 finish queries)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := PostVerifierTerminalWork Key Counter BaseWork) → ℂ)
    (xReads roleReads : List Key)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads)
    (roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads) :
    State Key (Output (Counter := Counter)) (Output (Counter := Counter))
      (PostVerifierTerminalWork Key Counter BaseWork) :=
  terminalMeasurementBranch xReads roleReads lookup xAnswers roleAnswers
    (SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers))

/-- Final quantitative terminal endpoint.  The fixed-advice role union is
evaluated once on `PhysicalProgramSkeleton.run skeleton initial`.  Claim loss
is then summed over every orthogonal X/role measurement outcome.  Thus the
common role mass is not duplicated by the number of classical branches. -/
theorem certified_common_state_roles_and_claim_failure_le
    (contexts : Role → SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork))
    (selected : ∀ role, (contexts role).role = role)
    {cap finish queries : Nat}
    (skeleton : SmzaRp05ConditionedExecution.PhysicalProgramSkeleton
      (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork)
      cap 0 finish queries)
    (certified : SmzaRp05ConditionedExecution.CertifiedFor contexts skeleton)
    (queriesLe : queries ≤ cap)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := PostVerifierTerminalWork Key Counter BaseWork) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers))
    (xReads roleReads compression : List Key)
    (roleReadNodup : roleReads.Nodup) (compressionNodup : compression.Nodup)
    (included : ∀ key ∈ roleReads, key ∈ compression)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xTotal : TotalOn xReads
      (SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers)))
    (roleTotal : TotalOn roleReads
      (SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers))) :
    let commonState :=
      SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers)
    normSquared
        (adaptiveProject
          (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
          cap commonState) +
      (∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
        ∑ roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads,
          normSquared
            (claimFailureProjection (branchClaims roleReads roleAnswers)
              (decompressList compression
                (terminalMeasurementBranch xReads roleReads lookup
                  xAnswers roleAnswers commonState)))) ≤
      (∑ role : Role,
        (6 * (cap : ℝ) ^ 2 * ((completeRoleLoss role : Rat) : ℝ) +
          36 * (cap : ℝ) ^ 3 / (2^512 : ℝ))) +
        ((2 * roleReads.length : Nat) : ℝ) /
          Fintype.card (Output (Counter := Counter)) * normSquared commonState := by
  dsimp only
  exact add_le_add
    (SmzaRp05ConditionedExecution.CertifiedFor.common_any_terminal_role_mass_le
      selected certified queriesLe registers subnormalized)
    (sum_terminal_measurement_claim_failure_le xReads roleReads compression
      roleReadNodup compressionNodup included lookup _ xTotal roleTotal)

/-- The analytic right-hand side of the common-state theorem is exactly
covered by the checked RP05 terminal ledger.  Four copies of the per-role
`36*T^3` term give `144*T^3`; the ledger deliberately reserves `150*T^3`.
The terminal full-vector read contributes the remaining linear term. -/
theorem common_terminal_rhs_le_terminal_extraction_loss
    (counter : Counter) (cap readCount : Nat) (readCountLe : readCount ≤ cap)
    (commonNorm : ℝ) (commonNormNonnegative : 0 ≤ commonNorm)
    (commonNormLeOne : commonNorm ≤ 1) :
    (∑ role : Role,
        (6 * (cap : ℝ) ^ 2 * ((completeRoleLoss role : Rat) : ℝ) +
          36 * (cap : ℝ) ^ 3 / (2^512 : ℝ))) +
      ((2 * readCount : Nat) : ℝ) /
          Fintype.card (Output (Counter := Counter)) * commonNorm ≤
        ((terminalExtractionLoss cap : Rat) : ℝ) := by
  have retentionBase :=
    (vector_retention_loss_le_digest counter readCount).trans (by gcongr :
      (2 * (readCount : ℝ)) / (2 : ℝ)^512 ≤
        (2 * (cap : ℝ)) / (2 : ℝ)^512)
  have retention :
      ((2 * readCount : Nat) : ℝ) /
          Fintype.card (Output (Counter := Counter)) * commonNorm ≤
        (2 * (cap : ℝ)) / (2 : ℝ)^512 := by
    calc
      _ ≤ ((2 * (cap : ℝ)) / (2 : ℝ)^512) * commonNorm := by
        exact mul_le_mul_of_nonneg_right retentionBase commonNormNonnegative
      _ ≤ (2 * (cap : ℝ)) / (2 : ℝ)^512 := by
        have coefficientNonnegative :
            0 ≤ (2 * (cap : ℝ)) / (2 : ℝ)^512 := by positivity
        simpa using mul_le_mul_of_nonneg_left commonNormLeOne coefficientNonnegative
  have roleSum :
      (∑ role : Role,
        (6 * (cap : ℝ) ^ 2 * ((completeRoleLoss role : Rat) : ℝ) +
          36 * (cap : ℝ) ^ 3 / (2^512 : ℝ))) =
        6 * (cap : ℝ)^2 * ((fourRoleLocalLoss : Rat) : ℝ) +
          144 * (cap : ℝ)^3 / (2 : ℝ)^512 := by
    have roles : (Finset.univ : Finset Role) =
        {.decsMatrix, .piopMatrix, .piopOpening, .decsSample} := by
      ext role
      cases role <;> simp
    rw [roles]
    simp [completeRoleLoss, fourRoleLocalLoss, sourceOnlyRoleLoss]
    ring_nf
  rw [roleSum]
  calc
    6 * (cap : ℝ)^2 * ((fourRoleLocalLoss : Rat) : ℝ) +
          144 * (cap : ℝ)^3 / (2 : ℝ)^512 +
        ((2 * readCount : Nat) : ℝ) /
          Fintype.card (Output (Counter := Counter)) * commonNorm ≤
      6 * (cap : ℝ)^2 * ((fourRoleLocalLoss : Rat) : ℝ) +
          144 * (cap : ℝ)^3 / (2 : ℝ)^512 +
        (2 * (cap : ℝ)) / (2 : ℝ)^512 :=
      by linarith only [retention]
    _ ≤ ((terminalExtractionLoss cap : Rat) : ℝ) := by
      unfold terminalExtractionLoss
      push_cast
      have capCubeNonnegative : (0 : ℝ) ≤ (cap : ℝ)^3 := by positivity
      nlinarith [capCubeNonnegative]

/-- The empty database cannot contain a populated selected-role bad cell. -/
theorem empty_not_current_role_event
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte)) :
    ¬currentRoleEvent model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized
      (empty : Database Key (Output (Counter := Counter))) := by
  rintro ⟨key, output, recorded, _, _⟩
  cases recorded

/-- Empty-database initialization is outside every literal current-role
event, independent of workspace amplitudes. -/
theorem initial_current_role_projection_zero
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel cap : Nat)
    (authorized : Finset (List Byte))
    (registers : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    project
      (currentRoleEvent model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized) cap
      (partialRandomOracleState (Output := Output (Counter := Counter)) ∅ registers) = 0 := by
  funext basis
  by_cases records : RecordsExactly
      (Output := Output (Counter := Counter)) ∅ basis.database
  · have same := (records_exactly_empty_iff basis.database).mp records
    have outside := empty_not_current_role_event model ns keyBytes counter
      routes role advice outerFuel innerFuel authorized
    simp [project, same, outside]
  · simp [project, partialRandomOracleState, records]

/-- On a bounded state, the unbounded diagonal database-event projector is
exactly the bounded `project` used by the implemented CMS lifting theorem. -/
theorem database_event_projection_eq_project_of_bounded
    {Property : Database Key (Output (Counter := Counter)) → Prop}
    (cap : Nat)
    (state : State Key (Output (Counter := Counter)) Phase Workspace)
    (bounded : BoundedState cap state) :
    databaseEventProjection Property state = project Property cap state := by
  funext basis
  by_cases accepted : Property basis.database
  · by_cases within : size basis.database ≤ cap
    · simp [databaseEventProjection, project, accepted, within]
    · have zero := bounded_state_apply_eq_zero_of_lt bounded basis
          (Nat.lt_of_not_ge within)
      simp [databaseEventProjection, project, accepted, within, zero]
  · simp [databaseEventProjection, project, accepted]
/-- Union of the four literal role events on one database. -/
def anyCurrentRoleEvent
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (advice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte)) :
    Database Key (Output (Counter := Counter)) → Prop :=
  fun database => ∃ role, currentRoleEvent model ns keyBytes counter routes role
    (advice role) outerFuel innerFuel authorized database

/-- The accepted-extraction theorem specialized to the common four-role
event above.  Every premise is parser/readback or protocol acceptance data;
neither disjunct of the conclusion is supplied. -/
theorem accepted_failure_implies_any_current_role_or_claim_failure
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : Namespace) (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (authorized : Finset (List Byte))
    (statement : Statement) (fresh : statement.toBytes ∉ authorized)
    (outerFuel innerFuel : Nat)
    (keys : Role → Key) (vectors : Role → Output (Counter := Counter))
    (claims : List (Key × Output (Counter := Counter)))
    (claimsContainRoles : ∀ role, (keys role, vectors role) ∈ claims)
    (database : Database Key (Output (Counter := Counter)))
    (trace : Trace) (messages : CausalPayloads ns trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (adviceAtStatement : ∀ role, allAdvice role statement = advice role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening)
    (piopResponseRead : strategy.piopResponse coefficients matrix =
      piopResponse messages.piop)
    (claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs)
    (roleQueries : ∀ role, ∃ parsed,
      parseStageQuery (keyBytes (keys role)) = some parsed ∧ parsed.role = role)
    (outerReadback : ∀ role,
      rawTraceDecoder (globalOnlineNext ns)
        (fun key => targetOfRaw role (keyBytes key))
        (fun _ decoded => preambleFromTrace ns role decoded) outerFuel
        (nonleafFilter (globalLeafStatement ns)
          (rawRecords keyBytes (vectorOutputBytes counter) database))
        (keys role) = some statement.toBytes)
    (innerReadback : ∀ role,
      extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (rawRecords keyBytes (vectorOutputBytes counter) database))
        innerFuel (targetOfRaw role (keyBytes (keys role))).1
          (targetOfRaw role (keyBytes (keys role))).2 = causalTrace trace role)
    (decsRead : actualDecsMatrixOutput (routes statement).decsMatrix
      (vectors .decsMatrix) = some coefficients)
    (matrixRead : actualPiopMatrixOutput (routes statement).piopMatrix
      (vectors .piopMatrix) = some matrix)
    (openingRead : actualPiopOpeningOutput (routes statement).piopOpening
      (vectors .piopOpening) = some opening)
    (queryRead : actualDecsSampleOutput (routes statement).decsSample
      (vectors .decsSample) = some query)
    (checks : AcceptedChecks refinement statement (causalOracle ns trace)
      (sourceResponse messages.fpp) strategy coefficients matrix opening query)
    (failed : ExtractionFailure refinement statement (causalOracle ns trace)
      (sourceResponse messages.fpp) coefficients) :
    anyCurrentRoleEvent model ns keyBytes counter routes allAdvice
        outerFuel innerFuel authorized database ∨
      ¬ClaimsDatabaseEvent claims database := by
  exact accepted_failure_current_event_or_claim_failure model refinement ns
    keyBytes counter routes authorized statement fresh outerFuel innerFuel
    keys vectors claims claimsContainRoles database trace messages advice allAdvice
    adviceAtStatement strategy coefficients matrix opening query earlier
    piopResponseRead claimedCoefficientsRead roleQueries outerReadback innerReadback
    decsRead matrixRead openingRead queryRead checks failed

/-- Re-express the deterministic accepted-failure classification in the exact
fixed-advice union event bounded by `common_any_terminal_role_mass_le`.
Together with the preceding theorem this removes the last event-shape seam;
the only alternative is the literal retained-claim failure. -/
theorem any_current_role_or_claim_failure_to_context_union
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : SparseTerminalWorkspace Key Counter BaseWork →
      Finset (List Byte))
    (work : PostVerifierTerminalWork Key Counter BaseWork)
    (database : Database Key (Output (Counter := Counter)))
    (claims : List (Key × Output (Counter := Counter)))
    (classified :
      anyCurrentRoleEvent model ns keyBytes counter routes allAdvice
          outerFuel innerFuel (authorizedOf work.2) database ∨
        ¬ClaimsDatabaseEvent claims database) :
    SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent
        (SmzaRp05ConditionedExecution.CertifiedFor.roleContexts model ns
          keyBytes counter routes allAdvice outerFuel innerFuel authorizedOf)
        work database ∨
      ¬ClaimsDatabaseEvent claims database := by
  rcases classified with current | claimFailure
  · left
    rcases current with ⟨role, roleEvent⟩
    exact ⟨role, roleEvent⟩
  · exact Or.inr claimFailure

/-- Exact diagonal union bound.  All four projectors inspect the same state;
there is no role-conditioned rerun. -/
theorem any_current_role_event_mass_le_sum
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (advice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (state : State Key (Output (Counter := Counter)) Phase Workspace) :
    normSquared
        (databaseEventProjection
          (anyCurrentRoleEvent model ns keyBytes counter routes advice
            outerFuel innerFuel authorized) state) ≤
      ∑ role : Role,
        normSquared
          (databaseEventProjection
            (currentRoleEvent model ns keyBytes counter routes role
              (advice role) outerFuel innerFuel authorized) state) := by
  unfold normSquared anyCurrentRoleEvent databaseEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  by_cases anyRole : ∃ role, currentRoleEvent model ns keyBytes counter
      routes role (advice role) outerFuel innerFuel authorized basis.database
  · obtain ⟨role, selected⟩ := anyRole
    have witness : ∃ chosen : Role,
        currentRoleEvent model ns keyBytes counter routes chosen (advice chosen)
          outerFuel innerFuel authorized basis.database := ⟨role, selected⟩
    have lower := Finset.single_le_sum
      (f := fun chosen : Role => Complex.normSq
        (if currentRoleEvent model ns keyBytes counter routes chosen
          (advice chosen) outerFuel innerFuel authorized basis.database then
            state basis else 0))
      (fun chosen _ => Complex.normSq_nonneg _)
      (Finset.mem_univ role)
    simpa [witness, selected] using lower
  · simp only [if_neg anyRole, Complex.normSq_zero]
    exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)

/-- Full-vector terminal retention is no worse than the 512-bit physical
digest denominator used by the security ledger. -/
theorem terminal_vector_retention_le_digest
    (counter : Counter) (claims queryBound : Nat) (bounded : claims ≤ queryBound) :
    ((2 * claims : Nat) : ℝ) /
        Fintype.card (Output (Counter := Counter)) ≤
      (2 * (queryBound : ℝ)) / (2 : ℝ)^512 := by
  exact (vector_retention_loss_le_digest counter claims).trans
    (by gcongr)

/-- The checked numerical ledger remains below its retained conservative
envelope and below 2^-130 at the production query cap. -/
theorem terminal_ledger_below_130_bits (queries : Nat)
    (bounded : queries ≤ 3 * 2^64) :
    terminalExtractionLoss queries < 1 / (2 : Rat)^130 :=
  terminal_extraction_loss_below_130_bits queries bounded

/-- Fully instantiated numerical closure for the single certified physical
execution.  The common role union is charged once, the complete terminal
measurement contributes one summed retention term, and both are below the
checked `2^-130` RP05 terminal ledger at the production query cap. -/
theorem certified_common_state_terminal_failure_below_130_bits
    (contexts : Role → SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork))
    (selected : ∀ role, (contexts role).role = role)
    {cap finish queries : Nat}
    (skeleton : SmzaRp05ConditionedExecution.PhysicalProgramSkeleton
      (Key := Key) (Counter := Counter)
      (BaseWork := SparseTerminalWorkspace Key Counter BaseWork)
      cap 0 finish queries)
    (certified : SmzaRp05ConditionedExecution.CertifiedFor contexts skeleton)
    (queriesLe : queries ≤ cap) (capLe : cap ≤ 3 * 2^64)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := PostVerifierTerminalWork Key Counter BaseWork) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers))
    (xReads roleReads compression : List Key)
    (roleReadNodup : roleReads.Nodup) (compressionNodup : compression.Nodup)
    (included : ∀ key ∈ roleReads, key ∈ compression)
    (readCountLe : roleReads.length ≤ cap)
    (lookup : Role → V8SmzaOracleParser.RawDigest → LookupNonce → Option Key)
    (xTotal : TotalOn xReads
      (SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers)))
    (roleTotal : TotalOn roleReads
      (SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers))) :
    let commonState :=
      SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState
          (Output := Output (Counter := Counter)) ∅ registers)
    normSquared
        (adaptiveProject
          (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
          cap commonState) +
      (∑ xAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) xReads,
        ∑ roleAnswers : ReadAnswers (Input := Key) (Output (Counter := Counter)) roleReads,
          normSquared
            (claimFailureProjection (branchClaims roleReads roleAnswers)
              (decompressList compression
                (terminalMeasurementBranch xReads roleReads lookup
                  xAnswers roleAnswers commonState)))) <
      1 / (2 : ℝ)^130 := by
  dsimp only
  let initial := partialRandomOracleState
    (Output := Output (Counter := Counter)) ∅ registers
  let commonState :=
    SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run skeleton initial
  have analytic := certified_common_state_roles_and_claim_failure_le
    contexts selected skeleton certified queriesLe registers subnormalized
    xReads roleReads compression roleReadNodup compressionNodup included lookup
    xTotal roleTotal
  have commonSubnormalized : Subnormalized commonState := by
    exact SmzaRp05ConditionedExecution.CertifiedFor.common_run_subnormalized
      certified .decsMatrix subnormalized
  have commonNormNonnegative : 0 ≤ normSquared commonState := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have numeric := common_terminal_rhs_le_terminal_extraction_loss
    (Counter := Counter) (counter := (contexts .decsMatrix).counter)
    cap roleReads.length readCountLe (normSquared commonState)
    commonNormNonnegative commonSubnormalized
  have ledgerReal : ((terminalExtractionLoss cap : Rat) : ℝ) <
      1 / (2 : ℝ)^130 := by
    have ledgerRat := terminal_ledger_below_130_bits cap capLe
    have castLedger : ((terminalExtractionLoss cap : Rat) : ℝ) <
        (((1 / (2 : Rat)^130) : Rat) : ℝ) :=
      (Rat.cast_lt (K := ℝ)).2 ledgerRat
    simpa only [Rat.cast_div, Rat.cast_one, Rat.cast_pow, Rat.cast_ofNat] using
      castLedger
  exact lt_of_le_of_lt (analytic.trans numeric) ledgerReal

end
end HegemonCrypto.SmallWood.SmzaRp05TerminalExtraction
