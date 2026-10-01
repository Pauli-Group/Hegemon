import SmzaRp05CurrentAdaptiveExecution
import SmzaRoleDomainConditioning
import SmzaRoleDomainActiveEmbedding
import SmzaConditionedRoleOracleBound
import SmzaRp05PartialReadout
import SmzaRp05ChallengeRecordErasure
import HegemonCrypto.SmallWoodV8Smz9HonestOpeningSchedule

/-!
# Exact other-role conditioning of the current adaptive execution

For one selected role, `otherRoleTransform` decompresses exactly the bounded
domains of the other three roles.  Selected-role inputs, canonical leaf/X
inputs, malformed inputs, and counters outside the consumed blocks remain in
the compressed CMS database.

The first section constructs the actual fixed-table/active-database split.
The fixed table is not stored in the sparse CMS database, and the earlier
role advice is decoded from that very table.  The selected role and the raw/X
complement are the only inputs of the live CMS query.

The exact total-table ordinary-query connection is
`fixed_active_oracle_family_run_eq_physical`.  On compressed states,
`PhysicalZeroProgram.other_role_transform_run` proves the literal adaptive
mark/write/X-copy induction for one role-independent physical tree.  An
arbitrary `Opcode` kernel is deliberately not conjugated.  What remains
separate is the charged-query isometry from a partially decompressed full-key
CMS state to the fixed-table `ActiveKey` CMS execution.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ConditionedExecution

open scoped BigOperators Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.DatabaseFiber
open SmzaChallengeStageTargets
open SmzaRoleDomainConditioning
open SmzaRp04CompleteRawRoleCells
open SmzaRp05TracePrefixes
open SmzaRp05PartialReadout
open SmzaRp05AdaptiveFilteredCollision
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05AdaptiveKernelInstantiation
open V8Smz9CoherentVectorMerkle
open SmzaRp04RawMcaSampling SmzaRp04RawRoleSampling
open SmzaRp05FilteredDecoderInstability SmzaRp05ChallengeRecordErasure

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false

local notation "Statement" => SmzaRp05StatementNamespace.Statement

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Output := VectorOutput Counter
abbrev Work := SmzaRp05CurrentAdaptiveExecution.Work
  (Counter := Counter) (BaseWork := BaseWork)
abbrev CmsState := State Key (Output (Counter := Counter))
  (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork))

/-- Cap-free CMS query unitary, used after fixed coordinates are moved out of
the sparse support count. -/
def uncappedQuery
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  controlledDecompress (phaseQueryState system (controlledDecompress state))

/-- The finite set placed in fixed advice for the selected role. -/
def fixedOtherKeys
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) : Finset Key :=
  Finset.univ.filter fun key =>
    FixedOtherRole ctx.role blockCap ctx.keyBytes key

@[simp]
theorem mem_fixed_other_keys
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (key : Key) :
    key ∈ fixedOtherKeys ctx blockCap ↔
      FixedOtherRole ctx.role blockCap ctx.keyBytes key := by
  simp [fixedOtherKeys]

/-- Canonical leaf/programming keys remain compressed.  This is the concrete
separation used by every marked-write constructor. -/
theorem canonical_leaf_not_fixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (key : Key) (statement : List Byte)
    (parsed : SmzaRp05FilteredReadback.globalLeafStatement
      ctx.leafNamespace (ctx.keyBytes key) = some statement) :
    key ∉ fixedOtherKeys ctx blockCap := by
  rw [mem_fixed_other_keys]
  unfold FixedOtherRole RoleActive
  rw [SmzaRp05ChallengeRecordErasure.global_leaf_statement_parse_stage_query_none
    ctx.leafNamespace (ctx.keyBytes key) statement parsed]
  simp

/-! ## Actual fixed-table / sparse-active database split -/

abbrev FixedTable
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) :=
  FixedOtherKey ctx.role blockCap ctx.keyBytes → Output (Counter := Counter)

abbrev ActiveDatabase
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) :=
  Database (ActiveKey ctx.role blockCap ctx.keyBytes) (Output (Counter := Counter))

/-- The database split is the role-table split specialized to optional CMS
records.  This is the finite equivalence used by the fixed-fiber isometry;
it does not enumerate either side. -/
def databaseRoleSplit
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) :
    Database Key (Output (Counter := Counter)) ≃
      (ActiveDatabase ctx blockCap ×
        (FixedOtherKey ctx.role blockCap ctx.keyBytes →
          Option (Output (Counter := Counter)))) :=
  roleTableSplit (Output := Option (Output (Counter := Counter)))
    ctx.role blockCap ctx.keyBytes

def fixedSomeTable
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    FixedOtherKey ctx.role blockCap ctx.keyBytes →
      Option (Output (Counter := Counter)) :=
  fun key => some (fixed key)

/-- Reconstruct the semantic full database from a sparse live database and
one total fixed table.  Fixed cells are outside the sparse support count. -/
def mergeFixedActive
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap) :
    Database Key (Output (Counter := Counter)) :=
  fun key =>
    if isActive : RoleActive ctx.role blockCap ctx.keyBytes key then
      active ⟨key, isActive⟩
    else
      some (fixed ⟨key, isActive⟩)

/-- Forget the fixed coordinates. -/
def restrictActive
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (database : Database Key (Output (Counter := Counter))) :
    ActiveDatabase ctx blockCap :=
  fun key => database key.val

/-- A physical database belongs to one fixed other-role table exactly when
every removed coordinate contains that table's value. -/
def fixedFiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (database : Database Key (Output (Counter := Counter))) : Prop :=
  ∀ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
    database key.val = some (fixed key)

@[simp]
theorem database_role_split_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (database : Database Key (Output (Counter := Counter))) :
    (databaseRoleSplit ctx blockCap database).1 =
      restrictActive ctx blockCap database := by
  rfl

@[simp]
theorem database_role_split_merge
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap) :
    (databaseRoleSplit ctx blockCap).symm
        (active, fixedSomeTable ctx blockCap fixed) =
      mergeFixedActive ctx blockCap fixed active := by
  apply (databaseRoleSplit ctx blockCap).injective
  apply Prod.ext
  · funext key
    simp [databaseRoleSplit, mergeFixedActive, key.property]
  · funext key
    have inactive : ¬ RoleActive ctx.role blockCap ctx.keyBytes key.val := by
      simpa only [FixedOtherRole] using key.property
    simp [databaseRoleSplit, fixedSomeTable, mergeFixedActive, inactive]

@[simp]
theorem restrict_merge_fixed_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap) :
    restrictActive ctx blockCap (mergeFixedActive ctx blockCap fixed active) = active := by
  funext key
  simp [restrictActive, mergeFixedActive, key.property]

@[simp]
theorem merge_fixed_active_at_fixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (key : FixedOtherKey ctx.role blockCap ctx.keyBytes) :
    mergeFixedActive ctx blockCap fixed active key.val = some (fixed key) := by
  have inactive : ¬RoleActive ctx.role blockCap ctx.keyBytes key.val := key.property
  simp [mergeFixedActive, inactive]

@[simp]
theorem merge_fixed_active_at_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (key : ActiveKey ctx.role blockCap ctx.keyBytes) :
    mergeFixedActive ctx blockCap fixed active key.val = active key := by
  simp [mergeFixedActive, key.property]

@[simp]
theorem merge_fixed_active_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap) :
    fixedFiber ctx blockCap fixed
      (mergeFixedActive ctx blockCap fixed active) := by
  intro key
  exact merge_fixed_active_at_fixed ctx blockCap fixed active key

theorem merge_restrict_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (database : Database Key (Output (Counter := Counter)))
    (fiber : fixedFiber ctx blockCap fixed database) :
    mergeFixedActive ctx blockCap fixed
        (restrictActive ctx blockCap database) = database := by
  funext key
  by_cases active : RoleActive ctx.role blockCap ctx.keyBytes key
  · simp [mergeFixedActive, restrictActive, active]
  · exact (merge_fixed_active_at_fixed ctx blockCap fixed
      (restrictActive ctx blockCap database) ⟨key, active⟩).trans
      (fiber ⟨key, active⟩).symm

theorem merge_set_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (database : ActiveDatabase ctx blockCap)
    (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (coordinate : Option (Output (Counter := Counter))) :
    mergeFixedActive ctx blockCap fixed
        (setDatabaseCoordinate database key coordinate) =
      setDatabaseCoordinate (mergeFixedActive ctx blockCap fixed database)
        key.val coordinate := by
  funext other
  by_cases same : other = key.val
  · subst other
    simp [mergeFixedActive, key.property]
  · by_cases active : RoleActive ctx.role blockCap ctx.keyBytes other
    · have different : (⟨other, active⟩ :
          ActiveKey ctx.role blockCap ctx.keyBytes) ≠ key := by
        intro equality
        exact same (congrArg Subtype.val equality)
      simp [mergeFixedActive, active, setDatabaseCoordinate, same, different]
    · simp [mergeFixedActive, active, setDatabaseCoordinate, same]

/-- Every retained selected-role/X claim is reconstructed literally from the
active database; the fixed table cannot shadow it. -/
theorem merge_fixed_active_claim_readback
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (claims : List (ActiveKey ctx.role blockCap ctx.keyBytes ×
      Output (Counter := Counter))) :
    (∀ claim ∈ claims,
      mergeFixedActive ctx blockCap fixed active claim.1.val = some claim.2) ↔
      ∀ claim ∈ claims, active claim.1 = some claim.2 := by
  simp

/-- Decode one earlier-role vector using the actual raw role readers. -/
def decodeEarlierVector
    (model : RelationModel) (routes : TypedRoutes model Counter)
    (statement : Statement) (role : Role)
    (vector : Output (Counter := Counter)) :
    Option (RoleOutput model statement role) :=
  match role with
  | .decsMatrix => actualDecsMatrixOutput (routes statement).decsMatrix vector
  | .piopMatrix => actualPiopMatrixOutput (routes statement).piopMatrix vector
  | .piopOpening => actualPiopOpeningOutput (routes statement).piopOpening vector
  | .decsSample => actualDecsSampleOutput (routes statement).decsSample vector

/-- Select the fixed vector at the grouped cell's counter-zero representative
and one exact parsed nonce.  The remaining vector coordinates are inside this
one `VectorOutput`; they are not separate candidate fixed keys.  For the three
non-opening roles the parser sets `nonce = 0`.  Opening advice is obtained by
the source's literal first-successful nonce scan. -/
def fixedVectorAtNonce
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (role : Role) (target : V8SmzaOracleParser.RawDigest) (nonce : Nat) :
    Option (Output (Counter := Counter)) := by
  classical
  exact if found : ∃ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      ∃ parsed, parseStageQuery (ctx.keyBytes key.val) = some parsed ∧
        parsed.role = role ∧ parsed.target = target ∧ parsed.nonce = nonce ∧
          parsed.counter = 0 then
    some (fixed (Classical.choose found))
  else none

/-- A successful lookup really selects a bounded fixed-role base key.  This
receipt deliberately does not claim that parser fields identify a unique key:
`Context.keyBytes` is allowed to have aliases. -/
theorem fixed_vector_at_nonce_has_base_key
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (role : Role) (target : V8SmzaOracleParser.RawDigest) (nonce : Nat)
    (value : Output (Counter := Counter))
    (read : fixedVectorAtNonce ctx blockCap fixed role target nonce = some value) :
    ∃ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      ∃ parsed, parseStageQuery (ctx.keyBytes key.val) = some parsed ∧
        parsed.role = role ∧ parsed.target = target ∧ parsed.nonce = nonce ∧
        parsed.counter = 0 ∧ fixed key = value := by
  classical
  by_cases found : ∃ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      ∃ parsed, parseStageQuery (ctx.keyBytes key.val) = some parsed ∧
        parsed.role = role ∧ parsed.target = target ∧ parsed.nonce = nonce ∧
          parsed.counter = 0
  · obtain ⟨parsed, parsedAt, sameRole, sameTarget, sameNonce, base⟩ :=
      Classical.choose_spec found
    have valueEq : fixed (Classical.choose found) = value := by
      exact Option.some.inj (by simpa only [fixedVectorAtNonce, dif_pos found] using read)
    exact ⟨Classical.choose found, parsed, parsedAt, sameRole, sameTarget,
      sameNonce, base, valueEq⟩
  · simp only [fixedVectorAtNonce, dif_neg found] at read
    contradiction

/-- First successful optional value in the supplied order.  This is kept
local rather than using a choice operator, so the ordering evidence remains
visible to later readback lemmas. -/
def firstSome {Index Value : Type*} (read : Index → Option Value) :
    List Index → Option Value
  | [] => none
  | index :: remaining =>
      match read index with
      | some value => some value
      | none => firstSome read remaining

theorem firstSome_append_selected
    {Index Value : Type*} (read : Index → Option Value)
    (before after : List Index) (selected : Index) (value : Value)
    (prior : ∀ index ∈ before, read index = none)
    (atSelected : read selected = some value) :
    firstSome read (before ++ selected :: after) = some value := by
  induction before with
  | nil => simp [firstSome, atSelected]
  | cons head tail inductionHypothesis =>
      rw [List.cons_append, firstSome, prior head (by simp)]
      exact inductionHypothesis (fun index member => prior index (by simp [member]))

/-- The exact source nonce order `0,...,15`.  It is the same list used by
`V8Smz9HonestOpeningSchedule.sourceChooseOpening`; all failed attempts remain
ordinary fixed-table reads and are therefore already included in `T`. -/
def canonicalOpeningNonceOrder : List (Fin 16) := List.ofFn id

/-- Deterministic acceptance data produced by the actual source verifier:
the transmitted nonce is exactly the nonce returned by the literal
`sourceChooseOpening` program over the physical raw-oracle table.  This is
not an advice-equality or a cryptographic premise; the runtime verifier's
canonical-nonce check is represented by this equality. -/
structure SourceVerifierOpeningAccepted
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : V8Smz9HiddenLeafQrom.DigestRegister) (pending : Bool)
    (oracle : V8Smz9HonestFinalGame.OtherRawInput bound →
      V8Smz9HiddenLeafQrom.DigestRegister)
    (transmitted : Fin 16) : Type where
  words : List SmallWoodTranscript.FieldWord
  selected :
    (V8Smz9HonestRequestSchedule.NonleafProgram.interpret oracle
      (V8Smz9HonestOpeningSchedule.sourceChooseOpening bound largeEnough
        digest pending)).selected = some (transmitted, words)

theorem source_verifier_opening_accepted_valid
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : V8Smz9HiddenLeafQrom.DigestRegister) (pending : Bool)
    (oracle : V8Smz9HonestFinalGame.OtherRawInput bound →
      V8Smz9HiddenLeafQrom.DigestRegister)
    (transmitted : Fin 16)
    (accepted : SourceVerifierOpeningAccepted bound largeEnough digest pending
      oracle transmitted) :
    accepted.words.length = 6 ∧
      V8Smz9HonestOpeningSchedule.SourceOpeningAdmissible
        (V8Smz9HonestOpeningSchedule.sourcePointVector accepted.words) := by
  exact V8Smz9HonestOpeningSchedule.source_selected_opening_is_valid
    bound largeEnough digest pending oracle transmitted accepted.words
      accepted.selected

/-- Decode the first successful opening in canonical nonce order from the
same fixed table used by the fixed-domain phase oracle.  A missing grouped
key or a decoder failure is an unsuccessful attempt; exhaustion is
fail-closed. -/
def fixedCanonicalOpeningAt
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (statement : Statement) (target : V8SmzaOracleParser.RawDigest) :
    Option (RoleOutput ctx.model statement .piopOpening) :=
  firstSome
    (fun nonce =>
      (fixedVectorAtNonce ctx blockCap fixed .piopOpening target nonce.val).bind
        (actualPiopOpeningOutput (ctx.routes statement).piopOpening))
    canonicalOpeningNonceOrder

@[simp]
theorem fixed_canonical_opening_at_is_literal_scan
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (statement : Statement) (target : V8SmzaOracleParser.RawDigest) :
    fixedCanonicalOpeningAt ctx blockCap fixed statement target =
      firstSome
        (fun nonce : Fin 16 =>
          (fixedVectorAtNonce ctx blockCap fixed .piopOpening target nonce.val).bind
            (actualPiopOpeningOutput (ctx.routes statement).piopOpening))
        (List.ofFn id) := by
  rfl

/-- Readback-facing form of canonicality.  A source-verifier proof supplies
the prefix split, failures of every earlier nonce, and success at the
transmitted nonce; this lemma then identifies fixed-table advice without an
assumed advice equality. -/
theorem fixed_canonical_opening_at_eq_of_prior_failures
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (statement : Statement) (target : V8SmzaOracleParser.RawDigest)
    (before after : List (Fin 16)) (transmitted : Fin 16)
    (opening : RoleOutput ctx.model statement .piopOpening)
    (nonceOrder : canonicalOpeningNonceOrder = before ++ transmitted :: after)
    (prior : ∀ nonce ∈ before,
      (fixedVectorAtNonce ctx blockCap fixed .piopOpening target nonce.val).bind
          (actualPiopOpeningOutput (ctx.routes statement).piopOpening) = none)
    (selected :
      (fixedVectorAtNonce ctx blockCap fixed .piopOpening target transmitted.val).bind
          (actualPiopOpeningOutput (ctx.routes statement).piopOpening) = some opening) :
    fixedCanonicalOpeningAt ctx blockCap fixed statement target = some opening := by
  unfold fixedCanonicalOpeningAt
  rw [nonceOrder]
  exact firstSome_append_selected _ before after transmitted opening prior selected

/-- Decode one earlier-table value.  The opening case is deliberately
different from the other roles: it runs the complete canonical nonce scan. -/
def fixedDecodedAt
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (statement : Statement) (role : Role)
    (target : V8SmzaOracleParser.RawDigest) :
    Option (RoleOutput ctx.model statement role) :=
  match role with
  | .decsMatrix =>
      (fixedVectorAtNonce ctx blockCap fixed .decsMatrix target 0).bind
        (actualDecsMatrixOutput (ctx.routes statement).decsMatrix)
  | .piopMatrix =>
      (fixedVectorAtNonce ctx blockCap fixed .piopMatrix target 0).bind
        (actualPiopMatrixOutput (ctx.routes statement).piopMatrix)
  | .piopOpening => fixedCanonicalOpeningAt ctx blockCap fixed statement target
  | .decsSample =>
      (fixedVectorAtNonce ctx blockCap fixed .decsSample target 0).bind
        (actualDecsSampleOutput (ctx.routes statement).decsSample)

/-- Earlier-role advice is a deterministic read of the same fixed table that
supplies fixed-role phase queries.  There is no independent advice input and
no arbitrary choice of an opening nonce. -/
def fixedAdvice
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    AllEarlierTables ctx.model ctx.role :=
  fun statement earlier _ target =>
    fixedDecodedAt ctx blockCap fixed statement earlier target

def contextAtFixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  { ctx with advice := fixedAdvice ctx blockCap fixed }

/-- Removing every challenge-role record is exact for both outer and inner
global decoders.  Therefore moving the fixed three role domains out of the
CMS database does not change a current label; their semantic contribution is
only `fixedAdvice`. -/
theorem fixed_challenge_records_decoder_inert
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (records : V8Smz9CoherentMerkleGeometry.Records
      V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (view : V8SmzaOracleParser.RawInput → Prop)
    (fuel : Nat) (stage : V8SmzaOracleParser.Stage)
    (target : V8SmzaOracleParser.RawDigest) :
    V8Smz9CoherentMerkleGeometry.extract
        (SmzaRp05FilteredDecoderInstability.globalOnlineNext ctx.leafNamespace)
        ((SmzaRp05ChallengeRecordErasure.eraseChallengeRecords records).filter
          fun record => view record.1) fuel stage target =
      V8Smz9CoherentMerkleGeometry.extract
        (SmzaRp05FilteredDecoderInstability.globalOnlineNext ctx.leafNamespace)
        (records.filter fun record => view record.1) fuel stage target := by
  exact SmzaRp05ChallengeRecordErasure.global_extract_filtered_erase_challenge
    ctx.leafNamespace records view fuel stage target

/-! ## Literal sparse query with fixed-role private phase -/

abbrev ActiveMemory
    (_ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :=
  ActiveRouteMemory Key (Output (Counter := Counter))
    (Work (Counter := Counter) (BaseWork := BaseWork))

abbrev ActiveState
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) :=
  State (ActiveKey ctx.role blockCap ctx.keyBytes) (Output (Counter := Counter))
    (Output (Counter := Counter)) (ActiveMemory ctx)

/-- Restrict one physical fixed-table fiber to the live `ActiveKey` CMS
database and route the original full query registers into private memory.
The fixed table used here is exactly the second component of
`databaseRoleSplit`; no populated fixed coordinate remains in the live
database or its support count. -/
def fixedFiberToActive
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    ActiveState ctx blockCap :=
  fun target =>
    activeRegisterEmbed vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (databaseSlice state
        (mergeFixedActive ctx blockCap fixed target.database))
      (basisRegisters target)

/-- Embed a routed sparse state back into the physical fixed-table fiber.
Off that fiber the amplitude is zero. -/
def activeToFixedFiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : ActiveState ctx blockCap) :
    CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  fun target =>
    if fixedFiber ctx blockCap fixed target.database then
      activeRegisterRestrict vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
        (databaseSlice state (restrictActive ctx blockCap target.database))
        (basisRegisters target)
    else 0

def RoutedActiveState
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (state : ActiveState ctx blockCap) : Prop :=
  ∀ basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (Output (Counter := Counter)) (Output (Counter := Counter)) (ActiveMemory ctx),
    ¬OnActiveRoute vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (basisRegisters basis) → state basis = 0

def fixedFiberProjection
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  fun basis => if fixedFiber ctx blockCap fixed basis.database then state basis else 0

theorem fixed_fiber_to_active_routed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    RoutedActiveState ctx blockCap dummy
      (fixedFiberToActive ctx blockCap dummy fixed state) := by
  intro basis offRoute
  simp [fixedFiberToActive, activeRegisterEmbed, offRoute]

@[simp]
theorem fixed_fiber_to_active_to_fixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : ActiveState ctx blockCap)
    (routed : RoutedActiveState ctx blockCap dummy state) :
    fixedFiberToActive ctx blockCap dummy fixed
        (activeToFixedFiber ctx blockCap dummy fixed state) = state := by
  funext target
  by_cases onRoute : OnActiveRoute vectorPhaseSystem ctx.role blockCap
      ctx.keyBytes dummy (basisRegisters target)
  · simp [fixedFiberToActive, activeRegisterEmbed, onRoute, databaseSlice,
      activeToFixedFiber, merge_fixed_active_fiber,
      restrict_merge_fixed_active, activeRegisterRestrict]
    exact congrArg (fun register : RegisterBasis
        (Input := ActiveKey ctx.role blockCap ctx.keyBytes)
        (Phase := Output (Counter := Counter)) (Workspace := ActiveMemory ctx) => state
      { input := register.1, phase := register.2.1,
        workspace := register.2.2, database := target.database })
      (by simpa [basisRegisters] using onRoute.symm)
  · simp [fixedFiberToActive, activeRegisterEmbed, onRoute,
      routed target onRoute]

@[simp]
theorem active_to_fixed_fiber_to_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    activeToFixedFiber ctx blockCap dummy fixed
        (fixedFiberToActive ctx blockCap dummy fixed state) =
      fixedFiberProjection ctx blockCap fixed state := by
  funext target
  by_cases fiber : fixedFiber ctx blockCap fixed target.database
  · have merged := merge_restrict_active
      ctx blockCap fixed target.database fiber
    simp [activeToFixedFiber, fixedFiberProjection, fiber,
      activeRegisterRestrict, fixedFiberToActive, databaseSlice, merged,
      basisRegisters]
  · simp [activeToFixedFiber, fixedFiberProjection, fiber]

theorem uncapped_query_preserves_routed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (state : ActiveState ctx blockCap)
    (routed : RoutedActiveState ctx blockCap dummy state) :
    RoutedActiveState ctx blockCap dummy
      (uncappedQuery vectorPhaseSystem state) := by
  intro target offRoute
  unfold uncappedQuery controlledDecompress
  rw [decompress_at_eq_sum_kernel]
  apply Finset.sum_eq_zero
  intro outer _
  apply mul_eq_zero_of_left
  unfold phaseQueryState
  dsimp only
  rw [decompress_at_eq_sum_kernel]
  apply mul_eq_zero_of_right
  apply Finset.sum_eq_zero
  intro inner _
  apply mul_eq_zero_of_left
  apply routed
  simpa only [basisRegisters] using offRoute

/-- Local-kernel factoring at one live coordinate.  The proof expands the
two decompression matrices and uses `merge_set_active_coordinate`; fixed
records are spectators and therefore never enter the sparse support. -/
theorem fixed_fiber_to_active_decompress_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed
        (decompressAt key.val state) =
      decompressAt key (fixedFiberToActive ctx blockCap dummy fixed state) := by
  funext target
  by_cases routed : OnActiveRoute vectorPhaseSystem ctx.role blockCap
      ctx.keyBytes dummy (basisRegisters target)
  · unfold fixedFiberToActive activeRegisterEmbed databaseSlice
    simp only [routed, if_true]
    rw [decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro coordinate _
    rw [merge_set_active]
    simp [basisRegisters, merge_fixed_active_at_active]
    intro offRoute
    exact False.elim (offRoute (by simpa only [basisRegisters] using routed))
  · unfold fixedFiberToActive activeRegisterEmbed
    simp only [routed, if_false]
    rw [decompress_at_eq_sum_kernel]
    symm
    apply Finset.sum_eq_zero
    intro coordinate _
    have stillOff : ¬OnActiveRoute vectorPhaseSystem ctx.role blockCap
        ctx.keyBytes dummy
        (basisRegisters
          { input := target.input
            phase := target.phase
            workspace := target.workspace
            database := setDatabaseCoordinate target.database key coordinate }) := by
      simpa only [basisRegisters] using routed
    simp [stillOff]

/-- One actual sparse query.  The first map is the real vector CMS query on
`ActiveKey`; the second is a database-independent phase evaluated from the
same fixed table. -/
def fixedActiveQuery
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (cap : Nat)
    (state : ActiveState ctx blockCap) : ActiveState ctx blockCap :=
  (transportContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
    (fixedOtherPhaseContraction vectorPhaseSystem ctx.role blockCap
      ctx.keyBytes fixed)).apply
    (cappedQueryState vectorPhaseSystem cap state)

def fixedActiveUncappedQuery
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : ActiveState ctx blockCap) : ActiveState ctx blockCap :=
  (transportContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
    (fixedOtherPhaseContraction vectorPhaseSystem ctx.role blockCap
      ctx.keyBytes fixed)).apply
    (uncappedQuery vectorPhaseSystem state)

theorem fixed_active_uncapped_query_preserves_routed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : ActiveState ctx blockCap)
    (_routed : RoutedActiveState ctx blockCap dummy state) :
    RoutedActiveState ctx blockCap dummy
      (fixedActiveUncappedQuery ctx blockCap dummy fixed state) := by
  intro target offRoute
  unfold fixedActiveUncappedQuery DatabaseIndependentContraction.apply
    liftRegisterKernel
  apply Finset.sum_eq_zero
  intro source _
  apply mul_eq_zero_of_right
  change transportedKernel vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (fixedOtherPhaseContraction vectorPhaseSystem ctx.role blockCap
        ctx.keyBytes fixed) source (basisRegisters target) = 0
  simp [transportedKernel, offRoute]

/-- Concrete fixed-fiber query operator obtained by the explicit sparse
isometry.  Unlike the rejected gauge definition, both maps are the
`databaseRoleSplit`/`activeRouteBasis` maps above and the middle operator is
the actual `ActiveKey` CMS query plus same-table fixed phase. -/
def fixedFiberUncappedQuery
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  activeToFixedFiber ctx blockCap dummy fixed
    (fixedActiveUncappedQuery ctx blockCap dummy fixed
      (fixedFiberToActive ctx blockCap dummy fixed state))

@[simp]
theorem fixed_fiber_query_restrict
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed
        (fixedFiberUncappedQuery ctx blockCap dummy fixed state) =
      fixedActiveUncappedQuery ctx blockCap dummy fixed
        (fixedFiberToActive ctx blockCap dummy fixed state) := by
  unfold fixedFiberUncappedQuery
  apply fixed_fiber_to_active_to_fixed
  exact fixed_active_uncapped_query_preserves_routed ctx blockCap dummy fixed _
    (fixed_fiber_to_active_routed ctx blockCap dummy fixed state)

theorem fixed_active_query_eq_uncapped_of_bounded
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (cap occupied : Nat)
    (state : ActiveState ctx blockCap)
    (room : occupied < cap) (bounded : BoundedState occupied state) :
    fixedActiveQuery ctx blockCap dummy fixed cap state =
      fixedActiveUncappedQuery ctx blockCap dummy fixed state := by
  unfold fixedActiveQuery fixedActiveUncappedQuery
  rw [capped_query_state_eq_query_state_of_bounded_lt
    vectorPhaseSystem cap occupied state room bounded]
  rw [query_state_eq_controlled_decompression_phase vectorPhaseSystem cap state
    (bounded_state_strict_support bounded room)]
  rfl

/-- Total-active-table readback of `fixedActiveQuery`: the live phase is the
ordinary active-table phase and the fixed phase is supplied privately. -/
theorem fixed_active_total_query_register
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (active : ActiveKey ctx.role blockCap ctx.keyBytes → Output (Counter := Counter))
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    (transportContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (fixedOtherPhaseContraction vectorPhaseSystem ctx.role blockCap
        ctx.keyBytes fixed)).applyRegister
      (phaseRegisterState vectorPhaseSystem active
        (activeRegisterEmbed vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
          registers)) =
      activeRegisterEmbed vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
        ((fixedOtherPhaseContraction vectorPhaseSystem ctx.role blockCap
          ctx.keyBytes fixed).applyRegister
          (liveRolePhaseRegisterState vectorPhaseSystem ctx.role blockCap
            ctx.keyBytes active registers)) := by
  rw [active_phase_query_embed,
    transport_contraction_applyRegister_embed]

/-- Exact execution bridge for every ordinary-query / database-independent
segment of the current verifier.  The left side is the real `ActiveKey`
oracle run with the fixed-role phase compiled into a private contraction;
the right side is the original full-oracle run at the table reconstructed
from the same active and fixed components.  This is the checked intertwining
theorem, not a caller-supplied run equality. -/
theorem fixed_active_oracle_family_run_eq_physical
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := Output (Counter := Counter))
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork))))
    (family : (Key → Output (Counter := Counter)) →
      RegisterBasis (Input := Key) (Phase := Output (Counter := Counter))
        (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (active : ActiveKey ctx.role blockCap ctx.keyBytes →
      Output (Counter := Counter)) :
    oracleFamilyRun vectorPhaseSystem
        (activeConditionedSteps vectorPhaseSystem ctx.role blockCap ctx.keyBytes
          dummy fixed steps)
        (fun live =>
          activeRegisterEmbed vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
            (family ((roleTableSplit ctx.role blockCap ctx.keyBytes).symm
              (live, fixed)))) active =
      activeRegisterEmbed vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
        (oracleFamilyRun vectorPhaseSystem steps family
          ((roleTableSplit ctx.role blockCap ctx.keyBytes).symm
            (active, fixed))) := by
  exact active_oracle_family_run_eq_full_embed vectorPhaseSystem ctx.role
    blockCap ctx.keyBytes dummy fixed steps family active

/-! ## Fixed-fiber preservation for the actual adaptive updates

The former draft defined an arbitrary full-state map and pulled it back to
the active database.  That is not a valid execution bridge: an arbitrary
kernel may inspect the removed table and its full-database boundedness proof
counts the populated fixed coordinates.  The facts below instead record the
literal property needed by the actual mark/write/copy constructors. -/

theorem fixed_fiber_iff_split_fixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (database : Database Key (Output (Counter := Counter))) :
    fixedFiber ctx blockCap fixed database ↔
      (databaseRoleSplit ctx blockCap database).2 =
        fixedSomeTable ctx blockCap fixed := by
  constructor
  · intro fiber
    funext key
    exact fiber key
  · intro same key
    exact congrFun same key

@[simp]
theorem merge_fixed_active_fixed_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap) :
    fixedFiber ctx blockCap fixed
      (mergeFixedActive ctx blockCap fixed active) := by
  intro key
  exact merge_fixed_active_at_fixed ctx blockCap fixed active key

theorem merge_restrict_active_of_fixed_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (database : Database Key (Output (Counter := Counter)))
    (fiber : fixedFiber ctx blockCap fixed database) :
    mergeFixedActive ctx blockCap fixed
        (restrictActive ctx blockCap database) = database := by
  funext key
  by_cases active : RoleActive ctx.role blockCap ctx.keyBytes key
  · simp [mergeFixedActive, restrictActive, active]
  · exact (merge_fixed_active_at_fixed ctx blockCap fixed
      (restrictActive ctx blockCap database) ⟨key, active⟩).trans
      (fiber ⟨key, active⟩).symm

theorem merge_set_active_coordinate
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (database : ActiveDatabase ctx blockCap)
    (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (coordinate : Option (Output (Counter := Counter))) :
    mergeFixedActive ctx blockCap fixed
        (setDatabaseCoordinate database key coordinate) =
      setDatabaseCoordinate (mergeFixedActive ctx blockCap fixed database)
        key.val coordinate := by
  exact merge_set_active ctx blockCap fixed database key coordinate

theorem restrict_set_active_coordinate
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (database : Database Key (Output (Counter := Counter)))
    (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (coordinate : Option (Output (Counter := Counter))) :
    restrictActive ctx blockCap
        (setDatabaseCoordinate database key.val coordinate) =
      setDatabaseCoordinate (restrictActive ctx blockCap database) key coordinate := by
  funext other
  by_cases same : other = key
  · subst other
    simp [restrictActive, setDatabaseCoordinate]
  · have valuesDifferent : other.val ≠ key.val := by
      intro equal
      apply same
      exact Subtype.ext equal
    simp [restrictActive, setDatabaseCoordinate, same, valuesDifferent]

theorem canonical_leaf_is_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (key : Key) (statement : List Byte)
    (parsed : SmzaRp05FilteredReadback.globalLeafStatement
      ctx.leafNamespace (ctx.keyBytes key) = some statement) :
    RoleActive ctx.role blockCap ctx.keyBytes key := by
  by_contra inactive
  apply canonical_leaf_not_fixed ctx blockCap key statement parsed
  rw [mem_fixed_other_keys]
  exact inactive

theorem fixed_fiber_preserved_by_active_coordinate
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (source target : Database Key (Output (Counter := Counter)))
    (key : Key) (active : RoleActive ctx.role blockCap ctx.keyBytes key)
    (sameOutside : ∀ other, other ≠ key → source other = target other)
    (sourceFiber : fixedFiber ctx blockCap fixed source) :
    fixedFiber ctx blockCap fixed target := by
  intro fixedKey
  have different : fixedKey.val ≠ key := by
    intro equal
    apply fixedKey.property
    simpa only [equal] using active
  exact (sameOutside fixedKey.val different).symm.trans (sourceFiber fixedKey)

/-- A literal marked canonical-leaf write cannot enter a removed role table.
This covers insertion, deletion, and retained-old replacement because only
equality away from the addressed key is used. -/
theorem marked_leaf_update_preserves_fixed_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (source target : Database Key (Output (Counter := Counter)))
    (key : Key) (statement : List Byte)
    (parsed : SmzaRp05FilteredReadback.globalLeafStatement
      ctx.leafNamespace (ctx.keyBytes key) = some statement)
    (sameOutside : ∀ other, other ≠ key → source other = target other)
    (sourceFiber : fixedFiber ctx blockCap fixed source) :
    fixedFiber ctx blockCap fixed target :=
  fixed_fiber_preserved_by_active_coordinate ctx blockCap fixed source target key
    (canonical_leaf_is_active ctx blockCap key statement parsed)
    sameOutside sourceFiber

theorem unchanged_database_preserves_fixed_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (source target : Database Key (Output (Counter := Counter)))
    (same : target = source) (sourceFiber : fixedFiber ctx blockCap fixed source) :
    fixedFiber ctx blockCap fixed target := by
  simpa only [same] using sourceFiber

/-! ## Active adaptive program with the retained slot in the right place -/

/-- After routing a full-key query into private memory, reassociate that
memory so the retained-old answer remains the outer `Option` expected by the
actual adaptive programming kernel.  The query input and phase are retained
in the base workspace and are never discarded. -/
structure RoutedBaseMemory (Key Counter BaseWork : Type) where
  queryInput : Key
  queryPhase : Output (Counter := Counter)
  base : BaseWork
deriving Fintype, DecidableEq

abbrev RoutedWork (Key Counter BaseWork : Type) :=
  Work (Counter := Counter)
    (BaseWork := RoutedBaseMemory Key Counter BaseWork)

def activeMemoryEquiv
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    ActiveMemory ctx ≃ RoutedWork Key Counter BaseWork where
  toFun memory :=
    (memory.original.2.2.1,
      ⟨memory.original.1, memory.original.2.1, memory.original.2.2.2⟩)
  invFun memory :=
    ⟨(memory.2.queryInput, memory.2.queryPhase,
      (memory.1, memory.2.base))⟩
  left_inv memory := by cases memory; rfl
  right_inv memory := by rcases memory with ⟨retained, input, phase, base⟩; rfl

def registerWorkspaceEquiv
    {Input Phase Left Right : Type*} (equivalence : Left ≃ Right) :
    RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Left) ≃
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Right) where
  toFun basis := (basis.1, basis.2.1, equivalence basis.2.2)
  invFun basis := (basis.1, basis.2.1, equivalence.symm basis.2.2)
  left_inv basis := by rcases basis with ⟨input, phase, workspace⟩; simp
  right_inv basis := by rcases basis with ⟨input, phase, workspace⟩; simp

def basisWorkspaceEquiv
    {Input Output Phase Left Right : Type*} (equivalence : Left ≃ Right) :
    Basis Input Output Phase Left ≃ Basis Input Output Phase Right where
  toFun basis :=
    { input := basis.input, phase := basis.phase
      workspace := equivalence basis.workspace, database := basis.database }
  invFun basis :=
    { input := basis.input, phase := basis.phase
      workspace := equivalence.symm basis.workspace, database := basis.database }
  left_inv basis := by cases basis; simp
  right_inv basis := by cases basis; simp

def reindexWorkspaceState
    {Input Output Phase Left Right : Type*} (equivalence : Left ≃ Right)
    (state : State Input Output Phase Left) : State Input Output Phase Right :=
  fun basis => state ((basisWorkspaceEquiv equivalence).symm basis)

theorem reindex_workspace_state_norm_squared
    {Input Output Phase Left Right : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Left] [DecidableEq Left]
    [Fintype Right] [DecidableEq Right]
    (equivalence : Left ≃ Right) (state : State Input Output Phase Left) :
    normSquared (reindexWorkspaceState equivalence state) = normSquared state := by
  unfold normSquared reindexWorkspaceState
  exact (basisWorkspaceEquiv (Input := Input) (Output := Output)
    (Phase := Phase) equivalence).symm.sum_comp
      (fun basis => Complex.normSq (state basis))

@[simp]
theorem reindex_workspace_state_symm
    {Input Output Phase Left Right : Type*} (equivalence : Left ≃ Right)
    (state : State Input Output Phase Left) :
    reindexWorkspaceState equivalence.symm
      (reindexWorkspaceState equivalence state) = state := by
  funext basis
  simp [reindexWorkspaceState, basisWorkspaceEquiv]

/-- Conjugate a database-independent gate through a workspace
reassociation.  This preserves its literal kernel and norm contraction; no
event or execution equality is supplied by a caller. -/
def reindexWorkspaceContraction
    {Input Output Phase Left Right : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Left] [DecidableEq Left]
    [Fintype Right] [DecidableEq Right]
    (equivalence : Left ≃ Right)
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Left)) :
    DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Right) where
  kernel := fun source target =>
    step.kernel ((registerWorkspaceEquiv equivalence).symm source)
      ((registerWorkspaceEquiv equivalence).symm target)
  contractive := by
    intro state
    let pulled := reindexWorkspaceState equivalence.symm state
    have recovered : reindexWorkspaceState equivalence pulled = state := by
      simpa [pulled] using reindex_workspace_state_symm equivalence.symm state
    rw [← recovered]
    rw [show liftRegisterKernel
          (fun source target =>
            step.kernel ((registerWorkspaceEquiv equivalence).symm source)
              ((registerWorkspaceEquiv equivalence).symm target))
          (reindexWorkspaceState equivalence pulled) =
        reindexWorkspaceState equivalence (step.apply pulled) by
      funext target
      unfold reindexWorkspaceState DatabaseIndependentContraction.apply
        liftRegisterKernel basisWorkspaceEquiv registerWorkspaceEquiv
      rw [← (registerWorkspaceEquiv equivalence).symm.sum_comp]
      rfl]
    apply state_norm_le_of_norm_squared_le
    rw [reindex_workspace_state_norm_squared,
      reindex_workspace_state_norm_squared]
    have squared := (sq_le_sq₀
      (state_norm_nonnegative (step.apply pulled))
      (state_norm_nonnegative pulled)).2 (step.contractive pulled)
    simpa only [state_norm_sq_eq_norm_squared] using squared

/-- Actual fixed-table transport of one role-independent private gate into
the re-associated sparse workspace used by `activeContext`. -/
def routedPrivateContraction
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := Output (Counter := Counter))
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork))) :
    DatabaseIndependentContraction
      (Input := ActiveKey ctx.role blockCap ctx.keyBytes)
      (Output := Output (Counter := Counter))
      (Phase := Output (Counter := Counter))
      (Workspace := RoutedWork Key Counter BaseWork) :=
  reindexWorkspaceContraction (activeMemoryEquiv ctx)
    (transportContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy step)

/-- The role-specific context used by the sparse adaptive telescope.  Its
database contains only `ActiveKey`; its advice is computed from `fixed`; and
authorization is read from the unchanged original base workspace. -/
def activeContext
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    Context (Key := ActiveKey ctx.role blockCap ctx.keyBytes)
      (Counter := Counter) (BaseWork := RoutedBaseMemory Key Counter BaseWork) where
  model := ctx.model
  leafNamespace := ctx.leafNamespace
  keyBytes := fun key => ctx.keyBytes key.val
  counter := ctx.counter
  routes := ctx.routes
  role := ctx.role
  advice := fixedAdvice ctx blockCap fixed
  outerFuel := ctx.outerFuel
  innerFuel := ctx.innerFuel
  authorizedOf := fun memory => ctx.authorizedOf memory.base

/-- Numerical adaptive endpoint on the correctly sparse database.  The
input is raw `ActualProgram` syntax, so all mark/write/copy support proofs are
compiled by `CurrentAdaptiveExecution`; no certified program or probability
bound is supplied by the caller.  A separate structural compiler must still
show that the single common physical opcode tree maps to this syntax for
each role. -/
theorem active_actual_program_bad_mass_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (T finish queries : Nat)
    (program : ActualProgram (activeContext ctx blockCap fixed) T 0 finish queries)
    (queriesLe : queries ≤ T)
    (registers : RegisterBasis
      (Input := ActiveKey ctx.role blockCap ctx.keyBytes)
      (Phase := Output (Counter := Counter))
      (Workspace := RoutedWork Key Counter BaseWork) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers)) :
    normSquared
        (adaptiveProject (event (activeContext ctx blockCap fixed)) T
          (AdaptiveProgram.run
            (ActualProgram.compile (activeContext ctx blockCap fixed) T program)
            (partialRandomOracleState
              (Output := Output (Counter := Counter)) ∅ registers))) ≤
      6 * (T : ℝ) ^ 2 * ((completeRoleLoss ctx.role : Rat) : ℝ) +
        36 * (T : ℝ) ^ 3 / (2^512 : ℝ) := by
  exact current_adaptive_role_bad_mass_le
    (activeContext ctx blockCap fixed) T finish queries program queriesLe
      registers subnormalized

/-- Partial decompression: other bounded roles are total; the selected role
and the complete X/raw complement remain compressed. -/
def otherRoleTransform
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace :=
  decompressFinset (fixedOtherKeys ctx blockCap) state

theorem uncapped_query_zero_phase_apply
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (state : State Input Output Phase Workspace)
    (target : Basis Input Output Phase Workspace)
    (zero : target.phase = system.zeroPhase) :
    uncappedQuery system state target = state target := by
  let coordinate := databaseEquiv (Output := Output) target.input target.database
  have databaseEq :
      (databaseEquiv (Output := Output) target.input).symm coordinate =
        target.database :=
    Equiv.symm_apply_apply
      (databaseEquiv (Output := Output) target.input) target.database
  rcases coordinate with ⟨base, targetCoordinate⟩
  have targetEq :
      ({ input := target.input
         phase := target.phase
         workspace := target.workspace
         database :=
           (databaseEquiv (Output := Output) target.input).symm
             (base, targetCoordinate) } :
        Basis Input Output Phase Workspace) = target := by
    cases target
    simp_all
  rw [← targetEq]
  unfold uncappedQuery
  change
    decompressAt target.input
        (phaseQueryState system (controlledDecompress state))
        { input := target.input, phase := target.phase,
          workspace := target.workspace,
          database := (databaseEquiv (Output := Output) target.input).symm
            (base, targetCoordinate) } = _
  rw [decompress_at_apply_coordinate]
  rw [database_fiber_state_phase_query]
  rw [database_fiber_state_eq_state_fiber]
  rw [state_fiber_controlled_decompress]
  change activeFiberQuery system target.phase
      (stateFiber state target.input target.phase target.workspace base)
      targetCoordinate =
    stateFiber state target.input target.phase target.workspace base targetCoordinate
  rw [zero, active_fiber_query_zero]

/-- Away from the query-register input, a finite decompression product
commutes with controlled decompression on that entire register fiber. -/
theorem decompress_list_controlled_agrees_of_omitted
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (inputs : List Input) (queryInput : Input)
    (state : State Input Output Phase Workspace)
    (_omitted : queryInput ∉ inputs) :
    AgreeOnInput queryInput
      (decompressList inputs (controlledDecompress state))
      (controlledDecompress (decompressList inputs state)) := by
  have controlledAt : AgreeOnInput queryInput
      (controlledDecompress state) (decompressAt queryInput state) :=
    (decompress_at_agrees_controlled queryInput state).symm
  have lifted := decompress_list_preserves_agreement inputs queryInput controlledAt
  intro target atInput
  calc
    decompressList inputs (controlledDecompress state) target =
        decompressList inputs (decompressAt queryInput state) target :=
      lifted target atInput
    _ = decompressAt queryInput (decompressList inputs state) target := by
      rw [decompress_at_decompress_list_commutes]
    _ = controlledDecompress (decompressList inputs state) target := by
      unfold controlledDecompress
      rw [atInput]

theorem controlled_decompress_preserves_agreement
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (queryInput : Input) {left right : State Input Output Phase Workspace}
    (agreement : AgreeOnInput queryInput left right) :
    AgreeOnInput queryInput
      (controlledDecompress left) (controlledDecompress right) := by
  apply AgreeOnInput.trans
    (decompress_at_agrees_controlled queryInput left).symm
  apply AgreeOnInput.trans
    (decompress_at_preserves_agreement queryInput queryInput agreement)
  exact decompress_at_agrees_controlled queryInput right

/-- Consequently the cap-free query commutes on every fiber whose input was
not decompressed. -/
theorem decompress_list_uncapped_query_agrees_of_omitted
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase) (inputs : List Input)
    (queryInput : Input) (state : State Input Output Phase Workspace)
    (omitted : queryInput ∉ inputs) :
    AgreeOnInput queryInput
      (decompressList inputs (uncappedQuery system state))
      (uncappedQuery system (decompressList inputs state)) := by
  unfold uncappedQuery
  have inner : AgreeOnInput queryInput
      (decompressList inputs
        (phaseQueryState system (controlledDecompress state)))
      (phaseQueryState system
        (controlledDecompress (decompressList inputs state))) :=
    AgreeOnInput.trans
      (decompress_list_phase_agrees system inputs queryInput
        (controlledDecompress state) omitted)
      (phase_query_preserves_agreement system queryInput
        (decompress_list_controlled_agrees_of_omitted
          inputs queryInput state omitted))
  exact AgreeOnInput.trans
    (decompress_list_controlled_agrees_of_omitted inputs queryInput
      (phaseQueryState system (controlledDecompress state)) omitted)
    (controlled_decompress_preserves_agreement queryInput inner)

theorem other_role_transform_uncapped_query_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (target : Basis Key (Output (Counter := Counter))
      (Output (Counter := Counter))
      (Work (Counter := Counter) (BaseWork := BaseWork)))
    (active : RoleActive ctx.role blockCap ctx.keyBytes target.input) :
    otherRoleTransform ctx blockCap
        (uncappedQuery vectorPhaseSystem state) target =
      uncappedQuery vectorPhaseSystem
        (otherRoleTransform ctx blockCap state) target := by
  apply decompress_list_uncapped_query_agrees_of_omitted
      vectorPhaseSystem (fixedOtherKeys ctx blockCap).toList target.input state
  · intro member
    have fixed : FixedOtherRole ctx.role blockCap ctx.keyBytes target.input :=
      (mem_fixed_other_keys ctx blockCap target.input).mp
        (Finset.mem_toList.mp member)
    exact fixed active
  · rfl

/-- A queried fixed coordinate is decompressed exactly once by the role
transform, so its compressed query becomes its ordinary phase query. -/
theorem other_role_transform_uncapped_query_fixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (target : Basis Key (Output (Counter := Counter))
      (Output (Counter := Counter))
      (Work (Counter := Counter) (BaseWork := BaseWork)))
    (fixed : FixedOtherRole ctx.role blockCap ctx.keyBytes target.input) :
    otherRoleTransform ctx blockCap
        (uncappedQuery vectorPhaseSystem state) target =
      phaseQueryState vectorPhaseSystem
        (otherRoleTransform ctx blockCap state) target := by
  let rest := (fixedOtherKeys ctx blockCap).erase target.input
  have member : target.input ∈ fixedOtherKeys ctx blockCap :=
    (mem_fixed_other_keys ctx blockCap target.input).mpr fixed
  have omitted : target.input ∉ rest.toList := by simp [rest]
  have factor (inputState : CmsState (Key := Key)
      (Counter := Counter) (BaseWork := BaseWork)) :
      otherRoleTransform ctx blockCap inputState =
        decompressList rest.toList (decompressAt target.input inputState) := by
    unfold otherRoleTransform
    rw [← Finset.insert_erase member,
      decompress_finset_insert _ _ _ (by simp)]
    exact decompress_at_decompress_list_commutes _ _ _
  have selected : AgreeOnInput target.input
      (decompressAt target.input (uncappedQuery vectorPhaseSystem state))
      (phaseQueryState vectorPhaseSystem (decompressAt target.input state)) := by
    intro basis atInput
    calc
      _ = controlledDecompress (uncappedQuery vectorPhaseSystem state) basis :=
        decompress_at_agrees_controlled target.input _ basis atInput
      _ = phaseQueryState vectorPhaseSystem (controlledDecompress state) basis := by
        rw [uncappedQuery, controlled_decompress_involutive]
      _ = phaseQueryState vectorPhaseSystem (decompressAt target.input state) basis :=
        phase_query_preserves_agreement vectorPhaseSystem target.input
          (decompress_at_agrees_controlled target.input state).symm basis atInput
  rw [factor, factor]
  exact (AgreeOnInput.trans
    (decompress_list_preserves_agreement rest.toList target.input selected)
    (decompress_list_phase_agrees vectorPhaseSystem rest.toList target.input
      (decompressAt target.input state) omitted)) target rfl

/-- Both branches of the same physical query, without capping populated
fixed-table cells or postulating an execution equality. -/
theorem other_role_transform_uncapped_query
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    otherRoleTransform ctx blockCap (uncappedQuery vectorPhaseSystem state) =
      fun target =>
        if RoleActive ctx.role blockCap ctx.keyBytes target.input then
          uncappedQuery vectorPhaseSystem (otherRoleTransform ctx blockCap state) target
        else phaseQueryState vectorPhaseSystem
          (otherRoleTransform ctx blockCap state) target := by
  funext target
  split
  · exact other_role_transform_uncapped_query_active ctx blockCap state target ‹_›
  · exact other_role_transform_uncapped_query_fixed ctx blockCap state target ‹_›

theorem other_role_transform_physical_query_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (queryBound : Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (strict : StrictSupport queryBound state)
    (target : Basis Key (Output (Counter := Counter))
      (Output (Counter := Counter))
      (Work (Counter := Counter) (BaseWork := BaseWork)))
    (active : RoleActive ctx.role blockCap ctx.keyBytes target.input) :
    otherRoleTransform ctx blockCap
        (queryState vectorPhaseSystem queryBound state) target =
      uncappedQuery vectorPhaseSystem
        (otherRoleTransform ctx blockCap state) target := by
  rw [query_state_eq_controlled_decompression_phase
    vectorPhaseSystem queryBound state strict]
  exact other_role_transform_uncapped_query_active
    ctx blockCap state target active

theorem decompress_list_involutive
    (inputs : List Key)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    decompressList inputs (decompressList inputs state) = state := by
  induction inputs with
  | nil => rfl
  | cons input remaining inductionHypothesis =>
      simp only [decompress_list_cons]
      rw [decompress_at_decompress_list_commutes]
      rw [decompress_at_involutive]
      exact inductionHypothesis

theorem decompress_list_norm_squared
    (inputs : List Key)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (decompressList inputs state) = normSquared state := by
  induction inputs with
  | nil => rfl
  | cons input remaining inductionHypothesis =>
      rw [decompress_list_cons, decompress_at_preserves_norm_squared,
        inductionHypothesis]

@[simp]
theorem other_role_transform_involutive
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    otherRoleTransform ctx blockCap (otherRoleTransform ctx blockCap state) = state := by
  exact decompress_list_involutive (fixedOtherKeys ctx blockCap).toList state

theorem other_role_transform_norm_squared
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (otherRoleTransform ctx blockCap state) = normSquared state := by
  exact decompress_list_norm_squared (fixedOtherKeys ctx blockCap).toList state

/-- The transformed initial state is literally the purification with exactly
the other three bounded role domains populated. -/
theorem other_role_transform_initial
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    otherRoleTransform ctx blockCap
        (partialRandomOracleState (Output := Output (Counter := Counter)) ∅ registers) =
      partialRandomOracleState (Output := Output (Counter := Counter))
        (fixedOtherKeys ctx blockCap) registers := by
  exact decompress_finset_empty_support (fixedOtherKeys ctx blockCap) registers

/-! ## Exact commutation of canonical-leaf programming -/

theorem decompress_at_coordinate_projection_commutes_of_ne
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (other selected : Key) (different : other ≠ selected)
    (answer : Output (Counter := Counter))
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    decompressAt other (coordinateEventProjection selected answer state) =
      coordinateEventProjection selected answer (decompressAt other state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  by_cases recorded : target.database selected = some answer
  · simp only [coordinateEventProjection, recorded, if_true,
      decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro coordinate _
    simp [set_database_coordinate_other target.database (Ne.symm different), recorded]
  · simp only [coordinateEventProjection, recorded, if_false]
    apply Finset.sum_eq_zero
    intro coordinate _
    simp [set_database_coordinate_other target.database (Ne.symm different), recorded]

theorem decompress_at_local_replace_commutes_of_ne
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (other selected : Key) (different : other ≠ selected)
    (old fresh : Output (Counter := Counter))
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    decompressAt other (localReplaceReadBranch selected old fresh state) =
      localReplaceReadBranch selected old fresh (decompressAt other state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  by_cases installed : target.database selected = some fresh
  · simp only [localReplaceReadBranch, installed, if_true,
      decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro coordinate _
    rw [set_database_coordinate_other target.database (Ne.symm different)]
    simp only [installed, if_true]
    rw [set_database_coordinate_commutes target.database other selected different]
    rw [set_database_coordinate_other target.database different]
  · simp only [localReplaceReadBranch, installed, if_false]
    apply Finset.sum_eq_zero
    intro coordinate _
    rw [set_database_coordinate_other target.database (Ne.symm different)]
    simp only [installed, if_false, zero_mul]

/-- A retained-answer programming kernel at a canonical leaf commutes with
decompression at every different role-table key.  This covers the entire
`D · replace · P · D` operator, not merely its database support relation. -/
theorem decompress_at_compressed_retained_commutes_of_ne
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (other selected : Key) (different : other ≠ selected)
    (old fresh : Output (Counter := Counter))
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    decompressAt other (compressedRetainedBranch selected old fresh state) =
      compressedRetainedBranch selected old fresh (decompressAt other state) := by
  unfold compressedRetainedBranch
  rw [decompress_at_commutes other selected]
  rw [decompress_at_local_replace_commutes_of_ne other selected different]
  rw [decompress_at_coordinate_projection_commutes_of_ne other selected different]
  rw [decompress_at_commutes other selected]

theorem decompress_list_compressed_retained_commutes_of_outside
    (inputs : List Key) (selected : Key)
    (outside : ∀ input ∈ inputs, input ≠ selected)
    (old fresh : Output (Counter := Counter))
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    decompressList inputs (compressedRetainedBranch selected old fresh state) =
      compressedRetainedBranch selected old fresh (decompressList inputs state) := by
  induction inputs with
  | nil => rfl
  | cons input remaining inductionHypothesis =>
      rw [decompress_list_cons, decompress_list_cons,
        inductionHypothesis (fun key member => outside key (by simp [member])),
        decompress_at_compressed_retained_commutes_of_ne input selected
          (outside input (by simp))]

theorem other_role_transform_compressed_retained_leaf
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (selected : Key) (statement : List Byte)
    (parsed : SmzaRp05FilteredReadback.globalLeafStatement
      ctx.leafNamespace (ctx.keyBytes selected) = some statement)
    (old fresh : Output (Counter := Counter))
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    otherRoleTransform ctx blockCap
        (compressedRetainedBranch selected old fresh state) =
      compressedRetainedBranch selected old fresh
        (otherRoleTransform ctx blockCap state) := by
  unfold otherRoleTransform decompressFinset
  apply decompress_list_compressed_retained_commutes_of_outside
  intro key member same
  subst selected
  exact canonical_leaf_not_fixed ctx blockCap key statement parsed
    (Finset.mem_toList.mp member)

theorem retained_none_slice_decompress_at
    (selected : Key)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter))
      (RetainedWorkspace (Output (Counter := Counter)) BaseWork)) :
    retainedNoneSlice (decompressAt selected state) =
      decompressAt selected (retainedNoneSlice state) := by
  funext target
  simp [retainedNoneSlice, decompress_at_eq_sum_kernel]

theorem decompress_at_retained_old_replace_commutes_of_ne
    (other selected : Key) (different : other ≠ selected)
    (fresh : Output (Counter := Counter))
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter))
      (RetainedWorkspace (Output (Counter := Counter)) BaseWork)) :
    decompressAt other (retainedOldReplace selected fresh state) =
      retainedOldReplace selected fresh (decompressAt other state) := by
  funext target
  cases slot : target.workspace.1 with
  | none =>
      rw [decompress_at_eq_sum_kernel]
      simp [retainedOldReplace, slot]
  | some old =>
      let readTarget : Basis Key (Output (Counter := Counter))
          (Output (Counter := Counter)) BaseWork :=
        { input := target.input, phase := target.phase,
          workspace := target.workspace.2, database := target.database }
      have left : decompressAt other (retainedOldReplace selected fresh state) target =
          decompressAt other
            (compressedRetainedBranch selected old fresh (retainedNoneSlice state))
            readTarget := by
        simp only [decompress_at_eq_sum_kernel]
        apply Finset.sum_congr rfl
        intro coordinate _
        simp [retainedOldReplace, slot, readTarget]
      have right : retainedOldReplace selected fresh (decompressAt other state) target =
          compressedRetainedBranch selected old fresh
            (decompressAt other (retainedNoneSlice state)) readTarget := by
        simp [retainedOldReplace, slot, retained_none_slice_decompress_at,
          readTarget]
      rw [left, right]
      exact congrArg (fun branch : State Key (Output (Counter := Counter))
          (Output (Counter := Counter)) BaseWork => branch readTarget)
        (decompress_at_compressed_retained_commutes_of_ne (Workspace := BaseWork)
          other selected different old fresh (retainedNoneSlice state))

theorem decompress_list_retained_old_replace_commutes_of_outside
    (inputs : List Key) (selected : Key)
    (outside : ∀ input ∈ inputs, input ≠ selected)
    (fresh : Output (Counter := Counter))
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter))
      (RetainedWorkspace (Output (Counter := Counter)) BaseWork)) :
    decompressList inputs (retainedOldReplace selected fresh state) =
      retainedOldReplace selected fresh (decompressList inputs state) := by
  induction inputs with
  | nil => rfl
  | cons input remaining inductionHypothesis =>
      rw [decompress_list_cons, decompress_list_cons,
        inductionHypothesis (fun key member => outside key (by simp [member])),
        decompress_at_retained_old_replace_commutes_of_ne input selected
          (outside input (by simp))]

/-- Whole-instrument form used by `.retainedWrite`: the orthogonal old-answer
history is preserved while the fixed-role decompressions commute through the
actual programming instruction. -/
theorem other_role_transform_retained_old_replace_leaf
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (selected : Key) (statement : List Byte)
    (parsed : SmzaRp05FilteredReadback.globalLeafStatement
      ctx.leafNamespace (ctx.keyBytes selected) = some statement)
    (fresh : Output (Counter := Counter))
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    otherRoleTransform ctx blockCap (retainedOldReplace selected fresh state) =
      retainedOldReplace selected fresh (otherRoleTransform ctx blockCap state) := by
  unfold otherRoleTransform decompressFinset
  apply decompress_list_retained_old_replace_commutes_of_outside
  intro key member same
  subst selected
  exact canonical_leaf_not_fixed ctx blockCap key statement parsed
    (Finset.mem_toList.mp member)

/-- Every actual register-only adversary/private/mark gate commutes with the
role conditioning transform.  Database dependence is excluded by the type
of `DatabaseIndependentContraction`. -/
theorem other_role_transform_private_commutes
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := Output (Counter := Counter))
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)))
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    otherRoleTransform ctx blockCap (step.apply state) =
      step.apply (otherRoleTransform ctx blockCap state) := by
  unfold otherRoleTransform decompressFinset
  exact step.decompress_list_apply_commutes _ state

theorem restrict_active_set_fixed_coordinate
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (database : Database Key (Output (Counter := Counter)))
    (fixedKey : FixedOtherKey ctx.role blockCap ctx.keyBytes)
    (coordinate : Option (Output (Counter := Counter))) :
    restrictActive ctx blockCap
        (setDatabaseCoordinate database fixedKey.val coordinate) =
      restrictActive ctx blockCap database := by
  funext activeKey
  unfold restrictActive
  apply set_database_coordinate_other
  intro same
  apply fixedKey.property
  simpa only [same] using activeKey.property

/-- Literal X-copy form: the workspace permutation is selected only from the
active database.  Consequently changing/decompressing a removed role-table
coordinate cannot change that permutation. -/
def activeDatabaseControlledWorkspaceUpdate
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (update : ActiveDatabase ctx blockCap → Workspace ≃ Workspace)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace :=
  databaseControlledWorkspaceUpdate
    (fun database => update (restrictActive ctx blockCap database)) state

theorem decompress_at_active_database_copy_commutes
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (update : ActiveDatabase ctx blockCap → Workspace ≃ Workspace)
    (fixedKey : FixedOtherKey ctx.role blockCap ctx.keyBytes)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    decompressAt fixedKey.val
        (activeDatabaseControlledWorkspaceUpdate ctx blockCap update state) =
      activeDatabaseControlledWorkspaceUpdate ctx blockCap update
        (decompressAt fixedKey.val state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold activeDatabaseControlledWorkspaceUpdate
  simp only [databaseControlledWorkspaceUpdate]
  simp_rw [restrict_active_set_fixed_coordinate ctx blockCap]
  rw [decompress_at_eq_sum_kernel]

theorem decompress_list_active_database_copy_commutes
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (update : ActiveDatabase ctx blockCap → Workspace ≃ Workspace)
    (inputs : List (FixedOtherKey ctx.role blockCap ctx.keyBytes))
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    decompressList (inputs.map Subtype.val)
        (activeDatabaseControlledWorkspaceUpdate ctx blockCap update state) =
      activeDatabaseControlledWorkspaceUpdate ctx blockCap update
        (decompressList (inputs.map Subtype.val) state) := by
  induction inputs with
  | nil => rfl
  | cons input remaining inductionHypothesis =>
      rw [List.map_cons, decompress_list_cons, decompress_list_cons,
        inductionHypothesis,
        decompress_at_active_database_copy_commutes ctx blockCap update input]

theorem decompress_list_active_database_copy_commutes_of_fixed
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (update : ActiveDatabase ctx blockCap → Workspace ≃ Workspace)
    (inputs : List Key)
    (fixed : ∀ key ∈ inputs,
      FixedOtherRole ctx.role blockCap ctx.keyBytes key)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    decompressList inputs
        (activeDatabaseControlledWorkspaceUpdate ctx blockCap update state) =
      activeDatabaseControlledWorkspaceUpdate ctx blockCap update
        (decompressList inputs state) := by
  induction inputs with
  | nil => rfl
  | cons input remaining inductionHypothesis =>
      rw [decompress_list_cons, decompress_list_cons,
        inductionHypothesis (fun key member => fixed key (by simp [member])),
        decompress_at_active_database_copy_commutes ctx blockCap update
          ⟨input, fixed input (by simp)⟩]

/-- Exact X-copy commutation used after the X measurement.  The copy may
depend arbitrarily on the complete active database, but never on a removed
fixed-role coordinate. -/
theorem other_role_transform_active_database_copy
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (update : ActiveDatabase ctx blockCap → Workspace ≃ Workspace)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    otherRoleTransform ctx blockCap
        (activeDatabaseControlledWorkspaceUpdate ctx blockCap update state) =
      activeDatabaseControlledWorkspaceUpdate ctx blockCap update
        (otherRoleTransform ctx blockCap state) := by
  unfold otherRoleTransform decompressFinset
  apply decompress_list_active_database_copy_commutes_of_fixed
  intro key member
  exact (mem_fixed_other_keys ctx blockCap key).mp (Finset.mem_toList.mp member)

/-! ## One role-independent tree for mark/write/X-copy operations -/

abbrev XKey (keys : Finset Key) := { key : Key // key ∈ keys }

def xView
    (keys : Finset Key)
    (database : Database Key (Output (Counter := Counter))) :
    XKey keys → Option (Output (Counter := Counter)) :=
  fun key => database key.val

def xActiveKey
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (key : XKey keys) : ActiveKey ctx.role blockCap ctx.keyBytes :=
  ⟨key.val, unrecognized_is_active ctx.role blockCap ctx.keyBytes key.val
    (unrecognized key.val key.property)⟩

def activeXView
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (database : ActiveDatabase ctx blockCap) :
    XKey keys → Option (Output (Counter := Counter)) :=
  fun key => database (xActiveKey ctx blockCap keys unrecognized key)

theorem active_x_view_restrict
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (database : Database Key (Output (Counter := Counter))) :
    activeXView ctx blockCap keys unrecognized
        (restrictActive ctx blockCap database) =
      xView keys database := by
  rfl

def xControlledWorkspaceUpdate
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (keys : Finset Key)
    (update : (XKey keys → Option (Output (Counter := Counter))) →
      Workspace ≃ Workspace)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace :=
  databaseControlledWorkspaceUpdate
    (fun database => update (xView keys database)) state

/-- The physical X-copy is literally an active-database-controlled copy once
the X keys are proved outside every parsed role domain.  This is an equality
of operators, not a supplied relation between their outputs. -/
theorem x_controlled_workspace_update_eq_active
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (update : (XKey keys → Option (Output (Counter := Counter))) →
      Workspace ≃ Workspace)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    xControlledWorkspaceUpdate keys update state =
      activeDatabaseControlledWorkspaceUpdate ctx blockCap
        (fun database =>
          update (activeXView ctx blockCap keys unrecognized database)) state := by
  rfl

/-- Exact commutation for the actual post-measurement X-copy.  The proof uses
the literal X-key parser fact to rewrite the physical operator to its active
view, then applies the fixed-coordinate calculation above. -/
theorem other_role_transform_x_copy
    {Workspace : Type} [Fintype Workspace] [DecidableEq Workspace]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (update : (XKey keys → Option (Output (Counter := Counter))) →
      Workspace ≃ Workspace)
    (state : State Key (Output (Counter := Counter))
      (Output (Counter := Counter)) Workspace) :
    otherRoleTransform ctx blockCap
        (xControlledWorkspaceUpdate keys update state) =
      xControlledWorkspaceUpdate keys update
        (otherRoleTransform ctx blockCap state) := by
  rw [x_controlled_workspace_update_eq_active ctx blockCap keys unrecognized,
    x_controlled_workspace_update_eq_active ctx blockCap keys unrecognized]
  exact other_role_transform_active_database_copy ctx blockCap _ state

/-! ## Certified database-blind opcodes -/

def databaseIndependentTransition
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (source target : Basis Input Output Phase Workspace) : ℂ :=
  if source.database = target.database then
    step.kernel (basisRegisters source) (basisRegisters target)
  else 0

theorem kernel_apply_database_independent_transition
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (state : State Input Output Phase Workspace) :
    kernelApply (databaseIndependentTransition step) state = step.apply state := by
  funext target
  unfold kernelApply databaseIndependentTransition
    DatabaseIndependentContraction.apply liftRegisterKernel
  rw [← (databaseRegisterEquiv Input Output Phase Workspace).sum_comp]
  rw [Fintype.sum_prod_type]
  rw [Finset.sum_eq_single target.database]
  · simp [databaseRegisterEquiv, basisRegisters]
  · intro database _ different
    apply Finset.sum_eq_zero
    intro source _
    simp [databaseRegisterEquiv, basisRegisters, different]
  · simp

theorem database_independent_transition_bounded
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (bound : Nat) {state : State Input Output Phase Workspace}
    (bounded : BoundedState bound state) :
    BoundedState bound (kernelApply (databaseIndependentTransition step) state) := by
  rw [kernel_apply_database_independent_transition]
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    have sourceZero : ∀ (source : RegisterBasis
        (Input := Input) (Phase := Phase) (Workspace := Workspace)),
        state (⟨source.1, source.2.1,
          source.2.2, target.database⟩ :
            Basis Input Output Phase Workspace) = 0 := by
      intro source
      exact bounded_state_apply_eq_zero_of_lt bounded _ above
    simp [project, within, DatabaseIndependentContraction.apply,
      liftRegisterKernel, sourceZero]

/-!
`PhysicalZeroProgram` is the role-independent physical syntax used between
charged oracle queries.  It admits only the concrete zero-charge operations
of the current verifier/simulator: a database-blind register gate (including
authorization marks), a retained-answer write at a parsed canonical leaf,
or the post-measurement copy from literal X keys.  In particular, no caller
can supply an arbitrary database-dependent transition or an execution
equality as an opcode certificate.
-/
inductive PhysicalZeroProgram
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) : Nat → Nat → Type _ where
  | nil (budget : Nat) : PhysicalZeroProgram ctx cap budget budget
  | privateGate
      {finish : Nat} (budget : Nat) (within : budget ≤ cap)
      (step : DatabaseIndependentContraction
        (Input := Key) (Output := Output (Counter := Counter))
        (Phase := Output (Counter := Counter))
        (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)))
      (authorization : ∀ source target, step.kernel source target ≠ 0 →
        ctx.authorizedOf source.2.2.2 = ctx.authorizedOf target.2.2.2)
      (remaining : PhysicalZeroProgram ctx cap budget finish) :
      PhysicalZeroProgram ctx cap budget finish
  | markGate
      {finish : Nat} (budget : Nat) (within : budget ≤ cap)
      (step : DatabaseIndependentContraction
        (Input := Key) (Output := Output (Counter := Counter))
        (Phase := Output (Counter := Counter))
        (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)))
      (authorization : ∀ source target, step.kernel source target ≠ 0 →
        ∃ statement, ctx.authorizedOf target.2.2.2 =
          (insert statement (ctx.authorizedOf source.2.2.2) : Finset (List Byte)))
      (remaining : PhysicalZeroProgram ctx cap budget finish) :
      PhysicalZeroProgram ctx cap budget finish
  | retainedLeafWrite
      {finish : Nat} (occupied : Nat) (room : occupied < cap)
      (key : Key) (statement : List Byte)
      (marked : ∀ work, statement ∈ ctx.authorizedOf work)
      (parsed : SmzaRp05FilteredReadback.globalLeafStatement
        ctx.leafNamespace (ctx.keyBytes key) = some statement)
      (fresh : Output (Counter := Counter))
      (remaining : PhysicalZeroProgram ctx cap (occupied + 1) finish) :
      PhysicalZeroProgram ctx cap occupied finish
  | markedLeafWrite
      {finish : Nat} (occupied : Nat) (room : occupied < cap)
      (key : Key) (statement : List Byte)
      (marked : ∀ work, statement ∈ ctx.authorizedOf work)
      (parsed : SmzaRp05FilteredReadback.globalLeafStatement
        ctx.leafNamespace (ctx.keyBytes key) = some statement)
      (fresh : Output (Counter := Counter))
      (remaining : PhysicalZeroProgram ctx cap (occupied + 1) finish) :
      PhysicalZeroProgram ctx cap occupied finish
  | copyX
      {finish : Nat} (budget : Nat) (within : budget ≤ cap)
      (keys : Finset Key)
      (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
      (update : (XKey keys → Option (Output (Counter := Counter))) →
        Work (Counter := Counter) (BaseWork := BaseWork) ≃
          Work (Counter := Counter) (BaseWork := BaseWork))
      (authorization : ∀ view workspace,
        ctx.authorizedOf ((update view).symm workspace).2 =
          ctx.authorizedOf workspace.2)
      (remaining : PhysicalZeroProgram ctx cap budget finish) :
      PhysicalZeroProgram ctx cap budget finish

namespace PhysicalZeroProgram

/-- Compile the certified physical syntax to the adaptive program consumed by
the CMS telescope.  Database locality is derived from the register-only
kernel, and the authorization premises are constructor data. -/
def compilePhysical
    {cap start finish : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    PhysicalZeroProgram ctx cap start finish → ActualProgram ctx cap start finish 0
  | .nil budget => .nil budget
  | .privateGate budget within step authorization remaining =>
      .cons (.privateKernel budget within
        (databaseIndependentTransition step)
        (by
          intro source target nonzero
          have same : source.database = target.database := by
            by_contra different
            simp [databaseIndependentTransition, different] at nonzero
          have kernelNonzero : step.kernel (basisRegisters source)
              (basisRegisters target) ≠ 0 := by
            simpa [databaseIndependentTransition, same] using nonzero
          exact ⟨authorization _ _ kernelNonzero, same⟩)
        (by
          intro state
          rw [kernel_apply_database_independent_transition]
          exact step.contractive state)
        (database_independent_transition_bounded step budget))
        (compilePhysical ctx remaining)
  | .markGate budget within step authorization remaining =>
      .cons (.mark budget within
        (databaseIndependentTransition step)
        (by
          intro source target nonzero
          have same : source.database = target.database := by
            by_contra different
            simp [databaseIndependentTransition, different] at nonzero
          have kernelNonzero : step.kernel (basisRegisters source)
              (basisRegisters target) ≠ 0 := by
            simpa [databaseIndependentTransition, same] using nonzero
          obtain ⟨statement, marked⟩ := authorization _ _ kernelNonzero
          exact ⟨statement, marked, same.symm⟩)
        (by
          intro state
          rw [kernel_apply_database_independent_transition]
          exact step.contractive state)
        (database_independent_transition_bounded step budget))
        (compilePhysical ctx remaining)
  | .retainedLeafWrite occupied room key statement marked parsed fresh remaining =>
      .cons (.retainedWrite occupied room key statement marked parsed fresh)
        (compilePhysical ctx remaining)
  | .markedLeafWrite occupied room key statement marked parsed fresh remaining =>
      .cons (.retainedWrite occupied room key statement marked parsed fresh)
        (compilePhysical ctx remaining)
  | .copyX budget within keys _ update authorization remaining =>
      .cons (.copy budget within
        (fun database => update (xView keys database))
        (fun database workspace => authorization (xView keys database) workspace))
        (compilePhysical ctx remaining)

/-- Literal execution of a zero-charge physical block. -/
def run
    {cap start finish : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    PhysicalZeroProgram ctx cap start finish →
      CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) →
        CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)
  | .nil _, state => state
  | .privateGate _ _ step _ remaining, state =>
      run ctx remaining (step.apply state)
  | .markGate _ _ step _ remaining, state =>
      run ctx remaining (step.apply state)
  | .retainedLeafWrite _ _ key _ _ _ fresh remaining, state =>
      run ctx remaining (retainedOldReplace key fresh state)
  | .markedLeafWrite _ _ key _ _ _ fresh remaining, state =>
      run ctx remaining (retainedOldReplace key fresh state)
  | .copyX _ _ keys _ update _ remaining, state =>
      run ctx remaining (xControlledWorkspaceUpdate keys update state)

theorem run_eq_compiled_physical
    {cap start finish : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (program : PhysicalZeroProgram ctx cap start finish)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    run ctx program state =
      AdaptiveProgram.run (ActualProgram.compile ctx cap (compilePhysical ctx program))
        state := by
  induction program generalizing state with
  | nil budget => rfl
  | privateGate budget within step authorization remaining ih =>
      simpa [run, compilePhysical, ActualProgram.compile, AdaptiveProgram.run,
        Opcode.compile, certifiedKernelStep,
        kernel_apply_database_independent_transition] using
        ih (step.apply state)
  | markGate budget within step authorization remaining ih =>
      simpa [run, compilePhysical, ActualProgram.compile, AdaptiveProgram.run,
        Opcode.compile, certifiedKernelStep,
        kernel_apply_database_independent_transition] using
        ih (step.apply state)
  | retainedLeafWrite occupied room key statement marked parsed fresh remaining ih =>
      simpa [run, compilePhysical, ActualProgram.compile, AdaptiveProgram.run,
        Opcode.compile, vectorRetainedOldReplaceStep, retainedOldReplaceStep] using
        ih (retainedOldReplace key fresh state)
  | markedLeafWrite occupied room key statement marked parsed fresh remaining ih =>
      simpa [run, compilePhysical, ActualProgram.compile, AdaptiveProgram.run,
        Opcode.compile, vectorRetainedOldReplaceStep, retainedOldReplaceStep] using
        ih (retainedOldReplace key fresh state)
  | copyX budget within keys unrecognized update authorization remaining ih =>
      simpa [run, compilePhysical, ActualProgram.compile, AdaptiveProgram.run,
        Opcode.compile, databaseControlledWorkspaceUpdateStep,
        xControlledWorkspaceUpdate] using
        ih (xControlledWorkspaceUpdate keys update state)

/-- Structural physical intertwining for every zero-charge block.  This is
the missing mark/write/X-copy induction: both sides execute the same syntax
from the same state, and the equality follows constructor-by-constructor from
literal database-blindness, canonical-leaf separation, and X-key separation. -/
theorem other_role_transform_run
    {cap start finish : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (program : PhysicalZeroProgram ctx cap start finish)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    otherRoleTransform ctx blockCap (run ctx program state) =
      run ctx program (otherRoleTransform ctx blockCap state) := by
  induction program generalizing state with
  | nil budget => rfl
  | privateGate budget within step authorization remaining inductionHypothesis =>
      rw [run, run, inductionHypothesis,
        other_role_transform_private_commutes ctx blockCap step]
  | markGate budget within step authorization remaining inductionHypothesis =>
      rw [run, run, inductionHypothesis,
        other_role_transform_private_commutes ctx blockCap step]
  | retainedLeafWrite occupied room key statement marked parsed fresh remaining inductionHypothesis =>
      rw [run, run, inductionHypothesis,
        other_role_transform_retained_old_replace_leaf
          ctx blockCap key statement parsed fresh]
  | markedLeafWrite occupied room key statement marked parsed fresh remaining inductionHypothesis =>
      rw [run, run, inductionHypothesis,
        other_role_transform_retained_old_replace_leaf
          ctx blockCap key statement parsed fresh]
  | copyX budget within keys unrecognized update authorization remaining inductionHypothesis =>
      rw [run, run, inductionHypothesis,
        other_role_transform_x_copy
          ctx blockCap keys unrecognized update]

/-- Same-common-state corollary.  The left side starts from the single
all-compressed physical execution and conditions its *output*.  The right
side runs the identical physical syntax from the exactly partially
decompressed initial state.  Thus no role-dependent execution is selected
by a caller and no populated fixed coordinate is counted in an active CMS
support cap. -/
theorem conditioned_initial_run
    {cap finish : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (program : PhysicalZeroProgram ctx cap 0 finish)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    otherRoleTransform ctx blockCap
        (run ctx program
          (partialRandomOracleState
            (Output := Output (Counter := Counter)) ∅ registers)) =
      run ctx program
        (partialRandomOracleState (Output := Output (Counter := Counter))
          (fixedOtherKeys ctx blockCap) registers) := by
  rw [other_role_transform_run, other_role_transform_initial]

end PhysicalZeroProgram

/-! ## Complete certified physical interaction -/

/-- A complete physical interaction alternates charged CMS queries with
certified zero-charge blocks.  The support indices are the actual compressed
database budgets; fixed other-role cells are not present in this state. -/
inductive CertifiedPhysicalProgram
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) : Nat → Nat → Nat → Type _ where
  | nil (budget : Nat) : CertifiedPhysicalProgram ctx cap budget budget 0
  | zero {start middle finish queries : Nat}
      (block : PhysicalZeroProgram ctx cap start middle)
      (remaining : CertifiedPhysicalProgram ctx cap middle finish queries) :
      CertifiedPhysicalProgram ctx cap start finish queries
  | query {finish queries : Nat}
      (occupied : Nat) (room : occupied < cap)
      (remaining : CertifiedPhysicalProgram ctx cap (occupied + 1) finish queries) :
      CertifiedPhysicalProgram ctx cap occupied finish (1 + queries)

namespace CertifiedPhysicalProgram

def conditionedQuery
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  fun target =>
    if RoleActive ctx.role blockCap ctx.keyBytes target.input then
      uncappedQuery vectorPhaseSystem state target
    else
      phaseQueryState vectorPhaseSystem state target

def conditionedRun
    {cap start finish queries : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) :
    CertifiedPhysicalProgram ctx cap start finish queries →
      CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) →
        CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)
  | .nil _, state => state
  | .zero block remaining, state =>
      conditionedRun ctx blockCap remaining
        (PhysicalZeroProgram.run ctx block state)
  | .query _ _ remaining, state =>
      conditionedRun ctx blockCap remaining
        (conditionedQuery ctx blockCap state)

def run
    {cap start finish queries : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    CertifiedPhysicalProgram ctx cap start finish queries →
      CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) →
        CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)
  | .nil _, state => state
  | .zero block remaining, state =>
      run ctx remaining (PhysicalZeroProgram.run ctx block state)
  | .query _ _ remaining, state =>
      run ctx remaining (cappedQueryState vectorPhaseSystem cap state)

def transportActual
    {cap start finish leftQueries rightQueries : Nat}
    {ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    (equal : leftQueries = rightQueries)
    (program : ActualProgram ctx cap start finish leftQueries) :
    ActualProgram ctx cap start finish rightQueries :=
  equal ▸ program

@[simp]
theorem compile_transportActual
    {cap start finish leftQueries rightQueries : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (equal : leftQueries = rightQueries)
    (program : ActualProgram ctx cap start finish leftQueries) :
    ActualProgram.compile ctx cap (transportActual equal program) =
      ActualProgram.compile ctx cap program := by
  cases equal
  rfl

def appendActual
    {cap start middle finish leftQueries rightQueries : Nat}
    {ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)} :
    ActualProgram ctx cap start middle leftQueries →
      ActualProgram ctx cap middle finish rightQueries →
        ActualProgram ctx cap start finish (leftQueries + rightQueries)
  | .nil _, right => transportActual (Nat.zero_add _).symm right
  | .cons first remaining, right =>
      transportActual (Nat.add_assoc _ _ _).symm
        (ActualProgram.cons first (appendActual remaining right))

def compilePhysical
    {cap start finish queries : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    CertifiedPhysicalProgram ctx cap start finish queries →
      ActualProgram ctx cap start finish queries
  | .nil budget => .nil budget
  | .zero block remaining =>
      transportActual (Nat.zero_add _)
        (appendActual (PhysicalZeroProgram.compilePhysical ctx block)
          (compilePhysical ctx remaining))
  | .query occupied room remaining =>
      .cons (.query occupied room) (compilePhysical ctx remaining)

theorem run_eq_compiled_physical
    {cap start finish queries : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (program : CertifiedPhysicalProgram ctx cap start finish queries)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    run ctx program state =
      AdaptiveProgram.run (ActualProgram.compile ctx cap (compilePhysical ctx program))
        state := by
  induction program generalizing state with
  | nil budget => rfl
  | zero block remaining ih =>
      rw [run, compilePhysical]
      simp only [compile_transportActual]
      induction block generalizing state with
      | nil budget =>
          simpa [PhysicalZeroProgram.run, PhysicalZeroProgram.compilePhysical,
            appendActual, ActualProgram.compile, AdaptiveProgram.run] using ih state
      | privateGate budget within step authorization tail tailIh =>
          simpa [PhysicalZeroProgram.run, PhysicalZeroProgram.compilePhysical,
            appendActual, compile_transportActual, ActualProgram.compile,
            AdaptiveProgram.run, Opcode.compile, certifiedKernelStep,
            kernel_apply_database_independent_transition] using
            tailIh remaining ih (step.apply state)
      | markGate budget within step authorization tail tailIh =>
          simpa [PhysicalZeroProgram.run, PhysicalZeroProgram.compilePhysical,
            appendActual, compile_transportActual, ActualProgram.compile,
            AdaptiveProgram.run, Opcode.compile, certifiedKernelStep,
            kernel_apply_database_independent_transition] using
            tailIh remaining ih (step.apply state)
      | retainedLeafWrite occupied room key statement marked parsed fresh tail tailIh =>
          simpa [PhysicalZeroProgram.run, PhysicalZeroProgram.compilePhysical,
            appendActual, compile_transportActual, ActualProgram.compile,
            AdaptiveProgram.run, Opcode.compile, vectorRetainedOldReplaceStep,
            retainedOldReplaceStep] using
            tailIh remaining ih (retainedOldReplace key fresh state)
      | markedLeafWrite occupied room key statement marked parsed fresh tail tailIh =>
          simpa [PhysicalZeroProgram.run, PhysicalZeroProgram.compilePhysical,
            appendActual, compile_transportActual, ActualProgram.compile,
            AdaptiveProgram.run, Opcode.compile, vectorRetainedOldReplaceStep,
            retainedOldReplaceStep] using
            tailIh remaining ih (retainedOldReplace key fresh state)
      | copyX budget within keys unrecognized update authorization tail tailIh =>
          simpa [PhysicalZeroProgram.run, PhysicalZeroProgram.compilePhysical,
            appendActual, compile_transportActual, ActualProgram.compile,
            AdaptiveProgram.run, Opcode.compile,
            databaseControlledWorkspaceUpdateStep, xControlledWorkspaceUpdate] using
            tailIh remaining ih (xControlledWorkspaceUpdate keys update state)
  | query occupied room remaining ih =>
      rw [run, compilePhysical, ActualProgram.compile, AdaptiveProgram.run]
      exact ih (cappedQueryState vectorPhaseSystem cap state)

theorem bounded_run
    {cap start finish queries : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (program : CertifiedPhysicalProgram ctx cap start finish queries)
    {state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    (bounded : BoundedState start state) :
    BoundedState finish (run ctx program state) := by
  rw [run_eq_compiled_physical]
  exact AdaptiveProgram.run_bounded (ActualProgram.compile ctx cap
    (compilePhysical ctx program)) bounded

/-- The entire common compressed execution may be conditioned after it runs,
or the same certified syntax may be run with each charged query split into
its active CMS action and fixed-table ordinary phase.  The support premise is
only on the compressed physical state. -/
theorem other_role_transform_run
    {cap start finish queries : Nat}
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (program : CertifiedPhysicalProgram ctx cap start finish queries)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState start state) :
    otherRoleTransform ctx blockCap (run ctx program state) =
      conditionedRun ctx blockCap program
        (otherRoleTransform ctx blockCap state) := by
  induction program generalizing state with
  | nil budget => rfl
  | zero block remaining ih =>
      have boundedBlock := AdaptiveProgram.run_bounded
        (ActualProgram.compile ctx cap
          (PhysicalZeroProgram.compilePhysical ctx block)) bounded
      rw [← PhysicalZeroProgram.run_eq_compiled_physical] at boundedBlock
      calc
        otherRoleTransform ctx blockCap (run ctx (.zero block remaining) state) =
            conditionedRun ctx blockCap remaining
              (otherRoleTransform ctx blockCap
                (PhysicalZeroProgram.run ctx block state)) := by
          rw [run]
          exact ih _ boundedBlock
        _ = conditionedRun ctx blockCap (.zero block remaining)
              (otherRoleTransform ctx blockCap state) := by
          rw [conditionedRun,
            PhysicalZeroProgram.other_role_transform_run]
  | query occupied room remaining ih =>
      have queryEq : cappedQueryState vectorPhaseSystem cap state =
          uncappedQuery vectorPhaseSystem state := by
        rw [capped_query_state_eq_query_state_of_bounded_lt
          vectorPhaseSystem cap occupied state room bounded]
        exact query_state_eq_controlled_decompression_phase vectorPhaseSystem cap
          state (bounded_state_strict_support bounded room)
      have boundedQuery : BoundedState (occupied + 1)
          (cappedQueryState vectorPhaseSystem cap state) := by
        exact (Opcode.compile ctx cap (.query occupied room)).preservesBounded bounded
      calc
        otherRoleTransform ctx blockCap (run ctx (.query occupied room remaining) state) =
            conditionedRun ctx blockCap remaining
              (otherRoleTransform ctx blockCap
                (cappedQueryState vectorPhaseSystem cap state)) := by
          rw [run]
          exact ih _ boundedQuery
        _ = conditionedRun ctx blockCap (.query occupied room remaining)
              (otherRoleTransform ctx blockCap state) := by
          rw [conditionedRun, queryEq, other_role_transform_uncapped_query]
          rfl

end CertifiedPhysicalProgram

/-! ## One proof-erased common physical program -/

inductive PhysicalProgramSkeleton
    (cap : Nat) : Nat → Nat → Nat → Type _ where
  | nil (budget : Nat) : PhysicalProgramSkeleton cap budget budget 0
  | query {finish queries : Nat}
      (occupied : Nat) (room : occupied < cap)
      (remaining : PhysicalProgramSkeleton cap (occupied + 1) finish queries) :
      PhysicalProgramSkeleton cap occupied finish (1 + queries)
  | privateGate {finish queries : Nat}
      (budget : Nat) (within : budget ≤ cap)
      (step : DatabaseIndependentContraction
        (Input := Key) (Output := Output (Counter := Counter))
        (Phase := Output (Counter := Counter))
        (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)))
      (remaining : PhysicalProgramSkeleton cap budget finish queries) :
      PhysicalProgramSkeleton cap budget finish queries
  | markGate {finish queries : Nat}
      (budget : Nat) (within : budget ≤ cap)
      (step : DatabaseIndependentContraction
        (Input := Key) (Output := Output (Counter := Counter))
        (Phase := Output (Counter := Counter))
        (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)))
      (remaining : PhysicalProgramSkeleton cap budget finish queries) :
      PhysicalProgramSkeleton cap budget finish queries
  | retainedLeafWrite {finish queries : Nat}
      (occupied : Nat) (room : occupied < cap)
      (key : Key) (statement : List Byte)
      (fresh : Output (Counter := Counter))
      (remaining : PhysicalProgramSkeleton cap (occupied + 1) finish queries) :
      PhysicalProgramSkeleton cap occupied finish queries
  | copyX {finish queries : Nat}
      (budget : Nat) (within : budget ≤ cap)
      (keys : Finset Key)
      (update : (XKey keys → Option (Output (Counter := Counter))) →
        Work (Counter := Counter) (BaseWork := BaseWork) ≃
          Work (Counter := Counter) (BaseWork := BaseWork))
      (remaining : PhysicalProgramSkeleton cap budget finish queries) :
      PhysicalProgramSkeleton cap budget finish queries

namespace PhysicalProgramSkeleton

def run {cap start finish queries : Nat} :
    PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries →
    CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) →
      CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)
  | .nil _, state => state
  | .query _ _ remaining, state =>
      run remaining (cappedQueryState vectorPhaseSystem cap state)
  | .privateGate _ _ step remaining, state => run remaining (step.apply state)
  | .markGate _ _ step remaining, state => run remaining (step.apply state)
  | .retainedLeafWrite _ _ key _ fresh remaining, state =>
      run remaining (retainedOldReplace key fresh state)
  | .copyX _ _ keys update remaining, state =>
      run remaining (xControlledWorkspaceUpdate keys update state)

end PhysicalProgramSkeleton

/-- Per-role semantic certificates for one executable skeleton.  No program
operator or run equality is supplied here; all executable fields occur once,
in `PhysicalProgramSkeleton`. -/
inductive CertifiedFor
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)) :
    {cap start finish queries : Nat} →
      PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
        (BaseWork := BaseWork) cap start finish queries → Type _ where
  | nil {cap : Nat} (budget : Nat) : CertifiedFor contexts (.nil budget)
  | query {cap finish queries : Nat} (occupied : Nat) (room : occupied < cap)
      {remaining : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
        (BaseWork := BaseWork) cap (occupied + 1) finish queries}
      (certified : CertifiedFor contexts remaining) :
      CertifiedFor contexts (.query occupied room remaining)
  | privateGate {cap finish queries : Nat}
      (budget : Nat) (within : budget ≤ cap)
      (step : DatabaseIndependentContraction
        (Input := Key) (Output := Output (Counter := Counter))
        (Phase := Output (Counter := Counter))
        (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)))
      {remaining : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
        (BaseWork := BaseWork) cap budget finish queries}
      (authorization : ∀ role source target, step.kernel source target ≠ 0 →
        (contexts role).authorizedOf source.2.2.2 =
          (contexts role).authorizedOf target.2.2.2)
      (certified : CertifiedFor contexts remaining) :
      CertifiedFor contexts (.privateGate budget within step remaining)
  | markGate {cap finish queries : Nat}
      (budget : Nat) (within : budget ≤ cap)
      (step : DatabaseIndependentContraction
        (Input := Key) (Output := Output (Counter := Counter))
        (Phase := Output (Counter := Counter))
        (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)))
      {remaining : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
        (BaseWork := BaseWork) cap budget finish queries}
      (authorization : ∀ role source target, step.kernel source target ≠ 0 →
        ∃ statement, (contexts role).authorizedOf target.2.2.2 =
          (insert statement ((contexts role).authorizedOf source.2.2.2) :
            Finset (List Byte)))
      (certified : CertifiedFor contexts remaining) :
      CertifiedFor contexts (.markGate budget within step remaining)
  | retainedLeafWrite {cap finish queries : Nat}
      (occupied : Nat) (room : occupied < cap)
      (key : Key) (statement : List Byte)
      (fresh : Output (Counter := Counter))
      {remaining : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
        (BaseWork := BaseWork) cap (occupied + 1) finish queries}
      (marked : ∀ role work,
        statement ∈ (contexts role).authorizedOf work)
      (parsed : ∀ role, SmzaRp05FilteredReadback.globalLeafStatement
        (contexts role).leafNamespace ((contexts role).keyBytes key) = some statement)
      (certified : CertifiedFor contexts remaining) :
      CertifiedFor contexts
        (.retainedLeafWrite occupied room key statement fresh remaining)
  | copyX {cap finish queries : Nat}
      (budget : Nat) (within : budget ≤ cap)
      (keys : Finset Key)
      (update : (XKey keys → Option (Output (Counter := Counter))) →
        Work (Counter := Counter) (BaseWork := BaseWork) ≃
          Work (Counter := Counter) (BaseWork := BaseWork))
      {remaining : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
        (BaseWork := BaseWork) cap budget finish queries}
      (unrecognized : ∀ role key, key ∈ keys →
        parseStageQuery ((contexts role).keyBytes key) = none)
      (authorization : ∀ role view workspace,
        (contexts role).authorizedOf ((update view).symm workspace).2 =
          (contexts role).authorizedOf workspace.2)
      (certified : CertifiedFor contexts remaining) :
      CertifiedFor contexts (.copyX budget within keys update remaining)

namespace CertifiedFor

/-- The four fixed-advice contexts used by the deterministic accepted-failure
classification.  Only `role` and `advice` vary; the executable program is the
single skeleton certified below. -/
def roleContexts
    (model : RelationModel) (leafNamespace : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte)) :
    Role → Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  fun role =>
    { model := model
      leafNamespace := leafNamespace
      keyBytes := keyBytes
      counter := counter
      routes := routes
      role := role
      advice := allAdvice role
      outerFuel := outerFuel
      innerFuel := innerFuel
      authorizedOf := authorizedOf }

@[simp] theorem role_contexts_role
    (model : RelationModel) (leafNamespace : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte)) (role : Role) :
    (roleContexts model leafNamespace keyBytes counter routes allAdvice
      outerFuel innerFuel authorizedOf role).role = role := rfl

@[simp] theorem role_contexts_advice
    (model : RelationModel) (leafNamespace : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte)) (role : Role) :
    (roleContexts model leafNamespace keyBytes counter routes allAdvice
      outerFuel innerFuel authorizedOf role).advice = allAdvice role := rfl

def program
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap start finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries}
    (certified : CertifiedFor contexts skeleton) (role : Role) :
    CertifiedPhysicalProgram (contexts role) cap start finish queries :=
  match certified with
  | .nil budget => .nil budget
  | .query occupied room certified => .query occupied room (program certified role)
  | .privateGate budget within step authorization certified =>
      .zero (.privateGate budget within step (authorization role) (.nil budget))
        (program certified role)
  | .markGate budget within step authorization certified =>
      .zero (.markGate budget within step (authorization role) (.nil budget))
        (program certified role)
  | .retainedLeafWrite occupied room key statement fresh marked parsed certified =>
      .zero (.retainedLeafWrite occupied room key statement (marked role)
        (parsed role) fresh (.nil (occupied + 1))) (program certified role)
  | .copyX budget within keys update unrecognized authorization certified =>
      .zero (.copyX budget within keys (unrecognized role) update
        (authorization role) (.nil budget)) (program certified role)

theorem program_run_eq_skeleton
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap start finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries}
    (certified : CertifiedFor contexts skeleton) (role : Role)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    CertifiedPhysicalProgram.run (contexts role) (program certified role) state =
      PhysicalProgramSkeleton.run skeleton state := by
  induction certified generalizing state with
  | nil budget => rfl
  | query occupied room certified ih =>
      exact ih (cappedQueryState vectorPhaseSystem cap state)
  | privateGate budget within step authorization certified ih =>
      exact ih (step.apply state)
  | markGate budget within step authorization certified ih =>
      exact ih (step.apply state)
  | retainedLeafWrite occupied room key statement fresh marked parsed certified ih =>
      exact ih (retainedOldReplace key fresh state)
  | copyX budget within keys update unrecognized authorization certified ih =>
      exact ih (xControlledWorkspaceUpdate keys update state)

theorem common_run_subnormalized
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap start finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries}
    (certified : CertifiedFor contexts skeleton) (role : Role)
    {state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    (subnormalized : Subnormalized state) :
    Subnormalized (PhysicalProgramSkeleton.run skeleton state) := by
  rw [← program_run_eq_skeleton certified role,
    CertifiedPhysicalProgram.run_eq_compiled_physical]
  exact AdaptiveProgram.run_subnormalized
    (ActualProgram.compile (contexts role) cap
      (CertifiedPhysicalProgram.compilePhysical (contexts role)
        (program certified role))) subnormalized

/-- Every role is bounded on the same terminal state produced by the single
proof-erased physical program.  The CMS support cap is the compressed common
database cap; no populated fixed table is charged. -/
theorem common_terminal_role_mass_le
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    (selected : ∀ role, (contexts role).role = role)
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (queriesLe : queries ≤ cap)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers))
    (role : Role) :
    normSquared
        (adaptiveProject (event (contexts role)) cap
          (PhysicalProgramSkeleton.run skeleton
            (partialRandomOracleState
              (Output := Output (Counter := Counter)) ∅ registers))) ≤
      6 * (cap : ℝ) ^ 2 * ((completeRoleLoss role : Rat) : ℝ) +
        36 * (cap : ℝ) ^ 3 / (2^512 : ℝ) := by
  have bound := current_adaptive_role_bad_mass_le (contexts role) cap finish queries
    (CertifiedPhysicalProgram.compilePhysical (contexts role)
      (program certified role)) queriesLe registers subnormalized
  rw [← CertifiedPhysicalProgram.run_eq_compiled_physical
    (contexts role) (program certified role),
    program_run_eq_skeleton certified role] at bound
  simpa [selected role] using bound

/-- Four-role form on the same terminal state.  This is an ordinary finite
sum of diagonal bad-event masses, not a union of separately conditioned
executions. -/
theorem sum_common_terminal_role_mass_le
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    (selected : ∀ role, (contexts role).role = role)
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (queriesLe : queries ≤ cap)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers)) :
    (∑ role : Role,
      normSquared
        (adaptiveProject (event (contexts role)) cap
          (PhysicalProgramSkeleton.run skeleton
            (partialRandomOracleState
              (Output := Output (Counter := Counter)) ∅ registers)))) ≤
      ∑ role : Role,
        (6 * (cap : ℝ) ^ 2 * ((completeRoleLoss role : Rat) : ℝ) +
          36 * (cap : ℝ) ^ 3 / (2^512 : ℝ)) := by
  apply Finset.sum_le_sum
  intro role _
  exact common_terminal_role_mass_le selected certified queriesLe registers
    subnormalized role

def anyContextRoleEvent
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)) :
    AdaptiveEvent Key (Output (Counter := Counter))
      (Work (Counter := Counter) (BaseWork := BaseWork)) :=
  fun workspace database => ∃ role, event (contexts role) workspace database

theorem any_context_role_event_mass_le_sum
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)) (cap : Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (adaptiveProject (anyContextRoleEvent contexts) cap state) ≤
      ∑ role : Role,
        normSquared (adaptiveProject (event (contexts role)) cap state) := by
  classical
  unfold normSquared adaptiveProject anyContextRoleEvent
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  by_cases within : size basis.database ≤ cap
  · by_cases anyRole : ∃ role, event (contexts role)
        basis.workspace basis.database
    · obtain ⟨role, selected⟩ := anyRole
      have leftCondition : size basis.database ≤ cap ∧
          (∃ chosen : Role,
            event (contexts chosen) basis.workspace basis.database) :=
        ⟨within, role, selected⟩
      simp only [if_pos leftCondition]
      calc
        Complex.normSq (state basis) = Complex.normSq
              (if size basis.database ≤ cap ∧
                  event (contexts role) basis.workspace basis.database
                then state basis else 0) := by simp [within, selected]
        _ ≤ ∑ chosen : Role,
            Complex.normSq
              (if size basis.database ≤ cap ∧
                event (contexts chosen) basis.workspace basis.database then
                state basis else 0) := by
          exact Finset.single_le_sum
            (s := Finset.univ)
            (f := fun chosen : Role => Complex.normSq
              (if size basis.database ≤ cap ∧
                event (contexts chosen) basis.workspace basis.database then
                state basis else 0))
            (fun chosen _ => Complex.normSq_nonneg _)
            (Finset.mem_univ role)
    · simp [within, anyRole]
      exact Finset.sum_nonneg (fun chosen _ => Complex.normSq_nonneg _)
  · simp [within]

/-- Direct four-role union bound on the one common terminal execution. -/
theorem common_any_terminal_role_mass_le
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    (selected : ∀ role, (contexts role).role = role)
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (queriesLe : queries ≤ cap)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers)) :
    normSquared
        (adaptiveProject (anyContextRoleEvent contexts) cap
          (PhysicalProgramSkeleton.run skeleton
            (partialRandomOracleState
              (Output := Output (Counter := Counter)) ∅ registers))) ≤
      ∑ role : Role,
        (6 * (cap : ℝ) ^ 2 * ((completeRoleLoss role : Rat) : ℝ) +
          36 * (cap : ℝ) ^ 3 / (2^512 : ℝ)) := by
  exact (any_context_role_event_mass_le_sum contexts cap _).trans
    (sum_common_terminal_role_mass_le selected certified queriesLe registers
      subnormalized)

theorem common_execution_conditioned
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap start finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries}
    (certified : CertifiedFor contexts skeleton)
    (blockCap : Role → Nat) (role : Role)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState start state) :
    otherRoleTransform (contexts role) blockCap
        (PhysicalProgramSkeleton.run skeleton state) =
      CertifiedPhysicalProgram.conditionedRun (contexts role) blockCap
        (program certified role)
        (otherRoleTransform (contexts role) blockCap state) := by
  rw [← program_run_eq_skeleton certified role]
  exact CertifiedPhysicalProgram.other_role_transform_run
    (contexts role) blockCap (program certified role) state bounded

end CertifiedFor


/-! ## X measurement and fixed-table averaging -/

/-- The already-recorded X measurement is on the live complement and hence
commutes with conditioning.  Disjointness is stated on the actual claim list,
not as an independence or probability premise. -/
theorem x_measurement_commutes_other_role_transform
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (xClaims : List (Key × Output (Counter := Counter)))
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (live : ∀ key, key ∈ fixedOtherKeys ctx blockCap →
      key ∉ xClaims.map Prod.fst) :
    xMeasuredProjection xClaims (otherRoleTransform ctx blockCap state) =
      otherRoleTransform ctx blockCap (xMeasuredProjection xClaims state) := by
  unfold otherRoleTransform decompressFinset
  apply x_measured_projection_decompress_list
  intro key member
  exact live key (by simpa using member)

/-- Exact finite orthogonal disintegration of a full-table execution mass.
This is the checked role-table equivalence; it is recorded here next to the
adaptive conjugation so callers do not replace conditioning by an informal
distribution argument. -/
theorem execution_mass_eq_fixed_other_average
    {Phase Workspace : Type*}
    [Fintype Phase] [Fintype Workspace]
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (family : (Key → Output (Counter := Counter)) →
      RegisterBasis (Input := Key) (Phase := Phase) (Workspace := Workspace) → ℂ)
    (selectedEvent : (Key → Output (Counter := Counter)) →
      RegisterBasis (Input := Key) (Phase := Phase) (Workspace := Workspace) → Prop) :
    uniformTableRegisterEventMass family selectedEvent =
      (∑ fixed : FixedOtherKey selected blockCap keyBytes →
          Output (Counter := Counter),
        uniformTableRegisterEventMass
          (fun active : ActiveKey selected blockCap keyBytes →
              Output (Counter := Counter) =>
            family ((roleTableSplit selected blockCap keyBytes).symm
              (active, fixed)))
          (fun active register =>
            selectedEvent ((roleTableSplit selected blockCap keyBytes).symm
              (active, fixed)) register)) /
        Fintype.card (FixedOtherKey selected blockCap keyBytes →
          Output (Counter := Counter)) := by
  exact uniform_full_table_mass_eq_fixed_average selected blockCap keyBytes
    family selectedEvent

end
end HegemonCrypto.SmallWood.SmzaRp05ConditionedExecution
