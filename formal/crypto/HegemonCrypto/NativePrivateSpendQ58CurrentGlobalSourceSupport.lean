import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalSourceClassification
import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalRoleReindex
import HegemonCrypto.NativePrivateSpendQ58CurrentLiteralCausalSupport
import HegemonCrypto.NativePrivateSpendQ58CurrentSourceRecordExtraction
import HegemonCrypto.NativePrivateSpendQ58CurrentChosenRoleTarget

/-! Current accepted adaptive history support on the ORIGINAL global program.
Relations are constructed from the immutable native CSR template and the same
namespace public77. The adversarial constructor, proof producers, arbitrary
public data, rejected branches and all their queries remain inside one global
execution. Logical observers only recover its existing data; they do not run
as new physical adversaries. A missing SAME-source witness is inserted into
one of FOUR causal events, with the selected stage existential internal.
Primitive NOTE18/COMPFF7/recipient/SINGLE bounds are not renamed as SHA512.
This source changes deterministic protocol support, not their typed games.
SOURCE ONLY: kernel, original initialized projection and release review remain
required; no efficient extractor or Rust-equivalence theorem is claimed.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalSourceSupport
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult rawLog answerLog)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaChallengeStageTargets (Role)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter RawDigest keyBytes zero decode encode)
end G
namespace H
export NativePrivateSpendQ58CurrentGlobalRawLogTransport
  (Stage adaptiveHistoryProgram historyProgram actualTerminalProducer actualTerminalRoot
   actualTerminalKeys actualTerminal_rawRecords_exact)
end H
namespace SC
export NativePrivateSpendQ58CurrentSourceCompletion (consistent_of_claims)
end SC
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport
  (SourceView activeSourceView source_keys_active_for_each_role)
end X
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay
  (fullClaims claimOracle current_claims_store_every_branch_vector)
end Q
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims (live activeClaims fixedCompatible)
end AC
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey FixedTable)
end A
namespace RC
export NativePrivateSpendQ58CurrentRoleClassifier (RoleActive parseCurrentStageQuery)
end RC
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end GF
namespace FM
export NativePrivateSpendQ58CurrentFiberMassTransport
  (Active FixedVectors activeBytes actualActiveEquiv actualFixed)
end FM
namespace RI
export NativePrivateSpendQ58CurrentRoleInsertion (pullDB pullFixed)
end RI
namespace CS
export NativePrivateSpendQ58CurrentCausalSourceJoin
  (SourceTemplate NativeDataReadback nativeRelation nativeTarget nativeBatch native_terms_exact
   causalBad causalRelation causalNonce causalPublic)
end CS
namespace CC
export NativePrivateSpendQ58CurrentCanonicalSourceClassifier
  (root Choice SourceWitness nativeRecords)
end CC
namespace RT
export NativePrivateSpendQ58CurrentCanonicalSourceClassifier.RetainedTarget
  (ActualInsertion InsertionAt TargetedRoleEvent chosen_role_inserts_retaining_actual_target)
end RT
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire ExecutionStages verifierProgram)
end E
namespace CM
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end CM
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel sourceTrace queryTarget queryStage)
end P
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass (roleBad roleEvent stage)
end N
namespace GM
export NativePrivateSpendQ58CurrentGlobalCausalMass (event)
end GM
namespace GC
export NativePrivateSpendQ58CurrentGlobalSourceClassification
  (globalSourceRecords observerSourceView actual_accepted_global_history_has_same_source_classifiers)
end GC
namespace GR
export NativePrivateSpendQ58CurrentGlobalRoleReindex
  (actualObserverIdentity activeKeys pullFixed pullDB current_role_bad_reindex)
end GR
namespace AP
export NativePrivateSpendQ58CurrentActualCausalPublic
  (actual_current_completed_piop_traces_have_same_public)
end AP
namespace LS
export NativePrivateSpendQ58CurrentLiteralCausalSupport
  (current_decs_sample_bad_derives_causal_nonce current_piop_matrix_bad_uses_actual_causal_public
   current_piop_opening_bad_uses_actual_causal_public)
end LS
namespace SE
export NativePrivateSpendQ58CurrentSourceRecordExtraction (current_source_extract_survives_filtration)
end SE
namespace AL
export NativePrivateSpendQ58CurrentActualTraceLabel (sourceRecords)
end AL
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext)
end F
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Native stage input omits the relation; immutable native getters determine
that field from the SAME77 namespace words. The producer and nonce are intact. -/
structure NativeStageInput where
  proofProducer : Program E.Wire
  ns : CM.Namespace
  nonce : Fin (2^32)

def nativeStage (template : CS.SourceTemplate) (input : NativeStageInput) : H.Stage :=
  { proofProducer := input.proofProducer
    ns := input.ns
    relation := CS.nativeRelation template
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt input.ns.binding i.val : Goldilocks))
    nonce := input.nonce }

/-- Pure ordinary constructor mapping; no extra oracle query or stage limit. -/
def nativeConstructor (template : CS.SourceTemplate)
    (constructor : Program (List NativeStageInput)) : Program (List H.Stage) :=
  constructor.bind fun inputs => .done (some (inputs.map (nativeStage template)))

private theorem native_relation_data (template : CS.SourceTemplate) (pub : Fin 77 → Goldilocks) :
    CS.NativeDataReadback template pub (CS.nativeRelation template pub) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro check
    exact CS.native_terms_exact (template.rawTerms check)
  · intro check before
    change CS.nativeTarget template pub check = template.nonpublicTarget check
    rw [CS.nativeTarget, dif_pos before]
  · intro i
    change CS.nativeTarget template pub ⟨1344517+i.val, by have bound := i.isLt; omega⟩ = pub i
    have notBefore : ¬1344517+i.val < 1344517 := by omega
    rw [CS.nativeTarget, dif_neg notBefore]
    exact congrArg pub (Fin.ext (Nat.add_sub_cancel_left 1344517 i.val))
  · intro batch operand
    rfl

theorem actual_native_constructor_derives_relation_data
    (template : CS.SourceTemplate) (constructor : Program (List NativeStageInput))
    (oracle : Oracle) (stages : List H.Stage)
    (constructed : (nativeConstructor template constructor).eval oracle = some stages)
    (i : Fin stages.length) :
    CS.NativeDataReadback template
      (fun j : Fin 77 => (V8SmzaOracleParser.wordAt stages[i.val].ns.binding j.val : Goldilocks))
      stages[i.val].relation := by
  obtain ⟨inputs, _produced, mapped⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle constructor
      (fun inputs => Program.done (some (inputs.map (nativeStage template)))) stages constructed
  have stageList : inputs.map (nativeStage template) = stages := Option.some.inj mapped
  have member : stages[i.val] ∈ inputs.map (nativeStage template) := by
    rw [stageList]
    exact List.getElem_mem i.isLt
  obtain ⟨input, _present, same⟩ := List.mem_map.mp member
  rw [← same]
  exact native_relation_data template _

variable {Result : Type} (program : Program Result)

def roleDatabase (role : Role)
    (database : Database (G.Key program) (VectorOutput G.Counter)) :
    Database (FM.Active role (G.keyBytes program)) (VectorOutput G.Counter) :=
  fun key => database key.val

def roleFixed (role : Role)
    (database : Database (G.Key program) (VectorOutput G.Counter)) :
    FM.FixedVectors (Counter := G.Counter) role (G.keyBytes program) :=
  fun key => (database key.val).getD 0

private def nativeDB (role : Role)
    (database : Database (G.Key program) (VectorOutput G.Counter)) :
    Database (A.ActiveKey (AC.live program role GF.currentRoleCaps)) (VectorOutput G.Counter) :=
  fun key => database key.val

private def nativeFixed (role : Role)
    (database : Database (G.Key program) (VectorOutput G.Counter)) :
    A.FixedTable (Counter := G.Counter) (AC.live program role GF.currentRoleCaps) :=
  fun key => (database key.val).getD 0

private theorem routed_native_raw (role : Role)
    (database : Database (G.Key program) (VectorOutput G.Counter)) :
    rawRecords (FM.activeBytes role (G.keyBytes program)) (vectorOutputBytes G.zero)
      (roleDatabase program role database) =
    rawRecords (fun key : A.ActiveKey (AC.live program role GF.currentRoleCaps) => G.keyBytes program key.val)
      (vectorOutputBytes G.zero) (nativeDB program role database) := by
  ext pair
  rcases pair with ⟨input, digest⟩
  simp only [SmzaRawDatabaseRecords.mem_raw_records_iff]
  constructor
  · rintro ⟨key, vector, stored, bytes, output⟩
    exact ⟨FM.actualActiveEquiv role (G.keyBytes program) key, vector, stored, bytes, output⟩
  · rintro ⟨key, vector, stored, bytes, output⟩
    refine ⟨(FM.actualActiveEquiv role (G.keyBytes program)).symm key, vector, ?_, bytes, output⟩
    exact stored

private theorem source_slice (role : Role)
    (database : Database (G.Key program) (VectorOutput G.Counter)) :
    AL.sourceRecords (rawRecords (FM.activeBytes role (G.keyBytes program)) (vectorOutputBytes G.zero)
      (roleDatabase program role database)) =
    AL.sourceRecords (rawRecords (G.keyBytes program) (vectorOutputBytes G.zero) database) := by
  ext pair
  rcases pair with ⟨input, digest⟩
  constructor
  · intro member
    obtain ⟨present, unparsed⟩ := Finset.mem_filter.mp member
    obtain ⟨key, vector, stored, bytes, output⟩ :=
      (SmzaRawDatabaseRecords.mem_raw_records_iff _ _ _ _ _).mp present
    exact Finset.mem_filter.mpr ⟨
      (SmzaRawDatabaseRecords.mem_raw_records_iff _ _ _ _ _).mpr
        ⟨key.val, vector, stored, bytes, output⟩, unparsed⟩
  · intro member
    obtain ⟨present, unparsed⟩ := Finset.mem_filter.mp member
    obtain ⟨key, vector, stored, bytes, output⟩ :=
      (SmzaRawDatabaseRecords.mem_raw_records_iff _ _ _ _ _).mp present
    have active : RC.RoleActive role GF.currentRoleCaps (G.keyBytes program) key := by
      have parser : RC.parseCurrentStageQuery (G.keyBytes program key) = none := bytes.symm ▸ unparsed
      simp only [RC.RoleActive, parser]
    let earlier := (FM.actualActiveEquiv role (G.keyBytes program)).symm ⟨key, active⟩
    exact Finset.mem_filter.mpr ⟨
      (SmzaRawDatabaseRecords.mem_raw_records_iff _ _ _ _ _).mpr
        ⟨earlier, vector, stored, bytes, output⟩, unparsed⟩

private theorem native_selected_claims (role : Role) (branch : Branches G.decode program)
    (database : Database (G.Key program) (VectorOutput G.Counter))
    (all : ClaimsDatabaseEvent (Q.fullClaims program branch) database) :
    ClaimsDatabaseEvent (AC.activeClaims program role GF.currentRoleCaps branch)
      (nativeDB program role database) := by
  intro claim member
  unfold AC.activeClaims at member
  obtain ⟨original, recorded, mapped⟩ := List.mem_filterMap.mp member
  by_cases active : AC.live program role GF.currentRoleCaps original.1
  · rw [dif_pos active] at mapped
    cases Option.some.inj mapped
    exact all original recorded
  · rw [dif_neg active] at mapped
    cases mapped

private theorem native_compatible (role : Role) (branch : Branches G.decode program)
    (database : Database (G.Key program) (VectorOutput G.Counter))
    (all : ClaimsDatabaseEvent (Q.fullClaims program branch) database) :
    AC.fixedCompatible program role GF.currentRoleCaps (nativeFixed program role database) branch := by
  intro call recorded inactive
  have stored := Q.current_claims_store_every_branch_vector program branch database all call recorded
  change (database (G.encode program call.1)).getD 0 = call.2
  rw [stored]
  rfl

attribute [local irreducible] NativePrivateSpendQ58CurrentDecsDynamicMass.fiberBad
  NativePrivateSpendQ58CurrentFiberMassTransport.matrixEvent
  NativePrivateSpendQ58CurrentFiberMassTransport.openingEvent

/-- Actual target retention derives the causal public label on the SAME
replayed stages. No readout, source coverage, frame validity or target is
supplied by the caller. Only the immutable ordinary native constructor data
is consumed at this interface; the public history wrapper derives it above. -/
theorem actual_chosen_role_derives_causal_event
    (producer : Program E.Wire) (ns : CM.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
    (branch : Branches G.decode (CC.root producer ns relation nonce))
    (database : Database (G.Key (CC.root producer ns relation nonce)) (VectorOutput G.Counter))
    (all : ClaimsDatabaseEvent (Q.fullClaims (CC.root producer ns relation nonce) branch) database)
    (accepted : branchResult G.decode (CC.root producer ns relation nonce) branch = some ())
    (template : CS.SourceTemplate)
    (data : CS.NativeDataReadback template
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) relation)
    (role : Role)
    (choice : CC.Choice producer ns relation nonce branch role
      (X.activeSourceView (CC.root producer ns relation nonce) role
        (nativeDB (CC.root producer ns relation nonce) role database))) :
    GM.event (CC.root producer ns relation nonce) template (fun _ => 0) role
      (roleFixed (CC.root producer ns relation nonce) role database)
      (roleDatabase (CC.root producer ns relation nonce) role database) := by
  let root := CC.root producer ns relation nonce
  have insertion := RT.chosen_role_inserts_retaining_actual_target producer ns relation nonce branch role
    (nativeFixed root role database) (nativeDB root role database)
    (native_compatible root role branch database all) (native_selected_claims root role branch database all)
    (fun _ => 0) accepted choice
  obtain ⟨wire, _produced, transcript, stages, clean, free, covered, final, inserted⟩ := insertion
  have rawEq := routed_native_raw root role database
  have recordEq : CC.nativeRecords producer ns relation nonce role (nativeDB root role database) =
      AL.sourceRecords (rawRecords (FM.activeBytes role (G.keyBytes root)) (vectorOutputBytes G.zero)
        (roleDatabase root role database)) := congrArg AL.sourceRecords rawEq.symm
  change NativePrivateSpendQ58CurrentCanonicalSourceClassifier.RetainedTarget.InsertionAt
    producer ns relation nonce role (nativeFixed root role database) (nativeDB root role database)
    (fun _ => 0) wire transcript stages at inserted
  cases role with
  | decsMatrix =>
    rcases inserted with ⟨key, vector, stored, bad⟩
    exact ⟨key, vector, stored, bad⟩
  | decsSample =>
    rcases inserted with ⟨key, vector, stored, bad⟩
    refine ⟨key, vector, stored, ?_⟩
    let causalTrace := P.currentLabel (FM.activeBytes .decsSample (G.keyBytes root))
      G.zero (N.stage .decsSample) (roleDatabase root .decsSample database) key
    have normalizedBad : N.roleBad root relation (fun _ => 0) nonce .decsSample
        (roleFixed root .decsSample database) causalTrace key vector := by
      dsimp (config := { instances := true, failIfUnchanged := false }) only
        [causalTrace, N.stage, RI.pullFixed, RI.pullDB, nativeFixed, nativeDB,
          roleFixed, roleDatabase,
          NativePrivateSpendQ58CurrentFiberMassTransport.actualFixedEquiv,
          FM.actualActiveEquiv] at bad ⊢
      exact bad
    with_reducible
      exact LS.current_decs_sample_bad_derives_causal_nonce root template (fun _ => 0)
        (roleFixed root .decsSample database) causalTrace key vector relation nonce normalizedBad
  | piopMatrix =>
    rcases inserted with ⟨key, vector, stored, parsed, bad⟩
    have labels := AP.actual_current_completed_piop_traces_have_same_public ns relation nonce wire
      _ transcript stages clean _ (recordEq ▸ free) (recordEq ▸ covered) final
    have readout : CS.causalPublic .piopMatrix
        (P.currentLabel (FM.activeBytes .piopMatrix (G.keyBytes root)) G.zero 26
          (roleDatabase root .piopMatrix database) key) =
        (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) := by
      unfold P.currentLabel P.sourceTrace P.queryTarget
      rw [parsed]
      change CS.causalPublic .piopMatrix (extract F.rawNext
        (rawRecords (FM.activeBytes .piopMatrix (G.keyBytes root)) (vectorOutputBytes G.zero)
          (roleDatabase root .piopMatrix database)) 26 .fpp stages.pcs.hashFpp) = _
      rw [← SE.current_source_extract_survives_filtration]
      exact labels.1
    refine ⟨key, vector, stored, ?_⟩
    let causalTrace := P.currentLabel (FM.activeBytes .piopMatrix (G.keyBytes root))
      G.zero (N.stage .piopMatrix) (roleDatabase root .piopMatrix database) key
    have normalizedBad : N.roleBad root relation (fun _ => 0) nonce .piopMatrix
        (roleFixed root .piopMatrix database) causalTrace key vector := by
      dsimp (config := { instances := true, failIfUnchanged := false }) only
        [causalTrace, N.stage, RI.pullFixed, RI.pullDB, nativeFixed, nativeDB,
          roleFixed, roleDatabase,
          NativePrivateSpendQ58CurrentFiberMassTransport.actualFixedEquiv,
          FM.actualActiveEquiv] at bad ⊢
      exact bad
    have normalizedReadout : CS.causalPublic .piopMatrix causalTrace =
        (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) := by
      dsimp (config := { failIfUnchanged := false }) only [causalTrace, N.stage] at readout ⊢
      exact readout
    with_reducible
      exact LS.current_piop_matrix_bad_uses_actual_causal_public root template (fun _ => 0)
        (roleFixed root .piopMatrix database) causalTrace key vector relation nonce
        (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks))
        normalizedReadout data normalizedBad
  | piopOpening =>
    rcases inserted with ⟨key, vector, stored, parsed, bad⟩
    have labels := AP.actual_current_completed_piop_traces_have_same_public ns relation nonce wire
      _ transcript stages clean _ (recordEq ▸ free) (recordEq ▸ covered) final
    have readout : CS.causalPublic .piopOpening
        (P.currentLabel (FM.activeBytes .piopOpening (G.keyBytes root)) G.zero 27
          (roleDatabase root .piopOpening database) key) =
        (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) := by
      unfold P.currentLabel P.sourceTrace P.queryTarget
      rw [parsed]
      change CS.causalPublic .piopOpening (extract F.rawNext
        (rawRecords (FM.activeBytes .piopOpening (G.keyBytes root)) (vectorOutputBytes G.zero)
          (roleDatabase root .piopOpening database)) 27 .piop wire.hPiop) = _
      rw [← SE.current_source_extract_survives_filtration]
      exact labels.2
    refine ⟨key, vector, stored, ?_⟩
    let causalTrace := P.currentLabel (FM.activeBytes .piopOpening (G.keyBytes root))
      G.zero (N.stage .piopOpening) (roleDatabase root .piopOpening database) key
    have normalizedBad : N.roleBad root relation (fun _ => 0) nonce .piopOpening
        (roleFixed root .piopOpening database) causalTrace key vector := by
      dsimp (config := { instances := true, failIfUnchanged := false }) only
        [causalTrace, N.stage, RI.pullFixed, RI.pullDB, nativeFixed, nativeDB,
          roleFixed, roleDatabase,
          NativePrivateSpendQ58CurrentFiberMassTransport.actualFixedEquiv,
          FM.actualActiveEquiv] at bad ⊢
      exact bad
    have normalizedReadout : CS.causalPublic .piopOpening causalTrace =
        (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) := by
      dsimp (config := { failIfUnchanged := false }) only [causalTrace, N.stage] at readout ⊢
      exact readout
    with_reducible
      exact LS.current_piop_opening_bad_uses_actual_causal_public root template (fun _ => 0)
        (roleFixed root .piopOpening database) causalTrace key vector relation nonce
        (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks))
        normalizedReadout data normalizedBad

variable (constructor : Program (List H.Stage))
local notation "Global" => H.adaptiveHistoryProgram constructor

private theorem actual_observer_label_eq (oracle : Oracle) (stages : List H.Stage)
    (constructed : constructor.eval oracle = some stages) (i : Fin stages.length) (role : Role)
    (database : Database (G.Key Global) (VectorOutput G.Counter))
    (key : FM.Active role (G.keyBytes (H.actualTerminalRoot constructor stages i))) :
    let identity := GR.actualObserverIdentity constructor oracle stages constructed i
    P.currentLabel (FM.activeBytes role (G.keyBytes (H.actualTerminalRoot constructor stages i)))
      G.zero (N.stage role) (GR.pullDB identity role (roleDatabase Global role database)) key =
    P.currentLabel (FM.activeBytes role (G.keyBytes Global)) G.zero (N.stage role)
      (roleDatabase Global role database) (GR.activeKeys identity role key) := by
  let identity := GR.actualObserverIdentity constructor oracle stages constructed i
  let observerDB := fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key)
  have rawEq : AL.sourceRecords (rawRecords
      (FM.activeBytes role (G.keyBytes (H.actualTerminalRoot constructor stages i)))
      (vectorOutputBytes G.zero) (GR.pullDB identity role (roleDatabase Global role database))) =
    AL.sourceRecords (rawRecords (FM.activeBytes role (G.keyBytes Global))
      (vectorOutputBytes G.zero) (roleDatabase Global role database)) := by
    change AL.sourceRecords (rawRecords
      (FM.activeBytes role (G.keyBytes (H.actualTerminalRoot constructor stages i)))
      (vectorOutputBytes G.zero) (roleDatabase (H.actualTerminalRoot constructor stages i) role observerDB)) = _
    rw [source_slice, H.actualTerminal_rawRecords_exact, ← source_slice Global role database]
  have bytes : FM.activeBytes role (G.keyBytes Global) (GR.activeKeys identity role key) =
      FM.activeBytes role (G.keyBytes (H.actualTerminalRoot constructor stages i)) key := by
    change G.keyBytes Global (identity.keys key.val) =
      G.keyBytes (H.actualTerminalRoot constructor stages i) key.val
    exact identity.bytes key.val
  let leftRaw := rawRecords
    (FM.activeBytes role (G.keyBytes (H.actualTerminalRoot constructor stages i)))
    (vectorOutputBytes G.zero) (GR.pullDB identity role (roleDatabase Global role database))
  let rightRaw := rawRecords (FM.activeBytes role (G.keyBytes Global))
    (vectorOutputBytes G.zero) (roleDatabase Global role database)
  let leftInput := FM.activeBytes role (G.keyBytes (H.actualTerminalRoot constructor stages i)) key
  let rightInput := FM.activeBytes role (G.keyBytes Global) (GR.activeKeys identity role key)
  have filtered := congrArg
    (fun records => P.sourceTrace (N.stage role) records leftInput) rawEq
  have leftFiltered := SE.current_source_extract_survives_filtration
    leftRaw (N.stage role) (P.queryTarget leftInput).1 (P.queryTarget leftInput).2
  have rightFiltered := SE.current_source_extract_survives_filtration
    rightRaw (N.stage role) (P.queryTarget leftInput).1 (P.queryTarget leftInput).2
  have inputEq : P.sourceTrace (N.stage role) rightRaw leftInput =
      P.sourceTrace (N.stage role) rightRaw rightInput :=
    congrArg (P.sourceTrace (N.stage role) rightRaw) bytes.symm
  exact leftFiltered.symm.trans (filtered.trans (rightFiltered.trans inputEq))

/-- Actual logical observers insert into original-program causal predicates.
The raw-label, fixed-cell and stored-vector transports are proved, never
supplied as an event-inclusion certificate. -/
theorem actual_observer_causal_event_is_global (oracle : Oracle) (stages : List H.Stage)
    (constructed : constructor.eval oracle = some stages) (i : Fin stages.length)
    (database : Database (G.Key Global) (VectorOutput G.Counter))
    (template : CS.SourceTemplate) (role : Role)
    (hit : GM.event (H.actualTerminalRoot constructor stages i) template (fun _ => 0) role
      (roleFixed (H.actualTerminalRoot constructor stages i) role
        (fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key)))
      (roleDatabase (H.actualTerminalRoot constructor stages i) role
        (fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key)))) :
    GM.event Global template (fun _ => 0) role (roleFixed Global role database)
      (roleDatabase Global role database) := by
  let identity := GR.actualObserverIdentity constructor oracle stages constructed i
  rcases hit with ⟨key, vector, stored, bad⟩
  let trace := P.currentLabel
    (FM.activeBytes role (G.keyBytes (H.actualTerminalRoot constructor stages i))) G.zero (N.stage role)
    (GR.pullDB identity role (roleDatabase Global role database)) key
  have labelEq := actual_observer_label_eq constructor oracle stages constructed i role database key
  have actualBad : N.roleBad Global (CS.causalRelation template role trace) (fun _ => 0)
      (CS.causalNonce (H.actualTerminalRoot constructor stages i) (fun _ => 0) role
        (GR.pullFixed identity role (roleFixed Global role database)) trace)
      role (roleFixed Global role database) trace (GR.activeKeys identity role key) vector := by
    rw [← GR.current_role_bad_reindex identity]
    exact bad
  refine ⟨GR.activeKeys identity role key, vector, stored, ?_⟩
  rw [← labelEq]
  cases role with
  | decsMatrix => exact actualBad
  | decsSample =>
    with_reducible
      exact LS.current_decs_sample_bad_derives_causal_nonce Global template (fun _ => 0)
        (roleFixed Global .decsSample database) trace _ vector _ _ actualBad
  | piopMatrix =>
    simpa only [CS.causalBad, NativePrivateSpendQ58CurrentCausalHistoryDensity.labelledBad,
      N.roleBad] using actualBad
  | piopOpening =>
    simpa only [CS.causalBad, NativePrivateSpendQ58CurrentCausalHistoryDensity.labelledBad,
      N.roleBad] using actualBad

/-- SAME-source witnesses for all actually constructed accepted stages.
Every observer branch is tied to the original raw log and original full DB. -/
def AllActualSourceWitnesses (branch : Branches G.decode Global)
    (database : Database (G.Key Global) (VectorOutput G.Counter)) : Prop :=
  let oracle := Q.claimOracle Global database (fun _ => 0)
  ∃ (stages : List H.Stage) (constructed : constructor.eval oracle = some stages),
    (H.historyProgram stages).eval oracle = some () ∧
    ∀ i : Fin stages.length,
      ∃ observerBranch : Branches G.decode (H.actualTerminalRoot constructor stages i),
        branchResult G.decode (H.actualTerminalRoot constructor stages i) observerBranch = some () ∧
        (rawLog G.decode (H.actualTerminalRoot constructor stages i) observerBranch).toFinset =
          (rawLog G.decode Global branch).toFinset ∧
        ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot constructor stages i) observerBranch)
          (fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key)) ∧
        CC.SourceWitness (H.actualTerminalProducer constructor stages i)
          stages[i.val].ns stages[i.val].relation stages[i.val].nonce observerBranch
          (GC.observerSourceView constructor oracle stages constructed i database)

/-- Closed deterministic global support statement. The actual native history
constructs its relations; global acceptance and full raw claims derive every
stage/observer/source classifier. If a SAME-source witness is missing, one
original global causal event occurs, or the SAME global source record collides.
There is no supplied stage, validity, public readout, event support or mass
assumption, and there is no invocation multiplier. -/
theorem actual_native_global_missing_source_has_one_causal_role
    (template : CS.SourceTemplate) (inputConstructor : Program (List NativeStageInput))
    (branch : Branches G.decode (H.adaptiveHistoryProgram (nativeConstructor template inputConstructor)))
    (database : Database (G.Key (H.adaptiveHistoryProgram (nativeConstructor template inputConstructor)))
      (VectorOutput G.Counter))
    (all : ClaimsDatabaseEvent
      (Q.fullClaims (H.adaptiveHistoryProgram (nativeConstructor template inputConstructor)) branch) database)
    (accepted : branchResult G.decode
      (H.adaptiveHistoryProgram (nativeConstructor template inputConstructor)) branch = some ())
    (missing : ¬AllActualSourceWitnesses (nativeConstructor template inputConstructor) branch database) :
    ¬RecordsCollisionFree (GC.globalSourceRecords (nativeConstructor template inputConstructor) database) ∨
      ∃ role, GM.event (H.adaptiveHistoryProgram (nativeConstructor template inputConstructor))
        template (fun _ => 0) role
        (roleFixed (H.adaptiveHistoryProgram (nativeConstructor template inputConstructor)) role database)
        (roleDatabase (H.adaptiveHistoryProgram (nativeConstructor template inputConstructor)) role database) := by
  let constructor := nativeConstructor template inputConstructor
  let global := H.adaptiveHistoryProgram constructor
  let oracle := Q.claimOracle global database (fun _ => 0)
  obtain ⟨stages, constructed, historyAccepted, classified⟩ :=
    GC.actual_accepted_global_history_has_same_source_classifiers constructor branch database all accepted
  by_cases free : RecordsCollisionFree (GC.globalSourceRecords constructor database)
  · have someChosen : ∃ i : Fin stages.length,
        ∃ observerBranch : Branches G.decode (H.actualTerminalRoot constructor stages i),
          branchResult G.decode (H.actualTerminalRoot constructor stages i) observerBranch = some () ∧
          ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot constructor stages i) observerBranch)
            (fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key)) ∧
          ∃ role, CC.Choice (H.actualTerminalProducer constructor stages i)
            stages[i.val].ns stages[i.val].relation stages[i.val].nonce observerBranch role
            (GC.observerSourceView constructor oracle stages constructed i database) := by
      by_contra noChosen
      apply missing
      refine ⟨stages, constructed, historyAccepted, ?_⟩
      intro i
      obtain ⟨observerBranch, observerAccepted, logEq, observerClaims, result⟩ := classified i
      refine ⟨observerBranch, observerAccepted, logEq, observerClaims, ?_⟩
      rcases result with collision | chosen | witness
      · exact (collision free).elim
      · exact (noChosen ⟨i, observerBranch, observerAccepted, observerClaims, chosen⟩).elim
      · exact witness
    obtain ⟨i, observerBranch, observerAccepted, observerClaims, role, choice⟩ := someChosen
    have data := actual_native_constructor_derives_relation_data template inputConstructor
      oracle stages constructed i
    have hit := actual_chosen_role_derives_causal_event
      (H.actualTerminalProducer constructor stages i) stages[i.val].ns stages[i.val].relation
      stages[i.val].nonce observerBranch
      (fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key))
      observerClaims observerAccepted template data role choice
    exact Or.inr ⟨role, actual_observer_causal_event_is_global constructor oracle stages constructed i
      database template role hit⟩
  · exact Or.inl free

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalSourceSupport
