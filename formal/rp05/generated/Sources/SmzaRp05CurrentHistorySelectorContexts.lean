import SmzaRp05CurrentHistoryVerifierProgram
import SmzaRp05CurrentAcceptedOrdinaryMassBound
import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentJointObserverKeys
import SmzaRp05GroupedSuffix

/-! # Selector contexts on a retained history stage

The terminal verifier observer of a retained stage uses the full history's
finite grouped-key universe. This file only transports the deterministic
program/key/context interfaces; it makes no probability, selector-coverage,
or quantum-state claim.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistorySelectorContexts

open SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram retainedPrefixAt stageVerifierAt
    terminalHistoryStageObserver terminalHistoryStageObserver_groups_eq
    terminalHistoryStageObserver_key_eq)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentAcceptedMassToScalar (currentAcceptedMassContexts)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05ExecutableAddressCompiler (groups)
open SmzaRp05CurrentFiniteGroupedProgram (Key included)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05LeafNamespace (Namespace)
open SmzaChallengeStageTargets (Role)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open HegemonCrypto.CanonicalBytes (Byte)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

private theorem included_cast_of_groups_eq {α β : Type}
    (first : Program α) (joint : Program β)
    (groupsEq : groups first = groups joint) (sameKey : Key first = Key joint)
    (key : Key first) :
  included joint (cast sameKey key) = included first key := by
  let sameUniverse := congrArg (insert (SmzaRp05GroupedSuffix.groupKeyOf [])) groupsEq
  have canonical : Key first = Key joint := by
    change { key : SmzaRp05GroupedSuffix.GroupKey //
        key ∈ insert (SmzaRp05GroupedSuffix.groupKeyOf []) (groups first) } =
      { key : SmzaRp05GroupedSuffix.GroupKey //
        key ∈ insert (SmzaRp05GroupedSuffix.groupKeyOf []) (groups joint) }
    exact SmzaRp05CurrentJointObserverKeys.subtype_type_eq_of_finset_eq _ _ sameUniverse
  have sameCanonical : sameKey = canonical := Subsingleton.elim _ _
  rw [sameCanonical]
  unfold included
  change (cast (SmzaRp05CurrentJointObserverKeys.subtype_type_eq_of_finset_eq _ _
    sameUniverse) key).val = key.val
  exact SmzaRp05CurrentJointObserverKeys.subtype_cast_val_of_finset_eq _ _
    sameUniverse key

private theorem context_keyBytes_cast {KeyLeft KeyRight : Type}
    [Fintype KeyLeft] [DecidableEq KeyLeft]
    [Fintype KeyRight] [DecidableEq KeyRight]
    (sameKey : KeyLeft = KeyRight)
    (ctx : Context (Key := KeyLeft) (Counter := GroupCounter)
      (BaseWork := BaseWork)) :
    (cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) sameKey) ctx).keyBytes =
      fun key => ctx.keyBytes (cast sameKey.symm key) := by
  cases sameKey
  rfl

private theorem cast_context_mk_keyBytes {KeyLeft KeyRight : Type}
    [Fintype KeyLeft] [DecidableEq KeyLeft]
    [Fintype KeyRight] [DecidableEq KeyRight]
    (sameKey : KeyLeft = KeyRight) (model : RelationModel)
    (ns : Namespace) (keyBytes : KeyLeft → V8SmzaOracleParser.RawInput)
    (counter : GroupCounter)
    (routes : SmzaRp05TracePrefixes.TypedRoutes model GroupCounter)
    (role : Role) (advice : AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte)) :
    cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) sameKey)
      (Context.mk model ns keyBytes counter routes role advice outerFuel
        innerFuel authorizedOf) =
    Context.mk model ns (fun key => keyBytes (cast sameKey.symm key))
      counter routes role advice outerFuel innerFuel authorizedOf := by
  cases sameKey
  rfl

def historyStageProducer (stages : List HistoryStage)
    (i : Fin stages.length) : Program ExistingProofFieldView :=
  (historyProgram stages).bind fun _ => retainedPrefixAt stages i

/-- The ordinary accepted endpoint's actual program for a retained stage is
the history observer itself, with no change to its producer or verifier. -/
theorem actualProgram_history_stage_eq_observer
    (stages : List HistoryStage) (i : Fin stages.length) :
    actualProgram (historyStageProducer stages i)
      (stages[i.val]).ns (stages[i.val]).statement
      (stages[i.val]).pending (stages[i.val]).nonce =
    terminalHistoryStageObserver stages i := by
  unfold actualProgram historyStageProducer terminalHistoryStageObserver
    stageVerifierAt
  exact HegemonCrypto.SmallWood.SmzaRp05CurrentJointAcceptedExecution.program_bind_assoc
    (historyProgram stages) (fun _ => retainedPrefixAt stages i)
    (fun wire => verifierProgram (stages[i.val]).ns currentDsl
      (stages[i.val]).statement (stages[i.val]).pending
      (stages[i.val]).nonce wire)

/-- The target verifier and terminal replay observer have the exact global
history key type, derived from the all-answer support equality. -/
theorem history_stage_target_key_eq_history
    (stages : List HistoryStage) (i : Fin stages.length) :
    Key (actualProgram (historyStageProducer stages i)
      (stages[i.val]).ns (stages[i.val]).statement
      (stages[i.val]).pending (stages[i.val]).nonce) =
    Key (historyProgram stages) := by
  calc
    _ = Key (terminalHistoryStageObserver stages i) :=
      congrArg Key (actualProgram_history_stage_eq_observer stages i)
    _ = Key (historyProgram stages) := terminalHistoryStageObserver_key_eq stages i

private theorem history_stage_target_groups_eq_history
    (stages : List HistoryStage) (i : Fin stages.length) :
    groups (actualProgram (historyStageProducer stages i)
      (stages[i.val]).ns (stages[i.val]).statement
      (stages[i.val]).pending (stages[i.val]).nonce) =
    groups (historyProgram stages) := by
  calc
    _ = groups (terminalHistoryStageObserver stages i) :=
      congrArg groups (actualProgram_history_stage_eq_observer stages i)
    _ = groups (historyProgram stages) :=
      terminalHistoryStageObserver_groups_eq stages i

/-- Transport preserves the literal key-byte map (`included` followed by the
group representative), not merely the carrier's cardinality. -/
theorem history_stage_context_keyBytes_eq
    (stages : List HistoryStage) (i : Fin stages.length)
    (commonNs : Namespace) (stageNsEq : (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (role : Role) :
    (cast (congrArg (fun key => Context (Key := key)
        (Counter := GroupCounter) (BaseWork := BaseWork))
        (history_stage_target_key_eq_history stages i))
      (currentAcceptedMassContexts (BaseWork := BaseWork)
        (historyStageProducer stages i) (stages[i.val]).ns
        (stages[i.val]).statement (stages[i.val]).pending
        (stages[i.val]).nonce model bounded advice 28 28 role)).keyBytes =
    (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
      model bounded commonNs role (advice role) 28 28 (fun _ => ∅)).keyBytes := by
  cases stageNsEq
  have keyEq := history_stage_target_key_eq_history stages i
  funext key
  change (cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) keyEq)
      (currentGroupedContext (BaseWork := BaseWork)
        (actualProgram (historyStageProducer stages i)
        (stages[i.val]).ns (stages[i.val]).statement
        (stages[i.val]).pending (stages[i.val]).nonce) model bounded
        (stages[i.val]).ns role (advice role) 28 28 (fun _ => ∅))).keyBytes key =
    (currentGroupedContext (historyProgram stages) model bounded
      (stages[i.val]).ns role (advice role) 28 28 (fun _ => ∅)).keyBytes key
  have castMap := context_keyBytes_cast keyEq
    (currentGroupedContext (BaseWork := BaseWork)
      (actualProgram (historyStageProducer stages i)
      (stages[i.val]).ns (stages[i.val]).statement
      (stages[i.val]).pending (stages[i.val]).nonce) model bounded
      (stages[i.val]).ns role (advice role) 28 28 (fun _ => ∅))
  rw [castMap]
  change groupRepresentative (included
      (actualProgram (historyStageProducer stages i)
        (stages[i.val]).ns (stages[i.val]).statement
        (stages[i.val]).pending (stages[i.val]).nonce)
      (cast keyEq.symm key)) =
    groupRepresentative (included (historyProgram stages) key)
  exact congrArg groupRepresentative
    (included_cast_of_groups_eq
      (historyProgram stages)
      (actualProgram (historyStageProducer stages i)
        (stages[i.val]).ns (stages[i.val]).statement
        (stages[i.val]).pending (stages[i.val]).nonce)
      (history_stage_target_groups_eq_history stages i).symm keyEq.symm key)

/-- The complete selector context is the same after the exact key transport:
same relation model/routes, common namespace, role/advice, 28/28 fuel, and
empty authorization list. -/
theorem history_stage_context_cast_eq
    (stages : List HistoryStage) (i : Fin stages.length)
    (commonNs : Namespace) (stageNsEq : (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (role : Role) :
    cast (congrArg (fun key => Context (Key := key)
        (Counter := GroupCounter) (BaseWork := BaseWork))
        (history_stage_target_key_eq_history stages i))
      (currentAcceptedMassContexts (BaseWork := BaseWork)
        (historyStageProducer stages i) (stages[i.val]).ns
        (stages[i.val]).statement (stages[i.val]).pending
        (stages[i.val]).nonce model bounded advice 28 28 role) =
    currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
      model bounded commonNs role (advice role) 28 28 (fun _ => ∅) := by
  cases stageNsEq
  let keyEq := history_stage_target_key_eq_history stages i
  let target := actualProgram (historyStageProducer stages i)
    (stages[i.val]).ns (stages[i.val]).statement
    (stages[i.val]).pending (stages[i.val]).nonce
  let targetBytes : Key target → V8SmzaOracleParser.RawInput :=
    fun key => groupRepresentative (included target key)
  let historyBytes : Key (historyProgram stages) → V8SmzaOracleParser.RawInput :=
    fun key => groupRepresentative
    (included (historyProgram stages) key)
  change cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) keyEq)
      (Context.mk (Key := Key target) (Counter := GroupCounter)
        (BaseWork := BaseWork) model (stages[i.val]).ns targetBytes
        SmzaRp05GroupedSuffix.groupZero
        (SmzaRp05CurrentGroupedRoutes.currentGroupedRoutes model bounded)
        role (advice role) 28 28 (fun _ => ∅)) =
    Context.mk (Key := Key (historyProgram stages)) (Counter := GroupCounter)
      (BaseWork := BaseWork) model (stages[i.val]).ns historyBytes
      SmzaRp05GroupedSuffix.groupZero
      (SmzaRp05CurrentGroupedRoutes.currentGroupedRoutes model bounded)
      role (advice role) 28 28 (fun _ => ∅)
  have castContext := cast_context_mk_keyBytes
    (KeyLeft := Key target) (KeyRight := Key (historyProgram stages))
    (BaseWork := BaseWork)
    keyEq model (stages[i.val]).ns
    targetBytes SmzaRp05GroupedSuffix.groupZero
    (SmzaRp05CurrentGroupedRoutes.currentGroupedRoutes model bounded)
    role (advice role) 28 28 (fun _ => ∅)
  have keyBytesEq := history_stage_context_keyBytes_eq (BaseWork := BaseWork) stages i
    (stages[i.val]).ns rfl model bounded advice role
  change (cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) keyEq)
      (currentGroupedContext (BaseWork := BaseWork) target model bounded
        (stages[i.val]).ns role (advice role) 28 28 (fun _ => ∅))).keyBytes =
    (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
      model bounded (stages[i.val]).ns role (advice role) 28 28 (fun _ => ∅)).keyBytes
    at keyBytesEq
  rw [context_keyBytes_cast (BaseWork := BaseWork) keyEq
    (currentGroupedContext (BaseWork := BaseWork) target model bounded
      (stages[i.val]).ns role (advice role) 28 28 (fun _ => ∅))] at keyBytesEq
  rw [castContext]
  exact congrArg
    (fun keyBytes : Key (historyProgram stages) → V8SmzaOracleParser.RawInput =>
      Context.mk (Key := Key (historyProgram stages)) (Counter := GroupCounter)
        (BaseWork := BaseWork) model (stages[i.val]).ns keyBytes
        SmzaRp05GroupedSuffix.groupZero
        (SmzaRp05CurrentGroupedRoutes.currentGroupedRoutes model bounded)
        role (advice role) 28 28 (fun _ => ∅))
    keyBytesEq

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentHistorySelectorContexts
