import SmzaRp05Current406EventSpec
import SmzaRp05ActiveFiberEvent
import SmzaRp05CurrentPhysicalEventBound
import SmzaRp05FilteredReadback
import SmzaRawDatabaseRecords
import SmzaRp05AdaptiveDynamicBad

/-! # Current-406 event on a fixed-table active fiber

For each current verifier role, this identifies the event computed from the
full merged database with the same event on its native active-key database.
The record equality is derived by erasing challenge-role records before each
filtered extractor pass; no historical event or event-inclusion premise is
used. -/
namespace HegemonCrypto.SmallWood.SmzaRp05Current406ActiveFiberEvent

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open SmzaRp05Current406EventSpec
open SmzaRp05ActiveFiberEvent
open SmzaRp05CurrentPhysicalEventBound
open SmzaRp05CurrentPiopRoleEvents
open SmzaRp05CurrentSourceRoleEvent
open SmzaRp05CurrentMatrixRoleEvent
open SmzaRp05CurrentRoleLabels
open SmzaRp05CurrentTracePrefixes406
open SmzaRp05TracePrefixes
open SmzaRp05FilteredDecoderInstability
open SmzaRp04AuthorizedLabelTransport
open SmzaRp04StatementRecordFilter
open SmzaRp05DependentAdviceEvent
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05ChallengeRecordErasure
open SmzaDynamicDatabaseSoundness
open SmzaRoleDomainConditioning
open SmzaChallengeStageTargets
open SmzaRp05LeafNamespace
open SmzaRp05FilteredReadback
open SmzaRawDatabaseRecords
open SmzaRp05AdaptiveDynamicBad
open V8Smz9CoherentVectorMerkle
open V8Smz9CoherentMerkleGeometry
open V8Smz9CoherentMerkleInstrument

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput := currentRawInputDecidableEq

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest

local notation "Statement" => List Byte
local notation "Trace" => SmzaRp05TracePrefixes.Trace

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- A complete current-label decoder gives the same label when its source
records come from the merged table or from the same active fiber. The outer
pass uses nonleaf records; the inner pass uses nonleaf-or-this-statement
records. Both equalities are instances of the checked filtered-extraction
transport. -/
private theorem current406_complete_label_merged_eq_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (role : Role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    {Label : Type}
    (fullLabel : Statement → RawInput → Trace → Label)
    (input : RawInput) :
    completeFilteredLabel (globalLeafStatement ctx.leafNamespace)
      (rawTraceDecoder (globalOnlineNext ctx.leafNamespace)
        (targetOfRaw role) (fun _ trace => preambleFromTrace ctx.leafNamespace role trace)
        outerFuel)
      (statementTraceDecoder (globalOnlineNext ctx.leafNamespace)
        (fun _ input => targetOfRaw role input) fullLabel innerFuel)
      authorized
      (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
        (mergeFixedActive ctx blockCap fixed active)) input =
    completeFilteredLabel (globalLeafStatement ctx.leafNamespace)
      (rawTraceDecoder (globalOnlineNext ctx.leafNamespace)
        (targetOfRaw role) (fun _ trace => preambleFromTrace ctx.leafNamespace role trace)
        outerFuel)
      (statementTraceDecoder (globalOnlineNext ctx.leafNamespace)
        (fun _ input => targetOfRaw role input) fullLabel innerFuel)
      authorized
      (rawRecords (fun key => ctx.keyBytes key.val) (vectorOutputBytes ctx.counter)
        active) input := by
  classical
  have outerEq :
      extract (globalOnlineNext ctx.leafNamespace)
          (nonleafFilter (globalLeafStatement ctx.leafNamespace)
            (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
              (mergeFixedActive ctx blockCap fixed active))) outerFuel
          (targetOfRaw role input).1 (targetOfRaw role input).2 =
      extract (globalOnlineNext ctx.leafNamespace)
          (nonleafFilter (globalLeafStatement ctx.leafNamespace)
            (rawRecords (fun key => ctx.keyBytes key.val) (vectorOutputBytes ctx.counter)
              active)) outerFuel
          (targetOfRaw role input).1 (targetOfRaw role input).2 := by
    unfold nonleafFilter
    convert extract_merged_filtered_eq_active ctx blockCap fixed active
      (fun raw => globalLeafStatement ctx.leafNamespace raw = none)
      outerFuel (targetOfRaw role input).1 (targetOfRaw role input).2
      using 1 <;> congr 1 <;> ext record <;> simp
  unfold completeFilteredLabel rawTraceDecoder statementTraceDecoder
    nonleafFilter oneStatementFilter
  unfold nonleafFilter at outerEq
  have outerTraceEq := congrArg (preambleFromTrace ctx.leafNamespace role) outerEq
  dsimp only
  rw [outerTraceEq]
  simp only [extract_merged_filtered_eq_active]

/-- Generic event transport for the current two-pass label decoder. The
selected-role witness itself is necessarily an active key, and the bad-label
predicate is preserved by exact equality of the decoded label. -/
private theorem current406_role_event_merged_iff_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    {Label : Type}
    (fullLabel : Statement → RawInput → Trace → Label)
    (bad : Statement → Label → VectorOutput Counter → Prop) :
    roleEvent ctx.keyBytes (vectorOutputBytes ctx.counter)
      (globalLeafStatement ctx.leafNamespace)
      (rawTraceDecoder (globalOnlineNext ctx.leafNamespace)
        (fun key => targetOfRaw ctx.role (ctx.keyBytes key))
        (fun _ trace => preambleFromTrace ctx.leafNamespace ctx.role trace) outerFuel)
      (statementTraceDecoder (globalOnlineNext ctx.leafNamespace)
        (fun _ key => targetOfRaw ctx.role (ctx.keyBytes key))
        (fun statement key trace => fullLabel statement (ctx.keyBytes key) trace) innerFuel)
      (fun key => InRoleDomain ctx.role (ctx.keyBytes key)) bad authorized
      (mergeFixedActive ctx blockCap fixed active) ↔
    roleEvent (fun key : ActiveKey ctx.role blockCap ctx.keyBytes => ctx.keyBytes key.val)
      (vectorOutputBytes ctx.counter) (globalLeafStatement ctx.leafNamespace)
      (rawTraceDecoder (globalOnlineNext ctx.leafNamespace)
        (fun key => targetOfRaw ctx.role (ctx.keyBytes key.val))
        (fun _ trace => preambleFromTrace ctx.leafNamespace ctx.role trace) outerFuel)
      (statementTraceDecoder (globalOnlineNext ctx.leafNamespace)
        (fun _ key => targetOfRaw ctx.role (ctx.keyBytes key.val))
        (fun statement key trace => fullLabel statement (ctx.keyBytes key.val) trace) innerFuel)
    (fun key => InRoleDomain ctx.role (ctx.keyBytes key.val)) bad authorized active := by
  constructor
  · rintro ⟨key, output, present, selected, badOutput⟩
    obtain ⟨query, parsed, sameRole⟩ := selected
    have live := selected_role_is_active ctx.role blockCap ctx.keyBytes key query parsed sameRole
    refine ⟨⟨key, live⟩, output, ?_, ⟨query, parsed, sameRole⟩, ?_⟩
    · exact (merge_fixed_active_at_active ctx blockCap fixed active ⟨key, live⟩).symm.trans present
    · have labelsSame := current406_complete_label_merged_eq_active ctx blockCap fixed active
        ctx.role outerFuel innerFuel authorized fullLabel (ctx.keyBytes key)
      exact (congrArg (fun label => AuthorizedBad bad label output) labelsSame).mp badOutput
  · rintro ⟨key, output, present, selected, badOutput⟩
    refine ⟨key.val, output, ?_, selected, ?_⟩
    · exact (merge_fixed_active_at_active ctx blockCap fixed active key).trans present
    · have labelsSame := current406_complete_label_merged_eq_active ctx blockCap fixed active
        ctx.role outerFuel innerFuel authorized fullLabel (ctx.keyBytes key.val)
      exact (congrArg (fun label => AuthorizedBad bad label output) labelsSame).mpr badOutput

/-- Exact full-database to native-active-database transport for the current
406 event selected by a conditioned role context. The context's actual role
is retained, so the fixed table and active database use the same partition. -/
theorem current406_base_merged_iff_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (authorized : Finset (List Byte)) :
    current406Base ctx authorized (mergeFixedActive ctx blockCap fixed active) ↔
      currentRoleEvent406Explicit ctx.model ctx.leafNamespace
        (fun key : ActiveKey ctx.role blockCap ctx.keyBytes => ctx.keyBytes key.val)
        ctx.counter ctx.routes ctx.role ctx.advice
        ctx.outerFuel ctx.innerFuel authorized active := by
  cases ctx with
  | mk model ns keyBytes counter routes role advice outerFuel innerFuel authorizedOf =>
      let ctx' : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
        { model := model, leafNamespace := ns, keyBytes := keyBytes,
          counter := counter, routes := routes, role := role, advice := advice,
          outerFuel := outerFuel, innerFuel := innerFuel, authorizedOf := authorizedOf }
      change currentRoleEvent406Explicit model ns keyBytes counter routes role advice
          outerFuel innerFuel authorized (mergeFixedActive ctx' blockCap fixed active) ↔
        currentRoleEvent406Explicit model ns
          (fun key : ActiveKey role blockCap keyBytes => keyBytes key.val)
          counter routes role advice outerFuel innerFuel authorized active
      cases role with
      | decsMatrix =>
          simpa [currentRoleEvent406Explicit,
            currentSourceMatrixRoleEvent406, currentMatrixRoleEvent406, currentOuter] using
            (current406_role_event_merged_iff_active ctx' blockCap fixed active
              outerFuel innerFuel authorized
              (fun statement _ trace => roleLabelsFromBytes model ns
                .decsMatrix advice statement trace)
              (currentMatrixRoleBad model routes))
      | piopMatrix =>
          simpa [currentRoleEvent406Explicit,
            currentPiopRoleEvent406, currentOuter, PiopRole.toRole] using
            (current406_role_event_merged_iff_active ctx' blockCap fixed active
              outerFuel innerFuel authorized
              (fun statement _ trace => currentRoleLabelsFromBytes406 model
                ns .piopMatrix advice statement trace)
              (fun _ label output => typedCompleteRawBad model routes
                .piopMatrix label output))
      | piopOpening =>
          simpa [currentRoleEvent406Explicit,
            currentPiopRoleEvent406, currentOuter, PiopRole.toRole] using
            (current406_role_event_merged_iff_active ctx' blockCap fixed active
              outerFuel innerFuel authorized
              (fun statement _ trace => currentRoleLabelsFromBytes406 model
                ns .piopOpening advice statement trace)
              (fun _ label output => typedCompleteRawBad model routes
                .piopOpening label output))
      | decsSample =>
          simpa [currentRoleEvent406Explicit,
            currentSourceRoleEvent406, currentOuter] using
            (current406_role_event_merged_iff_active ctx' blockCap fixed active
              outerFuel innerFuel authorized
              (fun statement _ trace => currentSourceRoleLabelsFromBytes406 model
                ns advice statement trace)
              (fun _ label output => currentSourceRoleBad406 model routes
                label output))

/-- The same equivalence as a literal pullback to one active fiber. The
authorization set is read from that fiber's retained base workspace. -/
theorem active_fiber_current406_base_eq_native
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (memory : ActiveMemory ctx) :
    activeFiberEvent ctx blockCap fixed
      (fun work database => current406Base ctx (ctx.authorizedOf work.2) database)
      memory =
    fun active => currentRoleEvent406Explicit ctx.model ctx.leafNamespace
      (fun key : ActiveKey ctx.role blockCap ctx.keyBytes => ctx.keyBytes key.val)
      ctx.counter ctx.routes ctx.role ctx.advice
      ctx.outerFuel ctx.innerFuel (ctx.authorizedOf memory.original.2.2.2) active := by
  funext active
  apply propext
  exact current406_base_merged_iff_active ctx blockCap fixed active
    (ctx.authorizedOf memory.original.2.2.2)

end
end HegemonCrypto.SmallWood.SmzaRp05Current406ActiveFiberEvent
