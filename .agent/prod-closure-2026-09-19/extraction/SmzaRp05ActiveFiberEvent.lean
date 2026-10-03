import SmzaRp05DependentAdviceEvent

/-! # Native active-key event for the same physical fixed fiber

Populated fixed-role records never count toward the sparse support. They
also cannot enter either VC extraction pass: their challenge frames are
rejected at every decoder stage. This identifies the literal pullback event
with the native active-key role event before invoking its instability bound.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ActiveFiberEvent

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsClassicalDatabase
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05DependentAdviceEvent SmzaRp05CurrentRoleLabels
open SmzaRp05ChallengeRecordErasure SmzaRp05FilteredReadback
open SmzaRp05FilteredDecoderInstability SmzaRp05AdaptiveDynamicBad
open SmzaRp04StatementRecordFilter SmzaRp04AuthorizedLabelTransport
open SmzaRawDatabaseRecords V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8Smz9CoherentMerkleGeometry
open SmzaRp05TracePrefixes

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 800000
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput := currentRawInputDecidableEq

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem erase_merged_records_eq_active_records
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap) :
    eraseChallengeRecords (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
      (mergeFixedActive ctx blockCap fixed active)) =
    eraseChallengeRecords (rawRecords (fun key => ctx.keyBytes key.val)
      (vectorOutputBytes ctx.counter) active) := by
  ext record
  simp only [eraseChallengeRecords, Finset.mem_filter]
  constructor
  · rintro ⟨recorded, retained⟩
    obtain ⟨key, output, present, inputEq, outputEq⟩ :=
      (mem_raw_records_iff ctx.keyBytes (vectorOutputBytes ctx.counter)
        (mergeFixedActive ctx blockCap fixed active) record.1 record.2).mp recorded
    have unrecognized : parseStageQuery (ctx.keyBytes key) = none := by
      rw [inputEq]
      exact Option.isNone_iff_eq_none.mp retained
    have live := unrecognized_is_active ctx.role blockCap ctx.keyBytes key unrecognized
    refine ⟨?_, retained⟩
    apply (mem_raw_records_iff _ _ _ _ _).mpr
    exact ⟨⟨key, live⟩, output,
      (merge_fixed_active_at_active ctx blockCap fixed active ⟨key, live⟩).symm.trans present,
      inputEq, outputEq⟩
  · rintro ⟨recorded, retained⟩
    obtain ⟨key, output, present, inputEq, outputEq⟩ :=
      (mem_raw_records_iff (fun key => ctx.keyBytes key.val)
        (vectorOutputBytes ctx.counter) active record.1 record.2).mp recorded
    refine ⟨?_, retained⟩
    apply (mem_raw_records_iff _ _ _ _ _).mpr
    exact ⟨key.val, output,
      (merge_fixed_active_at_active ctx blockCap fixed active key).trans present,
      inputEq, outputEq⟩

theorem extract_merged_filtered_eq_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (view : V8SmzaOracleParser.RawInput → Prop)
    (fuel : Nat) (stage : V8SmzaOracleParser.Stage)
    (target : V8SmzaOracleParser.RawDigest) :
    extract (globalOnlineNext ctx.leafNamespace)
      ((rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
        (mergeFixedActive ctx blockCap fixed active)).filter fun record => view record.1)
      fuel stage target =
    extract (globalOnlineNext ctx.leafNamespace)
      ((rawRecords (fun key => ctx.keyBytes key.val) (vectorOutputBytes ctx.counter)
        active).filter fun record => view record.1) fuel stage target := by
  rw [← global_extract_filtered_erase_challenge, erase_merged_records_eq_active_records,
    global_extract_filtered_erase_challenge]

/-- Indexing the label by literal raw input removes the irrelevant choice
of full-key or subtype-key representation from both decoding passes. -/
def inputLabel
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (authorized : Finset (List Byte))
    (records : V8Smz9CoherentMerkleGeometry.Records
      V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (input : V8SmzaOracleParser.RawInput) :=
  completeFilteredLabel (globalLeafStatement ctx.leafNamespace)
    (rawTraceDecoder (globalOnlineNext ctx.leafNamespace)
      (targetOfRaw ctx.role) (fun _ trace => preambleFromTrace ctx.leafNamespace ctx.role trace)
      ctx.outerFuel)
    (statementTraceDecoder (globalOnlineNext ctx.leafNamespace)
      (fun _ input => targetOfRaw ctx.role input)
      (fun statement _ trace => roleLabelsFromBytes ctx.model ctx.leafNamespace
        ctx.role ctx.advice statement trace) ctx.innerFuel)
    authorized records input

theorem input_label_merged_eq_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (authorized : Finset (List Byte)) (input : V8SmzaOracleParser.RawInput) :
    inputLabel ctx authorized
      (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
        (mergeFixedActive ctx blockCap fixed active)) input =
    inputLabel ctx authorized
      (rawRecords (fun key => ctx.keyBytes key.val)
        (vectorOutputBytes ctx.counter) active) input := by
  have outer : extract (globalOnlineNext ctx.leafNamespace)
      (nonleafFilter (globalLeafStatement ctx.leafNamespace)
        (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
          (mergeFixedActive ctx blockCap fixed active))) ctx.outerFuel
      (targetOfRaw ctx.role input).1 (targetOfRaw ctx.role input).2 =
    extract (globalOnlineNext ctx.leafNamespace)
      (nonleafFilter (globalLeafStatement ctx.leafNamespace)
        (rawRecords (fun key => ctx.keyBytes key.val)
          (vectorOutputBytes ctx.counter) active)) ctx.outerFuel
      (targetOfRaw ctx.role input).1 (targetOfRaw ctx.role input).2 := by
    unfold nonleafFilter
    convert extract_merged_filtered_eq_active ctx blockCap fixed active
      (fun raw => globalLeafStatement ctx.leafNamespace raw = none)
      ctx.outerFuel (targetOfRaw ctx.role input).1 (targetOfRaw ctx.role input).2
      using 1 <;> congr 1 <;> ext record <;> simp
  unfold inputLabel completeFilteredLabel rawTraceDecoder statementTraceDecoder
    nonleafFilter oneStatementFilter
  unfold nonleafFilter at outer
  rw [outer]
  simp only [extract_merged_filtered_eq_active]

theorem current_role_event_merged_iff_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap) (authorized : Finset (List Byte)) :
    currentRoleEvent ctx.model ctx.leafNamespace ctx.keyBytes ctx.counter ctx.routes
      ctx.role ctx.advice ctx.outerFuel ctx.innerFuel authorized
      (mergeFixedActive ctx blockCap fixed active) ↔
    currentRoleEvent ctx.model ctx.leafNamespace (fun key => ctx.keyBytes key.val)
      ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel authorized active := by
  constructor
  · rintro ⟨key, output, present, selected, bad⟩
    obtain ⟨query, parsed, sameRole⟩ := selected
    have live := selected_role_is_active ctx.role blockCap ctx.keyBytes key query parsed sameRole
    refine ⟨⟨key, live⟩, output, ?_, ⟨query, parsed, sameRole⟩, ?_⟩
    · exact (merge_fixed_active_at_active ctx blockCap fixed active ⟨key, live⟩).symm.trans present
    · have same := input_label_merged_eq_active ctx blockCap fixed active authorized (ctx.keyBytes key)
      exact (congrArg (fun label => AuthorizedBad
        (fun _ label output => typedCompleteRawBad ctx.model ctx.routes ctx.role label output)
        label output) same).mp bad
  · rintro ⟨key, output, present, selected, bad⟩
    refine ⟨key.val, output, ?_, selected, ?_⟩
    · exact (merge_fixed_active_at_active ctx blockCap fixed active key).trans present
    · have same := input_label_merged_eq_active ctx blockCap fixed active authorized (ctx.keyBytes key.val)
      exact (congrArg (fun label => AuthorizedBad
        (fun _ label output => typedCompleteRawBad ctx.model ctx.routes ctx.role label output)
        label output) same).mpr bad

theorem active_fiber_current_role_event_eq_native
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (memory : ActiveMemory ctx) :
    activeFiberEvent ctx blockCap fixed (event ctx) memory =
      currentRoleEvent ctx.model ctx.leafNamespace (fun key => ctx.keyBytes key.val)
        ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel
        (ctx.authorizedOf memory.original.2.2.2) := by
  funext active
  apply propext
  exact current_role_event_merged_iff_active ctx blockCap fixed active _

/-- The support cap here counts only the active CMS database. The fixed
table has disappeared by decoder equality, not by a new security premise. -/
theorem active_fiber_current_role_instability
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (cap : Nat) (memory : ActiveMemory ctx) :
    RealInstabilityBound (activeFiberEvent ctx blockCap fixed (event ctx) memory)
      cap (localBound ctx cap) := by
  rw [active_fiber_current_role_event_eq_native]
  let activeCtx : Context (Key := ActiveKey ctx.role blockCap ctx.keyBytes)
      (Counter := Counter) (BaseWork := BaseWork) :=
    { model := ctx.model, leafNamespace := ctx.leafNamespace
      keyBytes := fun key => ctx.keyBytes key.val, counter := ctx.counter
      routes := ctx.routes, role := ctx.role, advice := ctx.advice
      outerFuel := ctx.outerFuel, innerFuel := ctx.innerFuel, authorizedOf := ctx.authorizedOf }
  exact event_instability activeCtx cap memory.original.2.2

end
end HegemonCrypto.SmallWood.SmzaRp05ActiveFiberEvent
