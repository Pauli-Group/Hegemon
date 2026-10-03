import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentFixedEarlierAdvice
import SmzaRp05CurrentGroupedRecordReadback

/-! The current finite physical context uses the same program's grouped
representatives and literal counter intervals. Neither the key embedding nor
the counter routing is selected independently by a caller. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedContext

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentFiniteGroupedProgram (Key included)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaChallengeStageTargets (Role)
open SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.CanonicalBytes (Byte)

noncomputable section
set_option autoImplicit false

def currentGroupedContext
    {Result BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (program : Program Result) (model : RelationModel)
    (bounded : ModelWithinProtocol model) (ns : Namespace)
    (role : Role) (advice : AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorizedOf : BaseWork → Finset (List Byte)) :
    Context (Key := Key program) (Counter := GroupCounter) (BaseWork := BaseWork) where
  model := model
  leafNamespace := ns
  keyBytes := fun key => groupRepresentative (included program key)
  counter := groupZero
  routes := currentGroupedRoutes model bounded
  role := role
  advice := advice
  outerFuel := outerFuel
  innerFuel := innerFuel
  authorizedOf := authorizedOf

/-- The finite embedding is a restriction of the proved injective grouped
representative map; injectivity is not an extra context certificate. -/
theorem current_grouped_context_key_injective
    {Result BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (program : Program Result) (model : RelationModel)
    (bounded : ModelWithinProtocol model) (ns : Namespace)
    (role : Role) (advice : AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorizedOf : BaseWork → Finset (List Byte)) :
    Function.Injective
      (currentGroupedContext program model bounded ns role advice
        outerFuel innerFuel authorizedOf).keyBytes := by
  intro left right equal
  have sameGroup :=
    SmzaRp05CurrentFixedEarlierAdvice.current_grouped_representative_injective equal
  exact Subtype.ext sameGroup

/-- A parsed counter-zero representative determines its canonical grouped
prefix. This derives the key/prefix identity needed by stored-cell readback,
including every counter coordinate, rather than assuming that identity. -/
theorem parsed_representative_determines_grouped_counter_calls
    (key : SmzaRp05GroupedSuffix.GroupKey)
    (query : SmzaChallengeStageTargets.StageQuery)
    (parsed : SmzaChallengeStageTargets.parseStageQuery (groupRepresentative key) =
      some query) (base : query.counter = 0) :
    ∃ rolePrefix : SmzaRp05GroupedSuffix.CanonicalRolePrefix,
      key = Sum.inl rolePrefix ∧
      ∀ counter : GroupCounter,
        SmzaRp05GroupedSuffix.groupEncode (rolePrefix, counter) =
          SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput query counter.val := by
  have frame : groupRepresentative key =
      SmzaRp05CurrentGroupedRecordReadback.canonicalQueryPrefix query ++
        HegemonCrypto.CanonicalBytes.encodeLE 8 0 := by
    have exactFrame :=
      SmzaRp05AdaptiveRetainedAdviceParser.successful_query_frame_exact _ _ parsed
    simpa only [SmzaRp05AdaptiveRetainedAdviceParser.canonicalQueryBytes,
      SmzaRp05CurrentGroupedRecordReadback.canonicalQueryPrefix, base,
      List.append_assoc] using exactFrame
  have prefixParsed : SmzaChallengeStageTargets.parseStageQuery
      (SmzaRp05CurrentGroupedRecordReadback.canonicalQueryPrefix query ++
        HegemonCrypto.CanonicalBytes.encodeLE 8 0) = some query := by
    rw [← frame]
    exact parsed
  let rolePrefix : SmzaRp05GroupedSuffix.CanonicalRolePrefix :=
    ⟨query.role, SmzaRp05CurrentGroupedRecordReadback.canonicalQueryPrefix query,
      ⟨query, prefixParsed, rfl⟩⟩
  have encoded : SmzaRp05GroupedSuffix.groupEncode (rolePrefix, groupZero) =
      groupRepresentative key := frame.symm
  have address := SmzaRp05GroupedSuffix.group_address_encode rolePrefix groupZero
  rw [encoded, SmzaRp05GroupedSuffix.group_representative_address] at address
  refine ⟨rolePrefix, congrArg Prod.fst address, ?_⟩
  intro counter
  obtain ⟨actualQuery, read, _role, inputEq⟩ :=
    SmzaRp05CurrentGroupedRecordReadback.grouped_coordinate_eq_canonical_query_counter_input
      rolePrefix counter
  have sameQuery : actualQuery = query := Option.some.inj (read.symm.trans prefixParsed)
  simpa only [sameQuery] using inputEq

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedContext
