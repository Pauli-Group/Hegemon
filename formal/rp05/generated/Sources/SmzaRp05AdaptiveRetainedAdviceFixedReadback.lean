import SmzaRp05AdaptiveRetainedAdviceParser
import SmzaRp05AdaptiveRetainedAdviceReadback
import SmzaRp05AdaptiveRetainedAdvice

/-! The legacy fixed-table choice agrees with the actual read cell once
literal frame uniqueness and the physical key embedding are used. The
fixed value is then obtained from support of the original physical branch,
not from an independently postulated advice or readback table.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceFixedReadback

open scoped Classical
open HegemonCrypto.CmsCompressedOracle
open SmzaChallengeStageTargets SmzaRoleDomainConditioning
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05AdaptiveRetainedAdviceParser SmzaRp05AdaptiveRetainedAdviceReadback
open SmzaRp05PhysicalAcceptedReplayLite SmzaRp05AdaptiveRetainedAdviceTransport
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling
open SmzaRp05ExecutableMerkleVerifier (Program)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

/-- This structural injectivity also applies after restricting the actual
grouped key universe to any ex-ante finite set. -/
theorem grouped_representative_injective :
    Function.Injective SmzaRp05GroupedSuffix.groupRepresentative := by
  intro left right equal
  have addresses := congrArg SmzaRp05GroupedSuffix.groupAddress equal
  rw [SmzaRp05GroupedSuffix.group_representative_address,
    SmzaRp05GroupedSuffix.group_representative_address] at addresses
  exact congrArg Prod.fst addresses

theorem restricted_grouped_representative_injective
    (included : Key → SmzaRp05GroupedSuffix.GroupKey)
    (injection : Function.Injective included) :
    Function.Injective (fun key => SmzaRp05GroupedSuffix.groupRepresentative (included key)) :=
  grouped_representative_injective.comp injection

/-- No all-matching-keys receipt is required: parser reconstruction makes
the selected representative unique, and the key encoding removes aliases. -/
theorem fixed_vector_at_nonce_eq_actual_cell
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (keyInjection : Function.Injective ctx.keyBytes)
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (key : FixedOtherKey ctx.role blockCap ctx.keyBytes)
    (query : StageQuery) (parsed : parseStageQuery (ctx.keyBytes key.val) = some query)
    (base : query.counter = 0) :
    fixedVectorAtNonce ctx blockCap fixed query.role query.target query.nonce =
      some (fixed key) := by
  let found : ∃ candidate : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      ∃ parsedQuery, parseStageQuery (ctx.keyBytes candidate.val) = some parsedQuery ∧
        parsedQuery.role = query.role ∧ parsedQuery.target = query.target ∧
        parsedQuery.nonce = query.nonce ∧ parsedQuery.counter = 0 :=
    ⟨key, query, parsed, rfl, rfl, rfl, base⟩
  obtain ⟨chosenQuery, chosenParsed, sameRole, sameTarget, sameNonce, chosenBase⟩ :=
    Classical.choose_spec found
  have sameKey : Classical.choose found = key := by
    apply Subtype.ext
    apply keyInjection
    exact successful_query_fields_unique _ _ chosenQuery query chosenParsed parsed
      sameRole sameTarget sameNonce (chosenBase.trans base.symm)
  simp only [fixedVectorAtNonce, dif_pos found, sameKey]

/-- On a nonzero terminal same-table fiber, the value selected by the
existing advice lookup is the actual vector in the original answer log.
The only embedding obligation is ordinary injectivity, discharged for the
real grouped-key representative above. -/
theorem nonzero_physical_branch_fixed_vector_readback
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (keyInjection : Function.Injective ctx.keyBytes)
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput Counter) (VectorOutput Counter) (ActiveMemory ctx))
    (nonzero : fixedFiberToActive ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap (physicalRun encode decode program branch state)) basis ≠ 0)
    (call : RawInput × VectorOutput Counter)
    (recorded : call ∈ answerLog decode program branch)
    (query : StageQuery)
    (parsed : parseStageQuery (ctx.keyBytes (encode call.1)) = some query)
    (different : query.role ≠ ctx.role)
    (bounded : query.counter < blockCap query.role)
    (base : query.counter = 0) :
    fixedVectorAtNonce ctx blockCap fixed query.role query.target query.nonce =
      some call.2 := by
  have inactive := different_bounded_role_is_fixed ctx.role blockCap ctx.keyBytes
    (encode call.1) query parsed different bounded
  have receipt := nonzero_physical_fiber_fixed_answers ctx blockCap dummy fixed encode decode
    program branch state basis nonzero call recorded inactive
  exact (fixed_vector_at_nonce_eq_actual_cell ctx keyInjection blockCap fixed
    ⟨encode call.1, inactive⟩ query parsed base).trans (congrArg some receipt)

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceFixedReadback
