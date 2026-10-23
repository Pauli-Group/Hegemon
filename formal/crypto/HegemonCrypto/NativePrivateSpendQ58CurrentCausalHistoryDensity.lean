import HegemonCrypto.NativePrivateSpendQ58CurrentRoleEventPhysicalMass

/-! Current role densities with deterministic pre-insertion labels.

The relation and nonce below are functions of the actual current trace and
queried key. They have no active-database or inserted-answer argument. A fixed
other-role table can be captured when constructing these functions. This is
the uniform-density half of a global history lift, not an assertion that any
native accepted stage supplies these labels. That source identification and
global selector inclusion remain separate obligations. SOURCE ONLY.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCausalHistoryDensity
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open SmzaDynamicDatabaseSoundness
open SmzaChallengeStageTargets (Role)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open scoped Classical
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass
  (localLoss roleBad stage)
end N
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (Key Counter RawDigest keyBytes zero)
end G
namespace R
export NativePrivateSpendQ58CurrentFiberMassTransport
  (Active FixedVectors activeBytes actualFixed matrixEvent openingEvent)
end R
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents
  (currentLabel current_tracked_label_changes)
end P
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (Trace)
end F
namespace C
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end C
noncomputable section
set_option autoImplicit false
set_option Elab.async false
variable {Result : Type} (program : Program Result)

def labelledBad (fallback : G.RawDigest) (role : Role)
    (fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (relationAt : F.Trace → R.Active role (G.keyBytes program) → C.Relation)
    (nonceAt : F.Trace → R.Active role (G.keyBytes program) → Fin (2^32))
    (trace : F.Trace) (key : R.Active role (G.keyBytes program))
    (vector : VectorOutput G.Counter) : Prop :=
  N.roleBad program (relationAt trace key) fallback (nonceAt trace key)
    role fixed trace key vector

/-- Pointwise specialization of the four already-derived current densities.
No sum over stages, possible relations, or nonces occurs. -/
theorem current_causal_label_density (fallback : G.RawDigest) (role : Role)
    (fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (relationAt : F.Trace → R.Active role (G.keyBytes program) → C.Relation)
    (nonceAt : F.Trace → R.Active role (G.keyBytes program) → Fin (2^32))
    (injective : Function.Injective NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint)
    (sample : NativePrivateSpendQ58CurrentDecsSampleDensity.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point)
    (trace : F.Trace) (key : R.Active role (G.keyBytes program)) :
    outputEventProbability
      (labelledBad program fallback role fixed relationAt nonceAt trace key) ≤ N.localLoss role := by
  cases role with
  | decsMatrix =>
      exact NativePrivateSpendQ58CurrentMatrixRawOrder.current_vector_event_density
        (R.activeBytes .decsMatrix (G.keyBytes program))
        NativePrivateSpendQ58CurrentRoleEventPhysicalMass.matrixSelect injective trace key
  | decsSample =>
      exact NativePrivateSpendQ58CurrentDecsDynamicMass.current_decs_sample_per_calculated_trace
        program (R.actualFixed .decsSample (G.keyBytes program) fixed)
        fallback (nonceAt trace key) trace key.val sample point lookup
  | piopMatrix =>
      let component : VectorOutput G.Counter → Prop :=
        R.matrixEvent (relationAt trace key) (G.keyBytes program) fixed
          NativePrivateSpendQ58CurrentConstructorGrouping.decode
          NativePrivateSpendQ58CurrentClaimMatrixReadback.matrixSelect trace key
      have eventEq : labelledBad program fallback .piopMatrix fixed relationAt nonceAt trace key =
          component := by
        funext vector
        rfl
      have lossEq : N.localLoss .piopMatrix = NativePrivateSpendQ58CurrentTracePiopMass.matrixLoss := by
        rfl
      have known : outputEventProbability component ≤ NativePrivateSpendQ58CurrentTracePiopMass.matrixLoss := by
        dsimp only [component]
        delta R.matrixEvent
        with_reducible
          exact NativePrivateSpendQ58CurrentTracePiopMass.current_trace_matrix_per_label
            (relationAt trace key) (G.keyBytes program)
            (R.actualFixed .piopMatrix (G.keyBytes program) fixed)
            NativePrivateSpendQ58CurrentConstructorGrouping.decode
            NativePrivateSpendQ58CurrentClaimMatrixReadback.matrixSelect trace key.val
      exact Eq.mpr
        ((congrArg (fun event : VectorOutput G.Counter → Prop =>
            outputEventProbability event ≤ N.localLoss .piopMatrix) eventEq).trans
          (congrArg (fun loss : Rat => outputEventProbability component ≤ loss) lossEq)) known
  | piopOpening =>
      let component : VectorOutput G.Counter → Prop :=
        R.openingEvent (relationAt trace key) (G.keyBytes program) fixed
          NativePrivateSpendQ58CurrentConstructorGrouping.decode
          NativePrivateSpendQ58CurrentClaimMatrixReadback.matrixSelect
          NativePrivateSpendQ58CurrentOpeningVectorInsertion.openingSelect trace key
      have eventEq : labelledBad program fallback .piopOpening fixed relationAt nonceAt trace key =
          component := by
        funext vector
        rfl
      have lossEq : N.localLoss .piopOpening = NativePrivateSpendQ58CurrentTracePiopMass.openingLoss := by
        rfl
      have known : outputEventProbability component ≤ NativePrivateSpendQ58CurrentTracePiopMass.openingLoss := by
        dsimp only [component]
        delta R.openingEvent
        with_reducible
          exact NativePrivateSpendQ58CurrentTracePiopMass.current_trace_opening_per_label
            (relationAt trace key) (G.keyBytes program)
            (R.actualFixed .piopOpening (G.keyBytes program) fixed)
            NativePrivateSpendQ58CurrentConstructorGrouping.decode
            NativePrivateSpendQ58CurrentClaimMatrixReadback.matrixSelect
            NativePrivateSpendQ58CurrentOpeningVectorInsertion.openingSelect trace key.val
      exact Eq.mpr
        ((congrArg (fun event : VectorOutput G.Counter → Prop =>
            outputEventProbability event ≤ N.localLoss .piopOpening) eventEq).trans
          (congrArg (fun loss : Rat => outputEventProbability component ≤ loss) lossEq)) known

/-- A deterministic trace/key specialization has the same current label-change
and density cost. Choosing a stage from the active database after insertion is
outside this signature and is not certified by this theorem. -/
theorem current_causal_label_instability (fallback : G.RawDigest) (role : Role)
    (fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (relationAt : F.Trace → R.Active role (G.keyBytes program) → C.Relation)
    (nonceAt : F.Trace → R.Active role (G.keyBytes program) → Fin (2^32))
    (injective : Function.Injective NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint)
    (sample : NativePrivateSpendQ58CurrentDecsSampleDensity.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point)
    (budget : Nat) :
    InstabilityBound
      (DynamicBad (P.currentLabel (R.activeBytes role (G.keyBytes program)) G.zero (N.stage role))
        (labelledBad program fallback role fixed relationAt nonceAt)) budget
      ((3*budget : Rat)/(2^512 : Rat)+N.localLoss role) := by
  apply dynamic_bad_instability _ _ budget (N.localLoss role) ((3*budget : Rat)/(2^512 : Rat))
    (by
      cases role with
      | decsMatrix =>
          unfold N.localLoss NativePrivateSpendQ58CurrentMatrixDynamicMass.matrixLoss
          exact div_nonneg (by norm_num) (Nat.cast_nonneg _)
      | decsSample =>
          unfold N.localLoss NativePrivateSpendQ58CurrentDecsSampleDensity.loss
          exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
      | piopMatrix =>
          unfold N.localLoss NativePrivateSpendQ58CurrentTracePiopMass.matrixLoss
          exact pow_nonneg (div_nonneg zero_le_one (Nat.cast_nonneg _)) _
      | piopOpening =>
          unfold N.localLoss NativePrivateSpendQ58CurrentTracePiopMass.openingLoss
          exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _))
    (by
      exact div_nonneg (mul_nonneg (by norm_num) (Nat.cast_nonneg budget))
        (pow_nonneg (by norm_num) _))
  · exact current_causal_label_density program fallback role fixed relationAt nonceAt
      injective sample point lookup
  · exact P.current_tracked_label_changes
      (R.activeBytes role (G.keyBytes program)) G.zero (N.stage role) budget

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCausalHistoryDensity
