import HegemonCrypto.NativePrivateSpendQ58CurrentActualCausalPublic

/-! Literal current support consequences. A sample bad event already forces
successful evaluation of the same fixed canonical opening; its scan nonce is
derived, not supplied as a second execution assumption. PIOP relation data
uses the actual causal public readout and ordinary immutable native getters.
The selected stored-key/target readout is derived separately by the actual
insertion constructors. No selector inclusion or event mass is a premise.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLiteralCausalSupport
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentVectorMerkle (VectorOutput)
namespace CS
export NativePrivateSpendQ58CurrentCausalSourceJoin
  (SourceTemplate NativeDataReadback causalPublic causalRelation causalBad
   native_data_identifies_relation current_decs_sample_causal_support)
end CS
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Counter keyBytes RawDigest)
end G
namespace FM
export NativePrivateSpendQ58CurrentFiberMassTransport (FixedVectors Active actualFixed)
end FM
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end GF
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (canonicalOpening)
end E
namespace O
export NativePrivateSpendQ58CurrentFixedOpeningReplay (fixedOracle fixedOpening)
end O
namespace D
export NativePrivateSpendQ58CurrentDecsDynamicMass (fiberBad decsSampleBad)
end D
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass (childDigest)
end T
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (Trace)
end F
namespace R
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end R
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass (roleBad)
end N
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

attribute [local irreducible] NativePrivateSpendQ58CurrentDecsDynamicMass.fiberBad
  NativePrivateSpendQ58CurrentFiberMassTransport.matrixEvent
  NativePrivateSpendQ58CurrentFiberMassTransport.openingEvent

theorem current_decs_sample_bad_derives_causal_nonce {Result : Type} (program : Program Result)
    (template : CS.SourceTemplate) (fallback : G.RawDigest)
    (fixed : FM.FixedVectors (Counter := G.Counter) .decsSample (G.keyBytes program))
    (trace : F.Trace) (key : FM.Active .decsSample (G.keyBytes program))
    (vector : VectorOutput G.Counter) (relation : R.Relation) (nonce : Fin (2^32))
    (bad : N.roleBad program relation fallback nonce .decsSample fixed trace key vector) :
    CS.causalBad program template fallback .decsSample fixed trace key vector := by
  cases executed : (E.canonicalOpening false nonce (T.childDigest trace)).eval
      (O.fixedOracle program .decsSample GF.currentRoleCaps
        (FM.actualFixed .decsSample (G.keyBytes program) fixed) fallback) with
  | none =>
    simp only [N.roleBad, D.fiberBad, D.decsSampleBad, O.fixedOpening, executed,
      Option.map_none] at bad
  | some result =>
    with_reducible
      exact CS.current_decs_sample_causal_support program template fallback fixed trace key vector
        relation nonce result.1 result.2 executed bad

theorem current_piop_matrix_bad_uses_actual_causal_public {Result : Type} (program : Program Result)
    (template : CS.SourceTemplate) (fallback : G.RawDigest)
    (fixed : FM.FixedVectors (Counter := G.Counter) .piopMatrix (G.keyBytes program))
    (trace : F.Trace) (key : FM.Active .piopMatrix (G.keyBytes program))
    (vector : VectorOutput G.Counter) (relation : R.Relation) (nonce : Fin (2^32))
    (pub : Fin 77 → Goldilocks) (readout : CS.causalPublic .piopMatrix trace = pub)
    (data : CS.NativeDataReadback template pub relation)
    (bad : N.roleBad program relation fallback nonce .piopMatrix fixed trace key vector) :
    CS.causalBad program template fallback .piopMatrix fixed trace key vector := by
  have sameRelation : relation = CS.causalRelation template .piopMatrix trace := by
    unfold CS.causalRelation
    rw [readout]
    exact CS.native_data_identifies_relation template pub relation data
  simpa only [CS.causalBad, NativePrivateSpendQ58CurrentCausalHistoryDensity.labelledBad,
    N.roleBad, sameRelation] using bad

theorem current_piop_opening_bad_uses_actual_causal_public {Result : Type} (program : Program Result)
    (template : CS.SourceTemplate) (fallback : G.RawDigest)
    (fixed : FM.FixedVectors (Counter := G.Counter) .piopOpening (G.keyBytes program))
    (trace : F.Trace) (key : FM.Active .piopOpening (G.keyBytes program))
    (vector : VectorOutput G.Counter) (relation : R.Relation) (nonce : Fin (2^32))
    (pub : Fin 77 → Goldilocks) (readout : CS.causalPublic .piopOpening trace = pub)
    (data : CS.NativeDataReadback template pub relation)
    (bad : N.roleBad program relation fallback nonce .piopOpening fixed trace key vector) :
    CS.causalBad program template fallback .piopOpening fixed trace key vector := by
  have sameRelation : relation = CS.causalRelation template .piopOpening trace := by
    unfold CS.causalRelation
    rw [readout]
    exact CS.native_data_identifies_relation template pub relation data
  simpa only [CS.causalBad, NativePrivateSpendQ58CurrentCausalHistoryDensity.labelledBad,
    N.roleBad, sameRelation] using bad

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLiteralCausalSupport
