import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalRawLogTransport
import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalCausalMass
import SmzaRawDatabaseRecords

/-! Exact current key/table transport from the logical terminal observer to
the original adaptive history. The final public root constructs its identity
from actual constructor replay. Only data coordinates are transported; the
original physical execution, Born weights and lifetime query account are not
changed. No accepted-failure inclusion or event mass is assumed. SOURCE ONLY.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalRoleReindex
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaChallengeStageTargets (Role)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaDynamicDatabaseSoundness (DynamicBad)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (Key Counter RawInput RawDigest keyBytes key_bytes_injective encode decode zero)
end G
namespace H
export NativePrivateSpendQ58CurrentGlobalRawLogTransport
  (Stage adaptiveHistoryProgram actualTerminalRoot actualTerminalKeys
   actualTerminal_keyBytes_exact actualTerminal_encode_exact)
end H
namespace RC
export NativePrivateSpendQ58CurrentRoleClassifier
  (RoleActive FixedKey FixedTable fixedVectorAtNonce parseCurrentStageQuery
   fixed_vector_at_nonce_eq_actual_cell)
end RC
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps fixedGamma)
end GF
namespace FM
export NativePrivateSpendQ58CurrentFiberMassTransport
  (Active Fixed FixedVectors activeBytes actualActiveEquiv actualFixedEquiv
   actualFixed matrixEvent openingEvent)
end FM
namespace O
export NativePrivateSpendQ58CurrentFixedOpeningReplay (fixedOracle fixedOpening)
end O
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass
  (fppLabel fixedMatrix matrixBad openingBad)
end T
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass (stage roleBad roleEvent)
end N
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel sourceTrace)
end P
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (Trace)
end F
namespace R
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end R
namespace CS
export NativePrivateSpendQ58CurrentCausalSourceJoin (SourceTemplate causalBad causalRelation causalNonce)
end CS
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

variable {LeftResult RightResult : Type}
variable (left : Program LeftResult) (right : Program RightResult)

/-- Ordinary immutable key identity. The public observer instance below
derives both fields; no event, validity, selector or oracle answer appears. -/
structure KeyIdentity where
  keys : G.Key left ≃ G.Key right
  bytes : ∀ key, G.keyBytes right (keys key) = G.keyBytes left key
  encode : ∀ raw, keys (G.encode left raw) = G.encode right raw

variable {left right} (identity : KeyIdentity left right)

private theorem inverse_bytes (key : G.Key right) :
    G.keyBytes left (identity.keys.symm key) = G.keyBytes right key := by
  rw [← identity.bytes, Equiv.apply_symm_apply]

private theorem active_predicate (role : Role) (key : G.Key left) :
    RC.RoleActive role GF.currentRoleCaps (G.keyBytes right) (identity.keys key) =
      RC.RoleActive role GF.currentRoleCaps (G.keyBytes left) key := by
  unfold RC.RoleActive
  rw [identity.bytes]

private def nativeActive (role : Role) :
    { key : G.Key left // RC.RoleActive role GF.currentRoleCaps (G.keyBytes left) key } ≃
    { key : G.Key right // RC.RoleActive role GF.currentRoleCaps (G.keyBytes right) key } where
  toFun key := ⟨identity.keys key.val, by rw [active_predicate]; exact key.property⟩
  invFun key := ⟨identity.keys.symm key.val, by
    rw [← active_predicate identity role, Equiv.apply_symm_apply]; exact key.property⟩
  left_inv key := by apply Subtype.ext; exact identity.keys.symm_apply_apply key.val
  right_inv key := by apply Subtype.ext; exact identity.keys.apply_symm_apply key.val

private def nativeFixed (role : Role) :
    RC.FixedKey role GF.currentRoleCaps (G.keyBytes left) ≃
    RC.FixedKey role GF.currentRoleCaps (G.keyBytes right) where
  toFun key := ⟨identity.keys key.val, by rw [active_predicate]; exact key.property⟩
  invFun key := ⟨identity.keys.symm key.val, by
    rw [← active_predicate identity role, Equiv.apply_symm_apply]; exact key.property⟩
  left_inv key := by apply Subtype.ext; exact identity.keys.symm_apply_apply key.val
  right_inv key := by apply Subtype.ext; exact identity.keys.apply_symm_apply key.val

def activeKeys (role : Role) :
    FM.Active role (G.keyBytes left) ≃ FM.Active role (G.keyBytes right) :=
  (FM.actualActiveEquiv role (G.keyBytes left)).trans
    ((nativeActive identity role).trans (FM.actualActiveEquiv role (G.keyBytes right)).symm)

def fixedKeys (role : Role) :
    FM.Fixed role (G.keyBytes left) ≃ FM.Fixed role (G.keyBytes right) :=
  (FM.actualFixedEquiv role (G.keyBytes left)).trans
    ((nativeFixed identity role).trans (FM.actualFixedEquiv role (G.keyBytes right)).symm)

private theorem active_value (role : Role) (key : FM.Active role (G.keyBytes left)) :
    (activeKeys identity role key).val = identity.keys key.val := rfl

private theorem fixed_value (role : Role) (key : FM.Fixed role (G.keyBytes left)) :
    (fixedKeys identity role key).val = identity.keys key.val := rfl

def pullFixed (role : Role) (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes right)) :
    FM.FixedVectors (Counter := G.Counter) role (G.keyBytes left) :=
  fun key => fixed (fixedKeys identity role key)

def pullDB (role : Role)
    (database : Database (FM.Active role (G.keyBytes right)) (VectorOutput G.Counter)) :
    Database (FM.Active role (G.keyBytes left)) (VectorOutput G.Counter) :=
  fun key => database (activeKeys identity role key)

private def pullNativeFixed (role : Role)
    (fixed : RC.FixedTable (Counter := G.Counter) role GF.currentRoleCaps (G.keyBytes right)) :
    RC.FixedTable (Counter := G.Counter) role GF.currentRoleCaps (G.keyBytes left) :=
  fun key => fixed (nativeFixed identity role key)

private theorem actual_fixed (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes right)) :
    FM.actualFixed role (G.keyBytes left) (pullFixed identity role fixed) =
      pullNativeFixed identity role (FM.actualFixed role (G.keyBytes right) fixed) := by
  funext key
  rfl

private theorem fixed_vector (selected role : Role)
    (fixed : RC.FixedTable (Counter := G.Counter) selected GF.currentRoleCaps (G.keyBytes right))
    (target : G.RawDigest) (nonce : Nat) :
    RC.fixedVectorAtNonce selected GF.currentRoleCaps (G.keyBytes left)
      (pullNativeFixed identity selected fixed) role target nonce =
    RC.fixedVectorAtNonce selected GF.currentRoleCaps (G.keyBytes right) fixed role target nonce := by
  by_cases found : ∃ key : RC.FixedKey selected GF.currentRoleCaps (G.keyBytes left),
      ∃ query, RC.parseCurrentStageQuery (G.keyBytes left key.val) = some query ∧
        query.role = role ∧ query.target = target ∧ query.nonce = nonce ∧ query.counter = 0
  · obtain ⟨key, query, parsed, sameRole, sameTarget, sameNonce, base⟩ := found
    have leftRead := RC.fixed_vector_at_nonce_eq_actual_cell selected GF.currentRoleCaps
      (G.keyBytes left) (G.key_bytes_injective left) (pullNativeFixed identity selected fixed)
      key query parsed base
    have rightParsed : RC.parseCurrentStageQuery
        (G.keyBytes right (nativeFixed identity selected key).val) = some query := by
      change RC.parseCurrentStageQuery (G.keyBytes right (identity.keys key.val)) = some query
      rw [identity.bytes]
      exact parsed
    have rightRead := RC.fixed_vector_at_nonce_eq_actual_cell selected GF.currentRoleCaps
      (G.keyBytes right) (G.key_bytes_injective right) fixed
      (nativeFixed identity selected key) query rightParsed base
    rw [sameRole, sameTarget, sameNonce] at leftRead rightRead
    exact leftRead.trans rightRead.symm
  · have rightMissing : ¬∃ key : RC.FixedKey selected GF.currentRoleCaps (G.keyBytes right),
        ∃ query, RC.parseCurrentStageQuery (G.keyBytes right key.val) = some query ∧
          query.role = role ∧ query.target = target ∧ query.nonce = nonce ∧ query.counter = 0 := by
      rintro ⟨key, query, parsed, sameRole, sameTarget, sameNonce, base⟩
      apply found
      refine ⟨(nativeFixed identity selected).symm key, query, ?_, sameRole, sameTarget, sameNonce, base⟩
      change RC.parseCurrentStageQuery (G.keyBytes left (identity.keys.symm key.val)) = some query
      rw [inverse_bytes]
      exact parsed
    simp only [RC.fixedVectorAtNonce, dif_neg found, dif_neg rightMissing]

private theorem fpp_label (role : Role)
    (fixed : RC.FixedTable (Counter := G.Counter) role GF.currentRoleCaps (G.keyBytes right))
    (trace : F.Trace) :
    T.fppLabel role (G.keyBytes left) (pullNativeFixed identity role fixed) G.decode trace =
      T.fppLabel role (G.keyBytes right) fixed G.decode trace := by
  unfold T.fppLabel GF.fixedGamma
  rw [fixed_vector]

private theorem fixed_matrix
    (fixed : RC.FixedTable (Counter := G.Counter) .piopOpening GF.currentRoleCaps (G.keyBytes right))
    (target : G.RawDigest) :
    T.fixedMatrix (G.keyBytes left) (pullNativeFixed identity .piopOpening fixed)
      NativePrivateSpendQ58CurrentClaimMatrixReadback.matrixSelect target =
    T.fixedMatrix (G.keyBytes right) fixed
      NativePrivateSpendQ58CurrentClaimMatrixReadback.matrixSelect target := by
  unfold T.fixedMatrix
  rw [fixed_vector]

private theorem fixed_oracle (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes right)) (fallback : G.RawDigest) :
    O.fixedOracle left role GF.currentRoleCaps
      (FM.actualFixed role (G.keyBytes left) (pullFixed identity role fixed)) fallback =
    O.fixedOracle right role GF.currentRoleCaps
      (FM.actualFixed role (G.keyBytes right) fixed) fallback := by
  funext raw
  have liveEq : NativePrivateSpendQ58CurrentActiveBranchClaims.live right role GF.currentRoleCaps
      (G.encode right raw) =
      NativePrivateSpendQ58CurrentActiveBranchClaims.live left role GF.currentRoleCaps
        (G.encode left raw) := by
    rw [← identity.encode]
    exact active_predicate identity role (G.encode left raw)
  unfold O.fixedOracle
  by_cases inactive : ¬NativePrivateSpendQ58CurrentActiveBranchClaims.live left role GF.currentRoleCaps
      (G.encode left raw)
  · have rightInactive : ¬NativePrivateSpendQ58CurrentActiveBranchClaims.live right role GF.currentRoleCaps
        (G.encode right raw) := liveEq.symm ▸ inactive
    rw [dif_pos inactive, dif_pos rightInactive, actual_fixed]
    congr 1
    apply congrArg (FM.actualFixed role (G.keyBytes right) fixed)
    apply Subtype.ext
    exact identity.encode raw
  · have rightActive : ¬¬NativePrivateSpendQ58CurrentActiveBranchClaims.live right role GF.currentRoleCaps
        (G.encode right raw) := liveEq.symm ▸ inactive
    rw [dif_neg inactive, dif_neg rightActive]

private theorem fixed_opening (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes right))
    (fallback : G.RawDigest) (nonce : Fin (2^32)) (digest : G.RawDigest) :
    O.fixedOpening left role GF.currentRoleCaps
      (FM.actualFixed role (G.keyBytes left) (pullFixed identity role fixed)) fallback nonce digest =
    O.fixedOpening right role GF.currentRoleCaps
      (FM.actualFixed role (G.keyBytes right) fixed) fallback nonce digest := by
  unfold O.fixedOpening
  rw [fixed_oracle]

private theorem active_bytes (role : Role) (key : FM.Active role (G.keyBytes left)) :
    FM.activeBytes role (G.keyBytes right) (activeKeys identity role key) =
      FM.activeBytes role (G.keyBytes left) key := by
  change G.keyBytes right (identity.keys key.val) = G.keyBytes left key.val
  exact identity.bytes key.val

private theorem raw_exact (role : Role)
    (database : Database (FM.Active role (G.keyBytes right)) (VectorOutput G.Counter)) :
    rawRecords (FM.activeBytes role (G.keyBytes left)) (vectorOutputBytes G.zero)
      (pullDB identity role database) =
    rawRecords (FM.activeBytes role (G.keyBytes right)) (vectorOutputBytes G.zero) database := by
  ext pair
  rcases pair with ⟨input, digest⟩
  simp only [SmzaRawDatabaseRecords.mem_raw_records_iff]
  constructor
  · rintro ⟨key, vector, stored, bytes, output⟩
    exact ⟨activeKeys identity role key, vector, stored,
      (active_bytes identity role key).trans bytes, output⟩
  · rintro ⟨key, vector, stored, bytes, output⟩
    let earlier := (activeKeys identity role).symm key
    have back : activeKeys identity role earlier = key := (activeKeys identity role).apply_symm_apply key
    refine ⟨earlier, vector, ?_, ?_, output⟩
    · change database (activeKeys identity role earlier) = some vector
      rw [back]
      exact stored
    · rw [← active_bytes identity role earlier, back]
      exact bytes

private theorem label_exact (role : Role)
    (database : Database (FM.Active role (G.keyBytes right)) (VectorOutput G.Counter))
    (key : FM.Active role (G.keyBytes left)) :
    P.currentLabel (FM.activeBytes role (G.keyBytes left)) G.zero (N.stage role)
      (pullDB identity role database) key =
    P.currentLabel (FM.activeBytes role (G.keyBytes right)) G.zero (N.stage role)
      database (activeKeys identity role key) := by
  unfold P.currentLabel P.sourceTrace
  rw [raw_exact, active_bytes]

/-- All four literal current bad predicates preserve exactly their fixed
cells and actual raw frames. This proves equality, not an assumed inclusion. -/
theorem current_role_bad_reindex (relation : R.Relation) (fallback : G.RawDigest)
    (nonce : Fin (2^32)) (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes right))
    (trace : F.Trace) (key : FM.Active role (G.keyBytes left)) (vector : VectorOutput G.Counter) :
    N.roleBad left relation fallback nonce role (pullFixed identity role fixed) trace key vector =
      N.roleBad right relation fallback nonce role fixed trace (activeKeys identity role key) vector := by
  cases role with
  | decsMatrix =>
    unfold N.roleBad
    dsimp only
    unfold NativePrivateSpendQ58CurrentMatrixRawOrder.vectorBad
    rw [← active_bytes identity .decsMatrix key]
  | decsSample =>
    unfold N.roleBad
    dsimp only
    have bytes : G.keyBytes right (activeKeys identity .decsSample key).val =
        G.keyBytes left key.val :=
      (congrArg (G.keyBytes right) (active_value identity .decsSample key)).trans
        (identity.bytes key.val)
    unfold NativePrivateSpendQ58CurrentDecsDynamicMass.fiberBad
      NativePrivateSpendQ58CurrentDecsDynamicMass.decsSampleBad
    rw [fixed_opening identity .decsSample fixed fallback nonce
      (NativePrivateSpendQ58CurrentTracePiopMass.childDigest trace), actual_fixed, fpp_label, bytes]
  | piopMatrix =>
    unfold N.roleBad
    dsimp only
    unfold FM.matrixEvent T.matrixBad
    rw [actual_fixed, fpp_label, ← identity.bytes key.val]
    rfl
  | piopOpening =>
    unfold N.roleBad
    dsimp only
    unfold FM.openingEvent T.openingBad
    rw [actual_fixed, fpp_label, fixed_matrix, ← identity.bytes key.val]
    rfl

theorem current_role_event_reindex (relation : R.Relation) (fallback : G.RawDigest)
    (nonce : Fin (2^32)) (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes right))
    (database : Database (FM.Active role (G.keyBytes right)) (VectorOutput G.Counter)) :
    N.roleEvent left relation fallback nonce role (pullFixed identity role fixed)
      (pullDB identity role database) ↔ N.roleEvent right relation fallback nonce role fixed database := by
  unfold N.roleEvent DynamicBad
  constructor
  · rintro ⟨key, vector, stored, bad⟩
    refine ⟨activeKeys identity role key, vector, stored, ?_⟩
    rw [label_exact, current_role_bad_reindex] at bad
    exact bad
  · rintro ⟨key, vector, stored, bad⟩
    let earlier := (activeKeys identity role).symm key
    have back : activeKeys identity role earlier = key := (activeKeys identity role).apply_symm_apply key
    refine ⟨earlier, vector, ?_, ?_⟩
    · change database (activeKeys identity role earlier) = some vector
      rw [back]
      exact stored
    · rw [label_exact, current_role_bad_reindex, back]
      exact bad

/-- Source-derived observer identity. The chosen actual stage is data from
constructor execution; no source-failure, validity or selector input occurs. -/
def actualObserverIdentity (constructor : Program (List H.Stage)) (oracle : Oracle)
    (stages : List H.Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) :
    KeyIdentity (H.actualTerminalRoot constructor stages i) (H.adaptiveHistoryProgram constructor) where
  keys := H.actualTerminalKeys constructor oracle stages constructed i
  bytes := H.actualTerminal_keyBytes_exact constructor oracle stages constructed i
  encode := H.actualTerminal_encode_exact constructor oracle stages constructed i

theorem actual_global_observer_role_event_reindex
    (constructor : Program (List H.Stage)) (oracle : Oracle) (stages : List H.Stage)
    (constructed : constructor.eval oracle = some stages) (i : Fin stages.length)
    (relation : R.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32)) (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes (H.adaptiveHistoryProgram constructor)))
    (database : Database (FM.Active role (G.keyBytes (H.adaptiveHistoryProgram constructor)))
      (VectorOutput G.Counter)) :
    N.roleEvent (H.actualTerminalRoot constructor stages i) relation fallback nonce role
      (pullFixed (actualObserverIdentity constructor oracle stages constructed i) role fixed)
      (pullDB (actualObserverIdentity constructor oracle stages constructed i) role database) ↔
    N.roleEvent (H.adaptiveHistoryProgram constructor) relation fallback nonce role fixed database := by
  exact current_role_event_reindex (actualObserverIdentity constructor oracle stages constructed i)
    relation fallback nonce role fixed database

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalRoleReindex
