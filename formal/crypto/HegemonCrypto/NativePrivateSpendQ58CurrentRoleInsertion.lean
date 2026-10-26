import HegemonCrypto.NativePrivateSpendQ58CurrentRoleEventPhysicalMass
import HegemonCrypto.NativePrivateSpendQ58CurrentMatrixNativeJoin
import SmzaRawDatabaseRecords
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRoleInsertion
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaDynamicDatabaseSoundness (DynamicBad)
open SmzaChallengeStageTargets (Role)
open NativePrivateSpendQ58CurrentActiveBranchClaims (live)
open NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
open NativePrivateSpendQ58ActiveEventProjection (ActiveKey FixedTable)
open NativePrivateSpendQ58CurrentRoleEventPhysicalMass (roleEvent roleBad stage)
open NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter RawDigest keyBytes zero)
end G
namespace R
export NativePrivateSpendQ58CurrentFiberMassTransport
 (Active FixedVectors actualActiveEquiv actualFixedEquiv actualFixed activeBytes)
end R
namespace M
export NativePrivateSpendQ58CurrentMatrixNativeJoin
 (Context Stages prog oracle records bytes matrix_dynamic)
end M
namespace C
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end C
noncomputable section
set_option autoImplicit false
variable {Result : Type} (p : Program Result) (r : Role)
abbrev DB := Database (ActiveKey (live p r currentRoleCaps)) (VectorOutput G.Counter)
abbrev Fixed := FixedTable (Counter := G.Counter) (live p r currentRoleCaps)
def pullDB (db : DB p r) : Database (R.Active r (G.keyBytes p)) (VectorOutput G.Counter) :=
 fun key => db (R.actualActiveEquiv r (G.keyBytes p) key)
def pullFixed (fixed : Fixed p r) : R.FixedVectors (Counter := G.Counter) r (G.keyBytes p) :=
 fun key => fixed (R.actualFixedEquiv r (G.keyBytes p) key)
@[simp] theorem pull_fixed_exact (fixed : Fixed p r) :
 R.actualFixed r (G.keyBytes p) (pullFixed p r fixed) = fixed := by
 funext key
 rfl
private theorem raw_exact (db : DB p r) :
 rawRecords (R.activeBytes r (G.keyBytes p)) (vectorOutputBytes G.zero) (pullDB p r db) =
 rawRecords (fun key : ActiveKey (live p r currentRoleCaps) => G.keyBytes p key.val)
   (vectorOutputBytes G.zero) db := by
 ext pair
 rcases pair with ⟨input,digest⟩
 simp only [SmzaRawDatabaseRecords.mem_raw_records_iff]
 constructor
 · rintro ⟨key,v,stored,bytes,output⟩
   exact ⟨R.actualActiveEquiv r (G.keyBytes p) key,v,stored,bytes,output⟩
 · rintro ⟨key,v,stored,bytes,output⟩
   refine ⟨(R.actualActiveEquiv r (G.keyBytes p)).symm key,v,?_,bytes,output⟩
   simpa only [pullDB, Equiv.apply_symm_apply] using stored
/-- Exact coordinate transport only; final arm APIs derive their native event. -/
theorem native_event_reindex (relation : C.Relation) (fallback : G.RawDigest)
 (nonce : Fin (2^32)) (fixed : Fixed p r) (db : DB p r)
 (hit : DynamicBad
   (currentLabel (fun key : ActiveKey (live p r currentRoleCaps) => G.keyBytes p key.val) G.zero (stage r))
   (fun trace key v => roleBad p relation fallback nonce r (pullFixed p r fixed)
     trace ((R.actualActiveEquiv r (G.keyBytes p)).symm key) v) db) :
 roleEvent p relation fallback nonce r (pullFixed p r fixed) (pullDB p r db) := by
 rcases hit with ⟨key,v,stored,bad⟩
 unfold roleEvent DynamicBad
 refine ⟨(R.actualActiveEquiv r (G.keyBytes p)).symm key,v,?_,?_⟩
 · simpa only [pullDB, Equiv.apply_symm_apply] using stored
 · have label :
     currentLabel (R.activeBytes r (G.keyBytes p)) G.zero (stage r) (pullDB p r db)
       ((R.actualActiveEquiv r (G.keyBytes p)).symm key) =
     currentLabel (fun key : ActiveKey (live p r currentRoleCaps) => G.keyBytes p key.val)
       G.zero (stage r) db key := by
     unfold currentLabel NativePrivateSpendQ58CurrentPrequeryEvents.sourceTrace
     rw [raw_exact p r db]
     rfl
   rw [label]
   exact bad

theorem root_matrix (c : M.Context) (w : NativePrivateSpendQ58CurrentExecutableVerifier.Wire)
 (hw : c.producer.eval (M.oracle c) = some w)
 (t : NativePrivateSpendQ58CurrentExecutableVerifier.Transcript) (st : M.Stages c w t)
 (clean : st.pcs.pending = false) (canonical : SmzaRp05FilteredDecoderInstability.RawRecords)
 (same : canonical = M.records c)
 (arm : NativePrivateSpendQ58CurrentRecoveryGeometry.MatrixBad canonical st.pcs) :
 roleEvent (M.prog c) c.relation c.fallback c.nonce .decsMatrix
   (pullFixed (M.prog c) .decsMatrix c.fixed) (pullDB (M.prog c) .decsMatrix c.database) := by
 apply native_event_reindex
 have actual := M.matrix_dynamic c w hw t st clean (same ▸ arm)
 dsimp (config := { instances := true }) only [M.bytes,
   NativePrivateSpendQ58CurrentMatrixNativeJoin.live,
   NativePrivateSpendQ58CurrentMatrixNativeJoin.caps] at actual
 have bytesEq : M.bytes c =
     (fun key : ActiveKey (live (M.prog c) .decsMatrix currentRoleCaps) =>
       G.keyBytes (M.prog c) key.val) := by
   funext key
   rfl
 rw [bytesEq] at actual
 rcases actual with ⟨key, vector, stored, bad⟩
 refine ⟨key, vector, stored, ?_⟩
 have keyVal : ((R.actualActiveEquiv .decsMatrix (G.keyBytes (M.prog c))).symm key).val =
     key.val := by
   rfl
 have bytesAt : R.activeBytes .decsMatrix (G.keyBytes (M.prog c))
     ((R.actualActiveEquiv .decsMatrix (G.keyBytes (M.prog c))).symm key) =
     G.keyBytes (M.prog c) key.val := by
   change G.keyBytes (M.prog c)
     ((R.actualActiveEquiv .decsMatrix (G.keyBytes (M.prog c))).symm key).val =
       G.keyBytes (M.prog c) key.val
   exact congrArg (G.keyBytes (M.prog c)) keyVal
 have selectors : NativePrivateSpendQ58CurrentMatrixNativeJoin.select =
     NativePrivateSpendQ58CurrentRoleEventPhysicalMass.matrixSelect := by
   rfl
 rw [selectors] at bad
 unfold roleBad
 dsimp only [stage]
 unfold NativePrivateSpendQ58CurrentMatrixRawOrder.vectorBad at bad ⊢
 rw [bytesAt]
 exact bad
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRoleInsertion
