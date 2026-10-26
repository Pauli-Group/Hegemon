import HegemonCrypto.NativePrivateSpendQ58CurrentSourceSelectorTransport
import HegemonCrypto.NativePrivateSpendQ58CurrentNativeStageReplay
import HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel
import SmzaRawDatabaseRecords
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceCompletion
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog branch_claims_eq_answer_log physicalRun)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle (Basis State)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRawDatabaseRecords (mem_raw_records_iff)
open SmzaRp05FilteredDecoderInstability (RawRecords)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter RawInput RawDigest encode decode keyBytes zero nonzero_record_stored)
end G
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay
(fullClaims claimOracle current_grouped_claims_replay_actual_program)
end Q
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport
(sourceKeys SourceView live activeSourceView source_keys_active_for_each_role)
end X
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey)
end A
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (parseCurrentStageQuery)
end C
namespace AL
export NativePrivateSpendQ58CurrentActualTraceLabel (sourceRecords)
end AL
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire Transcript ExecutionStages verifierProgram)
end E
namespace NR
export NativePrivateSpendQ58CurrentNativeStageReplay (replay)
end NR
open SmzaChallengeStageTargets (Role)
open SmzaRp05ConditionedExecution (XKey)
open SmzaRp05CurrentBranchOracleAgreement (eval_eq_of_agrees_on_left_reads)
noncomputable section
set_option autoImplicit false
set_option Elab.async false
variable {Result:Type}

def lookup {Key Value:Type} [DecidableEq Key] (key:Key):List (Key × Value)→Option Value
 | [] => none
 |(next,value)::rest => if next=key then some value else lookup key rest
def Consistent {Key Value:Type}(claims:List (Key × Value)):Prop :=
 ∀ key left right,(key,left)∈claims→(key,right)∈claims→left=right
theorem lookup_of_mem {Key Value:Type} [DecidableEq Key] (claims:List (Key × Value))
(consistent:Consistent claims) (key:Key) (value:Value) (member:(key,value)∈claims) :
 lookup key claims=some value:=by
 induction claims with
 | nil => simp at member
 | cons head rest ih =>
  rcases head with ⟨next,other⟩
  rcases List.mem_cons.mp member with same | later
  · cases same;simp [lookup]
  · by_cases equal:next=key
    · subst next
      have values:=consistent key other value (List.mem_cons_self) (List.mem_cons_of_mem _ later)
      simp only [lookup,values,if_true]
    · simp only [lookup,if_neg equal]
      exact ih (fun k a b ha hb => consistent k a b (List.mem_cons_of_mem _ ha) (List.mem_cons_of_mem _ hb)) later
def SourceClaims (root:Program Result) (branch:Branches G.decode root) (view:X.SourceView root):Prop :=
 ∀ key value,(key,value)∈Q.fullClaims root branch→∀ member:key∈X.sourceKeys root,view ⟨key,member⟩=some value
def completeSourceView (root:Program Result) (branch:Branches G.decode root)
(view:X.SourceView root) (filler:VectorOutput G.Counter):Database (G.Key root) (VectorOutput G.Counter) :=
 fun key => if member:key∈X.sourceKeys root then view ⟨key,member⟩ else
  match lookup key (Q.fullClaims root branch) with
  | none => some filler
  | some value => some value
def canonicalRecords (root:Program Result) (view:X.SourceView root):RawRecords :=
 rawRecords (fun key:XKey (X.sourceKeys root) => G.keyBytes root key.val) (vectorOutputBytes G.zero) view
theorem complete_source_claims (root:Program Result) (branch:Branches G.decode root)
(view:X.SourceView root) (filler:VectorOutput G.Counter)
(sources:SourceClaims root branch view) (consistent:Consistent (Q.fullClaims root branch)) :
 ClaimsDatabaseEvent (Q.fullClaims root branch) (completeSourceView root branch view filler):=by
 rintro ⟨key,value⟩ member
 by_cases source:key∈X.sourceKeys root
 · simp only [completeSourceView,dif_pos source]
   exact sources key value member source
 · simp only [completeSourceView,dif_neg source,lookup_of_mem _ consistent key value member]
theorem consistent_of_claims (root:Program Result) (branch:Branches G.decode root)
(database:Database (G.Key root) (VectorOutput G.Counter))
(claims:ClaimsDatabaseEvent (Q.fullClaims root branch) database):Consistent (Q.fullClaims root branch):=by
 intro key left right hl hr
 exact Option.some.inj ((claims (key,left) hl).symm.trans (claims (key,right) hr))
theorem physical_full_claims {Work:Type} [Fintype Work] [DecidableEq Work]
(root:Program Result) (branch:Branches G.decode root)
(state:State (G.Key root) (VectorOutput G.Counter) (VectorOutput G.Counter) Work)
(basis:Basis (G.Key root) (VectorOutput G.Counter) (VectorOutput G.Counter) Work)
(nonzero:globalDecompress (physicalRun (G.encode root) G.decode root branch state) basis ≠ 0) :
 ClaimsDatabaseEvent (Q.fullClaims root branch) basis.database:=by
 intro claim member
 rw [Q.fullClaims,branch_claims_eq_answer_log] at member
 obtain ⟨call,recorded,same⟩:=List.mem_map.mp member
 subst claim
 exact G.nonzero_record_stored root branch state basis nonzero call recorded
theorem source_records_restriction (root:Program Result)
(database:Database (G.Key root) (VectorOutput G.Counter)) :
 AL.sourceRecords (rawRecords (G.keyBytes root) (vectorOutputBytes G.zero) database) =
 canonicalRecords root (fun key => database key.val):=by
 ext pair
 rcases pair with ⟨input,digest⟩
 constructor
 · intro member
   obtain ⟨present,unparsed⟩:=Finset.mem_filter.mp member
   obtain ⟨key,value,stored,inputEq,outputEq⟩:=(mem_raw_records_iff _ _ _ _ _).mp present
   have source:key∈X.sourceKeys root:=Finset.mem_filter.mpr ⟨Finset.mem_univ _,by simpa only [inputEq] using unparsed⟩
   exact (mem_raw_records_iff _ _ _ _ _).mpr ⟨⟨key,source⟩,value,stored,inputEq,outputEq⟩
 · intro member
   obtain ⟨key,value,stored,inputEq,outputEq⟩:=(mem_raw_records_iff _ _ _ _ _).mp member
   apply Finset.mem_filter.mpr
   exact ⟨(mem_raw_records_iff _ _ _ _ _).mpr ⟨key.val,value,stored,inputEq,outputEq⟩,
    by simpa only [inputEq] using (Finset.mem_filter.mp key.property).2⟩
theorem complete_source_records (root:Program Result) (branch:Branches G.decode root)
(view:X.SourceView root) (filler:VectorOutput G.Counter) :
 AL.sourceRecords (rawRecords (G.keyBytes root) (vectorOutputBytes G.zero) (completeSourceView root branch view filler)) =
 canonicalRecords root view:=by
 rw [source_records_restriction]
 congr 1
 funext key
 simp only [completeSourceView,dif_pos key.property]
theorem active_source_records (root:Program Result) (role:Role)
(database:Database (A.ActiveKey (X.live root role)) (VectorOutput G.Counter)) :
 AL.sourceRecords (rawRecords (fun key => G.keyBytes root key.val) (vectorOutputBytes G.zero) database) =
 canonicalRecords root (X.activeSourceView root role database):=by
 ext pair
 rcases pair with ⟨input,digest⟩
 constructor
 · intro member
   obtain ⟨present,unparsed⟩:=Finset.mem_filter.mp member
   obtain ⟨key,value,stored,inputEq,outputEq⟩:=(mem_raw_records_iff _ _ _ _ _).mp present
   have source:key.val∈X.sourceKeys root:=Finset.mem_filter.mpr ⟨Finset.mem_univ _,by simpa only [inputEq] using unparsed⟩
   apply (mem_raw_records_iff _ _ _ _ _).mpr
   exact ⟨⟨key.val,source⟩,value,stored,inputEq,outputEq⟩
 · intro member
   obtain ⟨key,value,stored,inputEq,outputEq⟩:=(mem_raw_records_iff _ _ _ _ _).mp member
   let active:A.ActiveKey (X.live root role):=⟨key.val,X.source_keys_active_for_each_role root role key.val key.property⟩
   apply Finset.mem_filter.mpr
   exact ⟨(mem_raw_records_iff _ _ _ _ _).mpr ⟨active,value,stored,inputEq,outputEq⟩,
    by simpa only [inputEq] using (Finset.mem_filter.mp key.property).2⟩
theorem full_claims_agree_on_reads (root:Program Result) (branch:Branches G.decode root)
(left right:Database (G.Key root) (VectorOutput G.Counter))
(leftClaims:ClaimsDatabaseEvent (Q.fullClaims root branch) left)
(rightClaims:ClaimsDatabaseEvent (Q.fullClaims root branch) right)
(lf rf:G.RawDigest) :
 ∀ input,(input,Q.claimOracle root left lf input)∈(root.record (Q.claimOracle root left lf)).2 →
  Q.claimOracle root left lf input=Q.claimOracle root right rf input:=by
 have equality:=(Q.current_grouped_claims_replay_actual_program root branch left leftClaims lf).trans
   (Q.current_grouped_claims_replay_actual_program root branch right rightClaims rf).symm
 intro input member
 have present:(input,Q.claimOracle root left lf input)∈(root.record (Q.claimOracle root right rf)).2:=by
  rw [← congrArg Prod.snd equality]
  exact member
 exact Program.recorded_call _ root _ present
abbrev Full (prod:Program E.Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
(rel:NativePrivateSpendQ58CurrentPublicOpening.Relation) (pending:Bool) (nonce:Fin (2^32)) :=
 prod.bind (E.verifierProgram ns rel pending nonce)
variable (prod:Program E.Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
  (rel:NativePrivateSpendQ58CurrentPublicOpening.Relation) (pending:Bool) (nonce:Fin (2^32))
  (branch:Branches G.decode (Full prod ns rel pending nonce))
  (left right:Database (G.Key (Full prod ns rel pending nonce)) (VectorOutput G.Counter))
  (leftClaims:ClaimsDatabaseEvent (Q.fullClaims (Full prod ns rel pending nonce) branch) left)
  (rightClaims:ClaimsDatabaseEvent (Q.fullClaims (Full prod ns rel pending nonce) branch) right)
  (lf rf:G.RawDigest)
include branch leftClaims rightClaims in
 theorem same_producer_full_claims (wire:E.Wire)
(produced:prod.eval (Q.claimOracle (Full prod ns rel pending nonce) left lf)=some wire) :
 prod.eval (Q.claimOracle (Full prod ns rel pending nonce) right rf)=some wire:=by
 have agree:=full_claims_agree_on_reads (Full prod ns rel pending nonce) branch left right leftClaims rightClaims lf rf
 have equality:=eval_eq_of_agrees_on_left_reads prod _ _ (fun input member =>
  agree input (Program.bind_log_left _ prod _ wire produced member))
 exact equality.symm.trans produced
include branch leftClaims rightClaims in
 def replay_native_stages (wire:E.Wire)
(produced:prod.eval (Q.claimOracle (Full prod ns rel pending nonce) left lf)=some wire)
(t:E.Transcript)
(st:E.ExecutionStages ns rel pending nonce wire (Q.claimOracle (Full prod ns rel pending nonce) left lf) t) :
 E.ExecutionStages ns rel pending nonce wire (Q.claimOracle (Full prod ns rel pending nonce) right rf) t:=by
 have agree:=full_claims_agree_on_reads (Full prod ns rel pending nonce) branch left right leftClaims rightClaims lf rf
 exact NR.replay ns rel pending nonce wire _ _ t st (fun input member =>
  agree input (Program.bind_log_right _ prod _ wire produced member))
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceCompletion
