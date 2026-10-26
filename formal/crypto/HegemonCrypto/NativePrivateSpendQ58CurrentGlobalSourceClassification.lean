import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalRawLogTransport
import HegemonCrypto.NativePrivateSpendQ58CurrentSameSourceSemanticJoin

/-! SAME global-source current history classification. The accepted original
adaptive branch determines every actual stage and a logical current G3 root.
The observer keeps ALL global source cells, including cells from the prefix,
and adds only duplicate recorded reads. It is never run as a new physical
carrier. Collision and current bad-role arms remain explicit. This is source
classification/semantic data transport, not the final initialized failure
mass theorem or an efficient extractor. SOURCE ONLY. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalSourceClassification
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult rawLog)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree)
namespace H
export NativePrivateSpendQ58CurrentGlobalRawLogTransport
  (Stage adaptiveHistoryProgram historyProgram actualTerminalProducer actualTerminalRoot
   actualTerminalKeys actualTerminal_rawRecords_exact
   current_accepted_adaptive_branch_has_same_global_source_observers)
end H
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter RawDigest decode keyBytes zero)
end G
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay (fullClaims claimOracle current_grouped_claims_replay_actual_program)
end Q
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport (SourceView sourceKeys)
end X
namespace SC
export NativePrivateSpendQ58CurrentSourceCompletion
  (SourceClaims consistent_of_claims source_records_restriction full_claims_agree_on_reads)
end SC
namespace CC
export NativePrivateSpendQ58CurrentCanonicalSourceClassifier
  (root records sourceOracle fullDB Choice SourceWitness accepted_source_witness_or_chosen_role)
end CC
namespace AL
export NativePrivateSpendQ58CurrentActualTraceLabel (sourceRecords)
end AL
namespace SJ
export NativePrivateSpendQ58CurrentSameSourceSemanticJoin
  (NativeSemanticSource actual_source_witness_supplies_same_native_semantics)
end SJ
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
local instance sourcePrimeFact : Fact (Nat.Prime HegemonCrypto.NativePrivateSpendLocalSemantics.modulus) :=
  ⟨HegemonCrypto.SmallWood.goldilocks_prime⟩

variable (constructor : Program (List H.Stage))
local notation "Global" => H.adaptiveHistoryProgram constructor

def globalSourceRecords
    (database : Database (G.Key Global) (VectorOutput G.Counter)) :=
  AL.sourceRecords (rawRecords (G.keyBytes Global) (vectorOutputBytes G.zero) database)

/-- Literal restriction of the SAME full global DB through the exact current
key equivalence. It receives neither a source witness nor a validity premise. -/
def observerSourceView (oracle : Oracle) (stages : List H.Stage)
    (constructed : constructor.eval oracle = some stages) (i : Fin stages.length)
    (database : Database (G.Key Global) (VectorOutput G.Counter)) :
    X.SourceView (H.actualTerminalRoot constructor stages i) :=
  fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key.val)

theorem observer_classifier_has_exact_global_source_records
    (oracle : Oracle) (stages : List H.Stage)
    (constructed : constructor.eval oracle = some stages) (i : Fin stages.length)
    (database : Database (G.Key Global) (VectorOutput G.Counter)) :
    CC.records (H.actualTerminalProducer constructor stages i)
        stages[i.val].ns stages[i.val].relation stages[i.val].nonce
        (observerSourceView constructor oracle stages constructed i database) =
      globalSourceRecords constructor database := by
  change NativePrivateSpendQ58CurrentSourceCompletion.canonicalRecords
    (H.actualTerminalRoot constructor stages i)
    (observerSourceView constructor oracle stages constructed i database) = _
  exact (SC.source_records_restriction (H.actualTerminalRoot constructor stages i)
    (fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key))).symm.trans
    (congrArg AL.sourceRecords
      (H.actualTerminal_rawRecords_exact constructor oracle stages constructed i database))

/-- Actual acceptance and original full raw claims DERIVE the selected stages,
logical observer branches and every current source classifier. No caller
stage/observer branch, source-event inclusion or semantic witness is supplied.
The stage existential stays inside the same four-role disjunction. -/
theorem actual_accepted_global_history_has_same_source_classifiers
    (branch : Branches G.decode Global)
    (database : Database (G.Key Global) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (Q.fullClaims Global branch) database)
    (accepted : branchResult G.decode Global branch = some ()) :
    let oracle := Q.claimOracle Global database (fun _ => 0)
    ∃ (stages : List H.Stage) (constructed : constructor.eval oracle = some stages)
      (_historyAccepted : (H.historyProgram stages).eval oracle = some ()),
      ∀ i : Fin stages.length,
        ∃ observerBranch : Branches G.decode (H.actualTerminalRoot constructor stages i),
          branchResult G.decode (H.actualTerminalRoot constructor stages i) observerBranch = some () ∧
          (rawLog G.decode (H.actualTerminalRoot constructor stages i) observerBranch).toFinset =
            (rawLog G.decode Global branch).toFinset ∧
          ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot constructor stages i) observerBranch)
            (fun key => database (H.actualTerminalKeys constructor oracle stages constructed i key)) ∧
          (¬ RecordsCollisionFree (globalSourceRecords constructor database) ∨
            (∃ role, CC.Choice (H.actualTerminalProducer constructor stages i)
              stages[i.val].ns stages[i.val].relation stages[i.val].nonce observerBranch role
              (observerSourceView constructor oracle stages constructed i database)) ∨
            CC.SourceWitness (H.actualTerminalProducer constructor stages i)
              stages[i.val].ns stages[i.val].relation stages[i.val].nonce observerBranch
              (observerSourceView constructor oracle stages constructed i database)) := by
  let oracle := Q.claimOracle Global database (fun _ => 0)
  obtain ⟨stages, constructed, historyAccepted, observers⟩ :=
    H.current_accepted_adaptive_branch_has_same_global_source_observers
      constructor branch database claims accepted (fun _ => 0)
  refine ⟨stages, constructed, historyAccepted, ?_⟩
  intro i
  obtain ⟨observerBranch, observerAccepted, logEq, observerClaims, _replay⟩ := observers i
  let view := observerSourceView constructor oracle stages constructed i database
  have coherent := SC.consistent_of_claims (H.actualTerminalRoot constructor stages i)
    observerBranch _ observerClaims
  have sources : SC.SourceClaims (H.actualTerminalRoot constructor stages i) observerBranch view := by
    intro key vector member source
    exact observerClaims (key, vector) member
  have classified := CC.accepted_source_witness_or_chosen_role
    (H.actualTerminalProducer constructor stages i) stages[i.val].ns stages[i.val].relation
    stages[i.val].nonce observerBranch view coherent sources observerAccepted
  refine ⟨observerBranch, observerAccepted, logEq, observerClaims, ?_⟩
  rcases classified with collision | chosen | witness
  · exact Or.inl ((observer_classifier_has_exact_global_source_records
      constructor oracle stages constructed i database) ▸ collision)
  · exact Or.inr (Or.inl chosen)
  · exact Or.inr (Or.inr witness)

/-- The same observer source witness, paired only with the original finite
relation/CSR certificate, supplies native G1 semantics on its exact recovered
assignment. The global source view and logical producer remain explicit. -/
theorem actual_global_source_witness_supplies_same_native_semantics
    (oracle : Oracle) (stages : List H.Stage)
    (constructed : constructor.eval oracle = some stages) (i : Fin stages.length)
    (database : Database (G.Key Global) (VectorOutput G.Counter))
    (observerBranch : Branches G.decode (H.actualTerminalRoot constructor stages i))
    (graph : HegemonCrypto.NativePrivateSpendPackedLowering.Graph Goldilocks)
    (layout : HegemonCrypto.NativePrivateSpendPackedLowering.Layout Goldilocks)
    (csr : HegemonCrypto.NativePrivateSpendCsrCertificate.RawCSR Goldilocks)
    (certificate : HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.RelationCertificate
      stages[i.val].relation graph layout csr)
    (witness : CC.SourceWitness (H.actualTerminalProducer constructor stages i)
      stages[i.val].ns stages[i.val].relation stages[i.val].nonce observerBranch
      (observerSourceView constructor oracle stages constructed i database)) :
    SJ.NativeSemanticSource (H.actualTerminalProducer constructor stages i)
      stages[i.val].ns stages[i.val].relation stages[i.val].nonce observerBranch
      (observerSourceView constructor oracle stages constructed i database) graph layout := by
  exact SJ.actual_source_witness_supplies_same_native_semantics
    (H.actualTerminalProducer constructor stages i) stages[i.val].ns stages[i.val].relation
    stages[i.val].nonce observerBranch
    (observerSourceView constructor oracle stages constructed i database) graph layout csr certificate witness

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalSourceClassification
