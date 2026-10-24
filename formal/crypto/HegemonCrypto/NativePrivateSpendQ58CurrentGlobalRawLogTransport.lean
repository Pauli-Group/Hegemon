import HegemonCrypto.NativePrivateSpendQ58CurrentClaimReplay
import HegemonCrypto.NativePrivateSpendQ58CurrentSourceTraceReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentFiberMassTransport
import SmzaRp05ExecutableBindSupport
import SmzaRp05ExecutableMerklePaths
import SmzaRawDatabaseRecords

/-! Literal current verifier histories on one executable oracle.

The outer constructor is an arbitrary adversarial Program returning the actual
stage list. Its queries, rejected continuations and current verifier reads stay
inside one adaptiveHistoryProgram. The static history is only its continuation.
Raw-log containment is derived from this same execution, not supplied as a
stage certificate. The terminal observer is logical deterministic record replay:
its records add duplicates and its all-answer current grouped universe is equal
to the original program. No CMS state, physical outcome or Born norm is replaced.
This source proves ordinary data transport only, not causal event support,
history soundness, native Rust equivalence or efficient extraction. SOURCE ONLY.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalRawLogTransport

open SmzaRp05ExecutableMerkleVerifier (Program Oracle Log)
open SmzaRp05ExecutableAddressCompiler (reachable recorded_key_reachable)
open SmzaRp05ExecutableBindSupport
  (reachable_subset_constant_bind reachable_constant_bind_subset_union)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult rawLog answerLog branch_claims_eq_answer_log)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRawDatabaseRecords (mem_raw_records_iff)
open scoped Classical

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire verifierProgram)
end E
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end M
namespace C
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end C
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (Counter zero Key GroupKey groups groupKeyOf included encode decode keyBytes
   included_encode_of_reachable)
end G
namespace CR
export NativePrivateSpendQ58CurrentClaimReplay
  (fullClaims claimOracle current_claims_store_every_branch_vector
   current_grouped_claims_replay_actual_program)
end CR
namespace RC
export NativePrivateSpendQ58CurrentRoleClassifier (RoleActive)
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end RC
namespace FT
export NativePrivateSpendQ58CurrentFiberMassTransport (routingTag)
end FT
namespace TR
export NativePrivateSpendQ58CurrentSourceTraceReadback
  (recorded_current_fpp_trace_readback)
end TR

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

structure Stage where
  proofProducer : Program E.Wire
  ns : M.Namespace
  relation : C.Relation
  nonce : Fin (2 ^ 32)

def stageProgram (stage : Stage) : Program Unit :=
  stage.proofProducer.bind (E.verifierProgram stage.ns stage.relation false stage.nonce)

def sequentialUnitProgram (first second : Program Unit) : Program Unit :=
  first.bind fun _ => second

def historyProgram : List Stage → Program Unit
  | [] => .done (some ())
  | stage :: rest => sequentialUnitProgram (stageProgram stage) (historyProgram rest)

/-- The admitted list itself may depend on arbitrary adversarial oracle reads. -/
def adaptiveHistoryProgram (constructor : Program (List Stage)) : Program Unit :=
  constructor.bind historyProgram

private theorem bind_assoc {α β γ : Type} (program : Program α)
    (next : α → Program β) (last : β → Program γ) :
    (program.bind next).bind last =
      program.bind (fun value => (next value).bind last) := by
  induction program with
  | done result => cases result <;> rfl
  | read raw cont ih =>
      simp only [Program.bind]
      congr 1
      funext digest
      exact ih digest

private theorem bind_unit_done (program : Program Unit) :
    program.bind (fun _ => (Program.done (some ()) : Program Unit)) = program := by
  induction program with
  | done result => cases result <;> rfl
  | read raw next ih =>
      simp only [Program.bind]
      congr 1
      funext answer
      exact ih answer

private theorem historyProgram_singleton (stage : Stage) :
    historyProgram [stage] = stageProgram stage := by
  change sequentialUnitProgram (stageProgram stage) (Program.done (some ())) = _
  exact bind_unit_done (stageProgram stage)

private theorem eval_bind_some_iff {α β : Type}
    (oracle : Oracle) (program : Program α) (next : α → Program β) (value : β) :
    (program.bind next).eval oracle = some value ↔
      ∃ result, program.eval oracle = some result ∧ (next result).eval oracle = some value := by
  rw [Program.eval_bind]
  simp only [Option.bind_eq_some_iff]

/-- A rejected prefix retains its original result and every actual raw query. -/
theorem record_bind_rejected {α β : Type} (oracle : Oracle)
    (program : Program α) (next : α → Program β)
    (rejected : program.eval oracle = none) :
    (program.bind next).record oracle = (none, (program.record oracle).2) := by
  induction program with
  | done result =>
      have equal : result = none := rejected
      subst result
      rfl
  | read raw cont ih =>
      have below := ih (oracle raw) rejected
      simpa only [Program.bind, Program.record] using
        congrArg (fun outcome : Option β × Log =>
          (outcome.1, (raw, oracle raw) :: outcome.2)) below

theorem historyProgram_append (earlier suffix : List Stage) :
    historyProgram (earlier ++ suffix) =
      sequentialUnitProgram (historyProgram earlier) (historyProgram suffix) := by
  induction earlier with
  | nil => rfl
  | cons stage rest ih =>
      change sequentialUnitProgram (stageProgram stage) (historyProgram (rest ++ suffix)) =
        sequentialUnitProgram
          (sequentialUnitProgram (stageProgram stage) (historyProgram rest))
          (historyProgram suffix)
      rw [ih]
      exact (bind_assoc (stageProgram stage)
        (fun _ => historyProgram rest) (fun _ => historyProgram suffix)).symm

theorem accepted_history_retains_prefix (oracle : Oracle) (earlier suffix : List Stage)
    (accepted : (historyProgram (earlier ++ suffix)).eval oracle = some ()) :
    (historyProgram earlier).eval oracle = some () := by
  rw [historyProgram_append] at accepted
  rcases (eval_bind_some_iff oracle (historyProgram earlier)
    (fun _ => historyProgram suffix) ()).mp accepted with ⟨result, prefixAccepted, _⟩
  cases result
  exact prefixAccepted

def historyPrefixAt (stages : List Stage) (i : Fin stages.length) : Program Unit :=
  historyProgram (stages.take (i.val + 1))

private theorem take_step_eq_nat (stages : List Stage) (n : Nat)
    (bound : n < stages.length) :
    stages.take (n + 1) = stages.take n ++ [stages[n]] := by
  induction stages generalizing n with
  | nil => simp only [List.length_nil] at bound; omega
  | cons head tail ih =>
      cases n with
      | zero => rfl
      | succ n =>
          have tailBound : n < tail.length := by simp only [List.length_cons] at bound; omega
          simpa only [List.take_succ_cons, List.getElem_cons_succ, List.cons_append] using
            congrArg (List.cons head) (ih n tailBound)

private theorem take_step_eq (stages : List Stage) (i : Fin stages.length) :
    stages.take (i.val + 1) = stages.take i.val ++ [stages[i.val]] :=
  take_step_eq_nat stages i.val i.isLt

def retainedPrefixAt (stages : List Stage) (i : Fin stages.length) : Program E.Wire :=
  (historyProgram (stages.take i.val)).bind fun _ => stages[i.val].proofProducer

def stageVerifierAt (stages : List Stage) (i : Fin stages.length) (wire : E.Wire) : Program Unit :=
  E.verifierProgram stages[i.val].ns stages[i.val].relation false stages[i.val].nonce wire

def indexedStageVerifierProgram (stages : List Stage) (i : Fin stages.length) : Program Unit :=
  (retainedPrefixAt stages i).bind (stageVerifierAt stages i)

theorem indexedStageVerifierProgram_eq_prefixAt (stages : List Stage) (i : Fin stages.length) :
    indexedStageVerifierProgram stages i = historyPrefixAt stages i := by
  unfold indexedStageVerifierProgram retainedPrefixAt historyPrefixAt
  rw [take_step_eq stages i, historyProgram_append]
  rw [historyProgram_singleton]
  change ((historyProgram (stages.take i.val)).bind
      (fun _ => stages[i.val].proofProducer)).bind (stageVerifierAt stages i) =
    (historyProgram (stages.take i.val)).bind (fun _ => stageProgram stages[i.val])
  exact bind_assoc _ _ _

theorem accepted_history_retains_indexed_stage (oracle : Oracle)
    (stages : List Stage) (i : Fin stages.length)
    (accepted : (historyProgram stages).eval oracle = some ()) :
    ∃ wire, (retainedPrefixAt stages i).eval oracle = some wire ∧
      (stageVerifierAt stages i wire).eval oracle = some () ∧
      stages[i.val].proofProducer.eval oracle = some wire := by
  have acceptedSplit :
      (historyProgram (stages.take (i.val + 1) ++ stages.drop (i.val + 1))).eval oracle = some () := by
    rw [List.take_append_drop]
    exact accepted
  have prefixAccepted := accepted_history_retains_prefix oracle _ _ acceptedSplit
  have indexedAccepted : (indexedStageVerifierProgram stages i).eval oracle = some () := by
    rw [indexedStageVerifierProgram_eq_prefixAt]
    exact prefixAccepted
  obtain ⟨wire, retained, verified⟩ :=
    (eval_bind_some_iff oracle (retainedPrefixAt stages i) (stageVerifierAt stages i) ()).mp indexedAccepted
  obtain ⟨_prefixResult, _earlier, produced⟩ :=
    (eval_bind_some_iff oracle (historyProgram (stages.take i.val))
      (fun _ => stages[i.val].proofProducer) wire).mp retained
  exact ⟨wire, retained, verified, produced⟩

theorem indexed_stage_log_subset_history (oracle : Oracle)
    (stages : List Stage) (i : Fin stages.length)
    (accepted : (historyProgram stages).eval oracle = some ()) :
    ((indexedStageVerifierProgram stages i).record oracle).2 ⊆
      ((historyProgram stages).record oracle).2 := by
  rw [indexedStageVerifierProgram_eq_prefixAt]
  have acceptedSplit :
      (historyProgram (stages.take (i.val + 1) ++ stages.drop (i.val + 1))).eval oracle = some () := by
    rw [List.take_append_drop]
    exact accepted
  have prefixAccepted := accepted_history_retains_prefix oracle _ _ acceptedSplit
  have included := Program.bind_log_left oracle
    (historyProgram (stages.take (i.val + 1)))
    (fun _ => historyProgram (stages.drop (i.val + 1))) () prefixAccepted
  change ((historyProgram (stages.take (i.val + 1))).record oracle).2 ⊆ _
  rw [show historyProgram stages = sequentialUnitProgram
    (historyProgram (stages.take (i.val + 1)))
    (historyProgram (stages.drop (i.val + 1))) by
      rw [← historyProgram_append, List.take_append_drop]]
  exact included

private theorem reachable_bind_monotone {α β γ : Type}
    (program : Program α) (left : α → Program β) (right : α → Program γ)
    (pointwise : ∀ value, reachable (left value) ⊆ reachable (right value)) :
    reachable (program.bind left) ⊆ reachable (program.bind right) := by
  induction program with
  | done result =>
      cases result with
      | none => exact Finset.Subset.refl _
      | some value => exact pointwise value
  | read raw next ih =>
      intro key member
      change key ∈ insert raw (Finset.univ.biUnion
        (fun answer : RawDigest => reachable ((next answer).bind left))) at member
      change key ∈ insert raw (Finset.univ.biUnion
        (fun answer : RawDigest => reachable ((next answer).bind right)))
      rcases Finset.mem_insert.mp member with head | below
      · exact Finset.mem_insert.mpr (Or.inl head)
      · obtain ⟨answer, answerMem, keyMem⟩ := Finset.mem_biUnion.mp below
        exact Finset.mem_insert_of_mem
          (Finset.mem_biUnion.mpr ⟨answer, answerMem, ih answer keyMem⟩)

private theorem reachable_bind_eq {α β γ : Type}
    (program : Program α) (left : α → Program β) (right : α → Program γ)
    (pointwise : ∀ value, reachable (left value) = reachable (right value)) :
    reachable (program.bind left) = reachable (program.bind right) := by
  apply Finset.Subset.antisymm
  · apply reachable_bind_monotone program left right
    intro value raw member
    rw [← pointwise value]
    exact member
  · apply reachable_bind_monotone program right left
    intro value raw member
    rw [pointwise value]
    exact member

private theorem reachable_actual_suffix {α β : Type} (oracle : Oracle)
    (program : Program α) (next : α → Program β) (value : α)
    (success : program.eval oracle = some value) :
    reachable (next value) ⊆ reachable (program.bind next) := by
  induction program with
  | done result =>
      have equal : result = some value := success
      subst result
      exact Finset.Subset.refl _
  | read raw cont ih =>
      have below := ih (oracle raw) success
      intro key member
      change key ∈ insert raw (Finset.univ.biUnion
        (fun answer : RawDigest => reachable ((cont answer).bind next)))
      exact Finset.mem_insert_of_mem
        (Finset.mem_biUnion.mpr ⟨oracle raw, Finset.mem_univ _, below member⟩)

private theorem reachable_constant_bind_eq {α β : Type}
    (program : Program α) (suffix : Program β)
    (covered : reachable suffix ⊆ reachable program) :
    reachable (program.bind (fun _ => suffix)) = reachable program := by
  apply Finset.Subset.antisymm
  · intro raw member
    rcases Finset.mem_union.mp (reachable_constant_bind_subset_union program suffix member) with before | after
    · exact before
    · exact covered after
  · exact reachable_subset_constant_bind program suffix

theorem historyPrefixAt_reachable_subset (stages : List Stage) (i : Fin stages.length) :
    reachable (historyPrefixAt stages i) ⊆ reachable (historyProgram stages) := by
  have included := reachable_subset_constant_bind
    (historyProgram (stages.take (i.val + 1))) (historyProgram (stages.drop (i.val + 1)))
  change reachable (historyProgram (stages.take (i.val + 1))) ⊆ _
  rw [show historyProgram stages = sequentialUnitProgram
    (historyProgram (stages.take (i.val + 1))) (historyProgram (stages.drop (i.val + 1))) by
      rw [← historyProgram_append, List.take_append_drop]]
  exact included

theorem indexedStage_reachable_subset (stages : List Stage) (i : Fin stages.length) :
    reachable (indexedStageVerifierProgram stages i) ⊆ reachable (historyProgram stages) := by
  rw [indexedStageVerifierProgram_eq_prefixAt]
  exact historyPrefixAt_reachable_subset stages i

def terminalHistoryStageObserver (stages : List Stage) (i : Fin stages.length) : Program Unit :=
  (historyProgram stages).bind fun _ => indexedStageVerifierProgram stages i

theorem terminalHistoryStageObserver_reachable_eq (stages : List Stage) (i : Fin stages.length) :
    reachable (terminalHistoryStageObserver stages i) = reachable (historyProgram stages) :=
  reachable_constant_bind_eq _ _ (indexedStage_reachable_subset stages i)

/-- Invalid indices are logical observer failure, with no extra oracle query. -/
def terminalObserverAtNat (stages : List Stage) (n : Nat) : Program Unit :=
  (historyProgram stages).bind fun _ =>
    if bound : n < stages.length then indexedStageVerifierProgram stages ⟨n, bound⟩
    else .done none

def adaptiveTerminalObserver (constructor : Program (List Stage)) (n : Nat) : Program Unit :=
  constructor.bind fun stages => terminalObserverAtNat stages n

theorem terminalObserverAtNat_reachable_eq (stages : List Stage) (n : Nat) :
    reachable (terminalObserverAtNat stages n) = reachable (historyProgram stages) := by
  by_cases bound : n < stages.length
  · simpa only [terminalObserverAtNat, terminalHistoryStageObserver, dif_pos bound] using
      terminalHistoryStageObserver_reachable_eq stages ⟨n, bound⟩
  · change reachable ((historyProgram stages).bind (fun _ =>
        if h : n < stages.length then indexedStageVerifierProgram stages ⟨n, h⟩ else .done none)) = _
    simp only [dif_neg bound]
    exact reachable_constant_bind_eq _ _ (by intro raw member; simp [reachable] at member)

theorem adaptiveTerminalObserver_reachable_eq (constructor : Program (List Stage)) (n : Nat) :
    reachable (adaptiveTerminalObserver constructor n) = reachable (adaptiveHistoryProgram constructor) :=
  reachable_bind_eq _ _ _ (fun stages => terminalObserverAtNat_reachable_eq stages n)

/-- Logical replay adds only records already present. This holds on rejected
histories and invalid observer indices too; it says nothing about CMS norms. -/
theorem terminalObserverAtNat_record_finset_eq (oracle : Oracle)
    (stages : List Stage) (n : Nat) :
    ((terminalObserverAtNat stages n).record oracle).2.toFinset =
      ((historyProgram stages).record oracle).2.toFinset := by
  cases outcome : (historyProgram stages).eval oracle with
  | none =>
      unfold terminalObserverAtNat
      rw [record_bind_rejected oracle _ _ outcome]
  | some resultValue =>
      cases resultValue
      by_cases bound : n < stages.length
      · unfold terminalObserverAtNat
        simp only [dif_pos bound]
        rw [Program.record_bind_success oracle _ _ () outcome]
        have included := indexed_stage_log_subset_history oracle stages ⟨n, bound⟩ outcome
        apply Finset.ext
        intro call
        simp only [List.mem_toFinset, List.mem_append]
        constructor
        · rintro (before | replay)
          · exact before
          · exact included replay
        · intro before
          exact Or.inl before
      · unfold terminalObserverAtNat
        simp only [dif_neg bound]
        rw [Program.record_bind_success oracle _ _ () outcome]
        simp only [Program.record, List.append_nil]

theorem adaptiveTerminalObserver_record_finset_eq (oracle : Oracle)
    (constructor : Program (List Stage)) (n : Nat) :
    ((adaptiveTerminalObserver constructor n).record oracle).2.toFinset =
      ((adaptiveHistoryProgram constructor).record oracle).2.toFinset := by
  cases constructed : constructor.eval oracle with
  | none =>
      unfold adaptiveTerminalObserver adaptiveHistoryProgram
      rw [record_bind_rejected oracle _ _ constructed,
        record_bind_rejected oracle _ _ constructed]
  | some stages =>
      unfold adaptiveTerminalObserver adaptiveHistoryProgram
      rw [Program.record_bind_success oracle _ _ stages constructed,
        Program.record_bind_success oracle _ _ stages constructed]
      rw [List.toFinset_append, List.toFinset_append,
        terminalObserverAtNat_record_finset_eq oracle stages n]

/-- Rejected original execution cannot start a logical observer continuation. -/
theorem adaptiveTerminalObserver_record_rejected (oracle : Oracle)
    (constructor : Program (List Stage)) (n : Nat)
    (rejected : (adaptiveHistoryProgram constructor).eval oracle = none) :
    (adaptiveTerminalObserver constructor n).record oracle =
      (adaptiveHistoryProgram constructor).record oracle := by
  cases constructed : constructor.eval oracle with
  | none =>
      unfold adaptiveTerminalObserver adaptiveHistoryProgram
      rw [record_bind_rejected oracle _ _ constructed,
        record_bind_rejected oracle _ _ constructed]
  | some stages =>
      have historyRejected : (historyProgram stages).eval oracle = none := by
        simpa only [adaptiveHistoryProgram, Program.eval_bind,
          constructed, Option.bind_some] using rejected
      have originalResult : ((historyProgram stages).record oracle).1 = none :=
        (Program.record_result oracle _).trans historyRejected
      unfold adaptiveTerminalObserver adaptiveHistoryProgram
      rw [Program.record_bind_success oracle _ _ stages constructed,
        Program.record_bind_success oracle _ _ stages constructed]
      unfold terminalObserverAtNat
      rw [record_bind_rejected oracle _ _ historyRejected, originalResult]

theorem adaptiveTerminalObserver_groups_eq (constructor : Program (List Stage)) (n : Nat) :
    G.groups (adaptiveTerminalObserver constructor n) = G.groups (adaptiveHistoryProgram constructor) := by
  unfold G.groups
  rw [adaptiveTerminalObserver_reachable_eq]

theorem adaptiveTerminalObserver_key_eq (constructor : Program (List Stage)) (n : Nat) :
    G.Key (adaptiveTerminalObserver constructor n) = G.Key (adaptiveHistoryProgram constructor) := by
  change { key : G.GroupKey // key ∈ insert (G.groupKeyOf [])
      (G.groups (adaptiveTerminalObserver constructor n)) } =
    { key : G.GroupKey // key ∈ insert (G.groupKeyOf []) (G.groups (adaptiveHistoryProgram constructor)) }
  rw [adaptiveTerminalObserver_groups_eq]

private def groupKeysEquiv {α β : Type} (left : Program α) (right : Program β)
    (same : G.groups left = G.groups right) : G.Key left ≃ G.Key right where
  toFun := fun key => ⟨key.val, by simpa only [same] using key.property⟩
  invFun := fun key => ⟨key.val, by simpa only [same] using key.property⟩
  left_inv := by intro key; apply Subtype.ext; rfl
  right_inv := by intro key; apply Subtype.ext; rfl

private theorem groupKeysEquiv_encode_exact {α β : Type}
    (left : Program α) (right : Program β)
    (same : G.groups left = G.groups right) (raw : RawInput) :
    groupKeysEquiv left right same (G.encode left raw) = G.encode right raw := by
  apply Subtype.ext
  change (G.encode left raw).val = (G.encode right raw).val
  by_cases member : G.groupKeyOf raw ∈ insert (G.groupKeyOf []) (G.groups left)
  · have member' : G.groupKeyOf raw ∈ insert (G.groupKeyOf []) (G.groups right) := by
      simpa only [same] using member
    simp only [G.encode, dif_pos member, dif_pos member']
  · have member' : G.groupKeyOf raw ∉ insert (G.groupKeyOf []) (G.groups right) := by
      simpa only [same] using member
    simp only [G.encode, dif_neg member, dif_neg member']

def adaptiveObserverKeys (constructor : Program (List Stage)) (n : Nat) :
    G.Key (adaptiveTerminalObserver constructor n) ≃ G.Key (adaptiveHistoryProgram constructor) :=
  groupKeysEquiv _ _ (adaptiveTerminalObserver_groups_eq constructor n)

theorem adaptiveObserver_encode_exact (constructor : Program (List Stage))
    (n : Nat) (raw : RawInput) :
    adaptiveObserverKeys constructor n
        (G.encode (adaptiveTerminalObserver constructor n) raw) =
      G.encode (adaptiveHistoryProgram constructor) raw := by
  exact groupKeysEquiv_encode_exact _ _
    (adaptiveTerminalObserver_groups_eq constructor n) raw

/-- The database is pulled back by the literal current-key equivalence;
every raw oracle reply is then identical, including the fallback branch. -/
theorem adaptiveObserver_claimOracle_exact (constructor : Program (List Stage))
    (n : Nat)
    (database : Database (G.Key (adaptiveHistoryProgram constructor)) (VectorOutput G.Counter))
    (fallback : RawDigest) :
    CR.claimOracle (adaptiveTerminalObserver constructor n)
        (fun key => database (adaptiveObserverKeys constructor n key)) fallback =
      CR.claimOracle (adaptiveHistoryProgram constructor) database fallback := by
  funext raw
  exact congrArg
    (fun key : G.Key (adaptiveHistoryProgram constructor) =>
      match database key with
      | none => fallback
      | some vector => G.decode raw vector)
    (adaptiveObserver_encode_exact constructor n raw)

theorem adaptiveObserver_keyBytes_exact (constructor : Program (List Stage)) (n : Nat)
    (key : G.Key (adaptiveTerminalObserver constructor n)) :
    G.keyBytes (adaptiveHistoryProgram constructor) (adaptiveObserverKeys constructor n key) =
      G.keyBytes (adaptiveTerminalObserver constructor n) key := rfl

theorem adaptiveObserver_role_exact (constructor : Program (List Stage)) (n : Nat)
    (role : SmzaChallengeStageTargets.Role) (key : G.Key (adaptiveTerminalObserver constructor n)) :
    RC.RoleActive role RC.currentRoleCaps (G.keyBytes (adaptiveHistoryProgram constructor))
      (adaptiveObserverKeys constructor n key) =
    RC.RoleActive role RC.currentRoleCaps (G.keyBytes (adaptiveTerminalObserver constructor n)) key := rfl

theorem adaptiveObserver_route_exact (constructor : Program (List Stage)) (n : Nat)
    (role : SmzaChallengeStageTargets.Role) (key : G.Key (adaptiveTerminalObserver constructor n)) :
    FT.routingTag role (G.keyBytes (adaptiveHistoryProgram constructor))
      (adaptiveObserverKeys constructor n key) =
    FT.routingTag role (G.keyBytes (adaptiveTerminalObserver constructor n)) key := rfl

theorem actual_history_reachable_subset (constructor : Program (List Stage))
    (oracle : Oracle) (stages : List Stage)
    (constructed : constructor.eval oracle = some stages) :
    reachable (historyProgram stages) ⊆ reachable (adaptiveHistoryProgram constructor) :=
  reachable_actual_suffix oracle constructor historyProgram stages constructed

private theorem current_groups_mono {α β : Type} (left : Program α) (right : Program β)
    (support : reachable left ⊆ reachable right) : G.groups left ⊆ G.groups right := by
  intro key member
  change key ∈ (reachable left).image G.groupKeyOf at member
  change key ∈ (reachable right).image G.groupKeyOf
  obtain ⟨raw, recorded, same⟩ := Finset.mem_image.mp member
  exact Finset.mem_image.mpr ⟨raw, support recorded, same⟩

def actualIndexedKeys (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) :
    G.Key (indexedStageVerifierProgram stages i) ↪ G.Key (adaptiveHistoryProgram constructor) where
  toFun := fun key => ⟨key.val, by
    rcases Finset.mem_insert.mp key.property with fallback | live
    · exact Finset.mem_insert.mpr (Or.inl fallback)
    · exact Finset.mem_insert_of_mem
        (current_groups_mono _ _
          ((indexedStage_reachable_subset stages i).trans
            (actual_history_reachable_subset constructor oracle stages constructed)) live)⟩
  inj' := by
    intro left right same
    apply Subtype.ext
    exact congrArg
      (fun key : G.Key (adaptiveHistoryProgram constructor) => key.val) same

theorem actualIndexed_keyBytes_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) (key : G.Key (indexedStageVerifierProgram stages i)) :
    G.keyBytes (adaptiveHistoryProgram constructor)
      (actualIndexedKeys constructor oracle stages constructed i key) =
    G.keyBytes (indexedStageVerifierProgram stages i) key := rfl

theorem actualIndexed_role_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) (role : SmzaChallengeStageTargets.Role)
    (key : G.Key (indexedStageVerifierProgram stages i)) :
    RC.RoleActive role RC.currentRoleCaps (G.keyBytes (adaptiveHistoryProgram constructor))
      (actualIndexedKeys constructor oracle stages constructed i key) =
    RC.RoleActive role RC.currentRoleCaps (G.keyBytes (indexedStageVerifierProgram stages i)) key := rfl

theorem actualIndexed_encode_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) (raw : RawInput)
    (reached : raw ∈ reachable (indexedStageVerifierProgram stages i)) :
    actualIndexedKeys constructor oracle stages constructed i
        (G.encode (indexedStageVerifierProgram stages i) raw) =
      G.encode (adaptiveHistoryProgram constructor) raw := by
  apply Subtype.ext
  change G.included (indexedStageVerifierProgram stages i)
      (G.encode (indexedStageVerifierProgram stages i) raw) =
    G.included (adaptiveHistoryProgram constructor) (G.encode (adaptiveHistoryProgram constructor) raw)
  rw [G.included_encode_of_reachable _ _ reached,
    G.included_encode_of_reachable _ _
      ((actual_history_reachable_subset constructor oracle stages constructed)
        (indexedStage_reachable_subset stages i reached))]

theorem actualIndexed_route_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) (role : SmzaChallengeStageTargets.Role)
    (key : G.Key (indexedStageVerifierProgram stages i)) :
    FT.routingTag role (G.keyBytes (adaptiveHistoryProgram constructor))
      (actualIndexedKeys constructor oracle stages constructed i key) =
    FT.routingTag role (G.keyBytes (indexedStageVerifierProgram stages i)) key := rfl

theorem indexedStage_eq_earlier_then_stage (stages : List Stage) (i : Fin stages.length) :
    indexedStageVerifierProgram stages i = sequentialUnitProgram
      (historyProgram (stages.take i.val)) (stageProgram stages[i.val]) := by
  rw [indexedStageVerifierProgram_eq_prefixAt]
  unfold historyPrefixAt
  rw [take_step_eq, historyProgram_append, historyProgram_singleton]

theorem accepted_history_retains_earlier (oracle : Oracle)
    (stages : List Stage) (i : Fin stages.length)
    (accepted : (historyProgram stages).eval oracle = some ()) :
    (historyProgram (stages.take i.val)).eval oracle = some () := by
  have acceptedSplit :
      (historyProgram (stages.take i.val ++ stages.drop i.val)).eval oracle = some () := by
    rw [List.take_append_drop]
    exact accepted
  exact accepted_history_retains_prefix oracle _ _ acceptedSplit

theorem accepted_history_retains_stage (oracle : Oracle)
    (stages : List Stage) (i : Fin stages.length)
    (accepted : (historyProgram stages).eval oracle = some ()) :
    (stageProgram stages[i.val]).eval oracle = some () := by
  obtain ⟨wire, _retained, verified, produced⟩ :=
    accepted_history_retains_indexed_stage oracle stages i accepted
  exact (eval_bind_some_iff oracle stages[i.val].proofProducer
    (E.verifierProgram stages[i.val].ns stages[i.val].relation false stages[i.val].nonce) ()).mpr
      ⟨wire, produced, verified⟩

theorem actual_stage_log_subset_history (oracle : Oracle)
    (stages : List Stage) (i : Fin stages.length)
    (accepted : (historyProgram stages).eval oracle = some ()) :
    ((stageProgram stages[i.val]).record oracle).2 ⊆
      ((historyProgram stages).record oracle).2 := by
  have earlierAccepted := accepted_history_retains_earlier oracle stages i accepted
  have included := Program.bind_log_right oracle (historyProgram (stages.take i.val))
    (fun _ => stageProgram stages[i.val]) () earlierAccepted
  change ((stageProgram stages[i.val]).record oracle).2 ⊆
    ((sequentialUnitProgram (historyProgram (stages.take i.val))
      (stageProgram stages[i.val])).record oracle).2 at included
  rw [← indexedStage_eq_earlier_then_stage] at included
  intro _call member
  exact indexed_stage_log_subset_history oracle stages i accepted (included member)

/-- The stage's all-answer support is retained because its earlier prefix
actually succeeds on this oracle. No caller support-inclusion field occurs. -/
theorem actualStage_reachable_subset (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (accepted : (historyProgram stages).eval oracle = some ()) (i : Fin stages.length) :
    reachable (stageProgram stages[i.val]) ⊆ reachable (adaptiveHistoryProgram constructor) := by
  have earlierAccepted := accepted_history_retains_earlier oracle stages i accepted
  have included := reachable_actual_suffix oracle (historyProgram (stages.take i.val))
    (fun _ => stageProgram stages[i.val]) () earlierAccepted
  change reachable (stageProgram stages[i.val]) ⊆
    reachable (sequentialUnitProgram (historyProgram (stages.take i.val))
      (stageProgram stages[i.val])) at included
  rw [← indexedStage_eq_earlier_then_stage] at included
  exact included.trans ((indexedStage_reachable_subset stages i).trans
    (actual_history_reachable_subset constructor oracle stages constructed))

def actualStageKeys (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (accepted : (historyProgram stages).eval oracle = some ()) (i : Fin stages.length) :
    G.Key (stageProgram stages[i.val]) ↪ G.Key (adaptiveHistoryProgram constructor) where
  toFun := fun key => ⟨key.val, by
    rcases Finset.mem_insert.mp key.property with fallback | live
    · exact Finset.mem_insert.mpr (Or.inl fallback)
    · exact Finset.mem_insert_of_mem
        (current_groups_mono _ _
          (actualStage_reachable_subset constructor oracle stages constructed accepted i) live)⟩
  inj' := by
    intro left right same
    apply Subtype.ext
    exact congrArg
      (fun key : G.Key (adaptiveHistoryProgram constructor) => key.val) same

theorem actualStage_keyBytes_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (accepted : (historyProgram stages).eval oracle = some ())
    (i : Fin stages.length) (key : G.Key (stageProgram stages[i.val])) :
    G.keyBytes (adaptiveHistoryProgram constructor)
      (actualStageKeys constructor oracle stages constructed accepted i key) =
    G.keyBytes (stageProgram stages[i.val]) key := rfl

theorem actualStage_role_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (accepted : (historyProgram stages).eval oracle = some ())
    (i : Fin stages.length) (role : SmzaChallengeStageTargets.Role)
    (key : G.Key (stageProgram stages[i.val])) :
    RC.RoleActive role RC.currentRoleCaps (G.keyBytes (adaptiveHistoryProgram constructor))
      (actualStageKeys constructor oracle stages constructed accepted i key) =
    RC.RoleActive role RC.currentRoleCaps (G.keyBytes (stageProgram stages[i.val])) key := rfl

theorem actualStage_route_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (accepted : (historyProgram stages).eval oracle = some ())
    (i : Fin stages.length) (role : SmzaChallengeStageTargets.Role)
    (key : G.Key (stageProgram stages[i.val])) :
    FT.routingTag role (G.keyBytes (adaptiveHistoryProgram constructor))
      (actualStageKeys constructor oracle stages constructed accepted i key) =
    FT.routingTag role (G.keyBytes (stageProgram stages[i.val])) key := rfl

theorem actualStage_encode_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (accepted : (historyProgram stages).eval oracle = some ())
    (i : Fin stages.length) (raw : RawInput)
    (reached : raw ∈ reachable (stageProgram stages[i.val])) :
    actualStageKeys constructor oracle stages constructed accepted i
        (G.encode (stageProgram stages[i.val]) raw) =
      G.encode (adaptiveHistoryProgram constructor) raw := by
  apply Subtype.ext
  change G.included (stageProgram stages[i.val]) (G.encode (stageProgram stages[i.val]) raw) =
    G.included (adaptiveHistoryProgram constructor) (G.encode (adaptiveHistoryProgram constructor) raw)
  rw [G.included_encode_of_reachable _ _ reached,
    G.included_encode_of_reachable _ _
      (actualStage_reachable_subset constructor oracle stages constructed accepted i reached)]

/-- Internal reconstruction uses the vector actually stored at each queried
raw input. The eventual public theorem derives these stores from the original
global branch claims; neither a stage branch nor an inclusion is supplied. -/
private theorem actual_branch_of_recorded_vectors {α : Type} (program : Program α)
    (oracle : Oracle) (read : RawInput → Option (VectorOutput G.Counter))
    (stored : ∀ raw, (raw, oracle raw) ∈ (program.record oracle).2 →
      ∃ vector, read raw = some vector ∧ G.decode raw vector = oracle raw) :
    ∃ branch : Branches G.decode program,
      branchResult G.decode program branch = program.eval oracle ∧
      rawLog G.decode program branch = (program.record oracle).2 ∧
      ∀ call ∈ answerLog G.decode program branch, read call.1 = some call.2 := by
  induction program with
  | done result =>
      refine ⟨PUnit.unit, rfl, rfl, ?_⟩
      intro call member
      cases member
  | read raw next ih =>
      obtain ⟨vector, headStored, decoded⟩ := stored raw
        (List.mem_cons_self (a := (raw, oracle raw))
          (l := ((next (oracle raw)).record oracle).2))
      have tailStored : ∀ input,
          (input, oracle input) ∈ ((next (G.decode raw vector)).record oracle).2 →
          ∃ answer, read input = some answer ∧ G.decode input answer = oracle input := by
        intro input member
        apply stored input
        change (input, oracle input) ∈
          (raw, oracle raw) :: ((next (oracle raw)).record oracle).2
        exact List.mem_cons_of_mem _ (by simpa only [decoded] using member)
      obtain ⟨tail, tailResult, tailLog, tailCells⟩ := ih (G.decode raw vector) tailStored
      refine ⟨⟨vector, tail⟩, ?_, ?_, ?_⟩
      · change branchResult G.decode (next (G.decode raw vector)) tail =
          (next (oracle raw)).eval oracle
        exact tailResult.trans (by rw [decoded])
      · change (raw, G.decode raw vector) :: rawLog G.decode (next (G.decode raw vector)) tail =
          (raw, oracle raw) :: ((next (oracle raw)).record oracle).2
        rw [tailLog, decoded]
      · intro call member
        change call ∈ (raw, vector) :: answerLog G.decode (next (G.decode raw vector)) tail at member
        rcases List.mem_cons.mp member with head | below
        · cases head
          exact headStored
        · exact tailCells call below

private theorem global_raw_record_has_stored_vector (constructor : Program (List Stage))
    (branch : Branches G.decode (adaptiveHistoryProgram constructor))
    (database : Database (G.Key (adaptiveHistoryProgram constructor)) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (CR.fullClaims (adaptiveHistoryProgram constructor) branch) database)
    (fallback : RawDigest) (raw : RawInput)
    (recorded : (raw, CR.claimOracle (adaptiveHistoryProgram constructor) database fallback raw) ∈
      rawLog G.decode (adaptiveHistoryProgram constructor) branch) :
    ∃ vector, database (G.encode (adaptiveHistoryProgram constructor) raw) = some vector ∧
      G.decode raw vector = CR.claimOracle (adaptiveHistoryProgram constructor) database fallback raw := by
  change (raw, CR.claimOracle (adaptiveHistoryProgram constructor) database fallback raw) ∈
    (answerLog G.decode (adaptiveHistoryProgram constructor) branch).map
      (fun call => (call.1, G.decode call.1 call.2)) at recorded
  obtain ⟨⟨input, vector⟩, member, same⟩ := List.mem_map.mp recorded
  have inputEq : input = raw := congrArg Prod.fst same
  subst input
  exact ⟨vector, CR.current_claims_store_every_branch_vector _ _ database claims
    (raw, vector) member, congrArg Prod.snd same⟩

/-- A genuine accepted global branch determines every stage branch, its
whole-vector claims on the SAME final database and its exact literal log.
No stage branch, event inclusion or selected-stage certificate is an input. -/
theorem current_accepted_adaptive_branch_has_actual_stage_branches_and_claims
    (constructor : Program (List Stage))
    (branch : Branches G.decode (adaptiveHistoryProgram constructor))
    (database : Database (G.Key (adaptiveHistoryProgram constructor)) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (CR.fullClaims (adaptiveHistoryProgram constructor) branch) database)
    (accepted : branchResult G.decode (adaptiveHistoryProgram constructor) branch = some ())
    (fallback : RawDigest) :
    let oracle := CR.claimOracle (adaptiveHistoryProgram constructor) database fallback
    ∃ (stages : List Stage) (constructed : constructor.eval oracle = some stages)
      (historyAccepted : (historyProgram stages).eval oracle = some ()),
      ∀ i : Fin stages.length, ∃ stageBranch : Branches G.decode (stageProgram stages[i.val]),
        branchResult G.decode (stageProgram stages[i.val]) stageBranch = some () ∧
        rawLog G.decode (stageProgram stages[i.val]) stageBranch ⊆
          rawLog G.decode (adaptiveHistoryProgram constructor) branch ∧
        rawLog G.decode (stageProgram stages[i.val]) stageBranch =
          ((stageProgram stages[i.val]).record oracle).2 ∧
        ClaimsDatabaseEvent (CR.fullClaims (stageProgram stages[i.val]) stageBranch)
          (fun key => database (actualStageKeys constructor oracle stages constructed historyAccepted i key)) ∧
        (stageProgram stages[i.val]).record
            (CR.claimOracle (stageProgram stages[i.val])
              (fun key => database (actualStageKeys constructor oracle stages constructed historyAccepted i key))
              fallback) =
          (stageProgram stages[i.val]).record oracle := by
  let oracle := CR.claimOracle (adaptiveHistoryProgram constructor) database fallback
  have replay := CR.current_grouped_claims_replay_actual_program
    (adaptiveHistoryProgram constructor) branch database claims fallback
  have ordinary : (adaptiveHistoryProgram constructor).eval oracle = some () :=
    (Program.record_result oracle _).symm.trans ((congrArg Prod.fst replay).trans accepted)
  obtain ⟨stages, constructed, historyAccepted⟩ :=
    (eval_bind_some_iff oracle constructor historyProgram ()).mp ordinary
  refine ⟨stages, constructed, historyAccepted, ?_⟩
  intro i
  have globalRecord : ((adaptiveHistoryProgram constructor).record oracle).2 =
      rawLog G.decode (adaptiveHistoryProgram constructor) branch := congrArg Prod.snd replay
  have stageSubset : ((stageProgram stages[i.val]).record oracle).2 ⊆
      ((adaptiveHistoryProgram constructor).record oracle).2 := by
    intro _call member
    exact Program.bind_log_right oracle constructor historyProgram stages constructed
      (actual_stage_log_subset_history oracle stages i historyAccepted member)
  rw [globalRecord] at stageSubset
  have vectors : ∀ raw, (raw, oracle raw) ∈ ((stageProgram stages[i.val]).record oracle).2 →
      ∃ vector, database (G.encode (adaptiveHistoryProgram constructor) raw) = some vector ∧
        G.decode raw vector = oracle raw := by
    intro raw member
    exact global_raw_record_has_stored_vector constructor branch database claims fallback raw
      (stageSubset member)
  obtain ⟨stageBranch, stageResult, stageLog, stageCells⟩ :=
    actual_branch_of_recorded_vectors (stageProgram stages[i.val]) oracle
      (fun raw => database (G.encode (adaptiveHistoryProgram constructor) raw)) vectors
  have localClaims : ClaimsDatabaseEvent (CR.fullClaims (stageProgram stages[i.val]) stageBranch)
      (fun key => database (actualStageKeys constructor oracle stages constructed historyAccepted i key)) := by
    intro claim member
    rw [CR.fullClaims, branch_claims_eq_answer_log] at member
    obtain ⟨call, logged, same⟩ := List.mem_map.mp member
    cases same
    change database (actualStageKeys constructor oracle stages constructed historyAccepted i
      (G.encode (stageProgram stages[i.val]) call.1)) = some call.2
    rw [actualStage_encode_exact constructor oracle stages constructed historyAccepted i call.1
      (SmzaRp05CurrentFiniteGroupedProgram.answer_log_input_reachable G.decode _ stageBranch call logged)]
    exact stageCells call logged
  refine ⟨stageBranch,
    stageResult.trans (accepted_history_retains_stage oracle stages i historyAccepted), ?_,
    stageLog, localClaims, ?_⟩
  · rw [stageLog]
    exact stageSubset
  · have localReplay := CR.current_grouped_claims_replay_actual_program
      (stageProgram stages[i.val]) stageBranch _ localClaims fallback
    have originalReplay : (stageProgram stages[i.val]).record oracle =
        (branchResult G.decode (stageProgram stages[i.val]) stageBranch,
          rawLog G.decode (stageProgram stages[i.val]) stageBranch) := by
      apply Prod.ext
      · exact (Program.record_result oracle _).trans stageResult.symm
      · exact stageLog.symm
    exact localReplay.trans originalReplay.symm

/-- Same actual adaptive branch supplies its returned list and every indexed
wire; the literal verifier log lies in that branch's complete raw log. -/
theorem current_accepted_adaptive_branch_has_actual_stages_and_rawlog
    (constructor : Program (List Stage))
    (branch : Branches G.decode (adaptiveHistoryProgram constructor))
    (database : Database (G.Key (adaptiveHistoryProgram constructor)) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (CR.fullClaims (adaptiveHistoryProgram constructor) branch) database)
    (accepted : branchResult G.decode (adaptiveHistoryProgram constructor) branch = some ())
    (fallback : RawDigest) :
    let oracle := CR.claimOracle (adaptiveHistoryProgram constructor) database fallback
    ∃ stages, constructor.eval oracle = some stages ∧
      (historyProgram stages).eval oracle = some () ∧
      ∀ i : Fin stages.length, ∃ wire,
        (retainedPrefixAt stages i).eval oracle = some wire ∧
        stages[i.val].proofProducer.eval oracle = some wire ∧
        (stageVerifierAt stages i wire).eval oracle = some () ∧
        ((indexedStageVerifierProgram stages i).record oracle).2 ⊆
          rawLog G.decode (adaptiveHistoryProgram constructor) branch ∧
        ((stageVerifierAt stages i wire).record oracle).2 ⊆
          rawLog G.decode (adaptiveHistoryProgram constructor) branch := by
  let oracle := CR.claimOracle (adaptiveHistoryProgram constructor) database fallback
  have replay := CR.current_grouped_claims_replay_actual_program
    (adaptiveHistoryProgram constructor) branch database claims fallback
  have ordinary : (adaptiveHistoryProgram constructor).eval oracle = some () :=
    (Program.record_result oracle _).symm.trans ((congrArg Prod.fst replay).trans accepted)
  obtain ⟨stages, constructed, historyAccepted⟩ :=
    (eval_bind_some_iff oracle constructor historyProgram ()).mp ordinary
  refine ⟨stages, constructed, historyAccepted, ?_⟩
  intro i
  obtain ⟨wire, retained, verified, produced⟩ :=
    accepted_history_retains_indexed_stage oracle stages i historyAccepted
  have globalRecord : ((adaptiveHistoryProgram constructor).record oracle).2 =
      rawLog G.decode (adaptiveHistoryProgram constructor) branch := congrArg Prod.snd replay
  have prefixSubset : ((indexedStageVerifierProgram stages i).record oracle).2 ⊆
      ((adaptiveHistoryProgram constructor).record oracle).2 := by
    intro _call member
    exact Program.bind_log_right oracle constructor historyProgram stages constructed
      (indexed_stage_log_subset_history oracle stages i historyAccepted member)
  have verifierSubset : ((stageVerifierAt stages i wire).record oracle).2 ⊆
      ((adaptiveHistoryProgram constructor).record oracle).2 := by
    intro _call member
    exact prefixSubset
      (Program.bind_log_right oracle (retainedPrefixAt stages i)
        (stageVerifierAt stages i) wire retained member)
  rw [globalRecord] at prefixSubset verifierSubset
  exact ⟨wire, retained, produced, verified, prefixSubset, verifierSubset⟩

/-- Logical terminal replay in the literal producer/verifier shape consumed
by the current source classifier. The original adaptive program is retained. -/
def actualTerminalProducer (constructor : Program (List Stage))
    (stages : List Stage) (i : Fin stages.length) : Program E.Wire :=
  (adaptiveHistoryProgram constructor).bind fun _ => retainedPrefixAt stages i

def actualTerminalRoot (constructor : Program (List Stage))
    (stages : List Stage) (i : Fin stages.length) : Program Unit :=
  (actualTerminalProducer constructor stages i).bind (stageVerifierAt stages i)

theorem actualTerminalRoot_eq_global_then_indexed (constructor : Program (List Stage))
    (stages : List Stage) (i : Fin stages.length) :
    actualTerminalRoot constructor stages i = (adaptiveHistoryProgram constructor).bind
      (fun _ => indexedStageVerifierProgram stages i) :=
  bind_assoc _ _ _

theorem actualTerminalRoot_reachable_eq (constructor : Program (List Stage))
    (oracle : Oracle) (stages : List Stage)
    (constructed : constructor.eval oracle = some stages) (i : Fin stages.length) :
    reachable (actualTerminalRoot constructor stages i) =
      reachable (adaptiveHistoryProgram constructor) := by
  rw [actualTerminalRoot_eq_global_then_indexed]
  exact reachable_constant_bind_eq _ _ ((indexedStage_reachable_subset stages i).trans
    (actual_history_reachable_subset constructor oracle stages constructed))

theorem actualTerminalRoot_groups_eq (constructor : Program (List Stage))
    (oracle : Oracle) (stages : List Stage)
    (constructed : constructor.eval oracle = some stages) (i : Fin stages.length) :
    G.groups (actualTerminalRoot constructor stages i) = G.groups (adaptiveHistoryProgram constructor) := by
  unfold G.groups
  rw [actualTerminalRoot_reachable_eq constructor oracle stages constructed i]

def actualTerminalKeys (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) :
    G.Key (actualTerminalRoot constructor stages i) ≃ G.Key (adaptiveHistoryProgram constructor) :=
  groupKeysEquiv _ _ (actualTerminalRoot_groups_eq constructor oracle stages constructed i)

theorem actualTerminal_encode_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) (raw : RawInput) :
    actualTerminalKeys constructor oracle stages constructed i
        (G.encode (actualTerminalRoot constructor stages i) raw) =
      G.encode (adaptiveHistoryProgram constructor) raw := by
  exact groupKeysEquiv_encode_exact _ _
    (actualTerminalRoot_groups_eq constructor oracle stages constructed i) raw

theorem actualTerminal_keyBytes_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) (key : G.Key (actualTerminalRoot constructor stages i)) :
    G.keyBytes (adaptiveHistoryProgram constructor)
      (actualTerminalKeys constructor oracle stages constructed i key) =
    G.keyBytes (actualTerminalRoot constructor stages i) key := rfl

theorem actualTerminal_role_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) (role : SmzaChallengeStageTargets.Role)
    (key : G.Key (actualTerminalRoot constructor stages i)) :
    RC.RoleActive role RC.currentRoleCaps (G.keyBytes (adaptiveHistoryProgram constructor))
      (actualTerminalKeys constructor oracle stages constructed i key) =
    RC.RoleActive role RC.currentRoleCaps (G.keyBytes (actualTerminalRoot constructor stages i)) key := rfl

theorem actualTerminal_route_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length) (role : SmzaChallengeStageTargets.Role)
    (key : G.Key (actualTerminalRoot constructor stages i)) :
    FT.routingTag role (G.keyBytes (adaptiveHistoryProgram constructor))
      (actualTerminalKeys constructor oracle stages constructed i key) =
    FT.routingTag role (G.keyBytes (actualTerminalRoot constructor stages i)) key := rfl

theorem actualTerminal_claimOracle_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length)
    (database : Database (G.Key (adaptiveHistoryProgram constructor)) (VectorOutput G.Counter))
    (fallback : RawDigest) :
    CR.claimOracle (actualTerminalRoot constructor stages i)
        (fun key => database (actualTerminalKeys constructor oracle stages constructed i key)) fallback =
      CR.claimOracle (adaptiveHistoryProgram constructor) database fallback := by
  funext raw
  exact congrArg
    (fun key : G.Key (adaptiveHistoryProgram constructor) =>
      match database key with
      | none => fallback
      | some vector => G.decode raw vector)
    (actualTerminal_encode_exact constructor oracle stages constructed i raw)

/-- All stored raw source records, including cells predating this history,
are preserved by the exact current-key equivalence. Applying sourceRecords
to both sides therefore preserves the classifier's entire canonical source. -/
theorem actualTerminal_rawRecords_exact (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length)
    (database : Database (G.Key (adaptiveHistoryProgram constructor)) (VectorOutput G.Counter)) :
    rawRecords (G.keyBytes (actualTerminalRoot constructor stages i)) (vectorOutputBytes G.zero)
        (fun key => database (actualTerminalKeys constructor oracle stages constructed i key)) =
      rawRecords (G.keyBytes (adaptiveHistoryProgram constructor)) (vectorOutputBytes G.zero) database := by
  apply Finset.ext
  intro pair
  rcases pair with ⟨input, digest⟩
  constructor
  · intro member
    obtain ⟨key, vector, stored, inputEq, digestEq⟩ := (mem_raw_records_iff _ _ _ _ _).mp member
    exact (mem_raw_records_iff _ _ _ _ _).mpr
      ⟨actualTerminalKeys constructor oracle stages constructed i key, vector, stored,
        (actualTerminal_keyBytes_exact constructor oracle stages constructed i key).trans inputEq, digestEq⟩
  · intro member
    obtain ⟨key, vector, stored, inputEq, digestEq⟩ := (mem_raw_records_iff _ _ _ _ _).mp member
    let earlier := (actualTerminalKeys constructor oracle stages constructed i).symm key
    have back : actualTerminalKeys constructor oracle stages constructed i earlier = key :=
      (actualTerminalKeys constructor oracle stages constructed i).apply_symm_apply key
    apply (mem_raw_records_iff _ _ _ _ _).mpr
    refine ⟨earlier, vector, ?_, ?_, digestEq⟩
    · rw [back]
      exact stored
    · rw [← actualTerminal_keyBytes_exact constructor oracle stages constructed i earlier, back]
      exact inputEq

theorem actualTerminalRoot_eval (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length)
    (accepted : (adaptiveHistoryProgram constructor).eval oracle = some ()) :
    (actualTerminalRoot constructor stages i).eval oracle = some () := by
  have historyAccepted : (historyProgram stages).eval oracle = some () := by
    simpa only [adaptiveHistoryProgram, Program.eval_bind, constructed, Option.bind_some] using accepted
  obtain ⟨wire, retained, verified, _produced⟩ :=
    accepted_history_retains_indexed_stage oracle stages i historyAccepted
  have indexedAccepted : (indexedStageVerifierProgram stages i).eval oracle = some () :=
    (eval_bind_some_iff oracle (retainedPrefixAt stages i) (stageVerifierAt stages i) ()).mpr
      ⟨wire, retained, verified⟩
  rw [actualTerminalRoot_eq_global_then_indexed, Program.eval_bind, accepted, Option.bind_some]
  exact indexedAccepted

/-- Every replay record is literally an already recorded global call. The
original program stays the physical carrier; this logical root is not run. -/
theorem actualTerminalRoot_record_finset_eq (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (constructed : constructor.eval oracle = some stages)
    (i : Fin stages.length)
    (accepted : (adaptiveHistoryProgram constructor).eval oracle = some ()) :
    ((actualTerminalRoot constructor stages i).record oracle).2.toFinset =
      ((adaptiveHistoryProgram constructor).record oracle).2.toFinset := by
  have historyAccepted : (historyProgram stages).eval oracle = some () := by
    simpa only [adaptiveHistoryProgram, Program.eval_bind, constructed, Option.bind_some] using accepted
  have included : ((indexedStageVerifierProgram stages i).record oracle).2 ⊆
      ((adaptiveHistoryProgram constructor).record oracle).2 := by
    intro _call member
    exact Program.bind_log_right oracle constructor historyProgram stages constructed
      (indexed_stage_log_subset_history oracle stages i historyAccepted member)
  rw [actualTerminalRoot_eq_global_then_indexed,
    Program.record_bind_success oracle _ _ () accepted]
  apply Finset.ext
  intro call
  simp only [List.mem_toFinset, List.mem_append]
  constructor
  · rintro (before | replay)
    · exact before
    · exact included replay
  · intro before
    exact Or.inl before

/-- Rejection remains fail-fast before the logical fixed-stage replay. -/
theorem actualTerminalRoot_record_rejected (constructor : Program (List Stage)) (oracle : Oracle)
    (stages : List Stage) (i : Fin stages.length)
    (rejected : (adaptiveHistoryProgram constructor).eval oracle = none) :
    (actualTerminalRoot constructor stages i).record oracle =
      (none, ((adaptiveHistoryProgram constructor).record oracle).2) := by
  rw [actualTerminalRoot_eq_global_then_indexed]
  exact record_bind_rejected oracle _ _ rejected

/-- The SAME global recorded source is presented to the current G3 root.
Its accepted branch and fullClaims are constructed from the original branch's
stored vectors. Key/oracle reindexing is exact over the entire universe,
including complement/fallback keys. No physical observer run is introduced. -/
theorem current_accepted_adaptive_branch_has_same_global_source_observers
    (constructor : Program (List Stage))
    (branch : Branches G.decode (adaptiveHistoryProgram constructor))
    (database : Database (G.Key (adaptiveHistoryProgram constructor)) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (CR.fullClaims (adaptiveHistoryProgram constructor) branch) database)
    (accepted : branchResult G.decode (adaptiveHistoryProgram constructor) branch = some ())
    (fallback : RawDigest) :
    let oracle := CR.claimOracle (adaptiveHistoryProgram constructor) database fallback
    ∃ (stages : List Stage) (constructed : constructor.eval oracle = some stages)
      (_historyAccepted : (historyProgram stages).eval oracle = some ()),
      ∀ i : Fin stages.length, ∃ observerBranch : Branches G.decode (actualTerminalRoot constructor stages i),
        branchResult G.decode (actualTerminalRoot constructor stages i) observerBranch = some () ∧
        (rawLog G.decode (actualTerminalRoot constructor stages i) observerBranch).toFinset =
          (rawLog G.decode (adaptiveHistoryProgram constructor) branch).toFinset ∧
        ClaimsDatabaseEvent (CR.fullClaims (actualTerminalRoot constructor stages i) observerBranch)
          (fun key => database (actualTerminalKeys constructor oracle stages constructed i key)) ∧
        (actualTerminalRoot constructor stages i).record
            (CR.claimOracle (actualTerminalRoot constructor stages i)
              (fun key => database (actualTerminalKeys constructor oracle stages constructed i key)) fallback) =
          (some (), rawLog G.decode (actualTerminalRoot constructor stages i) observerBranch) := by
  let oracle := CR.claimOracle (adaptiveHistoryProgram constructor) database fallback
  have replay := CR.current_grouped_claims_replay_actual_program
    (adaptiveHistoryProgram constructor) branch database claims fallback
  have ordinary : (adaptiveHistoryProgram constructor).eval oracle = some () :=
    (Program.record_result oracle _).symm.trans ((congrArg Prod.fst replay).trans accepted)
  obtain ⟨stages, constructed, historyAccepted⟩ :=
    (eval_bind_some_iff oracle constructor historyProgram ()).mp ordinary
  refine ⟨stages, constructed, historyAccepted, ?_⟩
  intro i
  have globalRecord : ((adaptiveHistoryProgram constructor).record oracle).2 =
      rawLog G.decode (adaptiveHistoryProgram constructor) branch := congrArg Prod.snd replay
  have observerRecord := actualTerminalRoot_record_finset_eq constructor oracle stages constructed i ordinary
  rw [globalRecord] at observerRecord
  have vectors : ∀ raw, (raw, oracle raw) ∈ ((actualTerminalRoot constructor stages i).record oracle).2 →
      ∃ vector, database (G.encode (adaptiveHistoryProgram constructor) raw) = some vector ∧
        G.decode raw vector = oracle raw := by
    intro raw member
    apply global_raw_record_has_stored_vector constructor branch database claims fallback raw
    exact List.mem_toFinset.mp (by rw [← observerRecord]; exact List.mem_toFinset.mpr member)
  obtain ⟨observerBranch, observerResult, observerLog, observerCells⟩ :=
    actual_branch_of_recorded_vectors (actualTerminalRoot constructor stages i) oracle
      (fun raw => database (G.encode (adaptiveHistoryProgram constructor) raw)) vectors
  have observerAccepted : branchResult G.decode (actualTerminalRoot constructor stages i) observerBranch = some () :=
    observerResult.trans (actualTerminalRoot_eval constructor oracle stages constructed i ordinary)
  have observerClaims : ClaimsDatabaseEvent (CR.fullClaims (actualTerminalRoot constructor stages i) observerBranch)
      (fun key => database (actualTerminalKeys constructor oracle stages constructed i key)) := by
    intro claim member
    rw [CR.fullClaims, branch_claims_eq_answer_log] at member
    obtain ⟨call, logged, same⟩ := List.mem_map.mp member
    cases same
    change database (actualTerminalKeys constructor oracle stages constructed i
      (G.encode (actualTerminalRoot constructor stages i) call.1)) = some call.2
    rw [actualTerminal_encode_exact]
    exact observerCells call logged
  refine ⟨observerBranch, observerAccepted, ?_, observerClaims, ?_⟩
  · rw [observerLog]
    exact observerRecord
  · have recorded := CR.current_grouped_claims_replay_actual_program
      (actualTerminalRoot constructor stages i) observerBranch _ observerClaims fallback
    rw [observerAccepted] at recorded
    exact recorded

private theorem current_recorded_path_mono
    (left right : SmzaRp05FilteredDecoderInstability.RawRecords) (included : left ⊆ right)
    (parserStage : V8SmzaOracleParser.Stage) (target : RawDigest) (path : List Nat) (input : RawInput)
    (recorded : SmzaRecordedTracePath.RecordedPath
      NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext left parserStage target path input) :
    SmzaRecordedTracePath.RecordedPath
      NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext right parserStage target path input := by
  induction recorded with
  | here stage target input member valid =>
      exact SmzaRecordedTracePath.RecordedPath.here stage target input (included member) valid
  | step stage target input edges index childStage childTarget rest leaf member parsed edge below ih =>
      exact SmzaRecordedTracePath.RecordedPath.step stage target input edges index childStage childTarget
        rest leaf (included member) parsed edge ih

/-- In the collision-free global case, every actual local current path keeps
its literal readback globally. This does not assert equality of incomplete
local and global extraction trees; extra global records can fill missing cuts.
The FPP conclusion invokes the retained CURRENT frame/trace readback directly. -/
theorem current_accepted_adaptive_branch_lifts_current_trace_readback
    (constructor : Program (List Stage))
    (branch : Branches G.decode (adaptiveHistoryProgram constructor))
    (database : Database (G.Key (adaptiveHistoryProgram constructor)) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (CR.fullClaims (adaptiveHistoryProgram constructor) branch) database)
    (accepted : branchResult G.decode (adaptiveHistoryProgram constructor) branch = some ())
    (fallback : RawDigest)
    (free : SmzaRecordedTracePath.RecordsCollisionFree
      (rawLog G.decode (adaptiveHistoryProgram constructor) branch).toFinset) :
    let oracle := CR.claimOracle (adaptiveHistoryProgram constructor) database fallback
    ∃ stages, constructor.eval oracle = some stages ∧
      (historyProgram stages).eval oracle = some () ∧
      ∀ i : Fin stages.length,
        (∀ (parserStage : V8SmzaOracleParser.Stage) (target : RawDigest)
            (path : List Nat) (input : RawInput),
          SmzaRecordedTracePath.RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
            ((stageProgram stages[i.val]).record oracle).2.toFinset parserStage target path input →
          ∀ (fuel : Nat), path.length < fuel →
            SmzaRecordedTracePath.readPath path
              (V8Smz9CoherentMerkleGeometry.extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
                (rawLog G.decode (adaptiveHistoryProgram constructor) branch).toFinset fuel parserStage target) =
              some input) ∧
        (∀ (input : RawInput) (target root : RawDigest),
          (input, target) ∈ ((stageProgram stages[i.val]).record oracle).2.toFinset →
          NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext .fpp input = some [(.root, root)] →
          V8Smz9CoherentMerkleGeometry.extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
              (rawLog G.decode (adaptiveHistoryProgram constructor) branch).toFinset 26 .fpp target =
            .record input [V8Smz9CoherentMerkleGeometry.extract
              NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
              (rawLog G.decode (adaptiveHistoryProgram constructor) branch).toFinset 25 .root root]) := by
  let oracle := CR.claimOracle (adaptiveHistoryProgram constructor) database fallback
  have replay := CR.current_grouped_claims_replay_actual_program
    (adaptiveHistoryProgram constructor) branch database claims fallback
  have ordinary : (adaptiveHistoryProgram constructor).eval oracle = some () :=
    (Program.record_result oracle _).symm.trans ((congrArg Prod.fst replay).trans accepted)
  obtain ⟨stages, constructed, historyAccepted⟩ :=
    (eval_bind_some_iff oracle constructor historyProgram ()).mp ordinary
  refine ⟨stages, constructed, historyAccepted, ?_⟩
  intro i
  have stageSubset : ((stageProgram stages[i.val]).record oracle).2 ⊆
      ((adaptiveHistoryProgram constructor).record oracle).2 := by
    intro _call member
    exact Program.bind_log_right oracle constructor historyProgram stages constructed
      (actual_stage_log_subset_history oracle stages i historyAccepted member)
  rw [congrArg Prod.snd replay] at stageSubset
  have recordsSubset : ((stageProgram stages[i.val]).record oracle).2.toFinset ⊆
      (rawLog G.decode (adaptiveHistoryProgram constructor) branch).toFinset := by
    intro call member
    exact List.mem_toFinset.mpr (stageSubset (List.mem_toFinset.mp member))
  constructor
  · intro parserStage target path input recorded fuel enough
    exact SmzaRecordedTracePath.recorded_path_readback _ _ free parserStage target path input
      (current_recorded_path_mono _ _ recordsSubset parserStage target path input recorded) fuel enough
  · intro input target root recorded edge
    exact TR.recorded_current_fpp_trace_readback _ free input target root (recordsSubset recorded) edge

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalRawLogTransport
