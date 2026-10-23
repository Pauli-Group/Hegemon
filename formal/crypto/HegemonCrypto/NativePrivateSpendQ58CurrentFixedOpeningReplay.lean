import HegemonCrypto.NativePrivateSpendQ58CurrentActiveBranchClaims

/-! Current first-valid16 opening replay on the same selected-role fiber.
The opening is calculated by CurrentExecutableVerifier.canonicalOpening,
including its capped field scan, nonce comparison and repeated selected read.
Every oracle equality below is derived from that literal record's call shapes,
the current constructor's recorded base parser, and same-branch fixed/active
claims. No Opening, per-key oracle agreement, or legacy profile is supplied.
SOURCE ONLY: no compiler receipt, DECS density, physical mass or G3 PASS. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFixedOpeningReplay

open SmzaRp05ExecutableMerkleVerifier (Program Oracle Log)
open SmzaRp05ExecutableChallengeStage
  (FieldWord fieldLoop scan returnedWords pendingFailure field_loop_executes_scan callCap)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog rawLog branchResult)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaChallengeStageTargets (Role)
open scoped Classical

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire Opening Transcript ExecutionStages decodeOpeningWords fieldKeys fieldXof
   openingAttempt openingScan canonicalOpening verifierProgram accepted_execution_has_stages)
end E
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (RawInput RawDigest Counter Key encode decode keyBytes frame nonceValue
   frame_is_literal_current recorded_current_base_parser)
end G
namespace B
export NativePrivateSpendQ58CurrentActiveBranchClaims
  (live activeClaims fixedCompatible current_active_claims_replay_same_program)
end B
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey merge)
end A
namespace T
export NativePrivateSpendQ58PartitionTransport (FixedTable)
end T
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay (claimOracle)
end Q
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier
  (RoleActive canonicalCurrentQueryBytes other_bounded_role_is_fixed)
end C
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate
  (preMatrixLog stages_verifier_has_pre_matrix_log)
end S
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end M
namespace P
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end P

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev FullProgram (producer : Program E.Wire) (ns : M.Namespace)
    (relation : P.Relation) (pending : Bool) (nonce : Fin (2 ^ 32)) :=
  producer.bind (E.verifierProgram ns relation pending nonce)

/-- Literal current role caps; the source opening sampler has five raw calls. -/
def currentCaps : Role → Nat
  | .decsMatrix => callCap 700
  | .piopMatrix => callCap 6722970
  | .piopOpening => callCap 6
  | .decsSample => callCap 80

theorem current_opening_cap : currentCaps .piopOpening = 5 := by decide

/-- A deterministic fixed-other-role oracle. Active keys use only fallback;
inactive keys read their actual fixed cell and actual coordinate decoder. -/
def fixedOracle {Result : Type} (program : Program Result) (selected : Role)
    (caps : Role → Nat)
    (fixed : T.FixedTable (Counter := G.Counter) (B.live program selected caps))
    (fallback : G.RawDigest) : Oracle := fun raw =>
  if inactive : ¬B.live program selected caps (G.encode program raw) then
    G.decode raw (fixed ⟨G.encode program raw, inactive⟩)
  else fallback

/-- Calculated current Opening. The argument list has no active database,
accepted Opening or first-nonce distribution assumption. -/
def fixedOpening {Result : Type} (program : Program Result) (selected : Role)
    (caps : Role → Nat)
    (fixed : T.FixedTable (Counter := G.Counter) (B.live program selected caps))
    (fallback : G.RawDigest) (nonce : Fin (2 ^ 32)) (digest : G.RawDigest) :
    Option E.Opening :=
  ((E.canonicalOpening false nonce digest).eval
    (fixedOracle program selected caps fixed fallback)).map Prod.fst

def attemptedOpening (oracle : Oracle) (digest : G.RawDigest) (nonce : Nat) :
    Option E.Opening :=
  E.decodeOpeningWords (returnedWords 6 (scan oracle 6 []
    (E.fieldKeys .piopOpening 6 digest nonce)))

theorem opening_attempt_exact (pending : Bool) (digest : G.RawDigest)
    (nonce : Nat) (oracle : Oracle) :
    (E.openingAttempt pending digest nonce).eval oracle =
      some (attemptedOpening oracle digest nonce,
        pendingFailure pending (scan oracle 6 [] (E.fieldKeys .piopOpening 6 digest nonce))) := by
  simp only [E.openingAttempt, E.fieldXof, Program.eval_bind,
    field_loop_executes_scan, Option.bind_some, Program.eval, attemptedOpening]

/-- Exact current first-valid evidence, including the repeated selected
nonce. Rejected words and exhausted samples are still source data here. -/
def FirstValid16 (oracle : Oracle) (nonce : Fin (2 ^ 32)) (digest : G.RawDigest)
    (opening : E.Opening) (finalPending : Bool) : Prop :=
  ∃ before after scanPending,
    List.range 16 = before ++ nonce.val :: after ∧
    (∀ earlier ∈ before, attemptedOpening oracle digest earlier = none) ∧
    attemptedOpening oracle digest nonce.val = some opening ∧
    (E.openingAttempt scanPending digest nonce.val).eval oracle =
      some (some opening, finalPending)

private theorem opening_scan_cons (digest : G.RawDigest) (nonce : Nat)
    (rest : List Nat) (pending : Bool) :
    E.openingScan digest (nonce :: rest) pending =
      (E.openingAttempt pending digest nonce).bind
        (fun (result, nextPending) =>
          match result with
          | none => E.openingScan digest rest nextPending
          | some points => .done (some (nonce, points, nextPending))) := rfl

private theorem opening_scan_first_valid (digest : G.RawDigest) (nonces : List Nat)
    (pending : Bool) (oracle : Oracle) (selected : Nat) (opening : E.Opening)
    (finalPending : Bool)
    (executed : (E.openingScan digest nonces pending).eval oracle =
      some (selected, opening, finalPending)) :
    ∃ before after, nonces = before ++ selected :: after ∧
      (∀ earlier ∈ before, attemptedOpening oracle digest earlier = none) ∧
      attemptedOpening oracle digest selected = some opening := by
  induction nonces generalizing pending with
  | nil => simp [E.openingScan, Program.eval] at executed
  | cons nonce rest ih =>
      let next : (Option E.Opening × Bool) → Program (Nat × E.Opening × Bool) :=
        fun (result, nextPending) =>
          match result with
          | none => E.openingScan digest rest nextPending
          | some points => .done (some (nonce, points, nextPending))
      have executedBind : ((E.openingAttempt pending digest nonce).bind next).eval oracle =
          some (selected, opening, finalPending) := by
        rw [opening_scan_cons] at executed
        exact executed
      obtain ⟨pair, attempted, continued⟩ := by
        with_reducible
          exact SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
            (E.openingAttempt pending digest nonce) next
            (selected, opening, finalPending) executedBind
      rcases pair with ⟨result, nextPending⟩
      have attemptValue : (E.openingAttempt pending digest nonce).eval oracle =
          some (attemptedOpening oracle digest nonce,
            pendingFailure pending (scan oracle 6 []
              (E.fieldKeys .piopOpening 6 digest nonce))) := by
        with_reducible
          exact opening_attempt_exact pending digest nonce oracle
      have pairValue :
          (attemptedOpening oracle digest nonce,
            pendingFailure pending (scan oracle 6 []
              (E.fieldKeys .piopOpening 6 digest nonce))) =
          (result, nextPending) := by
        with_reducible
          exact Option.some.inj (attemptValue.symm.trans attempted)
      have decoded : attemptedOpening oracle digest nonce = result := by
        have projected := congrArg (fun pair : Option E.Opening × Bool => pair.1) pairValue
        dsimp only [Prod.fst] at projected
        with_reducible
          exact projected
      cases result with
      | none =>
          simp only [next] at continued
          obtain ⟨before, after, order, prior, chosen⟩ := ih nextPending continued
          refine ⟨nonce :: before, after, ?_, ?_, chosen⟩
          · simp [order]
          · intro earlier member
            rcases List.mem_cons.mp member with equal | below
            · simpa only [equal] using decoded
            · exact prior earlier below
      | some points =>
          simp only [next, Program.eval] at continued
          have equal : (nonce, points, nextPending) = (selected, opening, finalPending) :=
            Option.some.inj continued
          have nonceEq : nonce = selected := congrArg Prod.fst equal
          have openingEq : points = opening := congrArg (fun pair => pair.2.1) equal
          subst selected
          subst points
          exact ⟨[], rest, rfl, by simp, decoded⟩

/-- First valid among the actual sixteen trials, nonce comparison, then the
actual repeat. This theorem imposes no uniform distribution on the nonce. -/
theorem canonical_opening_first_valid16 (pending : Bool) (nonce : Fin (2 ^ 32))
    (digest : G.RawDigest) (oracle : Oracle) (opening : E.Opening) (finalPending : Bool)
    (executed : (E.canonicalOpening pending nonce digest).eval oracle =
      some (opening, finalPending)) :
    FirstValid16 oracle nonce digest opening finalPending := by
  unfold E.canonicalOpening at executed
  obtain ⟨chosen, scanned, continued⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (E.openingScan digest (List.range 16) pending) _ (opening, finalPending) executed
  rcases chosen with ⟨expected, firstOpening, scanPending⟩
  by_cases equal : nonce.val = expected
  · simp only [if_pos equal] at continued
    obtain ⟨pair, repeated, returned⟩ :=
      SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
        (E.openingAttempt scanPending digest nonce.val) _ (opening, finalPending) continued
    rcases pair with ⟨result, repeatedPending⟩
    cases result with
    | none => simp [Program.eval] at returned
    | some points =>
        have pairEq : (points, repeatedPending) = (opening, finalPending) :=
          Option.some.inj returned
        have openingEq := congrArg Prod.fst pairEq
        have pendingEq := congrArg Prod.snd pairEq
        dsimp only [Prod.fst] at openingEq
        dsimp only [Prod.snd] at pendingEq
        subst points
        subst repeatedPending
        have attemptValue : (E.openingAttempt scanPending digest nonce.val).eval oracle =
            some (attemptedOpening oracle digest nonce.val,
              pendingFailure scanPending (scan oracle 6 []
                (E.fieldKeys .piopOpening 6 digest nonce.val))) := by
          with_reducible
            exact opening_attempt_exact scanPending digest nonce.val oracle
        have pairValue :
            (attemptedOpening oracle digest nonce.val,
              pendingFailure scanPending (scan oracle 6 []
                (E.fieldKeys .piopOpening 6 digest nonce.val))) =
            (some opening, finalPending) := by
          with_reducible
            exact Option.some.inj (attemptValue.symm.trans repeated)
        have decoded : attemptedOpening oracle digest nonce.val = some opening := by
          have projected := congrArg (fun pair : Option E.Opening × Bool => pair.1) pairValue
          dsimp only [Prod.fst] at projected
          with_reducible
            exact projected
        obtain ⟨before, after, order, prior, _firstDecoded⟩ :=
          opening_scan_first_valid digest (List.range 16) pending oracle expected
            firstOpening scanPending scanned
        exact ⟨before, after, scanPending, by simpa only [← equal] using order,
          prior, decoded, repeated⟩
  · simp [equal, Program.eval] at continued

private theorem field_loop_record_input_mem (oracle : Oracle) (requested : Nat)
    (accumulated : List FieldWord) (inputs : List G.RawInput)
    (call : G.RawInput × G.RawDigest)
    (recorded : call ∈ ((fieldLoop requested accumulated inputs).record oracle).2) :
    call.1 ∈ inputs := by
  induction inputs generalizing accumulated with
  | nil => simp [fieldLoop, Program.record] at recorded
  | cons input rest ih =>
      by_cases enough : requested ≤ accumulated.length
      · simp [fieldLoop, enough, Program.record] at recorded
      · simp only [fieldLoop, if_neg enough, Program.record, List.mem_cons] at recorded
        rcases recorded with same | below
        · subst call; exact List.mem_cons_self
        · exact List.mem_cons_of_mem input (ih _ below)

private theorem opening_attempt_log_eq (pending : Bool) (digest : G.RawDigest)
    (nonce : Nat) (oracle : Oracle) :
    ((E.openingAttempt pending digest nonce).record oracle).2 =
      ((fieldLoop 6 [] (E.fieldKeys .piopOpening 6 digest nonce)).record oracle).2 := by
  unfold E.openingAttempt E.fieldXof
  rw [Program.record_bind_success oracle (fieldLoop 6 [] _) _
    (scan oracle 6 [] _) (field_loop_executes_scan oracle 6 [] _)]
  simp only [Program.record, List.append_nil]

/-- The call shape is the current raw constructor, not a parser alias. -/
def OpeningFrame (digest : G.RawDigest) (raw : G.RawInput) : Prop :=
  ∃ nonce : Fin (2 ^ 32), ∃ counter : G.Counter,
    counter.val < 5 ∧ raw = G.frame .piopOpening digest nonce counter

private theorem opening_attempt_log_shape (pending : Bool) (digest : G.RawDigest)
    (nonce : Nat) (bounded : nonce < 2 ^ 32) (oracle : Oracle)
    (call : G.RawInput × G.RawDigest)
    (recorded : call ∈ ((E.openingAttempt pending digest nonce).record oracle).2) :
    OpeningFrame digest call.1 := by
  rw [opening_attempt_log_eq] at recorded
  have member := field_loop_record_input_mem oracle 6 [] _ call recorded
  change call.1 ∈ (List.range (callCap 6)).map
    (fun counter => C.canonicalCurrentQueryBytes ⟨.piopOpening, digest, nonce, counter⟩) at member
  obtain ⟨counter, inRange, rawEq⟩ := List.mem_map.mp member
  have small : counter < 5 := by simpa only [show callCap 6 = 5 by decide] using List.mem_range.mp inRange
  let c : G.Counter := ⟨counter, by omega⟩
  have literal : G.frame .piopOpening digest ⟨nonce, bounded⟩ c =
      C.canonicalCurrentQueryBytes ⟨.piopOpening, digest, nonce, counter⟩ := by
    simpa only [G.nonceValue, if_true] using
      G.frame_is_literal_current .piopOpening digest ⟨nonce, bounded⟩ c
  exact ⟨⟨nonce, bounded⟩, c, small, rawEq.symm.trans literal.symm⟩

private theorem opening_scan_log_shape (digest : G.RawDigest) (nonces : List Nat)
    (bounded : ∀ nonce ∈ nonces, nonce < 2 ^ 32) (pending : Bool) (oracle : Oracle)
    (call : G.RawInput × G.RawDigest)
    (recorded : call ∈ ((E.openingScan digest nonces pending).record oracle).2) :
    OpeningFrame digest call.1 := by
  revert bounded
  induction nonces generalizing pending with
  | nil =>
      intro bounded
      simp [E.openingScan, Program.record] at recorded
  | cons nonce rest ih =>
      intro bounded
      let pair := (attemptedOpening oracle digest nonce,
        pendingFailure pending (scan oracle 6 [] (E.fieldKeys .piopOpening 6 digest nonce)))
      let continuation : Option E.Opening × Bool → Program (Nat × E.Opening × Bool) :=
        fun pair => match pair.1 with
          | none => E.openingScan digest rest pair.2
          | some points => .done (some (nonce, points, pair.2))
      have attempted : (E.openingAttempt pending digest nonce).eval oracle = some pair :=
        opening_attempt_exact pending digest nonce oracle
      change call ∈ (((E.openingAttempt pending digest nonce).bind continuation).record oracle).2 at recorded
      rw [Program.record_bind_success oracle _ continuation pair attempted] at recorded
      rcases List.mem_append.mp recorded with earlier | below
      · exact opening_attempt_log_shape pending digest nonce
          (bounded nonce (List.mem_cons_self)) oracle call earlier
      · cases resultEq : pair.1 with
        | none =>
            have tail : call ∈ ((E.openingScan digest rest pair.2).record oracle).2 := by
              simpa only [continuation, resultEq] using below
            exact ih (pending := pair.2) (recorded := tail)
              (bounded := fun n member => bounded n (List.mem_cons_of_mem nonce member))
        | some points => simp only [continuation, resultEq, Program.record, List.not_mem_nil] at below

/-- Only current opening frames with nonce<2^32 and counter<5 occur in the
actual successful scan-plus-repeat record. Reachability is supplied by the
same branch later, never assumed for all hypothetical raw frames. -/
theorem canonical_opening_record_shape (pending : Bool) (nonce : Fin (2 ^ 32))
    (digest : G.RawDigest) (oracle : Oracle) (opening : E.Opening) (finalPending : Bool)
    (executed : (E.canonicalOpening pending nonce digest).eval oracle = some (opening, finalPending))
    (call : G.RawInput × G.RawDigest)
    (recorded : call ∈ ((E.canonicalOpening pending nonce digest).record oracle).2) :
    OpeningFrame digest call.1 := by
  unfold E.canonicalOpening at executed recorded
  obtain ⟨chosen, scanned, continued⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (E.openingScan digest (List.range 16) pending) _ (opening, finalPending) executed
  rcases chosen with ⟨expected, firstOpening, scanPending⟩
  by_cases equal : nonce.val = expected
  · rw [Program.record_bind_success oracle _ _ (expected, firstOpening, scanPending) scanned] at recorded
    rcases List.mem_append.mp recorded with earlier | repeated
    · apply opening_scan_log_shape digest (List.range 16) _ pending oracle call earlier
      intro n member
      have small := List.mem_range.mp member
      omega
    · simp only [if_pos equal] at repeated
      let pair := (attemptedOpening oracle digest nonce.val,
        pendingFailure scanPending (scan oracle 6 [] (E.fieldKeys .piopOpening 6 digest nonce.val)))
      have attempted : (E.openingAttempt scanPending digest nonce.val).eval oracle = some pair :=
        opening_attempt_exact scanPending digest nonce.val oracle
      rw [Program.record_bind_success oracle _ _ pair attempted] at repeated
      simp only [Program.record, List.append_nil] at repeated
      exact opening_attempt_log_shape scanPending digest nonce.val nonce.isLt oracle call repeated
  · simp only [if_neg equal, Program.eval] at continued
    cases continued

private theorem record_eq_of_derived_reads {Result : Type}
    (program : Program Result) (left right : Oracle)
    (derived : ∀ raw, (raw, left raw) ∈ (program.record left).2 → left raw = right raw) :
    program.record left = program.record right := by
  induction program generalizing left right with
  | done result => rfl
  | read raw next ih =>
      have head : left raw = right raw := derived raw (by simp [Program.record])
      have tail := ih (left raw) left right (by
        intro input member
        exact derived input (by simp only [Program.record, List.mem_cons]; exact Or.inr member))
      simp only [Program.record]
      rw [tail, head]

/-- Recorded base parsing plus the positive current opening cap proves
inactive status; compatibility then gives that very vector's fixed cell. -/
theorem recorded_opening_answer_is_fixed {Result : Type}
    (program : Program Result) (selected : Role) (caps : Role → Nat)
    (different : Role.piopOpening ≠ selected) (openingCap : 0 < caps .piopOpening)
    (fixed : T.FixedTable (Counter := G.Counter) (B.live program selected caps))
    (branch : Branches G.decode program)
    (compatible : B.fixedCompatible program selected caps fixed branch)
    (digest : G.RawDigest) (nonce : Fin (2 ^ 32)) (counter : G.Counter)
    (vector : VectorOutput G.Counter)
    (recorded : (G.frame .piopOpening digest nonce counter, vector) ∈ answerLog G.decode program branch)
    (fallback : G.RawDigest) :
    fixedOracle program selected caps fixed fallback (G.frame .piopOpening digest nonce counter) =
      G.decode (G.frame .piopOpening digest nonce counter) vector := by
  have parsed := G.recorded_current_base_parser program branch .piopOpening digest nonce counter vector recorded
  have inactive : ¬B.live program selected caps
      (G.encode program (G.frame .piopOpening digest nonce counter)) := by
    change ¬C.RoleActive selected caps (G.keyBytes program) _
    exact C.other_bounded_role_is_fixed selected caps (G.keyBytes program) _
      ⟨.piopOpening, digest, G.nonceValue .piopOpening nonce, 0⟩ parsed different openingCap
  have fixedEq := compatible (G.frame .piopOpening digest nonce counter, vector) recorded inactive
  simp only [fixedOracle, dif_pos inactive, fixedEq]

/-- Every equality is derived on this literal same-program branch. The
interface contains no oracle-agreement callback or preselected Opening. -/
theorem stages_opening_replays_fixed_other_role
    (producer : Program E.Wire) (ns : M.Namespace) (relation : P.Relation)
    (nonce : Fin (2 ^ 32)) (selected : Role) (caps : Role → Nat)
    (different : Role.piopOpening ≠ selected) (openingCap : 0 < caps .piopOpening)
    (fixed : T.FixedTable (Counter := G.Counter)
      (B.live (FullProgram producer ns relation false nonce) selected caps))
    (branch : Branches G.decode (FullProgram producer ns relation false nonce))
    (database : Database (A.ActiveKey
      (B.live (FullProgram producer ns relation false nonce) selected caps)) (VectorOutput G.Counter))
    (compatible : B.fixedCompatible (FullProgram producer ns relation false nonce) selected caps fixed branch)
    (claims : ClaimsDatabaseEvent (B.activeClaims
      (FullProgram producer ns relation false nonce) selected caps branch) database)
    (fallback : G.RawDigest) (wire : E.Wire)
    (produced : producer.eval (Q.claimOracle (FullProgram producer ns relation false nonce)
      (A.merge (B.live (FullProgram producer ns relation false nonce) selected caps) fixed database)
      fallback) = some wire)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation false nonce wire
      (Q.claimOracle (FullProgram producer ns relation false nonce)
        (A.merge (B.live (FullProgram producer ns relation false nonce) selected caps) fixed database)
        fallback) transcript) :
    (E.canonicalOpening false nonce wire.hPiop).eval
        (fixedOracle (FullProgram producer ns relation false nonce) selected caps fixed fallback) =
      some (stages.opening, stages.openingPending) ∧
    fixedOpening (FullProgram producer ns relation false nonce) selected caps fixed fallback nonce wire.hPiop =
      some stages.opening := by
  let program := FullProgram producer ns relation false nonce
  let oracle := Q.claimOracle program (A.merge (B.live program selected caps) fixed database) fallback
  let other := fixedOracle program selected caps fixed fallback
  have replay := B.current_active_claims_replay_same_program program selected caps fixed branch
    database compatible claims fallback
  have openingInVerifier : ((E.canonicalOpening false nonce wire.hPiop).record oracle).2 ⊆
      ((E.verifierProgram ns relation false nonce wire).record oracle).2 := by
    rw [S.stages_verifier_has_pre_matrix_log ns relation false nonce wire oracle transcript stages]
    intro call member
    exact List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inl member)))
  have openingInProgram : ((E.canonicalOpening false nonce wire.hPiop).record oracle).2 ⊆
      (program.record oracle).2 := by
    intro call member
    exact Program.bind_log_right oracle producer (E.verifierProgram ns relation false nonce)
      wire produced (openingInVerifier member)
  have derived : ∀ raw, (raw, oracle raw) ∈
      ((E.canonicalOpening false nonce wire.hPiop).record oracle).2 → oracle raw = other raw := by
    intro raw member
    obtain ⟨openingNonce, counter, _small, frameEq⟩ := canonical_opening_record_shape
      false nonce wire.hPiop oracle stages.opening stages.openingPending stages.openingExecuted
      (raw, oracle raw) member
    dsimp only [Prod.fst] at frameEq
    have inWhole := openingInProgram member
    have inRaw : (raw, oracle raw) ∈ rawLog G.decode program branch := by
      have logEq := congrArg Prod.snd replay
      dsimp only [Prod.snd] at logEq
      rw [← logEq]
      exact inWhole
    obtain ⟨call, recorded, same⟩ := List.mem_map.mp inRaw
    rcases call with ⟨input, vector⟩
    have inputEq : input = raw := congrArg Prod.fst same
    have digestEq : G.decode input vector = oracle raw := congrArg Prod.snd same
    have framed : (G.frame .piopOpening wire.hPiop openingNonce counter, vector) ∈
        answerLog G.decode program branch := by
      simpa only [inputEq, frameEq] using recorded
    have fixedAnswer := recorded_opening_answer_is_fixed program selected caps different openingCap
      fixed branch compatible wire.hPiop openingNonce counter vector framed fallback
    calc
      oracle raw = G.decode raw vector := by simpa only [inputEq] using digestEq.symm
      _ = other raw := by simpa only [other, frameEq] using fixedAnswer.symm
  have records := record_eq_of_derived_reads (E.canonicalOpening false nonce wire.hPiop) oracle other derived
  have evaluations : (E.canonicalOpening false nonce wire.hPiop).eval oracle =
      (E.canonicalOpening false nonce wire.hPiop).eval other := by
    exact (Program.record_result oracle _).symm.trans
      ((congrArg Prod.fst records).trans (Program.record_result other _))
  have fixedExecuted := evaluations.symm.trans stages.openingExecuted
  refine ⟨fixedExecuted, ?_⟩
  change ((E.canonicalOpening false nonce wire.hPiop).eval other).map Prod.fst = some stages.opening
  rw [fixedExecuted]
  rfl

/-- Accepted same-branch .decsSample claims derive actual stages and a
deterministically calculated Opening under the fixed-other-role oracle. -/
theorem current_accepted_decs_sample_branch_has_fixed_opening
    (producer : Program E.Wire) (ns : M.Namespace) (relation : P.Relation)
    (nonce : Fin (2 ^ 32))
    (fixed : T.FixedTable (Counter := G.Counter)
      (B.live (FullProgram producer ns relation false nonce) .decsSample currentCaps))
    (branch : Branches G.decode (FullProgram producer ns relation false nonce))
    (database : Database (A.ActiveKey
      (B.live (FullProgram producer ns relation false nonce) .decsSample currentCaps)) (VectorOutput G.Counter))
    (compatible : B.fixedCompatible (FullProgram producer ns relation false nonce) .decsSample currentCaps fixed branch)
    (claims : ClaimsDatabaseEvent (B.activeClaims
      (FullProgram producer ns relation false nonce) .decsSample currentCaps branch) database)
    (accepted : branchResult G.decode (FullProgram producer ns relation false nonce) branch = some ())
    (fallback : G.RawDigest) :
    let program := FullProgram producer ns relation false nonce
    let oracle := Q.claimOracle program (A.merge (B.live program .decsSample currentCaps) fixed database) fallback
    let other := fixedOracle program .decsSample currentCaps fixed fallback
    ∃ wire, producer.eval oracle = some wire ∧
      ∃ transcript, ∃ stages : E.ExecutionStages ns relation false nonce wire oracle transcript,
        transcript.pending = false ∧
        (E.canonicalOpening false nonce wire.hPiop).eval other =
          some (stages.opening, stages.openingPending) ∧
        fixedOpening program .decsSample currentCaps fixed fallback nonce wire.hPiop = some stages.opening ∧
        FirstValid16 other nonce wire.hPiop stages.opening stages.openingPending := by
  let program := FullProgram producer ns relation false nonce
  let oracle := Q.claimOracle program (A.merge (B.live program .decsSample currentCaps) fixed database) fallback
  have replay := B.current_active_claims_replay_same_program program .decsSample currentCaps
    fixed branch database compatible claims fallback
  have ordinary : program.eval oracle = some () :=
    (Program.record_result oracle program).symm.trans ((congrArg Prod.fst replay).trans accepted)
  obtain ⟨wire, produced, verifierAccepted⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle producer
      (E.verifierProgram ns relation false nonce) () ordinary
  obtain ⟨transcript, ⟨stages⟩, clean, _digest, _record⟩ :=
    E.accepted_execution_has_stages ns relation false nonce wire oracle verifierAccepted
  obtain ⟨fixedExecuted, calculated⟩ := stages_opening_replays_fixed_other_role
    producer ns relation nonce .decsSample currentCaps (by decide)
      (by rw [current_opening_cap]; decide) fixed branch database compatible claims fallback wire produced transcript stages
  exact ⟨wire, produced, transcript, stages, clean, fixedExecuted, calculated,
    canonical_opening_first_valid16 false nonce wire.hPiop
      (fixedOracle program .decsSample currentCaps fixed fallback) stages.opening
      stages.openingPending fixedExecuted⟩

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFixedOpeningReplay
