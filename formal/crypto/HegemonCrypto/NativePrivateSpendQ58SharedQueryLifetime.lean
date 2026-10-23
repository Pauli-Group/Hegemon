import HegemonCrypto.NativePrivateSpendQ58Ledger
import HegemonCrypto.NativeLaunchGlobalQueryReadBudget
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAccounting
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-!
# SMZD shared, source-inclusive raw-query accounting

The counted programs below retain source early stopping, field-XOF exhaustion,
six-point/16-nonce search, and the accepted request's ordinary reread. Histories
receive the preceding result and use one unchanged raw oracle, including failed
attempts. Six private branches use the same geometry, not six independent query
budgets. The source inventory accompanying this module records the literal Rust
calls and the frozen relation configuration used for the numerical counts.

The generic physical endpoint calls PR205's persistent-write compiler and its
disclosed external adaptive-reprogramming assumption. No new security-distance
or freshLoss coefficient is assumed. In particular the arithmetic Ledger result
is kept separate from that endpoint. This module does NOT discharge the current
Rust-to-program or q58 whole-view/simulator eligibility obligations, nor provide
a production lifetime policy or production authority.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58SharedQueryLifetime

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05SourceReadSchedule (readBudget)
open HegemonCrypto.NativeLaunchGlobalQueryReadBudget
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9HiddenLeafQrom (DigestRegister)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024

/-- Exact source cap, including zero requests. 40 denotes candidate WORDS
for the six-point request: five digest blocks, not forty digest blocks. -/
def fieldXofBlocks (requested : Nat) : Nat :=
  if requested = 0 then 0 else (requested + 32 + 7) / 8

theorem field_xof_cap_is_inherited (requested : Nat) :
    fieldXofBlocks requested = V8Smz9RawCounterCompiler.digestCallCap requested := rfl

/-- Literal profile bytes from SMALLWOOD_NATIVE_PRIVATE_SPEND_SMZD_SHA512_PROFILE_DOMAIN. -/
def profileDomain : List CanonicalBytes.Byte :=
  [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,
   110,97,116,105,118,101,45,112,114,105,118,97,116,101,45,115,112,101,110,100,46,
   115,109,122,100,46,115,104,97,53,49,50,46,112,114,111,102,105,108,101,46,118,49]

/-- The actual raw SHA512 frame: profile length/bytes, role length/bytes,
word count/u64LE words, then the u64LE counter. No branch label is inserted. -/
def counterPrefix (role : List CanonicalBytes.Byte) (words : List Nat) : RawInput :=
  CanonicalBytes.encodeLE 8 profileDomain.length ++ profileDomain ++
    CanonicalBytes.encodeLE 8 role.length ++ role ++
    CanonicalBytes.encodeLE 8 words.length ++ (words.map (CanonicalBytes.encodeLE 8)).flatten

def counterKey (role : List CanonicalBytes.Byte) (words : List Nat)
    (counter : Fin (2^64)) : RawInput :=
  V8Smz9RawCounterCompiler.counterInput (counterPrefix role words) counter

theorem exact_source_profile_length : profileDomain.length = 61 := by decide

/-- Reuse the complete raw-prefix partition, retaining all other raw inputs.
This includes arbitrary roles, malformed inputs and every six-branch history;
it does not resample an oracle per statement, request or branch. -/
def oraclePartition :
    (RawInput → DigestRegister) ≃
      (RawInput → Fin (2^64) → DigestRegister) ×
        (V8Smz9RawCounterCompiler.Complement
          (fun key : RawInput × Fin (2^64) =>
            V8Smz9RawCounterCompiler.counterInput key.1 key.2) → DigestRegister) :=
  V8Smz9RawCounterCompiler.rawTableFactorization
    (fun key : RawInput × Fin (2^64) =>
      V8Smz9RawCounterCompiler.counterInput key.1 key.2)
    V8Smz9RawCounterCompiler.counter_input_injective

theorem partition_retains_same_counter_reply (oracle : RawInput → DigestRegister)
    (role : List CanonicalBytes.Byte) (words : List Nat) (counter : Fin (2^64)) :
    (oraclePartition oracle).1 (counterPrefix role words) counter =
      oracle (counterKey role words counter) := rfl

theorem partition_restores_same_oracle (oracle : RawInput → DigestRegister) :
    oraclePartition.symm (oraclePartition oracle) = oracle := oraclePartition.symm_apply_apply oracle

def decsMatrixWords : Nat := 5 * 140
def piopMatrixWords : Nat := 5 * max 5210 1344146
def openingTrialCap : Nat := 16
def openingWords : Nat := 6
def fixedDecsWords : Nat := 80
def leaves : Nat := 2^23
def merkleDepth : Nat := 23
def openedLeaves : Nat := 58

theorem exact_field_xof_counters :
    fieldXofBlocks decsMatrixWords = 92 ∧
    piopMatrixWords = 6720730 ∧ fieldXofBlocks piopMatrixWords = 840096 ∧
    fieldXofBlocks openingWords = 5 ∧ 8 * fieldXofBlocks openingWords = 40 ∧
    fieldXofBlocks fixedDecsWords = 14 := by
  norm_num [fieldXofBlocks, decsMatrixWords, piopMatrixWords, openingWords, fixedDecsWords]

/-- The accepted little-endian canonical field words in one physical reply.
Only the first requested accepts will be returned by the block scanner. -/
def acceptedBlockWords (digest : RawDigest) : List Nat :=
  ((List.range 8).map fun lane =>
    CanonicalBytes.decodeLE ((List.ofFn digest).drop (8 * lane) |>.take 8)).filter
      (fun candidate => candidate < 18446744069414584321)

/-- Each executed source digest is a charged Program.read. Exhaustion is a
returned failure value so the caller may apply the delayed poison policy. -/
def fieldScan (key : Nat → RawInput) : Nat → Nat → Nat → List Nat →
    Program (Except Unit (List Nat))
  | 0, _, requested, accepted =>
      .done (some (if requested ≤ accepted.length then .ok (accepted.take requested) else .error ()))
  | fuel + 1, counter, requested, accepted =>
      if requested ≤ accepted.length then .done (some (.ok (accepted.take requested)))
      else .read (key counter) fun digest =>
        fieldScan key fuel (counter + 1) requested (accepted ++ acceptedBlockWords digest)

def fieldRequest (key : Nat → RawInput) (requested : Nat) :
    Program (Except Unit (List Nat)) :=
  fieldScan key (fieldXofBlocks requested) 0 requested []

/-- An actual ordered trace, not only a supremum over decoded vector answers.
The same theorem covers successful scans and exhaustion against any fixed
physical oracle. Repeated addresses remain separate entries in the log. -/
theorem field_scan_actual_trace_bound (oracle : Oracle) (key : Nat → RawInput)
    (fuel counter requested : Nat) (accepted : List Nat) :
    ((fieldScan key fuel counter requested accepted).record oracle).2.length ≤ fuel := by
  induction fuel generalizing counter accepted with
  | zero => simp [fieldScan, Program.record]
  | succ fuel ih =>
      rw [fieldScan]
      split
      · simp [Program.record]
      · simp only [Program.record, List.length_cons]
        exact Nat.succ_le_succ (ih _ _)

theorem field_request_actual_trace_bound (oracle : Oracle) (key : Nat → RawInput)
    (requested : Nat) :
    ((fieldRequest key requested).record oracle).2.length ≤ fieldXofBlocks requested :=
  field_scan_actual_trace_bound oracle key _ _ _ _

/-- Successful binding appends the next trace; a direct failure retains its
prefix. Both parts execute under exactly the same physical oracle. -/
theorem record_bind_length_le {A B : Type} (oracle : Oracle)
    (program : Program A) (next : A → Program B) (budget : Nat)
    (remaining : ∀ value, ((next value).record oracle).2.length ≤ budget) :
    ((program.bind next).record oracle).2.length ≤ (program.record oracle).2.length + budget := by
  induction program with
  | done result =>
      cases result with
      | none => simp [Program.bind, Program.record]
      | some value => simpa [Program.bind, Program.record] using remaining value
  | read raw cont ih =>
      simpa only [Program.bind, Program.record, List.length_cons, Nat.add_right_comm] using
        Nat.add_le_add_right (ih (oracle raw)) 1

variable {Counter Result State : Type} [Fintype Counter] [DecidableEq Counter]

theorem field_scan_read_bound (decode : RawInput → VectorOutput Counter → RawDigest)
    (key : Nat → RawInput) (fuel counter requested : Nat) (accepted : List Nat) :
    readBudget decode (fieldScan key fuel counter requested accepted) ≤ fuel := by
  induction fuel generalizing counter accepted with
  | zero => simp [fieldScan, readBudget]
  | succ fuel ih =>
      rw [fieldScan]
      split
      · simp [readBudget]
      · simp only [readBudget]
        exact Nat.succ_le_succ (Finset.sup_le fun answer _ => ih _ _)

theorem field_request_read_bound (decode : RawInput → VectorOutput Counter → RawDigest)
    (key : Nat → RawInput) (requested : Nat) :
    readBudget decode (fieldRequest key requested) ≤ fieldXofBlocks requested :=
  field_scan_read_bound decode key _ _ _ _

def poisonWordsFor (requested : Nat) : List Nat :=
  (List.range requested).map fun i => 18446744069414584320 - i
def poisonWords : List Nat := poisonWordsFor 6
def openingReply (reply : Except Unit (List Nat)) : List Nat :=
  match reply with | .ok words => words | .error _ => poisonWords
def replyFailed (reply : Except Unit (List Nat)) : Bool :=
  match reply with | .ok _ => false | .error _ => true

/-- A failed XOF poisons later success but does not stop the nonce search.
The successful trial is reread using EXACTLY the same key nonce/counter pair. -/
def openingSearch (key : Nat → Nat → RawInput) (valid : List Nat → Bool) :
    Nat → Nat → Bool → Program (Bool × Except Unit (Nat × List Nat))
  | 0, _, poisoned => .done (some (poisoned, .error ()))
  | fuel + 1, nonce, poisoned =>
      (fieldRequest (key nonce) openingWords).bind fun reply =>
        let pending := poisoned || replyFailed reply
        let words := openingReply reply
        if valid words then
          (fieldRequest (key nonce) openingWords).bind fun replay =>
            .done (some (pending || replyFailed replay, .ok (nonce, words)))
        else openingSearch key valid fuel (nonce + 1) pending

theorem opening_search_read_bound (decode : RawInput → VectorOutput Counter → RawDigest)
    (key : Nat → Nat → RawInput) (valid : List Nat → Bool)
    (fuel nonce : Nat) (poisoned : Bool) :
    readBudget decode (openingSearch key valid fuel nonce poisoned) ≤
      (fuel + 1) * fieldXofBlocks openingWords := by
  induction fuel generalizing nonce poisoned with
  | zero => simp [openingSearch, readBudget]
  | succ fuel ih =>
      rw [openingSearch]
      apply (readBudget_bind_le decode _ _
        ((fuel + 1) * fieldXofBlocks openingWords) ?_).trans
      · have bound := field_request_read_bound decode (key nonce) openingWords
        have blocks : fieldXofBlocks openingWords = 5 := by norm_num [fieldXofBlocks, openingWords]
        rw [blocks] at bound ⊢
        omega
      · intro reply
        dsimp
        split
        · apply (readBudget_bind_le decode _ _ 0 ?_).trans
          · have bound := field_request_read_bound decode (key nonce) openingWords
            simp only [Nat.add_zero]
            apply bound.trans
            have blocks : fieldXofBlocks openingWords = 5 := by norm_num [fieldXofBlocks, openingWords]
            rw [blocks]
            omega
          · intro replay
            simp [readBudget]
        · exact ih _ _

theorem sixteen_trials_and_accepted_reread (decode : RawInput → VectorOutput Counter → RawDigest)
    (key : Nat → Nat → RawInput) (valid : List Nat → Bool) (poisoned : Bool) :
    readBudget decode (openingSearch key valid openingTrialCap 0 poisoned) ≤ 85 := by
  simpa [openingTrialCap, fieldXofBlocks, openingWords] using
    opening_search_read_bound decode key valid openingTrialCap 0 poisoned

theorem opening_search_actual_trace_bound (oracle : Oracle)
    (key : Nat → Nat → RawInput) (valid : List Nat → Bool)
    (fuel nonce : Nat) (poisoned : Bool) :
    ((openingSearch key valid fuel nonce poisoned).record oracle).2.length ≤
      (fuel + 1) * fieldXofBlocks openingWords := by
  induction fuel generalizing nonce poisoned with
  | zero => simp [openingSearch, Program.record]
  | succ fuel ih =>
      rw [openingSearch]
      apply (record_bind_length_le oracle _ _
        ((fuel + 1) * fieldXofBlocks openingWords) ?_).trans
      · have bounded := field_request_actual_trace_bound oracle (key nonce) openingWords
        have blocks : fieldXofBlocks openingWords = 5 := by norm_num [fieldXofBlocks, openingWords]
        rw [blocks] at bounded ⊢
        omega
      · intro reply
        dsimp
        split
        · apply (record_bind_length_le oracle _ _ 0 ?_).trans
          · have bounded := field_request_actual_trace_bound oracle (key nonce) openingWords
            simp only [Nat.add_zero]
            apply bounded.trans
            have blocks : fieldXofBlocks openingWords = 5 := by norm_num [fieldXofBlocks, openingWords]
            rw [blocks]
            omega
          · intro replay
            simp [Program.record]
        · exact ih _ _

theorem actual_sixteen_trials_and_reread_bound (oracle : Oracle)
    (key : Nat → Nat → RawInput) (valid : List Nat → Bool) (poisoned : Bool) :
    ((openingSearch key valid openingTrialCap 0 poisoned).record oracle).2.length ≤ 85 := by
  simpa [openingTrialCap, fieldXofBlocks, openingWords] using
    opening_search_actual_trace_bound oracle key valid openingTrialCap 0 poisoned

/-- Source DECS follows an accepted PIOP plan even while poison is pending;
direct nonce failure stops before DECS. Only the final success checks poison. -/
def sourceOpeningAndDecs (openingKey : Nat → Nat → RawInput)
    (valid : List Nat → Bool) (decsDigestKey : Nat × List Nat → RawInput)
    (decsKey : RawDigest → Nat → RawInput) (enoughDistinct : List Nat → Bool)
    (poisoned : Bool) : Program (Except Unit (List Nat)) :=
  (openingSearch openingKey valid openingTrialCap 0 poisoned).bind fun selected =>
    match selected.2 with
    | .error _ => .done (some (.error ()))
    | .ok plan => .read (decsDigestKey plan) fun digest =>
      (fieldRequest (decsKey digest) fixedDecsWords).bind fun reply =>
        let words := match reply with | .ok words => words | .error _ => poisonWordsFor fixedDecsWords
        .done (some (if enoughDistinct words && !(selected.1 || replyFailed reply)
          then .ok words else .error ()))

theorem source_opening_decs_read_bound (decode : RawInput → VectorOutput Counter → RawDigest)
    (openingKey : Nat → Nat → RawInput) (valid : List Nat → Bool)
    (decsDigestKey : Nat × List Nat → RawInput) (decsKey : RawDigest → Nat → RawInput)
    (enoughDistinct : List Nat → Bool) (poisoned : Bool) :
    readBudget decode (sourceOpeningAndDecs openingKey valid decsDigestKey decsKey
      enoughDistinct poisoned) ≤ 100 := by
  unfold sourceOpeningAndDecs
  apply (readBudget_bind_le decode _ _ 15 ?_).trans
  · have bounded := sixteen_trials_and_accepted_reread decode openingKey valid poisoned
    omega
  · intro selected
    cases selected.2 with
    | error _ => simp [readBudget]
    | ok plan =>
        simp only [readBudget]
        apply Nat.succ_le_succ
        apply Finset.sup_le
        intro answer _
        apply (readBudget_bind_le decode _ _ 0 ?_).trans
        · have bounded := field_request_read_bound decode
            (decsKey (decode (decsDigestKey plan) answer)) fixedDecsWords
          simpa [fieldXofBlocks, fixedDecsWords] using bounded
        · intro reply
          simp [readBudget]

/-- Literal non-deduplicating verifier implementation hashes every selected
position at every level, even after subtree indices coincide. -/
def verifierMerkleReads : Nat := openedLeaves * (merkleDepth + 1)
def proverMerkleReads : Nat := leaves + (leaves - 1)
def proverReadCap : Nat :=
  proverMerkleReads + 2 + fieldXofBlocks decsMatrixWords +
    1 + fieldXofBlocks piopMatrixWords + 1 +
    (openingTrialCap + 1) * fieldXofBlocks openingWords +
    1 + fieldXofBlocks fixedDecsWords
def verifierReadCap : Nat :=
  verifierMerkleReads + 1 + fieldXofBlocks decsMatrixWords +
    1 + fieldXofBlocks piopMatrixWords + 1 +
    (openingTrialCap + 1) * fieldXofBlocks openingWords +
    1 + fieldXofBlocks fixedDecsWords
/-- The optional verifier trace rereads hash_fpp and the complete gamma stream
after piop_recompute_transcript already consumed both. -/
def verifierTraceReadCap : Nat := verifierReadCap + 1 + fieldXofBlocks piopMatrixWords

theorem exact_source_caps :
    proverMerkleReads = 16777215 ∧ verifierMerkleReads = 1392 ∧
    proverReadCap = 17617507 ∧ verifierReadCap = 841683 ∧
    verifierTraceReadCap = 1681780 := by
  norm_num [proverMerkleReads, verifierMerkleReads, proverReadCap, verifierReadCap,
    verifierTraceReadCap, leaves, openedLeaves, merkleDepth, openingTrialCap,
    fieldXofBlocks, decsMatrixWords, piopMatrixWords, openingWords, fixedDecsWords]

inductive Branch where
  | ordinary | approval | final | lock | claim | refund
deriving DecidableEq, Fintype

inductive Operation where
  | prove (branch : Branch) | verify (branch : Branch) | trace (branch : Branch)
deriving DecidableEq, Fintype

def operationCap : Operation → Nat
  | .prove _ => proverReadCap
  | .verify _ => verifierReadCap
  | .trace _ => verifierTraceReadCap

theorem six_branches_same_geometry (branch : Branch) :
    operationCap (.prove branch) = 17617507 ∧
    operationCap (.verify branch) = 841683 ∧
    operationCap (.trace branch) = 1681780 :=
  ⟨exact_source_caps.2.2.1, exact_source_caps.2.2.2.1, exact_source_caps.2.2.2.2⟩

/-- Budgets include prehistory, coherent adversary calls, source reads,
adaptive selection, fixed-write retrievals, every failed proof attempt and
every verifier reread. Counts are protocol-lifetime totals, never reset per
branch, accepted proof, restart or block. -/
structure Resources where
  prehistory : Nat
  adversary : Nat
  selection : Nat
  fixedWriteReads : Nat
  proofAttempts : Nat
  verificationAttempts : Nat
  traceAttempts : Nat

def chargedQueries (resources : Resources) : Nat :=
  resources.prehistory + resources.adversary + resources.selection + resources.fixedWriteReads +
    resources.proofAttempts * proverReadCap +
    resources.verificationAttempts * verifierReadCap + resources.traceAttempts * verifierTraceReadCap

theorem failed_attempt_is_charged (resources : Resources) :
    chargedQueries { resources with proofAttempts := resources.proofAttempts + 1 } =
      chargedQueries resources + proverReadCap := by
  unfold chargedQueries
  dsimp only
  rw [Nat.add_mul, Nat.one_mul]
  omega

/-- This reuses the inherited answer-adaptive read composition. The explicit
stageBound is the remaining source-program correspondence interface; it is
not an extraction, privacy or event-distance conclusion. -/
theorem shared_history_read_bound
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (stages : List (State → Program State)) (budget : (State → Program State) → Nat)
    (stageBound : ∀ stage ∈ stages, ∀ state, readBudget decode (stage state) ≤ budget stage)
    (initial : State) :
    readBudget decode (adaptiveHistory stages initial) ≤ (stages.map budget).sum :=
  readBudget_adaptiveHistory_le decode stages budget stageBound initial

/-- The history is evaluated against the original oracle, without a new
draw after selection or after failure. Every recorded reply equals that
same oracle at the literal input, including repeated accepted-query keys. -/
theorem persistent_history_reply
    (oracle : Oracle) (stages : List (State → Program State)) (initial : State)
    (call : RawInput × RawDigest)
    (member : call ∈ ((adaptiveHistory stages initial).record oracle).2) :
    call.2 = oracle call.1 :=
  Program.recorded_call oracle (adaptiveHistory stages initial) call member

theorem analysis_source_inclusive_cap (resources : Resources)
    (ordinary : resources.prehistory + resources.adversary + resources.selection +
      resources.fixedWriteReads ≤ 2^65)
    (provers : resources.proofAttempts ≤ 2^21)
    (verifiers : resources.verificationAttempts ≤ 2^21)
    (traces : resources.traceAttempts ≤ 2^21) :
    chargedQueries resources ≤ 3 * 2^64 := by
  rcases exact_source_caps with ⟨_, _, proverCap, verifierCap, traceCap⟩
  have p := Nat.mul_le_mul_right proverReadCap provers
  have v := Nat.mul_le_mul_right verifierReadCap verifiers
  have t := Nat.mul_le_mul_right verifierTraceReadCap traces
  unfold chargedQueries
  simp only [proverCap, verifierCap, traceCap] at p v t ⊢
  omega

/-- An explicit analysis envelope, not an enforced protocol lifetime policy.
Selection/fixed-write retrievals share the ordinary 2^65 cap rather than
receiving a free additional allowance. -/
def analysisResources : Resources :=
  ⟨2^64, 2^64, 0, 0, 2^21, 2^21, 2^21⟩

theorem exact_analysis_inclusive_queries :
    chargedQueries analysisResources = 36893530386094620672 := by
  norm_num [chargedQueries, analysisResources, proverReadCap, verifierReadCap, verifierTraceReadCap,
    proverMerkleReads, verifierMerkleReads, leaves, merkleDepth, openedLeaves,
    openingTrialCap, fieldXofBlocks, decsMatrixWords, piopMatrixWords, openingWords, fixedDecsWords]

theorem analysis_queries_below_shared_cap : chargedQueries analysisResources ≤ 3 * 2^64 := by
  rw [exact_analysis_inclusive_queries]
  norm_num

/-- Arithmetic specialization ONLY: it does not identify a physical accepted
failure event with the proposed freshLoss formula. -/
theorem q58_arithmetic_at_inclusive_cap (resources : Resources)
    (bounded : chargedQueries resources ≤ 3 * 2^64) :
    NativePrivateSpendQ58Ledger.freshLoss (chargedQueries resources) < 1 / (2 : ℚ)^128 :=
  NativePrivateSpendQ58Ledger.fresh_below_128_bits _ bounded

section Physical
variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

/-- Actual inherited physical accounting: fixed writes perform charged reads,
the correction log persists, and abort/instrument outcomes are retained.
The external GHHM primitive assumption remains explicit. -/
theorem shared_physical_reprogramming_bound
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := Input) (Work := Work))
    (program : V8Smz9MixedMaskCompiler.MixedProgram Input Work)
    (initial : V8Smz9HonestWholeViewGames.GameState (Input := Input) (Work := Work))
    (resources : Resources) (programs : Nat)
    (normalized : ‖initial‖ = 1)
    (queries : V8Smz9MixedMaskCompiler.queryCount program ≤ chargedQueries resources)
    (writes : V8Smz9MixedMaskCompiler.programmingCount program ≤ programs)
    (inputMass : V8Smz9MixedMaskCompiler.InputMassAtMost
      (ENNReal.ofReal ((2^512 : ℝ)⁻¹)) program) :
    |V8Smz9MixedMaskCompiler.acceptance true program initial -
      V8Smz9MixedMaskCompiler.acceptance false program initial| ≤
      (programs : ℝ) * (Real.sqrt ((chargedQueries resources : ℝ) * (2^512 : ℝ)⁻¹) +
        (chargedQueries resources : ℝ) * (2^512 : ℝ)⁻¹ / 2) :=
  V8Smz9MixedMaskCompiler.mixed_adaptive_reprogramming_bound ghhm program initial
    (chargedQueries resources) programs ((2^512 : ℝ)⁻¹) normalized queries writes
      (by positivity) inputMass

theorem numeric_physical_loss (queries programs : Nat)
    (queryCap : queries ≤ 3 * 2^64) (programCap : programs ≤ 2^45) :
    (programs : ℝ) * (Real.sqrt ((queries : ℝ) * (2^512 : ℝ)⁻¹) +
      (queries : ℝ) * (2^512 : ℝ)⁻¹ / 2) ≤ (2^177 : ℝ)⁻¹ := by
  have q : (queries : ℝ) ≤ (2 : ℝ)^66 := by
    exact_mod_cast (queryCap.trans (by norm_num : 3 * 2^64 ≤ 2^66))
  have p : (programs : ℝ) ≤ (2 : ℝ)^45 := by exact_mod_cast programCap
  have exposure : (queries : ℝ) * (2^512 : ℝ)⁻¹ ≤ ((2^223 : ℝ)⁻¹)^2 := by
    exact (mul_le_mul_of_nonneg_right q (by positivity)).trans (by norm_num)
  have root : Real.sqrt ((queries : ℝ) * (2^512 : ℝ)⁻¹) ≤ (2^223 : ℝ)⁻¹ :=
    Real.sqrt_le_iff.mpr ⟨by positivity, exposure⟩
  have linear : (queries : ℝ) * (2^512 : ℝ)⁻¹ / 2 ≤ (2^223 : ℝ)⁻¹ :=
    (div_le_div_of_nonneg_right exposure (by norm_num)).trans (by norm_num)
  calc
    _ ≤ (programs : ℝ) * ((2^222 : ℝ)⁻¹) := by
      apply mul_le_mul_of_nonneg_left _ (Nat.cast_nonneg _)
      exact (add_le_add root linear).trans (by norm_num)
    _ ≤ (2 : ℝ)^45 * ((2^222 : ℝ)⁻¹) :=
      mul_le_mul_of_nonneg_right p (by positivity)
    _ = _ := by norm_num

theorem shared_physical_128_specialization
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := Input) (Work := Work))
    (program : V8Smz9MixedMaskCompiler.MixedProgram Input Work)
    (initial : V8Smz9HonestWholeViewGames.GameState (Input := Input) (Work := Work))
    (resources : Resources) (programs : Nat) (normalized : ‖initial‖ = 1)
    (queries : V8Smz9MixedMaskCompiler.queryCount program ≤ chargedQueries resources)
    (writes : V8Smz9MixedMaskCompiler.programmingCount program ≤ programs)
    (inputMass : V8Smz9MixedMaskCompiler.InputMassAtMost
      (ENNReal.ofReal ((2^512 : ℝ)⁻¹)) program)
    (queryCap : chargedQueries resources ≤ 3 * 2^64) (programCap : programs ≤ 2^45) :
    |V8Smz9MixedMaskCompiler.acceptance true program initial -
      V8Smz9MixedMaskCompiler.acceptance false program initial| < (2^128 : ℝ)⁻¹ := by
  exact (shared_physical_reprogramming_bound ghhm program initial resources programs
    normalized queries writes inputMass).trans_lt
      ((numeric_physical_loss _ _ queryCap programCap).trans_lt (by norm_num))

end Physical
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58SharedQueryLifetime
