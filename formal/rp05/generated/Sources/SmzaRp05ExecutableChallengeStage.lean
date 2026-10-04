import SmzaRp05ExecutableMerkleVerifier

/-!
# Literal capped challenge stage on the executable raw-oracle program

SOURCE-ONLY, NOT COMPILED. No new proof bytes or accepting-check premises.
The raw counter framing uses the current SMZA profile, eight digest words,
the unchanged DECS coefficient/fixed-sampling roles, and a 64-bit LE counter.
The parser reads eight LE u64 words per block, rejects words >= p, stops
early, and retains source poison/pending-error behavior on exhaustion.

The stage after the Merkle core samples 700 uniform coefficients (92 digest
calls maximum) from hash_mt and calculates the five-by-38 MCA values from
the SAME input leaf payloads. The separate q38 sampler takes 50 field words
(11 calls maximum), first 38 distinct accepted indices, then sorts. It must
run BEFORE Merkle reconstruction: its seed is the DECS opening hash, not
hash_mt. It is deliberately not placed after the Merkle core here.

FIRST MISSING PRIMITIVE: a proof-connected executable `poly_restore` and
LVCS/PIOP reconstruction over the decoded RP05 proof fields. Rust does not
perform 5 MCA + 12 LVCS independent Boolean polynomial checks; it restores
polynomials/rows and finally compares the reconstructed PIOP hash with
proof.h_piop (after finishing the XOF scope). Inserting extra equation
guards against an arbitrary ClaimedTranscript would change acceptance.
Consequently this file does NOT claim full verifier/scalar acceptance.
The current raw-counter model equivalence and subsequent before-hash
preimage/readback join also remain to be checked, not inferred from tests.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableChallengeStage

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawInput RawDigest)
set_option autoImplicit false

def modulus : Nat := 18446744069414584321
abbrev FieldWord := Fin modulus

/-- Literal source cap: ceil(requested/8) plus four blocks, except zero. -/
def callCap (requested : Nat) : Nat :=
  if requested = 0 then 0 else (requested + 32 + 7) / 8

theorem current_caps : callCap 50 = 11 ∧ callCap 700 = 92 := by decide

def counterInput (role : List Byte) (digest : RawDigest) (counter : Nat) : RawInput :=
  encodeLE 8 V8SmzaOracleParser.profileDomain.length ++ V8SmzaOracleParser.profileDomain ++
    encodeLE 8 role.length ++ role ++ encodeLE 8 8 ++ List.ofFn digest ++ encodeLE 8 counter

def digestWords (digest : RawDigest) : List Nat :=
  (List.range 8).map fun index => decodeLE (((List.ofFn digest).drop (8 * index)).take 8)

def canonicalWord (word : Nat) : Option FieldWord :=
  if bounded : word < modulus then some ⟨word, bounded⟩ else none

def acceptedWords (digest : RawDigest) : List FieldWord :=
  (digestWords digest).filterMap canonicalWord

/-- The extra Option is source XOF exhaustion; it is not a failed program.
This distinction preserves the source's deferred pending-error behavior. -/
def fieldLoop (requested : Nat) (accumulated : List FieldWord) :
    List RawInput → Program (Option (List FieldWord))
  | [] => .done (some (if requested ≤ accumulated.length then
      some (accumulated.take requested) else none))
  | input :: rest =>
      if requested ≤ accumulated.length then .done (some (some (accumulated.take requested)))
      else .read input fun digest =>
        fieldLoop requested (accumulated ++ acceptedWords digest) rest

/-- Uninstrumented deterministic semantics; no log or accepted transcript
is among its arguments. -/
def scan (oracle : Oracle) (requested : Nat) (accumulated : List FieldWord) :
    List RawInput → Option (List FieldWord)
  | [] => if requested ≤ accumulated.length then some (accumulated.take requested) else none
  | input :: rest =>
      if requested ≤ accumulated.length then some (accumulated.take requested)
      else scan oracle requested (accumulated ++ acceptedWords (oracle input)) rest

theorem field_loop_executes_scan (oracle : Oracle) (requested : Nat)
    (accumulated : List FieldWord) (inputs : List RawInput) :
    (fieldLoop requested accumulated inputs).eval oracle =
      some (scan oracle requested accumulated inputs) := by
  induction inputs generalizing accumulated with
  | nil => rfl
  | cons input rest ih =>
      by_cases enough : requested ≤ accumulated.length
      · simp only [fieldLoop, scan, if_pos enough, Program.eval]
      · simpa only [fieldLoop, scan, if_neg enough, Program.eval] using
          ih (accumulated ++ acceptedWords (oracle input))

theorem scan_success_length (oracle : Oracle) (requested : Nat)
    (accumulated : List FieldWord) (inputs : List RawInput) (words : List FieldWord)
    (succeeded : scan oracle requested accumulated inputs = some words) :
    words.length = requested := by
  induction inputs generalizing accumulated with
  | nil =>
      by_cases enough : requested ≤ accumulated.length
      · have equal : accumulated.take requested = words := Option.some.inj (by
          simpa only [scan, if_pos enough] using succeeded)
        rw [← equal, List.length_take, Nat.min_eq_left enough]
      · simp only [scan, if_neg enough] at succeeded
        cases succeeded
  | cons input rest ih =>
      by_cases enough : requested ≤ accumulated.length
      · have equal : accumulated.take requested = words := Option.some.inj (by
          simpa only [scan, if_pos enough] using succeeded)
        rw [← equal, List.length_take, Nat.min_eq_left enough]
      · apply ih (accumulated ++ acceptedWords (oracle input))
        simpa only [scan, if_neg enough] using succeeded

def counterKeys (role : List Byte) (requested : Nat) (digest : RawDigest) : List RawInput :=
  (List.range (callCap requested)).map (counterInput role digest)

def fieldXof (role : List Byte) (requested : Nat) (digest : RawDigest) :
    Program (Option (List FieldWord)) := fieldLoop requested [] (counterKeys role requested digest)

def poisonWords (requested : Nat) : List FieldWord :=
  List.ofFn fun index : Fin requested =>
    ⟨modulus - 1 - index.val, by
      have positive : 0 < modulus := by decide
      omega⟩

def returnedWords (requested : Nat) (sampled : Option (List FieldWord)) : List FieldWord :=
  sampled.getD (poisonWords requested)

def pendingFailure (pending : Bool) (sampled : Option (List FieldWord)) : Bool :=
  pending || sampled.isNone

def zeroWord : FieldWord := ⟨0, by decide⟩

/-- Five coefficients blocks of 140 words, row-major exactly as
derive_decs_challenge(...Uniform).chunks_exact(140). -/
def gammaWord (words : List FieldWord) (row : Fin 5) (column : Fin 140) : Nat :=
  (words.getD (row.val * 140 + column.val) zeroWord).val

def mcaValue (input : Input) (words : List FieldWord) (row : Fin 5) (query : Fin 38) : Nat :=
  let sum := (List.range 140).foldl (fun acc column =>
    (acc + V8SmzaOracleParser.wordAt (input.payloads query) (14 + column) *
      (words.getD (row.val * 140 + column) zeroWord).val) % modulus) 0
  (sum + V8SmzaOracleParser.wordAt (input.payloads query) (155 + row.val)) % modulus

structure PostMerkle where
  root : RawDigest
  sampled : Option (List FieldWord)
  pending : Bool
  values : Fin 5 → Fin 38 → Nat

/-- Source stage after the checked Merkle core. XOF failure is retained as
data for the eventual scope-finish guard, not silently replaced by success. -/
def afterMerkle (input : Input) (root : RawDigest) : Program PostMerkle :=
  (fieldXof SmallWoodTranscript.decsCoefficientDomain 700 root).bind fun sampled =>
    .done (some ⟨root, sampled, pendingFailure input.pendingXofFailure sampled,
      mcaValue input (returnedWords 700 sampled)⟩)

def postMerkleProgram (ns : Namespace) (input : Input) : Program PostMerkle :=
  (merkleProgram ns input).bind (afterMerkle input)

theorem after_merkle_result (oracle : Oracle) (input : Input) (root : RawDigest) :
    (afterMerkle input root).eval oracle =
      let sampled := scan oracle 700 []
        (counterKeys SmallWoodTranscript.decsCoefficientDomain 700 root)
      some ⟨root, sampled, pendingFailure input.pendingXofFailure sampled,
        mcaValue input (returnedWords 700 sampled)⟩ := by
  simp only [afterMerkle, Program.eval_bind, fieldXof, field_loop_executes_scan,
    Option.bind_some, Program.eval]

-- Projection reasoning below needs only the returned constructor, not
-- normalization of the 92-block scan or the 38-by-23 Merkle execution.
attribute [local irreducible] scan counterKeys merkleProgram mcaValue returnedWords

/-- Success of the post-Merkle program itself supplies the previously
checked Merkle execution. The sampler is not a freely supplied certificate. -/
theorem post_merkle_has_executed_core (ns : Namespace) (oracle : Oracle) (input : Input)
    (result : PostMerkle)
    (succeeded : (postMerkleProgram ns input).eval oracle = some result) :
    (merkleProgram ns input).eval oracle = some result.root ∧
      result.sampled = scan oracle 700 []
        (counterKeys SmallWoodTranscript.decsCoefficientDomain 700 result.root) ∧
      result.pending = pendingFailure input.pendingXofFailure result.sampled ∧
      result.values = mcaValue input (returnedWords 700 result.sampled) := by
  have composed : ((merkleProgram ns input).eval oracle).bind
      (fun root => (afterMerkle input root).eval oracle) = some result := by
    exact (Program.eval_bind oracle _ _).symm.trans succeeded
  cases core : (merkleProgram ns input).eval oracle with
  | none =>
      simp only [core, Option.bind_none] at composed
      cases composed
  | some root =>
      have equal :
          (⟨root, scan oracle 700 []
              (counterKeys SmallWoodTranscript.decsCoefficientDomain 700 root),
            pendingFailure input.pendingXofFailure
              (scan oracle 700 [] (counterKeys SmallWoodTranscript.decsCoefficientDomain 700 root)),
            mcaValue input (returnedWords 700
              (scan oracle 700 [] (counterKeys SmallWoodTranscript.decsCoefficientDomain 700 root)))⟩ :
            PostMerkle) = result := Option.some.inj (by
              simpa only [core, Option.bind_some, after_merkle_result] using composed)
      have rootEq : result.root = root := (congrArg PostMerkle.root equal).symm
      have sampledEq : result.sampled = scan oracle 700 []
          (counterKeys SmallWoodTranscript.decsCoefficientDomain 700 root) :=
        (congrArg PostMerkle.sampled equal).symm
      refine ⟨congrArg some rootEq.symm, ?_, ?_, ?_⟩
      · rw [rootEq]
        exact sampledEq
      · rw [sampledEq]
        exact (congrArg PostMerkle.pending equal).symm
      · rw [sampledEq]
        exact (congrArg PostMerkle.values equal).symm

theorem finished_xof_has_exact_words (pending : Bool) (sampled : Option (List FieldWord))
    (finished : pendingFailure pending sampled = false) :
    pending = false ∧ ∃ words, sampled = some words := by
  cases pending <;> cases sampled <;> simp_all [pendingFailure]

/-- Literal first-distinct q38 collector. The source's p-1 poison values
can produce a full selection, so `queryResult` must retain pending rejection. -/
def collectIndices : List FieldWord → List Nat → List Nat
  | [], selected => selected
  | word :: rest, selected =>
      if selected.length = 38 then selected
      else if word.val < (modulus / 8388608) * 8388608 then
        let index := word.val % 8388608
        if index ∈ selected then collectIndices rest selected
        else collectIndices rest (selected.concat index)
      else collectIndices rest selected

def queryResult (pending : Bool) (sampled : Option (List FieldWord)) : Option (List Nat) :=
  let selected := (collectIndices (returnedWords 50 sampled) []).mergeSort
    (fun left right => decide (left ≤ right))
  if pendingFailure pending sampled then none
  else if selected.length = 38 then some selected else none

def queryProgram (pending : Bool) (openingDigest : RawDigest) : Program (List Nat) :=
  (fieldXof SmallWoodTranscript.decsFixedSamplingDomain 50 openingDigest).bind
    (fun sampled => .done (queryResult pending sampled))

theorem query_program_exact (oracle : Oracle) (pending : Bool) (openingDigest : RawDigest) :
    (queryProgram pending openingDigest).eval oracle =
      queryResult pending (scan oracle 50 []
        (counterKeys SmallWoodTranscript.decsFixedSamplingDomain 50 openingDigest)) := by
  simp only [queryProgram, Program.eval_bind, fieldXof, field_loop_executes_scan,
    Option.bind_some, Program.eval]

end HegemonCrypto.SmallWood.SmzaRp05ExecutableChallengeStage
