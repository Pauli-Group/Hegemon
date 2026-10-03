import SmzaRp05ExecutableChallengeStage

/-!
# Executable final RP05 digest gate

SOURCE-ONLY; not compiler-checked. This is a finalization COMPONENT, not a
decoded-proof verifier and not a new proof format. Its intermediate arrays
are the ordinary output of reconstruction, not proof-carried certificates.

Source anchors: smallwood_engine.rs `piop_recompute_transcript` appends the
eight hash_fpp words followed, for each of five repetitions, by all 489
nonlinear coefficients and the 132 nonconstant linear coefficients.
`hash_piop_transcript` frames those words under the current transcript role.
`verify_smallwood_proof_with_domain` (around 5598) performs that hash call,
then `sha512_field_xof_scope.finish()`, THEN compares to proof.h_piop.
Thus even a pending-XOF rejection must retain the final hash query.

The program below is uninstrumented: acceptance depends only on its ordinary
oracle evaluation. The recorder is a separate interpreter; the theorems
derive the final query and digest equality, including rejected-run logging.
No FiveMcaChecks, TwelveLvcsChecks, ScalarChecks, or accepted certificate is
an argument. No additional guard is inserted into source acceptance.

FIRST MISSING PRIMITIVE, deliberately NOT replaced with a supplied callback:
an executable current-RP05 reconstruction from the decoded existing proof.
It must implement `pcs_recompute_transcript` (including proof-connected
`poly_restore` and LVCS reconstruction), followed by current-relation
`piop_recompute_transcript`, and propagate the SAME deferred XOF state.
ExecutableChallengeStage supplies the five-by-38 MCA values, not these
restored coefficient arrays. Existing noncomputable polynomial models do
not implement this decoded-proof execution. Consequently no composition
from Merkle/ChallengeStage to this input, or full acceptance theorem, is
claimed here. In particular there is NO extra argument asserting success
of that missing computation.

An accepted final query is the AFTER reconstruction record only. A BEFORE
preimage of proof.h_piop must come from the same measured adversary execution;
it is neither a proof field nor derivable just from digest comparison.
The five/twelve checks and scalar extraction therefore remain unproved.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableFinalVerifier

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Oracle Program Log)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false

/-- Intermediate state produced by reconstruction; NOT an accepted witness
or an extension to the serialized RP05 proof. `linearHigh` is the corrected
out_plin[1..], not the proof's uncorrected high-coefficient vector. -/
structure ReconstructedTranscript where
  hashFpp : RawDigest
  nonlinear : Fin 5 → Fin 489 → FieldWord
  linearHigh : Fin 5 → Fin 132 → FieldWord
  pendingXofFailure : Bool

def coefficientBytes {n : Nat} (coefficients : Fin n → FieldWord) : List Byte :=
  (List.ofFn coefficients).flatMap fun word => encodeLE 8 word.val

/-- Source order is repetition-major, NOT all nonlinear rows followed by
all linear rows. The raw digest prefix is precisely eight LE u64 words. -/
def finalPayload (transcript : ReconstructedTranscript) : List Byte :=
  List.ofFn transcript.hashFpp ++
    (List.ofFn fun repetition : Fin 5 =>
      coefficientBytes (transcript.nonlinear repetition) ++
        coefficientBytes (transcript.linearHigh repetition)).flatten

def finalInput (transcript : ReconstructedTranscript) : RawInput :=
  V8SmzaOracleParser.framedInput SmallWoodTranscript.piopTranscriptDomain
    (finalPayload transcript)

theorem current_final_word_count : 8 + 5 * (489 + 132) = 3113 := by decide

/-- Literal final gate. `expected` is the existing decoded proof.h_piop. -/
def verdict (pending : Bool) (expected actual : RawDigest) : Option Unit :=
  if pending then none else if actual = expected then some () else none

/-- Hash first, including on pending-error runs; reject only afterwards. -/
def finalize (expected : RawDigest) (transcript : ReconstructedTranscript) :
    Program Unit :=
  .read (finalInput transcript) fun actual =>
    .done (verdict transcript.pendingXofFailure expected actual)

def accepts (oracle : Oracle) (expected : RawDigest)
    (transcript : ReconstructedTranscript) : Bool :=
  ((finalize expected transcript).eval oracle).isSome

theorem finalize_evaluates (oracle : Oracle) (expected : RawDigest)
    (transcript : ReconstructedTranscript) :
    (finalize expected transcript).eval oracle =
      verdict transcript.pendingXofFailure expected (oracle (finalInput transcript)) := by
  rfl

/-- The final read is retained regardless of whether either final guard fails. -/
theorem finalize_records (oracle : Oracle) (expected : RawDigest)
    (transcript : ReconstructedTranscript) :
    (finalize expected transcript).record oracle =
      (verdict transcript.pendingXofFailure expected (oracle (finalInput transcript)),
        [(finalInput transcript, oracle (finalInput transcript))]) := by
  rfl

theorem verdict_success (pending : Bool) (expected actual : RawDigest) :
    verdict pending expected actual = some () ↔
      pending = false ∧ actual = expected := by
  cases pending <;> simp [verdict]

/-- Success supplies a same-run AFTER hash query with the claimed digest.
This is not a claim that arbitrary supplied transcript arrays reconstruct
the proof, and does not supply the adversary's BEFORE query. -/
theorem accepted_final_query (oracle : Oracle) (expected : RawDigest)
    (transcript : ReconstructedTranscript)
    (succeeded : (finalize expected transcript).eval oracle = some ()) :
    transcript.pendingXofFailure = false ∧
      oracle (finalInput transcript) = expected ∧
      (finalInput transcript, expected) ∈
        ((finalize expected transcript).record oracle).2 := by
  rw [finalize_evaluates] at succeeded
  obtain ⟨clean, same⟩ := (verdict_success _ _ _).mp succeeded
  refine ⟨clean, same, ?_⟩
  rw [finalize_records]
  simp only [same, List.mem_singleton]

theorem instrumentation_does_not_change_result (oracle : Oracle)
    (expected : RawDigest) (transcript : ReconstructedTranscript) :
    ((finalize expected transcript).record oracle).1 =
      (finalize expected transcript).eval oracle :=
  Program.record_result oracle (finalize expected transcript)

end HegemonCrypto.SmallWood.SmzaRp05ExecutableFinalVerifier
