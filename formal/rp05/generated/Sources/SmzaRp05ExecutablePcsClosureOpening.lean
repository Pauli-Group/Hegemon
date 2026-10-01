import SmzaRp05ExecutablePcsClosure

/-!
# Actual first-success opening evidence

The opening transcript is extracted from a clean ordinary execution. Earlier
nonce vectors have actual sampler success and actual decoder failure; the
selected vector has actual decoder success. Nothing is required for unvisited
later nonces. The source's repeated selected-nonce read is preserved.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureOpening

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage
  (FieldWord scan returnedWords pendingFailure fieldLoop)
open SmzaRp05ExecutablePcsClosure (openingAttempt openingScan canonicalOpening)
open SmzaRp05CurrentOpeningProgram (openingFieldInputs decodeOpeningWords)
open V8Smz9PiopSoundness (Opening)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false
noncomputable section

def DecodedAt (oracle : Oracle) (digest : RawDigest) (nonce : Nat)
    (result : Option Opening) : Prop :=
  ∃ words, scan oracle 6 [] (openingFieldInputs digest nonce) = some words ∧
    decodeOpeningWords words = result

theorem opening_attempt_exact (pending : Bool) (digest : RawDigest) (nonce : Nat)
    (oracle : Oracle) :
    (openingAttempt pending digest nonce).eval oracle =
      let sampled := scan oracle 6 [] (openingFieldInputs digest nonce)
      some (decodeOpeningWords (returnedWords 6 sampled), pendingFailure pending sampled) := by
  simp only [openingAttempt, Program.eval_bind,
    SmzaRp05ExecutableChallengeStage.field_loop_executes_scan,
    Option.bind_some, Program.eval]

theorem opening_attempt_clean (pending : Bool) (digest : RawDigest) (nonce : Nat)
    (oracle : Oracle) (result : Option Opening) (nextPending : Bool)
    (executed : (openingAttempt pending digest nonce).eval oracle = some (result, nextPending))
    (clean : nextPending = false) :
    pending = false ∧ DecodedAt oracle digest nonce result := by
  rw [opening_attempt_exact] at executed
  have equal := Option.some.inj executed
  have decodedEqual := congrArg Prod.fst equal
  have pendingEqual := congrArg Prod.snd equal
  obtain ⟨earlierClean, words, sampled⟩ :=
    SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words _ _
      (pendingEqual.trans clean)
  refine ⟨earlierClean, words, sampled, ?_⟩
  simpa only [sampled, returnedWords, Option.getD_some] using decodedEqual

theorem opening_scan_clean (digest : RawDigest) (nonces : List Nat)
    (pending : Bool) (oracle : Oracle) (selected : Nat) (opening : Opening)
    (finalPending : Bool)
    (executed : (openingScan digest nonces pending).eval oracle =
      some (selected, opening, finalPending)) (clean : finalPending = false) :
    pending = false ∧ ∃ before after,
      nonces = before ++ selected :: after ∧
      (∀ nonce ∈ before, DecodedAt oracle digest nonce none) ∧
      DecodedAt oracle digest selected (some opening) := by
  induction nonces generalizing pending with
  | nil => simp [openingScan, Program.eval] at executed
  | cons nonce rest ih =>
      simp only [openingScan] at executed
      obtain ⟨attempt, attempted, continuation⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (openingAttempt pending digest nonce) _ (selected, opening, finalPending) executed
      rcases attempt with ⟨result, nextPending⟩
      cases result with
      | none =>
          obtain ⟨nextClean, before, after, decomposition, prior, decoded⟩ :=
            ih nextPending continuation
          obtain ⟨earlierClean, failed⟩ :=
            opening_attempt_clean pending digest nonce oracle none nextPending attempted nextClean
          refine ⟨earlierClean, nonce :: before, after, ?_, ?_, decoded⟩
          · simp [decomposition]
          · intro earlier member
            rcases List.mem_cons.mp member with equal | member
            · simpa only [equal] using failed
            · exact prior earlier member
      | some points =>
          have equal : (nonce, points, nextPending) = (selected, opening, finalPending) :=
            Option.some.inj continuation
          have nonceEqual : nonce = selected := congrArg Prod.fst equal
          have openingEqual : points = opening := congrArg (fun value => value.2.1) equal
          have pendingEqual : nextPending = finalPending := congrArg (fun value => value.2.2) equal
          subst selected
          subst points
          obtain ⟨earlierClean, decoded⟩ := opening_attempt_clean pending digest nonce oracle
            (some opening) nextPending attempted (pendingEqual.trans clean)
          exact ⟨earlierClean, [], rest, rfl, by simp, decoded⟩

/-- Clean acceptance of the canonical-opening stage yields precisely the
prior-failures/selected-success interface needed by fixed-nonce replay. -/
theorem canonical_opening_clean (pending : Bool) (nonce : Fin (2 ^ 32))
    (digest : RawDigest) (oracle : Oracle) (opening : Opening) (finalPending : Bool)
    (executed : (canonicalOpening pending nonce digest).eval oracle =
      some (opening, finalPending)) (clean : finalPending = false) :
    pending = false ∧ ∃ before after,
      List.range 16 = before ++ nonce.val :: after ∧
      (∀ earlier ∈ before, DecodedAt oracle digest earlier none) ∧
      DecodedAt oracle digest nonce.val (some opening) := by
  unfold canonicalOpening at executed
  obtain ⟨chosen, scanned, continuation⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (openingScan digest (List.range 16) pending) _ (opening, finalPending) executed
  rcases chosen with ⟨expected, earlierOpening, nextPending⟩
  by_cases equal : nonce.val = expected
  · simp only [if_pos equal] at continuation
    obtain ⟨attempt, attempted, returned⟩ :=
      SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
        (openingAttempt nextPending digest nonce.val) _ (opening, finalPending) continuation
    rcases attempt with ⟨result, repeatedPending⟩
    cases result with
    | none => simp [Program.eval] at returned
    | some points =>
        have pairEqual : (points, repeatedPending) = (opening, finalPending) :=
          Option.some.inj returned
        have openingEqual : points = opening := congrArg Prod.fst pairEqual
        have pendingEqual : repeatedPending = finalPending := congrArg Prod.snd pairEqual
        subst points
        obtain ⟨nextClean, decoded⟩ := opening_attempt_clean nextPending digest nonce.val
          oracle (some opening) repeatedPending attempted (pendingEqual.trans clean)
        obtain ⟨earlierClean, before, after, decomposition, prior, _firstDecoded⟩ :=
          opening_scan_clean digest (List.range 16) pending oracle expected earlierOpening
            nextPending scanned nextClean
        exact ⟨earlierClean, before, after, by simpa only [equal] using decomposition,
          prior, decoded⟩
  · simp [equal, Program.eval] at continuation

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureOpening
