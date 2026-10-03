import SmzaRp05CurrentFieldCounterParser
import SmzaRp04RawRoleSampling

/-! A successful capped source read consumes only a prefix of its digest
coordinates. Agreement on that actual prefix determines its result; no
unqueried digest value is fabricated from a retained raw-query log. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ConsumedFieldReadback

open HegemonCrypto.SmallWood.SmzaRp05CurrentFieldCounterParser
open SmzaRp04RawRoleSampling
open V8Smz9HonestRequestSchedule V8Smz9HiddenLeafQrom
open V8Smz9RawCounterCompiler V8Smz9CappedRawSampler
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentVectorMerkle
open V8Smz9RuntimeRandomness V8Smz9WholeViewObservation
open scoped Classical
noncomputable section
set_option autoImplicit false

def consumedFieldKeys {Input : Type*} (requested : Nat)
    (oracle : Input → DigestRegister) (accepted : List FieldWord) : List Input → List Input
  | [] => []
  | input :: rest => if requested ≤ accepted.length then [] else
      input :: consumedFieldKeys requested oracle
        (accepted ++ acceptedFieldWords (sourceDigestWords (oracle input))) rest

theorem source_field_loop_eq_of_consumed_agreement {Input : Type}
    (requested : Nat) (left right : Input → DigestRegister)
    (inputs : List Input) (accepted : List FieldWord)
    (agree : ∀ input ∈ consumedFieldKeys requested left accepted inputs,
      left input = right input) :
    NonleafProgram.interpret left (sourceFieldReadLoop requested accepted inputs) =
      NonleafProgram.interpret right (sourceFieldReadLoop requested accepted inputs) := by
  induction inputs generalizing accepted with
  | nil =>
      unfold sourceFieldReadLoop
      split <;> simp only [NonleafProgram.interpret]
  | cons input rest ih =>
      by_cases enough : requested ≤ accepted.length
      · simp [sourceFieldReadLoop, NonleafProgram.interpret, enough]
      · have same : left input = right input := agree input (by
          simp [consumedFieldKeys, enough])
        have below : ∀ key ∈ consumedFieldKeys requested left
            (accepted ++ acceptedFieldWords (sourceDigestWords (left input))) rest,
            left key = right key := by
          intro key member
          exact agree key (by simp [consumedFieldKeys, enough, member])
        simp only [sourceFieldReadLoop, if_neg enough, NonleafProgram.interpret]
        rw [← same]
        exact ih _ below

/-- The raw field-sampler output, including failure, is fixed by just the
digest blocks actually consumed by the source early-stop loop. -/
theorem raw_field_sample_eq_of_consumed_agreement
    (blocks requested : Nat) (left right : Fin blocks → DigestRegister)
    (agree : ∀ counter ∈ consumedFieldKeys requested left []
        (List.ofFn (fun index : Fin blocks => index)), left counter = right counter) :
    rawFieldSample blocks requested (fun counter => rawDigestBits.symm (left counter)) =
      rawFieldSample blocks requested (fun counter => rawDigestBits.symm (right counter)) := by
  have loops := source_field_loop_eq_of_consumed_agreement requested left right
    (List.ofFn (fun index : Fin blocks => index)) [] agree
  rw [source_field_loop_is_counter_parser, source_field_loop_is_counter_parser] at loops
  have parsed :
      (rawFieldSample blocks requested (fun counter => rawDigestBits.symm (left counter))).map
          List.ofFn =
      (rawFieldSample blocks requested (fun counter => rawDigestBits.symm (right counter))).map
          List.ofFn := by
    calc
      (rawFieldSample blocks requested
        (fun counter => rawDigestBits.symm (left counter))).map List.ofFn =
          parseCounterVector requested
            (fun counter => sourceDigestOfByteBlock
              (rawDigestBits.symm (left counter))) :=
                (exact_literal_byte_counter_parser requested
                  (fun counter => rawDigestBits.symm (left counter))).symm
      _ = parseCounterVector requested
            (fun counter => sourceDigest (left counter)) := by
              apply congrArg (parseCounterVector requested)
              funext counter
              exact source_digest_of_raw_bits (left counter)
      _ = parseCounterVector requested
            (fun counter => sourceDigest (right counter)) := loops
      _ = (rawFieldSample blocks requested
            (fun counter => rawDigestBits.symm (right counter))).map List.ofFn :=
              exact_literal_byte_counter_parser requested
                (fun counter => rawDigestBits.symm (right counter))
  cases leftResult : rawFieldSample blocks requested
      (fun counter => rawDigestBits.symm (left counter)) with
  | none =>
      cases rightResult : rawFieldSample blocks requested
          (fun counter => rawDigestBits.symm (right counter)) with
      | none => rfl
      | some words => simp [leftResult, rightResult] at parsed
  | some words =>
      cases rightResult : rawFieldSample blocks requested
          (fun counter => rawDigestBits.symm (right counter)) with
      | none => simp [leftResult, rightResult] at parsed
      | some other =>
          have same : words = other := List.ofFn_injective (by
            simpa only [leftResult, rightResult, Option.map_some, Option.some.injEq] using parsed)
          exact congrArg some same

end
end HegemonCrypto.SmallWood.SmzaRp05ConsumedFieldReadback
