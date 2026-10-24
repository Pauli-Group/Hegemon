import HegemonCrypto.NativeLaunchRelationModelStatement

/-!
Two-stage deterministic raw-query binding for the native RP06/HTLC source at
c9983d0060634c5ce05bb8e0bd72028bb3b322a5 (runtime identical to 6758fe30).
The final PIOP transcript begins with the eight words of H(FPP input).
The only modeled acceptance check is final digest comparison. Recorded query provenance
and absence of collisions on the finite relevant inputs imply raw FPP equality.
History membership is not chronological precedence or authenticated Rust
execution. No probability, QROM, polynomial, semantic or release claim follows.
-/
set_option autoImplicit false
namespace HegemonCrypto.NativeLaunchFppHistoryBinding
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput profileDomain)
open NativeLaunchRelationModelStatement (typed_payload_append)
open SmallWood.V8Smz9RawCounterCompiler
  (typedWordPayload typed_word_payload_length typed_word_payload_injective
   typed_word_payload_is_source_payload)
open SmallWood.V8Smz9WholeViewObservation (RawSha512OracleKey)

abbrev Digest := Fin 8 → Word
abbrev Oracle := RawInput → Digest
abbrev History := List RawInput

/-- Literal `hegemon.smallwood.level5.piop-transcript` role. -/
def finalRole : List Byte :=
  [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,108,101,118,101,108,53,46,112,105,111,112,45,116,114,97,110,115,99,114,105,112,116]

def digestBytes (digest : Digest) : RawInput := typedWordPayload (List.ofFn digest)
def finalHeader (family : Family) (tail : List Word) : RawInput :=
  encodeLE 8 (profileDomain family).length ++ profileDomain family ++
  encodeLE 8 finalRole.length ++ finalRole ++ encodeLE 8 (8 + tail.length)
def headerBytes (family : Family) : Nat := 24 + (profileDomain family).length + finalRole.length
def finalFrame (family : Family) (digest : Digest) (tail : List Word) : RawInput :=
  finalHeader family tail ++
    (digestBytes digest ++ (typedWordPayload tail ++ encodeLE 8 0))

theorem literal_role_length : finalRole.length = 40 := by decide

/-- Exact conventional SHA-512 preimage, including zero counter. -/
theorem final_frame_is_raw_preimage (family : Family) (digest : Digest) (tail : List Word) :
    finalFrame family digest tail =
      (RawSha512OracleKey.mk (some (profileDomain family)) finalRole
        ((List.ofFn digest ++ tail).map Fin.val) 0).preimage := by
  simp only [RawSha512OracleKey.preimage, List.length_map]
  rw [← typed_word_payload_is_source_payload]
  simp only [finalFrame, finalHeader, digestBytes, List.length_append, List.length_ofFn,
    typed_payload_append, List.append_assoc]

theorem digest_bytes_length (digest : Digest) : (digestBytes digest).length = 64 := by
  simp [digestBytes, typed_word_payload_length]

theorem final_header_length (family : Family) (tail : List Word) :
    (finalHeader family tail).length = headerBytes family := by
  simp only [finalHeader, headerBytes, List.length_append, encodeLE_length]
  omega

/-- The offset is independent of tail length: the word-count field occupies eight bytes. -/
theorem final_digest_projection (family : Family) (digest : Digest) (tail : List Word) :
    ((finalFrame family digest tail).drop (headerBytes family)).take 64 = digestBytes digest := by
  unfold finalFrame
  rw [← final_header_length family tail, List.drop_left, ← digest_bytes_length digest]
  exact List.take_left

theorem final_frame_digest_injective (family : Family) (left right : Digest)
    (ltail rtail : List Word) (equal : finalFrame family left ltail = finalFrame family right rtail) :
    left = right := by
  have projected := congrArg (fun bytes => (bytes.drop (headerBytes family)).take 64) equal
  rw [final_digest_projection, final_digest_projection] at projected
  exact List.ofFn_injective (typed_word_payload_injective projected)

/-- The source hashes reconstructed FPP bytes, prefixes that digest, then hashes the final frame. -/
def reconstructedFinal (H : Oracle) (family : Family) (fpp : RawInput) (tail : List Word) : RawInput :=
  finalFrame family (H fpp) tail
def reconstructedDigest (H : Oracle) (family : Family) (fpp : RawInput) (tail : List Word) : Digest :=
  H (reconstructedFinal H family fpp tail)

/-- The list adds exactly the two verifier query inputs to the recorded history. -/
def relevantInputs (H : Oracle) (history : History) (family : Family)
    (fpp : RawInput) (tail : List Word) : History :=
  fpp :: reconstructedFinal H family fpp tail :: history

def RelevantCollision (H : Oracle) (inputs : History) : Prop :=
  ∃ left ∈ inputs, ∃ right ∈ inputs, left ≠ right ∧ H left = H right

/-- This is finite-set collision exclusion, not injectivity on all raw strings. -/
theorem equal_of_no_relevant_collision (H : Oracle) (inputs : History)
    (clean : ¬ RelevantCollision H inputs) (left right : RawInput)
    (leftMem : left ∈ inputs) (rightMem : right ∈ inputs) (equal : H left = H right) :
    left = right := by
  by_contra different
  exact clean ⟨left, leftMem, right, rightMem, different, equal⟩

/-- The recorded final query contains the digest of the recorded FPP query.
Membership alone intentionally imposes no temporal order. -/
def RecordedChain (H : Oracle) (history : History) (family : Family)
    (priorFpp : RawInput) (priorTail : List Word) (claimed : Digest) : Prop :=
  priorFpp ∈ history ∧
  finalFrame family (H priorFpp) priorTail ∈ history ∧
  H (finalFrame family (H priorFpp) priorTail) = claimed

theorem accepted_digest_binds_raw_fpp (H : Oracle) (history : History) (family : Family)
    (priorFpp rebuiltFpp : RawInput) (priorTail rebuiltTail : List Word) (claimed : Digest)
    (recorded : RecordedChain H history family priorFpp priorTail claimed)
    (accepted : reconstructedDigest H family rebuiltFpp rebuiltTail = claimed)
    (clean : ¬ RelevantCollision H (relevantInputs H history family rebuiltFpp rebuiltTail)) :
    priorFpp = rebuiltFpp := by
  obtain ⟨priorMem, finalMem, priorDigest⟩ := recorded
  have finalEqual : finalFrame family (H priorFpp) priorTail =
      reconstructedFinal H family rebuiltFpp rebuiltTail :=
    equal_of_no_relevant_collision H _ clean _ _
      (by simp [relevantInputs, finalMem])
      (by simp [relevantInputs])
      (priorDigest.trans accepted.symm)
  have fppDigestEqual : H priorFpp = H rebuiltFpp :=
    final_frame_digest_injective family _ _ priorTail rebuiltTail finalEqual
  exact equal_of_no_relevant_collision H _ clean _ _
    (by simp [relevantInputs, priorMem]) (by simp [relevantInputs]) fppDigestEqual

/-- Deterministic cover only: absent selected provenance or a relevant collision
or raw-key agreement. It assigns no probability to either exceptional event. -/
theorem accepted_event_cover (H : Oracle) (history : History) (family : Family)
    (priorFpp rebuiltFpp : RawInput) (priorTail rebuiltTail : List Word) (claimed : Digest)
    (accepted : reconstructedDigest H family rebuiltFpp rebuiltTail = claimed) :
    ¬ RecordedChain H history family priorFpp priorTail claimed ∨
    RelevantCollision H (relevantInputs H history family rebuiltFpp rebuiltTail) ∨
    priorFpp = rebuiltFpp := by
  by_cases recorded : RecordedChain H history family priorFpp priorTail claimed
  · by_cases collision : RelevantCollision H (relevantInputs H history family rebuiltFpp rebuiltTail)
    · exact Or.inr (Or.inl collision)
    · exact Or.inr (Or.inr (accepted_digest_binds_raw_fpp H history family
        priorFpp rebuiltFpp priorTail rebuiltTail claimed recorded accepted collision))
  · exact Or.inl recorded

end HegemonCrypto.NativeLaunchFppHistoryBinding
