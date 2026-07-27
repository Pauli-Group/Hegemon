import HegemonCrypto.SmallWoodProofWire

namespace HegemonCrypto
namespace SmallWoodCandidateWire

open CanonicalBytes

structure CountedWire where
  countBytes : List Byte
  payloadBytes : List Byte
deriving DecidableEq, Repr

namespace CountedWire

def count (wire : CountedWire) : Nat :=
  decodeLE wire.countBytes

def encode (wire : CountedWire) : List Byte :=
  wire.countBytes ++ wire.payloadBytes

def Canonical (itemWidth : Nat) (wire : CountedWire) : Prop :=
  wire.countBytes.length = 8
    ∧ wire.payloadBytes.length = wire.count * itemWidth

end CountedWire

def decodeCountedPrefix
    (itemWidth : Nat)
    (input : List Byte) : Option (CountedWire × List Byte) := do
  let (countBytes, afterCount) ← readFixed 8 input
  let count := decodeLE countBytes
  let (payloadBytes, suffix) ← readFixed (count * itemWidth) afterCount
  some ({ countBytes, payloadBytes }, suffix)

theorem decodeCountedPrefix_encode
    (itemWidth : Nat)
    (wire : CountedWire)
    (suffix : List Byte)
    (canonical : wire.Canonical itemWidth) :
    decodeCountedPrefix itemWidth (wire.encode ++ suffix) = some (wire, suffix) := by
  rcases canonical with ⟨count_length, payload_length⟩
  change wire.payloadBytes.length = decodeLE wire.countBytes * itemWidth at payload_length
  simp [decodeCountedPrefix, CountedWire.encode, count_length, payload_length,
    List.append_assoc]

theorem decodeCountedPrefix_sound
    {itemWidth : Nat}
    {input : List Byte}
    {wire : CountedWire}
    {suffix : List Byte}
    (decoded : decodeCountedPrefix itemWidth input = some (wire, suffix)) :
    wire.Canonical itemWidth ∧ input = wire.encode ++ suffix := by
  unfold decodeCountedPrefix at decoded
  cases countResult : readFixed 8 input with
  | none => simp [countResult] at decoded
  | some countPair =>
      rcases countPair with ⟨countBytes, afterCount⟩
      cases payloadResult : readFixed (decodeLE countBytes * itemWidth) afterCount with
      | none => simp [countResult, payloadResult] at decoded
      | some payloadPair =>
          rcases payloadPair with ⟨payloadBytes, finalSuffix⟩
          simp [countResult, payloadResult] at decoded
          rcases decoded with ⟨wire_eq, suffix_eq⟩
          subst wire
          subst suffix
          rcases readFixed_sound countResult with ⟨count_length, input_eq⟩
          rcases readFixed_sound payloadResult with
            ⟨payload_length, after_count_eq⟩
          constructor
          · exact ⟨count_length, payload_length⟩
          · simp only [CountedWire.encode]
            rw [input_eq, after_count_eq, List.append_assoc]

def countedCodec (itemWidth : Nat) : PrefixCodec CountedWire where
  encode := CountedWire.encode
  decode := decodeCountedPrefix itemWidth
  canonical := CountedWire.Canonical itemWidth
  decode_encode := decodeCountedPrefix_encode itemWidth
  decode_sound := decodeCountedPrefix_sound

def maximumArithmetizationVariant : Nat := 9
def activeArithmetizationVariant : Nat := 9

structure CurrentCandidateWire where
  arithmetizationBytes : List Byte
  innerProof : CountedWire
  auxiliaryWitnessWords : CountedWire
deriving DecidableEq, Repr

namespace CurrentCandidateWire

def arithmetization (wire : CurrentCandidateWire) : Nat :=
  decodeLE wire.arithmetizationBytes

def encode (wire : CurrentCandidateWire) : List Byte :=
  wire.arithmetizationBytes
    ++ wire.innerProof.encode
    ++ wire.auxiliaryWitnessWords.encode

def Canonical (wire : CurrentCandidateWire) : Prop :=
  wire.arithmetizationBytes.length = 4
    ∧ wire.arithmetization <= maximumArithmetizationVariant
    ∧ wire.innerProof.Canonical 1
    ∧ wire.auxiliaryWitnessWords.Canonical 8

def ActiveWrapper (wire : CurrentCandidateWire) : Prop :=
  wire.Canonical
    ∧ wire.auxiliaryWitnessWords.count = 0

def ActiveVerifierInput (wire : CurrentCandidateWire) : Prop :=
  wire.ActiveWrapper
    ∧ wire.arithmetization = activeArithmetizationVariant
    ∧ wire.innerProof.payloadBytes ≠ []

end CurrentCandidateWire

def decodeCurrentCandidatePrefix
    (input : List Byte) : Option (CurrentCandidateWire × List Byte) := do
  let (arithmetizationBytes, afterArithmetization) ← readFixed 4 input
  if decodeLE arithmetizationBytes <= maximumArithmetizationVariant then
    let (innerProof, afterInnerProof) ←
      decodeCountedPrefix 1 afterArithmetization
    let (auxiliaryWitnessWords, suffix) ←
      decodeCountedPrefix 8 afterInnerProof
    some ({ arithmetizationBytes, innerProof, auxiliaryWitnessWords }, suffix)
  else
    none

theorem decodeCurrentCandidatePrefix_encode
    (wire : CurrentCandidateWire)
    (suffix : List Byte)
    (canonical : wire.Canonical) :
    decodeCurrentCandidatePrefix (wire.encode ++ suffix) = some (wire, suffix) := by
  rcases canonical with
    ⟨arithmetization_length, arithmetization_bound, innerCanonical,
      auxiliaryCanonical⟩
  change
    decodeLE wire.arithmetizationBytes <= maximumArithmetizationVariant
    at arithmetization_bound
  unfold decodeCurrentCandidatePrefix CurrentCandidateWire.encode
  simp only [List.append_assoc]
  rw [readFixed_append arithmetization_length]
  simp [arithmetization_bound]
  rw [decodeCountedPrefix_encode 1 wire.innerProof
    (wire.auxiliaryWitnessWords.encode ++ suffix) innerCanonical]
  simp only [Option.bind_some]
  rw [decodeCountedPrefix_encode 8 wire.auxiliaryWitnessWords suffix auxiliaryCanonical]
  rfl

theorem decodeCurrentCandidatePrefix_sound
    {input : List Byte}
    {wire : CurrentCandidateWire}
    {suffix : List Byte}
    (decoded : decodeCurrentCandidatePrefix input = some (wire, suffix)) :
    wire.Canonical ∧ input = wire.encode ++ suffix := by
  unfold decodeCurrentCandidatePrefix at decoded
  cases arithmetizationResult : readFixed 4 input with
  | none => simp [arithmetizationResult] at decoded
  | some arithmetizationPair =>
      rcases arithmetizationPair with
        ⟨arithmetizationBytes, afterArithmetization⟩
      simp [arithmetizationResult] at decoded
      rcases decoded with ⟨arithmetization_bound, decoded⟩
      cases innerResult : decodeCountedPrefix 1 afterArithmetization with
      | none => simp [innerResult] at decoded
      | some innerPair =>
          rcases innerPair with ⟨innerProof, afterInnerProof⟩
          cases auxiliaryResult : decodeCountedPrefix 8 afterInnerProof with
          | none => simp [innerResult, auxiliaryResult] at decoded
          | some auxiliaryPair =>
              rcases auxiliaryPair with ⟨auxiliaryWitnessWords, finalSuffix⟩
              simp [innerResult, auxiliaryResult] at decoded
              rcases decoded with ⟨wire_eq, suffix_eq⟩
              subst wire
              subst suffix
              rcases readFixed_sound arithmetizationResult with
                ⟨arithmetization_length, input_eq⟩
              rcases decodeCountedPrefix_sound innerResult with
                ⟨innerCanonical, after_arithmetization_eq⟩
              rcases decodeCountedPrefix_sound auxiliaryResult with
                ⟨auxiliaryCanonical, after_inner_eq⟩
              constructor
              · exact
                  ⟨arithmetization_length, arithmetization_bound,
                    innerCanonical, auxiliaryCanonical⟩
              · unfold CurrentCandidateWire.encode
                rw [input_eq, after_arithmetization_eq, after_inner_eq]
                simp [List.append_assoc]

def decodeCurrentCandidateExact (input : List Byte) : Option CurrentCandidateWire := do
  let (wire, suffix) ← decodeCurrentCandidatePrefix input
  if suffix = [] then some wire else none

theorem decodeCurrentCandidateExact_encode
    (wire : CurrentCandidateWire)
    (canonical : wire.Canonical) :
    decodeCurrentCandidateExact wire.encode = some wire := by
  unfold decodeCurrentCandidateExact
  rw [show wire.encode = wire.encode ++ [] by simp]
  rw [decodeCurrentCandidatePrefix_encode wire [] canonical]
  rfl

theorem decodeCurrentCandidateExact_sound
    {input : List Byte}
    {wire : CurrentCandidateWire}
    (decoded : decodeCurrentCandidateExact input = some wire) :
    wire.Canonical ∧ input = wire.encode := by
  unfold decodeCurrentCandidateExact at decoded
  cases prefixResult : decodeCurrentCandidatePrefix input with
  | none => simp [prefixResult] at decoded
  | some prefixPair =>
      rcases prefixPair with ⟨parsedWire, suffix⟩
      simp [prefixResult] at decoded
      rcases decoded with ⟨suffix_empty, wire_eq⟩
      subst parsedWire
      subst suffix
      simpa using decodeCurrentCandidatePrefix_sound prefixResult

def decodeActiveWrapperExact (input : List Byte) : Option CurrentCandidateWire := do
  let wire ← decodeCurrentCandidateExact input
  if wire.auxiliaryWitnessWords.count = 0 then some wire else none

theorem decodeActiveWrapperExact_encode
    (wire : CurrentCandidateWire)
    (active : wire.ActiveWrapper) :
    decodeActiveWrapperExact wire.encode = some wire := by
  rcases active with ⟨canonical, auxiliary_empty⟩
  unfold decodeActiveWrapperExact
  rw [decodeCurrentCandidateExact_encode wire canonical]
  simp [auxiliary_empty]

theorem decodeActiveWrapperExact_sound
    {input : List Byte}
    {wire : CurrentCandidateWire}
    (decoded : decodeActiveWrapperExact input = some wire) :
    wire.ActiveWrapper ∧ input = wire.encode := by
  unfold decodeActiveWrapperExact at decoded
  cases currentResult : decodeCurrentCandidateExact input with
  | none => simp [currentResult] at decoded
  | some parsedWire =>
      simp [currentResult] at decoded
      rcases decoded with ⟨auxiliary_empty, wire_eq⟩
      subst parsedWire
      rcases decodeCurrentCandidateExact_sound currentResult with
        ⟨canonical, input_eq⟩
      exact ⟨⟨canonical, auxiliary_empty⟩, input_eq⟩

structure LegacyCandidateWire where
  arithmetizationBytes : List Byte
  innerProof : CountedWire
deriving DecidableEq, Repr

namespace LegacyCandidateWire

def arithmetization (wire : LegacyCandidateWire) : Nat :=
  decodeLE wire.arithmetizationBytes

def encode (wire : LegacyCandidateWire) : List Byte :=
  wire.arithmetizationBytes ++ wire.innerProof.encode

def Canonical (wire : LegacyCandidateWire) : Prop :=
  wire.arithmetizationBytes.length = 4
    ∧ wire.arithmetization <= maximumArithmetizationVariant
    ∧ wire.innerProof.Canonical 1

end LegacyCandidateWire

theorem active_version_rejects_canonical_legacy_wrapper
    (wire : LegacyCandidateWire)
    (canonical : wire.Canonical) :
    decodeActiveWrapperExact wire.encode = none := by
  rcases canonical with
    ⟨arithmetization_length, arithmetization_bound, innerCanonical⟩
  change
    decodeLE wire.arithmetizationBytes <= maximumArithmetizationVariant
    at arithmetization_bound
  have inner_decoded :
      decodeCountedPrefix 1 wire.innerProof.encode =
        some (wire.innerProof, []) := by
    simpa using decodeCountedPrefix_encode 1 wire.innerProof [] innerCanonical
  have auxiliary_rejected : decodeCountedPrefix 8 [] = none := by
    rfl
  have current_rejected : decodeCurrentCandidatePrefix wire.encode = none := by
    unfold decodeCurrentCandidatePrefix LegacyCandidateWire.encode
    rw [readFixed_append arithmetization_length]
    simp [arithmetization_bound, inner_decoded, auxiliary_rejected]
  simp [decodeActiveWrapperExact, decodeCurrentCandidateExact, current_rejected]

structure ActiveProofArtifact where
  wrapper : CurrentCandidateWire
  proof : SmallWoodProofWire.ProofWire
deriving DecidableEq, Repr

namespace ActiveProofArtifact

def encode (artifact : ActiveProofArtifact) : List Byte :=
  artifact.wrapper.encode

def Canonical (artifact : ActiveProofArtifact) : Prop :=
  artifact.wrapper.ActiveWrapper
    ∧ artifact.wrapper.arithmetization = activeArithmetizationVariant
    ∧ artifact.proof.Canonical
    ∧ artifact.wrapper.innerProof.payloadBytes = artifact.proof.encode

end ActiveProofArtifact

def decodeActiveProofArtifactExact
    (input : List Byte) : Option ActiveProofArtifact := do
  let wrapper ← decodeActiveWrapperExact input
  if wrapper.arithmetization = activeArithmetizationVariant then
    let proof ←
      SmallWoodProofWire.decodeProofExact wrapper.innerProof.payloadBytes
    some { wrapper, proof }
  else
    none

theorem decodeActiveProofArtifactExact_encode
    (artifact : ActiveProofArtifact)
    (canonical : artifact.Canonical) :
    decodeActiveProofArtifactExact artifact.encode = some artifact := by
  rcases canonical with
    ⟨wrapperCanonical, activeArithmetization, proofCanonical,
      payload_eq⟩
  unfold decodeActiveProofArtifactExact ActiveProofArtifact.encode
  rw [decodeActiveWrapperExact_encode artifact.wrapper wrapperCanonical]
  simp [activeArithmetization]
  rw [payload_eq]
  rw [SmallWoodProofWire.decodeProofExact_encode artifact.proof proofCanonical]
  rfl

theorem decodeActiveProofArtifactExact_sound
    {input : List Byte}
    {artifact : ActiveProofArtifact}
    (decoded : decodeActiveProofArtifactExact input = some artifact) :
    artifact.Canonical ∧ input = artifact.encode := by
  unfold decodeActiveProofArtifactExact at decoded
  cases wrapperResult : decodeActiveWrapperExact input with
  | none => simp [wrapperResult] at decoded
  | some wrapper =>
      simp [wrapperResult] at decoded
      rcases decoded with ⟨activeArithmetization, decoded⟩
      cases proofResult :
          SmallWoodProofWire.decodeProofExact wrapper.innerProof.payloadBytes with
      | none => simp [proofResult] at decoded
      | some proof =>
          simp [proofResult] at decoded
          subst artifact
          rcases decodeActiveWrapperExact_sound wrapperResult with
            ⟨wrapperCanonical, input_eq⟩
          rcases SmallWoodProofWire.decodeProofExact_sound proofResult with
            ⟨proofCanonical, payload_eq⟩
          constructor
          · exact
              ⟨wrapperCanonical, activeArithmetization, proofCanonical,
                payload_eq⟩
          · exact input_eq

end SmallWoodCandidateWire
end HegemonCrypto
