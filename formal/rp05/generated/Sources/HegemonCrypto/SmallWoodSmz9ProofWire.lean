import HegemonCrypto.SmallWoodProofWire

set_option maxRecDepth 20000

namespace HegemonCrypto
namespace SmallWoodSmz9ProofWire

open CanonicalBytes
open SmallWoodProofWire

def openedLeafCount : Nat := 20
def openedLeafTapeBytes : Nat := 64
def openedLeafTapesBytes : Nat := openedLeafCount * openedLeafTapeBytes
def maximumAuthPathDepth : Nat := 23
def maximumCompactAuthenticationNodes : Nat := 372
def maximumInnerProofBytes : Nat := 131072

/-!
SMZ9 has the same compact-path encoding as SMZ8 under a fresh identity.  It fixes twenty paths,
allows canonical zero-length paths supplied by the aggregate multiproof, and bounds each path by
the depth-23 DECS tree.  The verifier separately enforces the 372-node aggregate maximum.
-/
def AuthPathsCanonical (paths : AuthPathsWire) : Prop :=
  paths.Canonical
    ∧ paths.rowCount = openedLeafCount
    ∧ ∀ lengthByte ∈ paths.pathLengthBytes,
        lengthByte.val ≤ maximumAuthPathDepth

def decodeAuthPathsPrefix
    (input : List Byte) : Option (AuthPathsWire × List Byte) := do
  let (paths, suffix) ← SmallWoodProofWire.decodeAuthPathsPrefix input
  if paths.rowCount = openedLeafCount
      ∧ ∀ lengthByte ∈ paths.pathLengthBytes,
          lengthByte.val ≤ maximumAuthPathDepth then
    some (paths, suffix)
  else
    none

theorem decodeAuthPathsPrefix_encode
    (paths : AuthPathsWire)
    (suffix : List Byte)
    (canonical : AuthPathsCanonical paths) :
    decodeAuthPathsPrefix (paths.encode ++ suffix) = some (paths, suffix) := by
  rcases canonical with ⟨baseCanonical, exactCount, depthBound⟩
  unfold decodeAuthPathsPrefix
  rw [SmallWoodProofWire.decodeAuthPathsPrefix_encode paths suffix baseCanonical]
  change
    (if paths.rowCount = openedLeafCount
          ∧ ∀ lengthByte ∈ paths.pathLengthBytes,
              lengthByte.val ≤ maximumAuthPathDepth then
        some (paths, suffix)
      else
        none) = some (paths, suffix)
  rw [if_pos ⟨exactCount, depthBound⟩]

theorem decodeAuthPathsPrefix_sound
    {input : List Byte}
    {paths : AuthPathsWire}
    {suffix : List Byte}
    (decoded : decodeAuthPathsPrefix input = some (paths, suffix)) :
    AuthPathsCanonical paths ∧ input = paths.encode ++ suffix := by
  unfold decodeAuthPathsPrefix at decoded
  cases baseResult : SmallWoodProofWire.decodeAuthPathsPrefix input with
  | none => simp [baseResult] at decoded
  | some pair =>
      rcases pair with ⟨candidate, rest⟩
      rw [baseResult] at decoded
      change
        (if candidate.rowCount = openedLeafCount
              ∧ ∀ lengthByte ∈ candidate.pathLengthBytes,
                  lengthByte.val ≤ maximumAuthPathDepth then
            some (candidate, rest)
          else none) = some (paths, suffix) at decoded
      split at decoded
      · rename_i exactShape
        have pairEq : (candidate, rest) = (paths, suffix) := Option.some.inj decoded
        cases pairEq
        rcases SmallWoodProofWire.decodeAuthPathsPrefix_sound baseResult with
          ⟨baseCanonical, inputEq⟩
        exact ⟨⟨baseCanonical, exactShape.1, exactShape.2⟩, inputEq⟩
      · contradiction

def authPathsCodec : PrefixCodec AuthPathsWire where
  encode := AuthPathsWire.encode
  decode := decodeAuthPathsPrefix
  canonical := AuthPathsCanonical
  decode_encode := decodeAuthPathsPrefix_encode
  decode_sound := decodeAuthPathsPrefix_sound

/-! SMZ9 requires opened-row-scalar mode and carries no auxiliary witness words.  Refining the
shared codec preserves the exact mode-1 grammar, including both four-byte zero counters, while
rejecting mode 0 and every nonempty auxiliary payload. -/
def OpenedWitnessSmz9 (opened : OpenedWitnessWire) : Prop :=
  match opened with
  | .none => False
  | .rowScalars _ wordCountBytes limbCountBytes wordBytes =>
      decodeLE wordCountBytes = 0
        ∧ decodeLE limbCountBytes = 0
        ∧ wordBytes = []

instance (opened : OpenedWitnessWire) : Decidable (OpenedWitnessSmz9 opened) := by
  cases opened <;> simp [OpenedWitnessSmz9] <;> infer_instance

def openedWitnessSmz9Codec : PrefixCodec OpenedWitnessWire :=
  PrefixCodec.refine openedWitnessCodec OpenedWitnessSmz9

structure DecsWire where
  authPaths : AuthPathsWire
  leafTapeBytes : List Byte
  maskingEvaluations : MatrixWire
  highCoefficients : MatrixWire
deriving DecidableEq, Repr

def decsCodec : PrefixCodec DecsWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair authPathsCodec
      (PrefixCodec.pair (PrefixCodec.fixed openedLeafTapesBytes)
        (PrefixCodec.pair matrixCodec matrixCodec)))
    (fun value =>
      { authPaths := value.1, leafTapeBytes := value.2.1,
        maskingEvaluations := value.2.2.1, highCoefficients := value.2.2.2 })
    (fun decs =>
      (decs.authPaths, (decs.leafTapeBytes,
        (decs.maskingEvaluations, decs.highCoefficients))))
    (by intro value; rcases value with ⟨auth, tapes, masking, high⟩; rfl)
    (by intro value; cases value; rfl)

structure PcsWire where
  randomCombinationTails : MatrixWire
  subsetEvaluations : MatrixWire
  partialEvaluations : MatrixWire
  decs : DecsWire
deriving DecidableEq, Repr

def pcsCodec : PrefixCodec PcsWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair matrixCodec
      (PrefixCodec.pair matrixCodec (PrefixCodec.pair matrixCodec decsCodec)))
    (fun value =>
      { randomCombinationTails := value.1, subsetEvaluations := value.2.1,
        partialEvaluations := value.2.2.1, decs := value.2.2.2 })
    (fun pcs =>
      (pcs.randomCombinationTails,
        (pcs.subsetEvaluations, (pcs.partialEvaluations, pcs.decs))))
    (by intro value; rcases value with ⟨rcombi, subset, partialMatrix, decs⟩; rfl)
    (by intro value; cases value; rfl)

structure ProofWire where
  saltBytes : List Byte
  nonceBytes : List Byte
  piopHashBytes : List Byte
  piop : PiopWire
  pcs : PcsWire
  openedWitness : OpenedWitnessWire
deriving DecidableEq, Repr

def proofPayloadCodec : PrefixCodec ProofWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair (PrefixCodec.fixed 32)
      (PrefixCodec.pair (PrefixCodec.fixed 4)
        (PrefixCodec.pair (PrefixCodec.fixed digestBytes)
          (PrefixCodec.pair piopCodec
            (PrefixCodec.pair pcsCodec openedWitnessSmz9Codec)))))
    (fun value =>
      { saltBytes := value.1, nonceBytes := value.2.1, piopHashBytes := value.2.2.1,
        piop := value.2.2.2.1, pcs := value.2.2.2.2.1,
        openedWitness := value.2.2.2.2.2 })
    (fun proof =>
      (proof.saltBytes, (proof.nonceBytes,
        (proof.piopHashBytes, (proof.piop, (proof.pcs, proof.openedWitness))))))
    (by
      intro value
      rcases value with ⟨salt, nonce, hash, piop, pcs, opened⟩
      rfl)
    (by intro value; cases value; rfl)

def proofMagic : List Byte := [83, 77, 90, 57]

theorem proofMagic_length : proofMagic.length = 4 := by rfl

def ProofWire.encode (proof : ProofWire) : List Byte :=
  proofMagic ++ proofPayloadCodec.encode proof

def ProofWire.Canonical (proof : ProofWire) : Prop :=
  proofPayloadCodec.canonical proof

def decodeProofPrefix (input : List Byte) : Option (ProofWire × List Byte) := do
  let (magic, afterMagic) ← readFixed 4 input
  if magic = proofMagic then proofPayloadCodec.decode afterMagic else none

theorem decodeProofPrefix_encode
    (proof : ProofWire) (suffix : List Byte) (canonical : proof.Canonical) :
    decodeProofPrefix (proof.encode ++ suffix) = some (proof, suffix) := by
  unfold ProofWire.Canonical at canonical
  unfold decodeProofPrefix ProofWire.encode
  rw [List.append_assoc, readFixed_append proofMagic_length]
  simp [proofPayloadCodec.decode_encode proof suffix canonical]

theorem decodeProofPrefix_sound
    {input : List Byte} {proof : ProofWire} {suffix : List Byte}
    (decoded : decodeProofPrefix input = some (proof, suffix)) :
    proof.Canonical ∧ input = proof.encode ++ suffix := by
  unfold decodeProofPrefix at decoded
  cases magicResult : readFixed 4 input with
  | none => simp [magicResult] at decoded
  | some magicPair =>
      rcases magicPair with ⟨magic, afterMagic⟩
      simp [magicResult] at decoded
      rcases decoded with ⟨magicEq, decoded⟩
      rcases proofPayloadCodec.decode_sound decoded with ⟨canonical, afterMagicEq⟩
      rcases readFixed_sound magicResult with ⟨_, inputEq⟩
      subst magic
      constructor
      · exact canonical
      · unfold ProofWire.encode
        rw [inputEq, afterMagicEq, List.append_assoc]

/-! The cap is checked before any matrix, path, tape, or witness collection decoder runs. -/
def decodeProofExact (input : List Byte) : Option ProofWire :=
  if input.length ≤ maximumInnerProofBytes then do
    let (proof, suffix) ← decodeProofPrefix input
    if suffix = [] then some proof else none
  else none

theorem decodeProofExact_encode
    (proof : ProofWire) (canonical : proof.Canonical)
    (withinCap : proof.encode.length ≤ maximumInnerProofBytes) :
    decodeProofExact proof.encode = some proof := by
  unfold decodeProofExact
  rw [if_pos withinCap]
  rw [show proof.encode = proof.encode ++ [] by simp]
  rw [decodeProofPrefix_encode proof [] canonical]
  rfl

theorem decodeProofExact_sound
    {input : List Byte} {proof : ProofWire}
    (decoded : decodeProofExact input = some proof) :
    proof.Canonical ∧ input = proof.encode ∧ input.length ≤ maximumInnerProofBytes := by
  unfold decodeProofExact at decoded
  split at decoded
  · rename_i withinCap
    cases prefixResult : decodeProofPrefix input with
    | none => simp [prefixResult] at decoded
    | some prefixPair =>
        rcases prefixPair with ⟨parsedProof, suffix⟩
        simp [prefixResult] at decoded
        rcases decoded with ⟨suffixEmpty, proofEq⟩
        subst parsedProof
        subst suffix
        rcases decodeProofPrefix_sound prefixResult with ⟨canonical, inputEq⟩
        exact ⟨canonical, by simpa using inputEq, withinCap⟩
  · contradiction

theorem decodeProofExact_rejects_oversize
    {input : List Byte} (oversize : maximumInnerProofBytes < input.length) :
    decodeProofExact input = none := by
  simp [decodeProofExact, Nat.not_le_of_lt oversize]

namespace Examples

def zeroBytes (count : Nat) : List Byte := List.replicate count 0

def zeroMatrix : MatrixWire :=
  { rowCountBytes := encodeLE 2 0, columnCountBytes := encodeLE 2 0, valueBytes := [] }

def zeroLengthAuthPaths : AuthPathsWire :=
  { rowCountBytes := encodeLE 2 openedLeafCount,
    pathLengthBytes := zeroBytes openedLeafCount, nodeBytes := [] }

def wrongCountAuthPaths : AuthPathsWire :=
  { rowCountBytes := encodeLE 2 (openedLeafCount - 1),
    pathLengthBytes := zeroBytes (openedLeafCount - 1), nodeBytes := [] }

def excessiveDepthAuthPaths : AuthPathsWire :=
  { rowCountBytes := encodeLE 2 openedLeafCount,
    pathLengthBytes := 24 :: zeroBytes (openedLeafCount - 1),
    nodeBytes := zeroBytes (24 * digestBytes) }

def zeroPiop : PiopWire :=
  { polynomialHighs := zeroMatrix, linearHighs := zeroMatrix }

def makeDecs (authPaths : AuthPathsWire) : DecsWire :=
  { authPaths, leafTapeBytes := zeroBytes openedLeafTapesBytes,
    maskingEvaluations := zeroMatrix, highCoefficients := zeroMatrix }

def makePcs (authPaths : AuthPathsWire) : PcsWire :=
  { randomCombinationTails := zeroMatrix, subsetEvaluations := zeroMatrix,
    partialEvaluations := zeroMatrix, decs := makeDecs authPaths }

def makeProof (authPaths : AuthPathsWire) : ProofWire :=
  { saltBytes := zeroBytes 32, nonceBytes := zeroBytes 4,
    piopHashBytes := zeroBytes digestBytes, piop := zeroPiop,
    pcs := makePcs authPaths,
    openedWitness := .rowScalars zeroMatrix (encodeLE 4 0) (encodeLE 4 0) [] }

def canonicalMinimalProof : ProofWire := makeProof zeroLengthAuthPaths
def wrongCountProof : ProofWire := makeProof wrongCountAuthPaths
def excessiveDepthProof : ProofWire := makeProof excessiveDepthAuthPaths
def wrongMagicBytes : List Byte :=
  [0, 77, 90, 57] ++ proofPayloadCodec.encode canonicalMinimalProof
def trailingBytes : List Byte := canonicalMinimalProof.encode ++ [0]

theorem canonical_minimal_proof_is_canonical : canonicalMinimalProof.Canonical := by
  simp [ProofWire.Canonical, proofPayloadCodec, PrefixCodec.xmap, PrefixCodec.pair,
    PrefixCodec.fixed, piopCodec, pcsCodec, decsCodec, openedWitnessSmz9Codec,
    PrefixCodec.refine, OpenedWitnessSmz9, openedWitnessCodec,
    OpenedWitnessWire.Canonical, matrixCodec, authPathsCodec, AuthPathsCanonical,
    canonicalMinimalProof, makeProof, zeroPiop, makePcs, makeDecs, zeroLengthAuthPaths,
    zeroMatrix, zeroBytes, openedLeafCount, openedLeafTapeBytes, openedLeafTapesBytes,
    maximumAuthPathDepth, MatrixWire.Canonical, MatrixWire.rowCount, MatrixWire.columnCount,
    AuthPathsWire.Canonical, AuthPathsWire.rowCount, AuthPathsWire.nodeCount,
    maximumCollectionRows, digestBytes, fieldWordsCanonicalB, fieldOrder,
    encodeLE_length, decodeLE_encodeLE]

theorem canonical_minimal_proof_within_cap :
    canonicalMinimalProof.encode.length ≤ maximumInnerProofBytes := by decide

theorem canonical_minimal_proof_roundtrips :
    decodeProofExact canonicalMinimalProof.encode = some canonicalMinimalProof := by
  exact decodeProofExact_encode canonicalMinimalProof canonical_minimal_proof_is_canonical
    canonical_minimal_proof_within_cap

theorem wrong_magic_rejects : decodeProofExact wrongMagicBytes = none := by decide
theorem wrong_path_count_rejects : decodeProofExact wrongCountProof.encode = none := by decide
theorem excessive_path_depth_rejects :
    decodeProofExact excessiveDepthProof.encode = none := by decide
theorem trailing_byte_rejects : decodeProofExact trailingBytes = none := by decide

end Examples

end SmallWoodSmz9ProofWire
end HegemonCrypto
