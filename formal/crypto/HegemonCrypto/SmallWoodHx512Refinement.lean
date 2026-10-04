import HegemonCrypto.CanonicalBytes

set_option maxRecDepth 100000

/-!
# Inactive HX512 fresh-core codec and eight-event verifier refinement

This file specifies two deterministic implementation boundaries for the fresh,
unallocated SmallWood/HX512 candidate:

* the complete response-core byte grammar whose first 192 bytes are exactly
  `raw_decs_root64 || h3_piop_input64 || h5_piop_transcript64`; and
* the exact eight-event eager transcript and the verifier's deferred
  `root -> h3 -> h5` readback state machine.

The codec theorems are mathematical parser theorems.  The transcript theorem
is parametric in pure SHA-512 and SHAKE256 request functions and compares a
reference oracle to an implementation oracle only under explicit extensional
request agreement.  Nothing here proves a concrete hash random-oracle model,
QROM security, complete zero knowledge, relation/compiler refinement, Rust
execution refinement, consensus binding, or production authorization.
-/

namespace HegemonCrypto.SmallWood.Hx512Refinement

open HegemonCrypto.CanonicalBytes

/-! ## Profile-owned fresh core codec -/

def digestBytes : Nat := 64
def deferredPrefixBytes : Nat := 3 * digestBytes
def goldilocksModulus : Nat := 0xffff_ffff_0000_0001
def exactPackingFactor : Nat := 1024
def exactMaximumConstraintDegree : Nat := 6
def exactPiopOpeningCount : Nat := 6
def exactDecsDomainSize : Nat := 2 ^ 20
def exactDecsQueryCount : Nat := 48
def exactLeafTapeBytes : Nat := 72
def exactAuthenticationPathDepth : Nat := 20

def encodeBE (width value : Nat) : List Byte :=
  (encodeLE width value).reverse

def decodeBE (bytes : List Byte) : Nat :=
  decodeLE bytes.reverse

@[simp] theorem encodeBE_length (width value : Nat) :
    (encodeBE width value).length = width := by
  simp [encodeBE, encodeLE_length]

theorem decodeBE_encodeBE (width value : Nat) :
    decodeBE (encodeBE width value) = value % 256 ^ width := by
  simp [decodeBE, encodeBE, decodeLE_encodeLE]

def fieldWordsCanonicalBE (bytes : List Byte) : Bool :=
  bytes.length % 8 == 0 &&
    (List.range (bytes.length / 8)).all (fun index =>
      decide (decodeBE ((bytes.drop (index * 8)).take 8) < goldilocksModulus))

structure MatrixShape where
  rows : Nat
  columns : Nat
deriving DecidableEq, Repr

namespace MatrixShape

def cellBytes (shape : MatrixShape) : Nat :=
  shape.rows * shape.columns * 8

def Canonical (shape : MatrixShape) : Prop :=
  0 < shape.rows ∧ shape.rows < 2 ^ 32 ∧
    0 < shape.columns ∧ shape.columns < 2 ^ 32

end MatrixShape

structure MatrixWire where
  rowCountBytes : List Byte
  columnCountBytes : List Byte
  valueBytes : List Byte
deriving DecidableEq, Repr

namespace MatrixWire

def encode (matrix : MatrixWire) : List Byte :=
  matrix.rowCountBytes ++ matrix.columnCountBytes ++ matrix.valueBytes

def CanonicalFor (matrix : MatrixWire) (shape : MatrixShape) : Prop :=
  matrix.rowCountBytes.length = 4 ∧
    matrix.columnCountBytes.length = 4 ∧
    matrix.valueBytes.length = shape.cellBytes ∧
    matrix.rowCountBytes = encodeBE 4 shape.rows ∧
    matrix.columnCountBytes = encodeBE 4 shape.columns ∧
    fieldWordsCanonicalBE matrix.valueBytes = true

end MatrixWire

def matrixRawCodec (shape : MatrixShape) :
    PrefixCodec (List Byte × (List Byte × List Byte)) :=
  PrefixCodec.pair (PrefixCodec.fixed 4)
    (PrefixCodec.pair (PrefixCodec.fixed 4)
      (PrefixCodec.fixed shape.cellBytes))

def matrixCodec (shape : MatrixShape) : PrefixCodec MatrixWire :=
  PrefixCodec.xmap
    (PrefixCodec.refine (matrixRawCodec shape) fun value =>
      value.1 = encodeBE 4 shape.rows ∧
        value.2.1 = encodeBE 4 shape.columns ∧
        fieldWordsCanonicalBE value.2.2 = true)
    (fun value =>
      { rowCountBytes := value.1
        columnCountBytes := value.2.1
        valueBytes := value.2.2 })
    (fun matrix =>
      (matrix.rowCountBytes, (matrix.columnCountBytes, matrix.valueBytes)))
    (by intro value; rcases value with ⟨row, column, cells⟩; rfl)
    (by intro matrix; cases matrix; rfl)

theorem matrixCodec_canonical_iff
    (shape : MatrixShape) (matrix : MatrixWire) :
    (matrixCodec shape).canonical matrix ↔ matrix.CanonicalFor shape := by
  unfold matrixCodec matrixRawCodec MatrixWire.CanonicalFor
  constructor
  · rintro ⟨⟨rowLength, columnLength, valueLength⟩,
        rowExact, columnExact, valuesCanonical⟩
    exact ⟨rowLength, columnLength, valueLength,
      rowExact, columnExact, valuesCanonical⟩
  · rintro ⟨rowLength, columnLength, valueLength,
        rowExact, columnExact, valuesCanonical⟩
    exact ⟨⟨rowLength, columnLength, valueLength⟩,
      rowExact, columnExact, valuesCanonical⟩

structure AuthenticationPathsWire where
  pathCountBytes : List Byte
  pathLengthBytes : List Byte
  nodeBytes : List Byte
deriving DecidableEq, Repr

def pathLengthAt (lengthBytes : List Byte) (index : Nat) : Nat :=
  decodeBE ((lengthBytes.drop (index * 4)).take 4)

def authenticationNodeCount (pathCount : Nat) (lengthBytes : List Byte) : Nat :=
  (List.range pathCount).map (pathLengthAt lengthBytes) |>.sum

def authenticationLengthsCanonicalB
    (pathCount maximumDepth : Nat) (lengthBytes : List Byte) : Bool :=
  lengthBytes.length == pathCount * 4 &&
    (List.range pathCount).all (fun index =>
      let length := pathLengthAt lengthBytes index
      decide (0 < length ∧ length ≤ maximumDepth))

namespace AuthenticationPathsWire

def encode (paths : AuthenticationPathsWire) : List Byte :=
  paths.pathCountBytes ++ paths.pathLengthBytes ++ paths.nodeBytes

def CanonicalFor
    (paths : AuthenticationPathsWire)
    (pathCount maximumDepth : Nat) : Prop :=
  paths.pathCountBytes.length = 4 ∧
    paths.pathCountBytes = encodeBE 4 pathCount ∧
    paths.pathLengthBytes.length = pathCount * 4 ∧
    authenticationLengthsCanonicalB pathCount maximumDepth
        paths.pathLengthBytes = true ∧
    paths.nodeBytes.length =
      authenticationNodeCount pathCount paths.pathLengthBytes * digestBytes

end AuthenticationPathsWire

def decodeAuthenticationPathsPrefix
    (pathCount maximumDepth : Nat)
    (input : List Byte) : Option (AuthenticationPathsWire × List Byte) := do
  let (pathCountBytes, afterCount) ← readFixed 4 input
  if pathCountBytes = encodeBE 4 pathCount then
    let (pathLengthBytes, afterLengths) ← readFixed (pathCount * 4) afterCount
    if authenticationLengthsCanonicalB pathCount maximumDepth pathLengthBytes then
      let nodeCount := authenticationNodeCount pathCount pathLengthBytes
      let (nodeBytes, suffix) ← readFixed (nodeCount * digestBytes) afterLengths
      some ({ pathCountBytes, pathLengthBytes, nodeBytes }, suffix)
    else
      none
  else
    none

theorem decodeAuthenticationPathsPrefix_encode
    (pathCount maximumDepth : Nat)
    (paths : AuthenticationPathsWire)
    (suffix : List Byte)
    (canonical : paths.CanonicalFor pathCount maximumDepth) :
    decodeAuthenticationPathsPrefix pathCount maximumDepth
        (paths.encode ++ suffix) = some (paths, suffix) := by
  rcases canonical with
    ⟨countLength, countExact, lengthsLength, lengthsCanonical, nodesLength⟩
  simp [decodeAuthenticationPathsPrefix, AuthenticationPathsWire.encode,
    countLength, countExact, lengthsLength, lengthsCanonical, nodesLength,
    List.append_assoc]

theorem decodeAuthenticationPathsPrefix_sound
    {pathCount maximumDepth : Nat}
    {input : List Byte}
    {paths : AuthenticationPathsWire}
    {suffix : List Byte}
    (decoded : decodeAuthenticationPathsPrefix pathCount maximumDepth input =
      some (paths, suffix)) :
    paths.CanonicalFor pathCount maximumDepth ∧
      input = paths.encode ++ suffix := by
  unfold decodeAuthenticationPathsPrefix at decoded
  cases countResult : readFixed 4 input with
  | none => simp [countResult] at decoded
  | some countPair =>
      rcases countPair with ⟨pathCountBytes, afterCount⟩
      simp [countResult] at decoded
      rcases decoded with ⟨countExact, decoded⟩
      cases lengthsResult : readFixed (pathCount * 4) afterCount with
      | none => simp [lengthsResult] at decoded
      | some lengthsPair =>
          rcases lengthsPair with ⟨pathLengthBytes, afterLengths⟩
          simp [lengthsResult] at decoded
          rcases decoded with ⟨lengthsCanonical, decoded⟩
          cases nodesResult :
              readFixed
                (authenticationNodeCount pathCount pathLengthBytes * digestBytes)
                afterLengths with
          | none => simp [nodesResult] at decoded
          | some nodesPair =>
              rcases nodesPair with ⟨nodeBytes, finalSuffix⟩
              simp [nodesResult] at decoded
              rcases decoded with ⟨pathsEq, suffixEq⟩
              subst paths
              subst suffix
              rcases readFixed_sound countResult with ⟨countLength, inputEq⟩
              rcases readFixed_sound lengthsResult with
                ⟨lengthsLength, afterCountEq⟩
              rcases readFixed_sound nodesResult with
                ⟨nodesLength, afterLengthsEq⟩
              constructor
              · exact ⟨countLength, countExact, lengthsLength,
                  lengthsCanonical, nodesLength⟩
              · simp only [AuthenticationPathsWire.encode]
                rw [inputEq, afterCountEq, afterLengthsEq]
                simp [List.append_assoc]

def authenticationPathsCodec
    (pathCount maximumDepth : Nat) : PrefixCodec AuthenticationPathsWire where
  encode := AuthenticationPathsWire.encode
  decode := decodeAuthenticationPathsPrefix pathCount maximumDepth
  canonical := fun paths => paths.CanonicalFor pathCount maximumDepth
  decode_encode := decodeAuthenticationPathsPrefix_encode pathCount maximumDepth
  decode_sound := decodeAuthenticationPathsPrefix_sound

structure FreshCoreGeometry where
  packingFactor : Nat
  maximumConstraintDegree : Nat
  rho : Nat
  eta : Nat
  beta : Nat
  piopOpeningCount : Nat
  decsDomainSize : Nat
  decsQueryCount : Nat
  nonlinearConstraintCount : Nat
  linearConstraintCount : Nat
  lvcsRows : Nat
  ppolHigh : MatrixShape
  plinHigh : MatrixShape
  randomCombinationTails : MatrixShape
  subsetEvaluations : MatrixShape
  partialEvaluations : MatrixShape
  maskingEvaluations : MatrixShape
  highCoefficients : MatrixShape
  openedWitness : MatrixShape
  authenticationPathCount : Nat
  authenticationPathDepth : Nat
  leafTapeBytes : Nat
deriving DecidableEq, Repr

namespace FreshCoreGeometry

def CanonicalProfile (geometry : FreshCoreGeometry) : Prop :=
  geometry.packingFactor = exactPackingFactor ∧
    geometry.maximumConstraintDegree = exactMaximumConstraintDegree ∧
    geometry.rho = 5 ∧
    geometry.eta = 5 ∧
    geometry.beta = 2 ∧
    geometry.piopOpeningCount = exactPiopOpeningCount ∧
    geometry.decsDomainSize = exactDecsDomainSize ∧
    geometry.decsQueryCount = exactDecsQueryCount ∧
    0 < geometry.nonlinearConstraintCount ∧
    0 < geometry.linearConstraintCount ∧
    0 < geometry.lvcsRows ∧
    geometry.ppolHigh.Canonical ∧
    geometry.plinHigh.Canonical ∧
    geometry.randomCombinationTails.Canonical ∧
    geometry.subsetEvaluations.Canonical ∧
    geometry.partialEvaluations.Canonical ∧
    geometry.maskingEvaluations.Canonical ∧
    geometry.highCoefficients.Canonical ∧
    geometry.openedWitness.Canonical ∧
    geometry.authenticationPathCount = geometry.decsQueryCount ∧
    geometry.authenticationPathDepth = exactAuthenticationPathDepth ∧
    geometry.leafTapeBytes = exactLeafTapeBytes ∧
    geometry.ppolHigh.rows = geometry.rho ∧
    geometry.plinHigh.rows = geometry.rho ∧
    geometry.randomCombinationTails.rows = geometry.beta * geometry.piopOpeningCount ∧
    geometry.randomCombinationTails.columns = geometry.decsQueryCount ∧
    geometry.subsetEvaluations.rows = geometry.decsQueryCount ∧
    geometry.partialEvaluations.rows = geometry.piopOpeningCount ∧
    geometry.maskingEvaluations.rows = geometry.decsQueryCount ∧
    geometry.maskingEvaluations.columns = geometry.eta ∧
    geometry.highCoefficients.rows = geometry.eta ∧
    geometry.openedWitness.rows = geometry.piopOpeningCount

def openedTapePayloadBytes (geometry : FreshCoreGeometry) : Nat :=
  geometry.authenticationPathCount * geometry.leafTapeBytes

end FreshCoreGeometry

structure FreshCorePrefix where
  rawDecsRoot : List Byte
  h3PiopInput : List Byte
  h5PiopTranscript : List Byte
deriving DecidableEq, Repr

namespace FreshCorePrefix

def encode (prefix : FreshCorePrefix) : List Byte :=
  prefix.rawDecsRoot ++ prefix.h3PiopInput ++ prefix.h5PiopTranscript

def Canonical (prefix : FreshCorePrefix) : Prop :=
  prefix.rawDecsRoot.length = digestBytes ∧
    prefix.h3PiopInput.length = digestBytes ∧
    prefix.h5PiopTranscript.length = digestBytes

end FreshCorePrefix

def freshCorePrefixCodec : PrefixCodec FreshCorePrefix :=
  PrefixCodec.xmap
    (PrefixCodec.pair (PrefixCodec.fixed digestBytes)
      (PrefixCodec.pair (PrefixCodec.fixed digestBytes)
        (PrefixCodec.fixed digestBytes)))
    (fun value =>
      { rawDecsRoot := value.1
        h3PiopInput := value.2.1
        h5PiopTranscript := value.2.2 })
    (fun prefix =>
      (prefix.rawDecsRoot, (prefix.h3PiopInput, prefix.h5PiopTranscript)))
    (by intro value; rcases value with ⟨root, h3, h5⟩; rfl)
    (by intro prefix; cases prefix; rfl)

theorem freshCorePrefixCodec_canonical_iff (prefix : FreshCorePrefix) :
    freshCorePrefixCodec.canonical prefix ↔ prefix.Canonical := by
  unfold freshCorePrefixCodec FreshCorePrefix.Canonical
  constructor
  · rintro ⟨rootLength, h3Length, h5Length⟩
    exact ⟨rootLength, h3Length, h5Length⟩
  · rintro ⟨rootLength, h3Length, h5Length⟩
    exact ⟨rootLength, h3Length, h5Length⟩

theorem fresh_core_prefix_exact_bytes
    (prefix : FreshCorePrefix) (canonical : prefix.Canonical) :
    prefix.encode.length = deferredPrefixBytes := by
  rcases canonical with ⟨rootLength, h3Length, h5Length⟩
  simp [FreshCorePrefix.encode, deferredPrefixBytes, digestBytes,
    rootLength, h3Length, h5Length]

structure PiopResponseWire where
  ppolHigh : MatrixWire
  plinHigh : MatrixWire
deriving DecidableEq, Repr

def piopResponseCodec (geometry : FreshCoreGeometry) : PrefixCodec PiopResponseWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair (matrixCodec geometry.ppolHigh)
      (matrixCodec geometry.plinHigh))
    (fun value => { ppolHigh := value.1, plinHigh := value.2 })
    (fun wire => (wire.ppolHigh, wire.plinHigh))
    (by intro value; cases value; rfl)
    (by intro wire; cases wire; rfl)

structure PcsResponseHeadWire where
  randomCombinationTails : MatrixWire
  subsetEvaluations : MatrixWire
  partialEvaluations : MatrixWire
deriving DecidableEq, Repr

def pcsResponseHeadCodec
    (geometry : FreshCoreGeometry) : PrefixCodec PcsResponseHeadWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair (matrixCodec geometry.randomCombinationTails)
      (PrefixCodec.pair (matrixCodec geometry.subsetEvaluations)
        (matrixCodec geometry.partialEvaluations)))
    (fun value =>
      { randomCombinationTails := value.1
        subsetEvaluations := value.2.1
        partialEvaluations := value.2.2 })
    (fun wire =>
      (wire.randomCombinationTails,
        (wire.subsetEvaluations, wire.partialEvaluations)))
    (by intro value; rcases value with ⟨randomTails, subset, partialValues⟩; rfl)
    (by intro wire; cases wire; rfl)

structure DecsResponseWire where
  authenticationPaths : AuthenticationPathsWire
  openedLeafTapes : List Byte
  maskingEvaluations : MatrixWire
  highCoefficients : MatrixWire
deriving DecidableEq, Repr

def decsResponseCodec (geometry : FreshCoreGeometry) : PrefixCodec DecsResponseWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair
      (authenticationPathsCodec geometry.authenticationPathCount
        geometry.authenticationPathDepth)
      (PrefixCodec.pair
        (PrefixCodec.fixed geometry.openedTapePayloadBytes)
        (PrefixCodec.pair (matrixCodec geometry.maskingEvaluations)
          (matrixCodec geometry.highCoefficients))))
    (fun value =>
      { authenticationPaths := value.1
        openedLeafTapes := value.2.1
        maskingEvaluations := value.2.2.1
        highCoefficients := value.2.2.2 })
    (fun wire =>
      (wire.authenticationPaths,
        (wire.openedLeafTapes,
          (wire.maskingEvaluations, wire.highCoefficients))))
    (by
      intro value
      rcases value with ⟨paths, tapes, masking, high⟩
      rfl)
    (by intro wire; cases wire; rfl)

structure FreshCoreWire where
  prefix : FreshCorePrefix
  piop : PiopResponseWire
  pcs : PcsResponseHeadWire
  decs : DecsResponseWire
  openedWitness : MatrixWire
deriving DecidableEq, Repr

def freshCorePayloadCodec (geometry : FreshCoreGeometry) : PrefixCodec FreshCoreWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair freshCorePrefixCodec
      (PrefixCodec.pair (piopResponseCodec geometry)
        (PrefixCodec.pair (pcsResponseHeadCodec geometry)
          (PrefixCodec.pair (decsResponseCodec geometry)
            (matrixCodec geometry.openedWitness)))))
    (fun value =>
      { prefix := value.1
        piop := value.2.1
        pcs := value.2.2.1
        decs := value.2.2.2.1
        openedWitness := value.2.2.2.2 })
    (fun wire =>
      (wire.prefix,
        (wire.piop, (wire.pcs, (wire.decs, wire.openedWitness)))))
    (by
      intro value
      rcases value with ⟨prefix, piop, pcs, decs, opened⟩
      rfl)
    (by intro wire; cases wire; rfl)

namespace FreshCoreWire

def encode (wire : FreshCoreWire) (geometry : FreshCoreGeometry) : List Byte :=
  (freshCorePayloadCodec geometry).encode wire

def CanonicalFor (wire : FreshCoreWire) (geometry : FreshCoreGeometry) : Prop :=
  geometry.CanonicalProfile ∧ (freshCorePayloadCodec geometry).canonical wire

end FreshCoreWire

theorem fresh_core_wire_prefix_canonical
    {geometry : FreshCoreGeometry}
    {wire : FreshCoreWire}
    (canonical : wire.CanonicalFor geometry) :
    wire.prefix.Canonical := by
  exact (freshCorePrefixCodec_canonical_iff wire.prefix).1 canonical.2.1

theorem fresh_core_wire_begins_with_exact_192_byte_prefix
    {geometry : FreshCoreGeometry}
    {wire : FreshCoreWire}
    (canonical : wire.CanonicalFor geometry) :
    wire.prefix.encode.length = deferredPrefixBytes :=
  fresh_core_prefix_exact_bytes wire.prefix
    (fresh_core_wire_prefix_canonical canonical)

def decodeFreshCoreExact
    (geometry : FreshCoreGeometry) (input : List Byte) : Option FreshCoreWire := do
  let (wire, suffix) ← (freshCorePayloadCodec geometry).decode input
  if suffix = [] then some wire else none

def decodeFreshCoreExactCapped
    (geometry : FreshCoreGeometry)
    (maximumPayloadBytes : Nat)
    (input : List Byte) : Option FreshCoreWire :=
  if input = [] then none
  else if maximumPayloadBytes < input.length then none
  else decodeFreshCoreExact geometry input

theorem decodeFreshCoreExact_encode
    (geometry : FreshCoreGeometry)
    (wire : FreshCoreWire)
    (canonical : wire.CanonicalFor geometry) :
    decodeFreshCoreExact geometry (wire.encode geometry) = some wire := by
  unfold decodeFreshCoreExact FreshCoreWire.encode
  rw [show (freshCorePayloadCodec geometry).encode wire =
      (freshCorePayloadCodec geometry).encode wire ++ [] by simp]
  rw [(freshCorePayloadCodec geometry).decode_encode wire [] canonical.2]
  rfl

theorem decodeFreshCoreExact_sound
    {geometry : FreshCoreGeometry}
    {input : List Byte}
    {wire : FreshCoreWire}
    (geometryCanonical : geometry.CanonicalProfile)
    (decoded : decodeFreshCoreExact geometry input = some wire) :
    wire.CanonicalFor geometry ∧ input = wire.encode geometry := by
  unfold decodeFreshCoreExact at decoded
  cases prefixResult : (freshCorePayloadCodec geometry).decode input with
  | none => simp [prefixResult] at decoded
  | some prefixPair =>
      rcases prefixPair with ⟨parsedWire, suffix⟩
      simp [prefixResult] at decoded
      rcases decoded with ⟨suffixEmpty, wireEq⟩
      subst parsedWire
      subst suffix
      rcases (freshCorePayloadCodec geometry).decode_sound prefixResult with
        ⟨wireCanonical, inputEq⟩
      exact ⟨⟨geometryCanonical, wireCanonical⟩, by simpa [FreshCoreWire.encode] using inputEq⟩

theorem canonical_fresh_core_encoding_injective
    {geometry : FreshCoreGeometry}
    {left right : FreshCoreWire}
    (leftCanonical : left.CanonicalFor geometry)
    (rightCanonical : right.CanonicalFor geometry)
    (sameBytes : left.encode geometry = right.encode geometry) :
    left = right := by
  have leftDecoded := decodeFreshCoreExact_encode geometry left leftCanonical
  have rightDecoded := decodeFreshCoreExact_encode geometry right rightCanonical
  rw [sameBytes, rightDecoded] at leftDecoded
  exact (Option.some.inj leftDecoded).symm

theorem decodeFreshCoreExact_rejects_trailing_bytes
    (geometry : FreshCoreGeometry)
    (wire : FreshCoreWire)
    (suffix : List Byte)
    (canonical : wire.CanonicalFor geometry)
    (suffixNonempty : suffix ≠ []) :
    decodeFreshCoreExact geometry (wire.encode geometry ++ suffix) = none := by
  unfold decodeFreshCoreExact FreshCoreWire.encode
  rw [(freshCorePayloadCodec geometry).decode_encode wire suffix canonical.2]
  simp [suffixNonempty]

theorem decodeFreshCoreExactCapped_encode
    (geometry : FreshCoreGeometry)
    (maximumPayloadBytes : Nat)
    (wire : FreshCoreWire)
    (canonical : wire.CanonicalFor geometry)
    (encodedNonempty : wire.encode geometry ≠ [])
    (withinCap : (wire.encode geometry).length ≤ maximumPayloadBytes) :
    decodeFreshCoreExactCapped geometry maximumPayloadBytes
      (wire.encode geometry) = some wire := by
  simp [decodeFreshCoreExactCapped, encodedNonempty,
    Nat.not_lt_of_ge withinCap, decodeFreshCoreExact_encode geometry wire canonical]

theorem decodeFreshCoreExactCapped_sound
    {geometry : FreshCoreGeometry}
    {maximumPayloadBytes : Nat}
    {input : List Byte}
    {wire : FreshCoreWire}
    (geometryCanonical : geometry.CanonicalProfile)
    (decoded : decodeFreshCoreExactCapped geometry maximumPayloadBytes input = some wire) :
    input ≠ [] ∧ input.length ≤ maximumPayloadBytes ∧
      wire.CanonicalFor geometry ∧ input = wire.encode geometry := by
  unfold decodeFreshCoreExactCapped at decoded
  split at decoded
  · simp_all
  split at decoded
  · simp_all
  rename_i inputNonempty notWithinCap
  have withinCap : input.length ≤ maximumPayloadBytes := Nat.le_of_not_gt notWithinCap
  rcases decodeFreshCoreExact_sound geometryCanonical decoded with
    ⟨canonical, exactBytes⟩
  exact ⟨inputNonempty, withinCap, canonical, exactBytes⟩

theorem decodeFreshCoreExactCapped_rejects_over_cap
    (geometry : FreshCoreGeometry)
    (maximumPayloadBytes : Nat)
    (input : List Byte)
    (overCap : maximumPayloadBytes < input.length) :
    decodeFreshCoreExactCapped geometry maximumPayloadBytes input = none := by
  cases input with
  | nil => simp at overCap
  | cons head tail =>
      simp [decodeFreshCoreExactCapped, overCap]

/-! ## Exact eager and deferred eight-event schedule -/

abbrev Digest := List Byte
abbrev TranscriptMessage := List Byte
abbrev Challenge := List Nat

def CanonicalDigest (digest : Digest) : Prop :=
  digest.length = digestBytes

inductive TranscriptStage where
  | decsRootBinding
  | decsCoefficientChallenge
  | piopInputBinding
  | piopCoefficientChallenge
  | piopTranscriptBinding
  | piopOpeningChallenge
  | decsOpeningBinding
  | decsQueryChallenge
deriving DecidableEq, Repr

def exactEightEventSchedule : List TranscriptStage :=
  [ .decsRootBinding,
    .decsCoefficientChallenge,
    .piopInputBinding,
    .piopCoefficientChallenge,
    .piopTranscriptBinding,
    .piopOpeningChallenge,
    .decsOpeningBinding,
    .decsQueryChallenge ]

theorem exact_eight_event_schedule_length :
    exactEightEventSchedule.length = 8 := by
  rfl

inductive XofSamplerKind where
  | canonicalGoldilocksField
  | canonicalSortedDistinctIndex
deriving DecidableEq, Repr

structure XofRequestDescriptor where
  kind : XofSamplerKind
  requested : Nat
  modulusOrDomain : Nat
  sortedDistinct : Bool
deriving DecidableEq, Repr

def decsCoefficientDescriptor
    (geometry : FreshCoreGeometry) : XofRequestDescriptor :=
  { kind := .canonicalGoldilocksField
    requested := geometry.eta * geometry.lvcsRows
    modulusOrDomain := goldilocksModulus
    sortedDistinct := false }

def piopCoefficientDescriptor
    (geometry : FreshCoreGeometry) : XofRequestDescriptor :=
  { kind := .canonicalGoldilocksField
    requested := geometry.rho *
      max geometry.nonlinearConstraintCount geometry.linearConstraintCount
    modulusOrDomain := goldilocksModulus
    sortedDistinct := false }

def piopOpeningDescriptor
    (geometry : FreshCoreGeometry) : XofRequestDescriptor :=
  { kind := .canonicalGoldilocksField
    requested := geometry.piopOpeningCount
    modulusOrDomain := goldilocksModulus
    sortedDistinct := false }

def decsQueryDescriptor
    (geometry : FreshCoreGeometry) : XofRequestDescriptor :=
  { kind := .canonicalSortedDistinctIndex
    requested := geometry.decsQueryCount
    modulusOrDomain := geometry.decsDomainSize
    sortedDistinct := true }

structure XofResult where
  challenge : Challenge
  nextChain : Digest
deriving DecidableEq, Repr

@[ext] structure TranscriptOracle where
  sha512Request :
    Digest → Nat → TranscriptStage → Digest → TranscriptMessage → Digest
  shake256Request :
    Digest → Nat → TranscriptStage → Digest →
      XofRequestDescriptor → XofResult

structure OracleOutputWidths (oracle : TranscriptOracle) : Prop where
  sha512DigestBytes :
    ∀ statementBinding ordinal stage priorChain message,
      (oracle.sha512Request statementBinding ordinal stage priorChain message).length =
        digestBytes
  shake256NextChainDigestBytes :
    ∀ statementBinding ordinal stage priorChain descriptor,
      (oracle.shake256Request statementBinding ordinal stage priorChain descriptor).nextChain.length =
        digestBytes

structure EightEventMessages where
  geometry : FreshCoreGeometry
  salt : List Byte
  rawDecsRoot : Digest
  piopInput : TranscriptMessage
  piopTranscript : TranscriptMessage
  decsOpening : TranscriptMessage
deriving DecidableEq, Repr

namespace EightEventMessages

def Canonical (messages : EightEventMessages) : Prop :=
  messages.geometry.CanonicalProfile ∧
    messages.salt.length = digestBytes ∧
    messages.rawDecsRoot.length = digestBytes ∧
    messages.piopInput ≠ [] ∧
    messages.piopTranscript ≠ [] ∧
    messages.decsOpening ≠ []

end EightEventMessages

def decsRootRequestMessage (salt rawDecsRoot : List Byte) : List Byte :=
  encodeBE 4 exactDecsDomainSize ++
    encodeBE 2 salt.length ++ salt ++
    encodeBE 2 rawDecsRoot.length ++ rawDecsRoot

theorem decs_root_request_message_exact_136_bytes
    {salt rawDecsRoot : List Byte}
    (saltLength : salt.length = digestBytes)
    (rootLength : rawDecsRoot.length = digestBytes) :
    (decsRootRequestMessage salt rawDecsRoot).length = 136 := by
  simp [decsRootRequestMessage, saltLength, rootLength, digestBytes]

structure EightEventRun where
  after0 : Digest
  challenge1 : Challenge
  after1 : Digest
  after2 : Digest
  challenge3 : Challenge
  after3 : Digest
  after4 : Digest
  challenge5 : Challenge
  after5 : Digest
  after6 : Digest
  challenge7 : Challenge
  after7 : Digest
deriving DecidableEq, Repr

def eagerRun
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (messages : EightEventMessages) : EightEventRun :=
  let after0 := oracle.sha512Request statementBinding 0
    .decsRootBinding statementBinding
      (decsRootRequestMessage messages.salt messages.rawDecsRoot)
  let event1 := oracle.shake256Request statementBinding 1
    .decsCoefficientChallenge after0
      (decsCoefficientDescriptor messages.geometry)
  let after2 := oracle.sha512Request statementBinding 2
    .piopInputBinding event1.nextChain messages.piopInput
  let event3 := oracle.shake256Request statementBinding 3
    .piopCoefficientChallenge after2
      (piopCoefficientDescriptor messages.geometry)
  let after4 := oracle.sha512Request statementBinding 4
    .piopTranscriptBinding event3.nextChain messages.piopTranscript
  let event5 := oracle.shake256Request statementBinding 5
    .piopOpeningChallenge after4
      (piopOpeningDescriptor messages.geometry)
  let after6 := oracle.sha512Request statementBinding 6
    .decsOpeningBinding event5.nextChain messages.decsOpening
  let event7 := oracle.shake256Request statementBinding 7
    .decsQueryChallenge after6
      (decsQueryDescriptor messages.geometry)
  { after0
    challenge1 := event1.challenge
    after1 := event1.nextChain
    after2
    challenge3 := event3.challenge
    after3 := event3.nextChain
    after4
    challenge5 := event5.challenge
    after5 := event5.nextChain
    after6
    challenge7 := event7.challenge
    after7 := event7.nextChain }

structure DeferredPrefix where
  rawDecsRoot : Digest
  claimedH3 : Digest
  claimedH5 : Digest
deriving DecidableEq, Repr

namespace DeferredPrefix

def Canonical (prefix : DeferredPrefix) : Prop :=
  prefix.rawDecsRoot.length = digestBytes ∧
    prefix.claimedH3.length = digestBytes ∧
    prefix.claimedH5.length = digestBytes

def ofFreshCorePrefix (prefix : FreshCorePrefix) : DeferredPrefix :=
  { rawDecsRoot := prefix.rawDecsRoot
    claimedH3 := prefix.h3PiopInput
    claimedH5 := prefix.h5PiopTranscript }

theorem ofFreshCorePrefix_canonical
    {prefix : FreshCorePrefix} (canonical : prefix.Canonical) :
    (ofFreshCorePrefix prefix).Canonical := by
  exact canonical

end DeferredPrefix

def deferredRun
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (messages : EightEventMessages)
    (prefix : DeferredPrefix) : EightEventRun :=
  let after0 := oracle.sha512Request statementBinding 0
    .decsRootBinding statementBinding
      (decsRootRequestMessage messages.salt prefix.rawDecsRoot)
  let event1 := oracle.shake256Request statementBinding 1
    .decsCoefficientChallenge after0
      (decsCoefficientDescriptor messages.geometry)
  let after2 := prefix.claimedH3
  let event3 := oracle.shake256Request statementBinding 3
    .piopCoefficientChallenge after2
      (piopCoefficientDescriptor messages.geometry)
  let after4 := prefix.claimedH5
  let event5 := oracle.shake256Request statementBinding 5
    .piopOpeningChallenge after4
      (piopOpeningDescriptor messages.geometry)
  let after6 := oracle.sha512Request statementBinding 6
    .decsOpeningBinding event5.nextChain messages.decsOpening
  let event7 := oracle.shake256Request statementBinding 7
    .decsQueryChallenge after6
      (decsQueryDescriptor messages.geometry)
  { after0
    challenge1 := event1.challenge
    after1 := event1.nextChain
    after2
    challenge3 := event3.challenge
    after3 := event3.nextChain
    after4
    challenge5 := event5.challenge
    after5 := event5.nextChain
    after6
    challenge7 := event7.challenge
    after7 := event7.nextChain }

inductive DeferredVerifierState where
  | awaitingReconstructedRoot
  | awaitingReconstructedPiopInput
  | awaitingReconstructedPiopTranscript
  | readyToFinish
  | poisoned
deriving DecidableEq, Repr

structure DeferredVerifier where
  prefix : DeferredPrefix
  run : EightEventRun
  state : DeferredVerifierState
deriving DecidableEq, Repr

def driveDeferred
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (messages : EightEventMessages)
    (prefix : DeferredPrefix) : DeferredVerifier :=
  { prefix
    run := deferredRun oracle statementBinding messages prefix
    state := .awaitingReconstructedRoot }

def verifyReconstructedRoot
    (verifier : DeferredVerifier)
    (reconstructedRoot : Digest) : DeferredVerifier :=
  match verifier.state with
  | .awaitingReconstructedRoot =>
      if reconstructedRoot = verifier.prefix.rawDecsRoot then
        { verifier with state := .awaitingReconstructedPiopInput }
      else
        { verifier with state := .poisoned }
  | _ => { verifier with state := .poisoned }

def verifyReconstructedPiopInput
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (verifier : DeferredVerifier)
    (reconstructedPiopInput : TranscriptMessage) : DeferredVerifier :=
  match verifier.state with
  | .awaitingReconstructedPiopInput =>
      let recomputed := oracle.sha512Request statementBinding 2
        .piopInputBinding verifier.run.after1 reconstructedPiopInput
      if recomputed = verifier.prefix.claimedH3 then
        { verifier with state := .awaitingReconstructedPiopTranscript }
      else
        { verifier with state := .poisoned }
  | _ => { verifier with state := .poisoned }

def verifyReconstructedPiopTranscript
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (verifier : DeferredVerifier)
    (reconstructedPiopTranscript : TranscriptMessage) : DeferredVerifier :=
  match verifier.state with
  | .awaitingReconstructedPiopTranscript =>
      let recomputed := oracle.sha512Request statementBinding 4
        .piopTranscriptBinding verifier.run.after3 reconstructedPiopTranscript
      if recomputed = verifier.prefix.claimedH5 then
        { verifier with state := .readyToFinish }
      else
        { verifier with state := .poisoned }
  | _ => { verifier with state := .poisoned }

def finishDeferred (verifier : DeferredVerifier) : Option Digest :=
  match verifier.state with
  | .readyToFinish => some verifier.run.after7
  | _ => none

structure ReconstructedDeferredInputs where
  rawDecsRoot : Digest
  piopInput : TranscriptMessage
  piopTranscript : TranscriptMessage
deriving DecidableEq, Repr

def runDeferredVerifier
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (messages : EightEventMessages)
    (prefix : DeferredPrefix)
    (reconstructed : ReconstructedDeferredInputs) : DeferredVerifier :=
  let afterRoot := verifyReconstructedRoot
    (driveDeferred oracle statementBinding messages prefix)
    reconstructed.rawDecsRoot
  let afterH3 := verifyReconstructedPiopInput oracle statementBinding
    afterRoot reconstructed.piopInput
  verifyReconstructedPiopTranscript oracle statementBinding
    afterH3 reconstructed.piopTranscript

structure OrderedDeferredEqualities
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (drive : EightEventRun)
    (prefix : DeferredPrefix)
    (reconstructed : ReconstructedDeferredInputs) : Prop where
  root : reconstructed.rawDecsRoot = prefix.rawDecsRoot
  h3 : oracle.sha512Request statementBinding 2 .piopInputBinding
      drive.after1 reconstructed.piopInput = prefix.claimedH3
  h5 : oracle.sha512Request statementBinding 4 .piopTranscriptBinding
      drive.after3 reconstructed.piopTranscript = prefix.claimedH5

theorem deferred_acceptance_requires_root_then_h3_then_h5
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (messages : EightEventMessages)
    (prefix : DeferredPrefix)
    (reconstructed : ReconstructedDeferredInputs)
    (accepted : finishDeferred
      (runDeferredVerifier oracle statementBinding messages prefix reconstructed) =
        some (deferredRun oracle statementBinding messages prefix).after7) :
    OrderedDeferredEqualities oracle statementBinding
      (deferredRun oracle statementBinding messages prefix) prefix reconstructed := by
  by_cases root : reconstructed.rawDecsRoot = prefix.rawDecsRoot
  · by_cases h3 : oracle.sha512Request statementBinding 2 .piopInputBinding
        (deferredRun oracle statementBinding messages prefix).after1
        reconstructed.piopInput = prefix.claimedH3
    · by_cases h5 : oracle.sha512Request statementBinding 4 .piopTranscriptBinding
          (deferredRun oracle statementBinding messages prefix).after3
          reconstructed.piopTranscript = prefix.claimedH5
      · exact ⟨root, h3, h5⟩
      · simp [finishDeferred, runDeferredVerifier, verifyReconstructedRoot,
          verifyReconstructedPiopInput, verifyReconstructedPiopTranscript,
          driveDeferred, root, h3, h5] at accepted
    · simp [finishDeferred, runDeferredVerifier, verifyReconstructedRoot,
        verifyReconstructedPiopInput, verifyReconstructedPiopTranscript,
        driveDeferred, root, h3] at accepted
  · simp [finishDeferred, runDeferredVerifier, verifyReconstructedRoot,
      verifyReconstructedPiopInput, verifyReconstructedPiopTranscript,
      driveDeferred, root] at accepted

theorem root_then_h3_then_h5_suffices_for_deferred_acceptance
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (messages : EightEventMessages)
    (prefix : DeferredPrefix)
    (reconstructed : ReconstructedDeferredInputs)
    (equalities : OrderedDeferredEqualities oracle statementBinding
      (deferredRun oracle statementBinding messages prefix) prefix reconstructed) :
    finishDeferred
      (runDeferredVerifier oracle statementBinding messages prefix reconstructed) =
        some (deferredRun oracle statementBinding messages prefix).after7 := by
  rcases equalities with ⟨root, h3, h5⟩
  simp [finishDeferred, runDeferredVerifier, verifyReconstructedRoot,
    verifyReconstructedPiopInput, verifyReconstructedPiopTranscript,
    driveDeferred, root, h3, h5]

def eagerPrefix (messages : EightEventMessages) (run : EightEventRun) : DeferredPrefix :=
  { rawDecsRoot := messages.rawDecsRoot
    claimedH3 := run.after2
    claimedH5 := run.after4 }

theorem eagerPrefix_canonical
    (oracle : TranscriptOracle)
    (widths : OracleOutputWidths oracle)
    (statementBinding : Digest)
    (messages : EightEventMessages)
    (messagesCanonical : messages.Canonical) :
    (eagerPrefix messages (eagerRun oracle statementBinding messages)).Canonical := by
  refine ⟨messagesCanonical.2.2.1, ?_, ?_⟩
  · simpa [eagerPrefix, eagerRun] using
      widths.sha512DigestBytes statementBinding 2 .piopInputBinding
        (eagerRun oracle statementBinding messages).after1 messages.piopInput
  · simpa [eagerPrefix, eagerRun] using
      widths.sha512DigestBytes statementBinding 4 .piopTranscriptBinding
        (eagerRun oracle statementBinding messages).after3 messages.piopTranscript

def reconstructedFromMessages
    (messages : EightEventMessages) : ReconstructedDeferredInputs :=
  { rawDecsRoot := messages.rawDecsRoot
    piopInput := messages.piopInput
    piopTranscript := messages.piopTranscript }

theorem same_oracle_eager_deferred_equivalence
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (messages : EightEventMessages) :
    let eager := eagerRun oracle statementBinding messages
    let prefix := eagerPrefix messages eager
    finishDeferred
      (runDeferredVerifier oracle statementBinding messages prefix
        (reconstructedFromMessages messages)) = some eager.after7 := by
  simp [eagerRun, eagerPrefix, reconstructedFromMessages, finishDeferred,
    runDeferredVerifier, verifyReconstructedRoot,
    verifyReconstructedPiopInput, verifyReconstructedPiopTranscript,
    driveDeferred, deferredRun]

theorem canonical_same_oracle_eager_deferred_equivalence
    (oracle : TranscriptOracle)
    (statementBinding : Digest)
    (messages : EightEventMessages)
    (_statementCanonical : CanonicalDigest statementBinding)
    (_messagesCanonical : messages.Canonical) :
    let eager := eagerRun oracle statementBinding messages
    let prefix := eagerPrefix messages eager
    finishDeferred
      (runDeferredVerifier oracle statementBinding messages prefix
        (reconstructedFromMessages messages)) = some eager.after7 := by
  exact same_oracle_eager_deferred_equivalence oracle statementBinding messages

/-!
These are request-by-request implementation-refinement assumptions, not
cryptographic assumptions.  They say that the Rust request framing and
samplers compute the same pure functions as the Lean reference on every
input.  Determinism follows from representing each primitive as a function.
-/
structure HashXofRequestRefinement
    (reference implementation : TranscriptOracle) : Prop where
  sha512RequestAgreement :
    ∀ statementBinding ordinal stage priorChain message,
      implementation.sha512Request statementBinding ordinal stage priorChain message =
        reference.sha512Request statementBinding ordinal stage priorChain message
  shake256RequestAgreement :
    ∀ statementBinding ordinal stage priorChain descriptor,
      implementation.shake256Request statementBinding ordinal stage priorChain descriptor =
        reference.shake256Request statementBinding ordinal stage priorChain descriptor

theorem implementation_oracle_eq_reference
    {reference implementation : TranscriptOracle}
    (refinement : HashXofRequestRefinement reference implementation) :
    implementation = reference := by
  apply TranscriptOracle.ext
  · funext statementBinding ordinal stage priorChain message
    exact refinement.sha512RequestAgreement
      statementBinding ordinal stage priorChain message
  · funext statementBinding ordinal stage priorChain descriptor
    exact refinement.shake256RequestAgreement
      statementBinding ordinal stage priorChain descriptor

theorem eager_deferred_equivalence_under_hash_xof_refinement
    (reference implementation : TranscriptOracle)
    (refinement : HashXofRequestRefinement reference implementation)
    (statementBinding : Digest)
    (messages : EightEventMessages)
    (statementCanonical : CanonicalDigest statementBinding)
    (messagesCanonical : messages.Canonical) :
    let eager := eagerRun reference statementBinding messages
    let prefix := eagerPrefix messages eager
    finishDeferred
      (runDeferredVerifier implementation statementBinding messages prefix
        (reconstructedFromMessages messages)) = some eager.after7 := by
  have oracleEq := implementation_oracle_eq_reference refinement
  subst implementation
  exact canonical_same_oracle_eager_deferred_equivalence reference statementBinding messages
    statementCanonical messagesCanonical

/-! ## Fail-closed source, identity, and refinement authority -/

structure SourcePin where
  relativePath : String
  sha512Hex : String
deriving DecidableEq, Repr

def frozenTranscriptSourcePin : SourcePin :=
  { relativePath := "circuits/transaction/src/smallwood_hx512_transcript.rs"
    sha512Hex :=
      "a33f9c8962ab6127ccc6866bafe1166186d4a3875843d55b7ac612b62e7ae5154726696ad35725f1d5eab22d53a343a9796de11b70fafce8f958b27846742b7c" }

/- The engine writer has not yet handed off a quiescent source snapshot. -/
def frozenEngineSourcePin : Option SourcePin := none

/- No release-owned magic/version/suite/action/network identity is allocated. -/
def canonicalFreshProtocolIdentity : Option (List Byte) := none

/-!
The q48/s6/eta5 constants above are a structural codec/schedule profile only.
They are not a soundness profile.  SmallWood Theorem 1 / Equation 14 retains
the high-degree codeword-weight contribution customarily written using
`C(N, d + 2) / p^eta`; replacing it with a bare `p^-eta` is not justified by
any theorem retained in this repository.  This explicit false proposition
prevents the parser and state-machine lemmas from being relabeled as a
security certificate.
-/
def SmallWoodEquation14HighDegreeTermDischarged : Prop := False

theorem q48_s6_eta5_has_no_soundness_authority :
    ¬ SmallWoodEquation14HighDegreeTermDischarged := by
  intro impossible
  exact impossible

inductive ExternalRefinementObligation where
  | transcriptSourceReadback
  | engineSourceFreezeAndReadback
  | exactGeometryFreeze
  | canonicalProtocolIdentityAllocation
  | rustFreshCoreCodecConformance
  | rustSha512RequestFramingRefinement
  | rustShake256SamplerRefinement
  | abstractOracleOutputWidthRefinement
  | smallWoodEquation14HighDegreeCodewordWeight
  | rustEagerDeferredScheduleRefinement
  | compiledRelationRefinement
  | completeZeroKnowledge
  | composedPqQromSecurity
  | verifierConsensusLifecycleRefinement
  | retainedArtifactAndReleaseManifest
deriving DecidableEq, Repr

def allExternalRefinementObligations : List ExternalRefinementObligation :=
  [ .transcriptSourceReadback,
    .engineSourceFreezeAndReadback,
    .exactGeometryFreeze,
    .canonicalProtocolIdentityAllocation,
    .rustFreshCoreCodecConformance,
    .rustSha512RequestFramingRefinement,
    .rustShake256SamplerRefinement,
    .abstractOracleOutputWidthRefinement,
    .smallWoodEquation14HighDegreeCodewordWeight,
    .rustEagerDeferredScheduleRefinement,
    .compiledRelationRefinement,
    .completeZeroKnowledge,
    .composedPqQromSecurity,
    .verifierConsensusLifecycleRefinement,
    .retainedArtifactAndReleaseManifest ]

theorem external_refinement_obligations_exhaustive
    (obligation : ExternalRefinementObligation) :
    obligation ∈ allExternalRefinementObligations := by
  cases obligation <;> decide

theorem external_refinement_obligations_duplicate_free :
    allExternalRefinementObligations.Nodup := by
  unfold allExternalRefinementObligations
  decide

inductive ExternalRefinementEvidence : ExternalRefinementObligation → Prop

structure CompleteExternalRefinementEvidence : Type where
  evidence : ∀ obligation, ExternalRefinementEvidence obligation

def retainedExternalRefinementEvidence : Option CompleteExternalRefinementEvidence := none

def ProductionAuthorized : Prop :=
  ∃ evidence : CompleteExternalRefinementEvidence,
    retainedExternalRefinementEvidence = some evidence ∧
      frozenEngineSourcePin.isSome = true ∧
      canonicalFreshProtocolIdentity.isSome = true

theorem no_external_refinement_obligation_is_discharged
    (obligation : ExternalRefinementObligation) :
    ¬ ExternalRefinementEvidence obligation := by
  intro impossible
  cases impossible

theorem production_authority_fails_closed :
    ¬ ProductionAuthorized := by
  intro authorized
  rcases authorized with ⟨evidence, retained, _, _⟩
  simp [retainedExternalRefinementEvidence] at retained

end HegemonCrypto.SmallWood.Hx512Refinement
