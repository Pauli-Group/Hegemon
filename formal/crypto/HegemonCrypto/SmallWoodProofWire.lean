import HegemonCrypto.CanonicalBytes
import HegemonCrypto.Goldilocks

namespace HegemonCrypto
namespace SmallWoodProofWire

open CanonicalBytes

def maximumCollectionRows : Nat := 96
def digestBytes : Nat := 64
def fieldOrder : Nat :=
  Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus

def fieldWordsCanonicalB (bytes : List Byte) : Bool :=
  bytes.length % 8 == 0 &&
    (List.range (bytes.length / 8)).all (fun index =>
      decide (decodeLE ((bytes.drop (index * 8)).take 8) < fieldOrder))

structure MatrixWire where
  rowCountBytes : List Byte
  columnCountBytes : List Byte
  valueBytes : List Byte
deriving DecidableEq, Repr

namespace MatrixWire

def rowCount (matrix : MatrixWire) : Nat :=
  decodeLE matrix.rowCountBytes

def columnCount (matrix : MatrixWire) : Nat :=
  decodeLE matrix.columnCountBytes

def encode (matrix : MatrixWire) : List Byte :=
  matrix.rowCountBytes ++ matrix.columnCountBytes ++ matrix.valueBytes

def Canonical (matrix : MatrixWire) : Prop :=
  matrix.rowCountBytes.length = 2
    ∧ matrix.columnCountBytes.length = 2
    ∧ matrix.rowCount <= maximumCollectionRows
    ∧ (matrix.rowCount = 0 ↔ matrix.columnCount = 0)
    ∧ matrix.valueBytes.length = matrix.rowCount * matrix.columnCount * 8
    ∧ fieldWordsCanonicalB matrix.valueBytes = true

end MatrixWire

def decodeMatrixPrefix (input : List Byte) : Option (MatrixWire × List Byte) := do
  let (rowCountBytes, afterRows) ← readFixed 2 input
  let (columnCountBytes, afterColumns) ← readFixed 2 afterRows
  let rows := decodeLE rowCountBytes
  let columns := decodeLE columnCountBytes
  if rows <= maximumCollectionRows then
    if (rows = 0 ↔ columns = 0) then
      let (valueBytes, suffix) ← readFixed (rows * columns * 8) afterColumns
      if fieldWordsCanonicalB valueBytes then
        some ({ rowCountBytes, columnCountBytes, valueBytes }, suffix)
      else
        none
    else
      none
  else
    none

theorem decodeMatrixPrefix_encode
    (matrix : MatrixWire)
    (suffix : List Byte)
    (canonical : matrix.Canonical) :
    decodeMatrixPrefix (matrix.encode ++ suffix) = some (matrix, suffix) := by
  rcases canonical with
    ⟨rows_length, columns_length, rows_bound, zero_shape, values_length,
      values_canonical⟩
  change decodeLE matrix.rowCountBytes <= maximumCollectionRows at rows_bound
  change
    (decodeLE matrix.rowCountBytes = 0 ↔ decodeLE matrix.columnCountBytes = 0)
    at zero_shape
  change
    matrix.valueBytes.length =
      decodeLE matrix.rowCountBytes * decodeLE matrix.columnCountBytes * 8
    at values_length
  simp [decodeMatrixPrefix, MatrixWire.encode, rows_length, columns_length,
    rows_bound, zero_shape, values_length, values_canonical, List.append_assoc]

theorem decodeMatrixPrefix_sound
    {input : List Byte}
    {matrix : MatrixWire}
    {suffix : List Byte}
    (decoded : decodeMatrixPrefix input = some (matrix, suffix)) :
    matrix.Canonical ∧ input = matrix.encode ++ suffix := by
  unfold decodeMatrixPrefix at decoded
  cases rowsResult : readFixed 2 input with
  | none => simp [rowsResult] at decoded
  | some rowsPair =>
      rcases rowsPair with ⟨rowCountBytes, afterRows⟩
      cases columnsResult : readFixed 2 afterRows with
      | none => simp [rowsResult, columnsResult] at decoded
      | some columnsPair =>
          rcases columnsPair with ⟨columnCountBytes, afterColumns⟩
          simp [rowsResult, columnsResult] at decoded
          rcases decoded with ⟨rows_bound, zero_shape, decoded⟩
          cases valuesResult :
              readFixed
                (decodeLE rowCountBytes * decodeLE columnCountBytes * 8)
                afterColumns with
          | none => simp [valuesResult] at decoded
          | some valuesPair =>
              rcases valuesPair with ⟨valueBytes, finalSuffix⟩
              simp [valuesResult] at decoded
              rcases decoded with ⟨values_canonical, matrix_eq, suffix_eq⟩
              subst matrix
              subst suffix
              rcases readFixed_sound rowsResult with
                ⟨rows_length, input_eq⟩
              rcases readFixed_sound columnsResult with
                ⟨columns_length, after_rows_eq⟩
              rcases readFixed_sound valuesResult with
                ⟨values_length, after_columns_eq⟩
              constructor
              · exact
                  ⟨rows_length, columns_length, rows_bound, zero_shape,
                    values_length, values_canonical⟩
              · simp only [MatrixWire.encode]
                rw [input_eq, after_rows_eq, after_columns_eq]
                simp [List.append_assoc]

def matrixCodec : PrefixCodec MatrixWire where
  encode := MatrixWire.encode
  decode := decodeMatrixPrefix
  canonical := MatrixWire.Canonical
  decode_encode := decodeMatrixPrefix_encode
  decode_sound := decodeMatrixPrefix_sound

structure AuthPathsWire where
  rowCountBytes : List Byte
  pathLengthBytes : List Byte
  nodeBytes : List Byte
deriving DecidableEq, Repr

namespace AuthPathsWire

def rowCount (paths : AuthPathsWire) : Nat :=
  decodeLE paths.rowCountBytes

def nodeCount (paths : AuthPathsWire) : Nat :=
  (paths.pathLengthBytes.map Fin.val).sum

def encode (paths : AuthPathsWire) : List Byte :=
  paths.rowCountBytes ++ paths.pathLengthBytes ++ paths.nodeBytes

def Canonical (paths : AuthPathsWire) : Prop :=
  paths.rowCountBytes.length = 2
    ∧ paths.rowCount <= maximumCollectionRows
    ∧ paths.pathLengthBytes.length = paths.rowCount
    ∧ (∀ lengthByte ∈ paths.pathLengthBytes, lengthByte.val ≠ 0)
    ∧ paths.nodeBytes.length = paths.nodeCount * digestBytes

end AuthPathsWire

def decodeAuthPathsPrefix (input : List Byte) : Option (AuthPathsWire × List Byte) := do
  let (rowCountBytes, afterRows) ← readFixed 2 input
  let rows := decodeLE rowCountBytes
  if rows <= maximumCollectionRows then
    let (pathLengthBytes, afterLengths) ← readFixed rows afterRows
    if ∀ lengthByte ∈ pathLengthBytes, lengthByte.val ≠ 0 then
      let nodeCount := (pathLengthBytes.map Fin.val).sum
      let (nodeBytes, suffix) ← readFixed (nodeCount * digestBytes) afterLengths
      some ({ rowCountBytes, pathLengthBytes, nodeBytes }, suffix)
    else
      none
  else
    none

theorem decodeAuthPathsPrefix_encode
    (paths : AuthPathsWire)
    (suffix : List Byte)
    (canonical : paths.Canonical) :
    decodeAuthPathsPrefix (paths.encode ++ suffix) = some (paths, suffix) := by
  rcases canonical with
    ⟨rows_length, rows_bound, path_lengths_length, paths_nonempty, nodes_length⟩
  change decodeLE paths.rowCountBytes <= maximumCollectionRows at rows_bound
  change paths.pathLengthBytes.length = decodeLE paths.rowCountBytes at path_lengths_length
  change
    paths.nodeBytes.length =
      (paths.pathLengthBytes.map Fin.val).sum * digestBytes
    at nodes_length
  have no_zero : ¬(0 : Byte) ∈ paths.pathLengthBytes := by
    intro zero_mem
    exact paths_nonempty 0 zero_mem (by decide)
  simp [decodeAuthPathsPrefix, AuthPathsWire.encode, rows_length, rows_bound,
    path_lengths_length, no_zero, nodes_length, List.append_assoc]

theorem decodeAuthPathsPrefix_sound
    {input : List Byte}
    {paths : AuthPathsWire}
    {suffix : List Byte}
    (decoded : decodeAuthPathsPrefix input = some (paths, suffix)) :
    paths.Canonical ∧ input = paths.encode ++ suffix := by
  unfold decodeAuthPathsPrefix at decoded
  cases rowsResult : readFixed 2 input with
  | none => simp [rowsResult] at decoded
  | some rowsPair =>
      rcases rowsPair with ⟨rowCountBytes, afterRows⟩
      simp [rowsResult] at decoded
      rcases decoded with ⟨rows_bound, decoded⟩
      cases lengthsResult : readFixed (decodeLE rowCountBytes) afterRows with
      | none => simp [lengthsResult] at decoded
      | some lengthsPair =>
          rcases lengthsPair with ⟨pathLengthBytes, afterLengths⟩
          simp [lengthsResult] at decoded
          rcases decoded with ⟨no_zero, decoded⟩
          cases nodesResult :
              readFixed
                ((pathLengthBytes.map Fin.val).sum * digestBytes)
                afterLengths with
          | none => simp [nodesResult] at decoded
          | some nodesPair =>
              rcases nodesPair with ⟨nodeBytes, finalSuffix⟩
              simp [nodesResult] at decoded
              rcases decoded with ⟨paths_eq, suffix_eq⟩
              subst paths
              subst suffix
              rcases readFixed_sound rowsResult with
                ⟨rows_length, input_eq⟩
              rcases readFixed_sound lengthsResult with
                ⟨path_lengths_length, after_rows_eq⟩
              rcases readFixed_sound nodesResult with
                ⟨nodes_length, after_lengths_eq⟩
              have paths_nonempty :
                  ∀ lengthByte ∈ pathLengthBytes, lengthByte.val ≠ 0 := by
                intro lengthByte member value_zero
                exact no_zero lengthByte member (Fin.ext value_zero)
              constructor
              · exact
                  ⟨rows_length, rows_bound, path_lengths_length,
                    paths_nonempty, nodes_length⟩
              · simp only [AuthPathsWire.encode]
                rw [input_eq, after_rows_eq, after_lengths_eq]
                simp [List.append_assoc]

def authPathsCodec : PrefixCodec AuthPathsWire where
  encode := AuthPathsWire.encode
  decode := decodeAuthPathsPrefix
  canonical := AuthPathsWire.Canonical
  decode_encode := decodeAuthPathsPrefix_encode
  decode_sound := decodeAuthPathsPrefix_sound

inductive OpenedWitnessWire where
  | none
  | rowScalars
      (matrix : MatrixWire)
      (auxiliaryWordCountBytes : List Byte)
      (auxiliaryLimbCountBytes : List Byte)
      (auxiliaryWordBytes : List Byte)
deriving DecidableEq, Repr

namespace OpenedWitnessWire

def encode : OpenedWitnessWire -> List Byte
  | .none => [0]
  | .rowScalars matrix wordCountBytes limbCountBytes wordBytes =>
      [1] ++ matrix.encode ++ wordCountBytes ++ limbCountBytes ++ wordBytes

def Canonical : OpenedWitnessWire -> Prop
  | .none => True
  | .rowScalars matrix wordCountBytes limbCountBytes wordBytes =>
      matrix.Canonical
        ∧ wordCountBytes.length = 4
        ∧ limbCountBytes.length = 4
        ∧ decodeLE limbCountBytes <= decodeLE wordCountBytes
        ∧ wordBytes.length = decodeLE wordCountBytes * 8
        ∧ fieldWordsCanonicalB wordBytes = true

end OpenedWitnessWire

def decodeOpenedWitnessPrefix
    (input : List Byte) : Option (OpenedWitnessWire × List Byte) := do
  let (mode, afterMode) ← readByte input
  if mode = (0 : Byte) then
    some (.none, afterMode)
  else if mode = (1 : Byte) then
    let (matrix, afterMatrix) ← decodeMatrixPrefix afterMode
    let (wordCountBytes, afterWordCount) ← readFixed 4 afterMatrix
    let (limbCountBytes, afterLimbCount) ← readFixed 4 afterWordCount
    if decodeLE limbCountBytes <= decodeLE wordCountBytes then
      let (wordBytes, suffix) ←
        readFixed (decodeLE wordCountBytes * 8) afterLimbCount
      if fieldWordsCanonicalB wordBytes then
        some (.rowScalars matrix wordCountBytes limbCountBytes wordBytes, suffix)
      else
        none
    else
      none
  else
    none

theorem decodeOpenedWitnessPrefix_encode
    (openedWitness : OpenedWitnessWire)
    (suffix : List Byte)
    (canonical : openedWitness.Canonical) :
    decodeOpenedWitnessPrefix (openedWitness.encode ++ suffix) =
      some (openedWitness, suffix) := by
  cases openedWitness with
  | none => simp [decodeOpenedWitnessPrefix, OpenedWitnessWire.encode, readByte]
  | rowScalars matrix wordCountBytes limbCountBytes wordBytes =>
      rcases canonical with
        ⟨matrixCanonical, wordCountLength, limbCountLength, limbBound,
          wordBytesLength, wordBytesCanonical⟩
      simp only [OpenedWitnessWire.encode, List.cons_append, List.nil_append]
      unfold decodeOpenedWitnessPrefix
      simp [readByte]
      rw [decodeMatrixPrefix_encode matrix
        (wordCountBytes ++ (limbCountBytes ++ (wordBytes ++ suffix)))
        matrixCanonical]
      simp only [Option.bind_some]
      rw [readFixed_append wordCountLength]
      simp only [Option.bind_some]
      rw [readFixed_append limbCountLength]
      simp only [Option.bind_some, if_pos limbBound]
      rw [readFixed_append wordBytesLength]
      simp [wordBytesCanonical]

theorem decodeOpenedWitnessPrefix_sound
    {input : List Byte}
    {openedWitness : OpenedWitnessWire}
    {suffix : List Byte}
    (decoded : decodeOpenedWitnessPrefix input = some (openedWitness, suffix)) :
    openedWitness.Canonical ∧ input = openedWitness.encode ++ suffix := by
  unfold decodeOpenedWitnessPrefix at decoded
  cases modeResult : readByte input with
  | none => simp [modeResult] at decoded
  | some modePair =>
      rcases modePair with ⟨mode, afterMode⟩
      by_cases mode_zero : mode = (0 : Byte)
      · simp [modeResult, mode_zero] at decoded
        rcases decoded with ⟨opened_eq, suffix_eq⟩
        subst openedWitness
        subst suffix
        constructor
        · trivial
        · have input_eq := readByte_sound modeResult
          simpa [OpenedWitnessWire.encode, mode_zero] using input_eq
      · by_cases mode_one : mode = (1 : Byte)
        · simp [modeResult, mode_one] at decoded
          cases matrixResult : decodeMatrixPrefix afterMode with
          | none => simp [matrixResult] at decoded
          | some matrixPair =>
              rcases matrixPair with ⟨matrix, afterMatrix⟩
              cases wordCountResult : readFixed 4 afterMatrix with
              | none => simp [matrixResult, wordCountResult] at decoded
              | some wordCountPair =>
                  rcases wordCountPair with ⟨wordCountBytes, afterWordCount⟩
                  cases limbCountResult : readFixed 4 afterWordCount with
                  | none =>
                      simp [matrixResult, wordCountResult, limbCountResult] at decoded
                  | some limbCountPair =>
                      rcases limbCountPair with ⟨limbCountBytes, afterLimbCount⟩
                      simp [matrixResult, wordCountResult, limbCountResult] at decoded
                      rcases decoded with ⟨limbBound, decoded⟩
                      cases wordsResult :
                          readFixed (decodeLE wordCountBytes * 8) afterLimbCount with
                      | none => simp [wordsResult] at decoded
                      | some wordsPair =>
                          rcases wordsPair with ⟨wordBytes, finalSuffix⟩
                          simp [wordsResult] at decoded
                          rcases decoded with
                            ⟨wordBytesCanonical, opened_eq, suffix_eq⟩
                          subst openedWitness
                          subst suffix
                          rcases decodeMatrixPrefix_sound matrixResult with
                            ⟨matrixCanonical, after_mode_eq⟩
                          rcases readFixed_sound wordCountResult with
                            ⟨wordCountLength, after_matrix_eq⟩
                          rcases readFixed_sound limbCountResult with
                            ⟨limbCountLength, after_word_count_eq⟩
                          rcases readFixed_sound wordsResult with
                            ⟨wordBytesLength, after_limb_count_eq⟩
                          constructor
                          · exact
                              ⟨matrixCanonical, wordCountLength, limbCountLength,
                                limbBound, wordBytesLength, wordBytesCanonical⟩
                          · have input_eq := readByte_sound modeResult
                            simp only [OpenedWitnessWire.encode]
                            rw [input_eq, mode_one, after_mode_eq, after_matrix_eq,
                              after_word_count_eq, after_limb_count_eq]
                            simp [List.append_assoc]
        · simp [modeResult, mode_zero, mode_one] at decoded

def openedWitnessCodec : PrefixCodec OpenedWitnessWire where
  encode := OpenedWitnessWire.encode
  decode := decodeOpenedWitnessPrefix
  canonical := OpenedWitnessWire.Canonical
  decode_encode := decodeOpenedWitnessPrefix_encode
  decode_sound := decodeOpenedWitnessPrefix_sound

structure PiopWire where
  polynomialHighs : MatrixWire
  linearHighs : MatrixWire
deriving DecidableEq, Repr

def piopCodec : PrefixCodec PiopWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair matrixCodec matrixCodec)
    (fun pair => { polynomialHighs := pair.1, linearHighs := pair.2 })
    (fun piop => (piop.polynomialHighs, piop.linearHighs))
    (by intro value; cases value; rfl)
    (by intro value; cases value; rfl)

structure DecsWire where
  authPaths : AuthPathsWire
  maskingEvaluations : MatrixWire
  highCoefficients : MatrixWire
deriving DecidableEq, Repr

def decsCodec : PrefixCodec DecsWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair authPathsCodec
      (PrefixCodec.pair matrixCodec matrixCodec))
    (fun value =>
      { authPaths := value.1,
        maskingEvaluations := value.2.1,
        highCoefficients := value.2.2 })
    (fun decs =>
      (decs.authPaths, (decs.maskingEvaluations, decs.highCoefficients)))
    (by intro value; cases value with | mk auth rest => cases rest; rfl)
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
      (PrefixCodec.pair matrixCodec
        (PrefixCodec.pair matrixCodec decsCodec)))
    (fun value =>
      { randomCombinationTails := value.1,
        subsetEvaluations := value.2.1,
        partialEvaluations := value.2.2.1,
        decs := value.2.2.2 })
    (fun pcs =>
      (pcs.randomCombinationTails,
        (pcs.subsetEvaluations, (pcs.partialEvaluations, pcs.decs))))
    (by
      intro value
      cases value with
      | mk randomTails rest =>
          cases rest with
          | mk subset rest => cases rest; rfl)
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
            (PrefixCodec.pair pcsCodec openedWitnessCodec)))))
    (fun value =>
      { saltBytes := value.1,
        nonceBytes := value.2.1,
        piopHashBytes := value.2.2.1,
        piop := value.2.2.2.1,
        pcs := value.2.2.2.2.1,
        openedWitness := value.2.2.2.2.2 })
    (fun proof =>
      (proof.saltBytes,
        (proof.nonceBytes,
          (proof.piopHashBytes,
            (proof.piop, (proof.pcs, proof.openedWitness))))))
    (by
      intro value
      cases value with
      | mk salt rest =>
          cases rest with
          | mk nonce rest =>
              cases rest with
              | mk hash rest =>
                  cases rest with
                  | mk piop rest => cases rest; rfl)
    (by intro value; cases value; rfl)

def proofMagic : List Byte := [83, 77, 87, 50]

theorem proofMagic_length : proofMagic.length = 4 := by
  rfl

namespace ProofWire

def encode (proof : ProofWire) : List Byte :=
  proofMagic ++ proofPayloadCodec.encode proof

def Canonical (proof : ProofWire) : Prop :=
  proofPayloadCodec.canonical proof

end ProofWire

def decodeProofPrefix (input : List Byte) : Option (ProofWire × List Byte) := do
  let (magic, afterMagic) ← readFixed 4 input
  if magic = proofMagic then
    proofPayloadCodec.decode afterMagic
  else
    none

theorem decodeProofPrefix_encode
    (proof : ProofWire)
    (suffix : List Byte)
    (canonical : proof.Canonical) :
    decodeProofPrefix (proof.encode ++ suffix) = some (proof, suffix) := by
  unfold ProofWire.Canonical at canonical
  unfold decodeProofPrefix ProofWire.encode
  rw [List.append_assoc]
  rw [readFixed_append proofMagic_length]
  simp [proofPayloadCodec.decode_encode proof suffix canonical]

theorem decodeProofPrefix_sound
    {input : List Byte}
    {proof : ProofWire}
    {suffix : List Byte}
    (decoded : decodeProofPrefix input = some (proof, suffix)) :
    proof.Canonical ∧ input = proof.encode ++ suffix := by
  unfold decodeProofPrefix at decoded
  cases magicResult : readFixed 4 input with
  | none => simp [magicResult] at decoded
  | some magicPair =>
      rcases magicPair with ⟨magic, afterMagic⟩
      simp [magicResult] at decoded
      rcases decoded with ⟨magic_eq, decoded⟩
      rcases proofPayloadCodec.decode_sound decoded with
        ⟨canonical, after_magic_eq⟩
      rcases readFixed_sound magicResult with ⟨_, input_eq⟩
      subst magic
      constructor
      · exact canonical
      · unfold ProofWire.encode
        rw [input_eq, after_magic_eq, List.append_assoc]

def decodeProofExact (input : List Byte) : Option ProofWire := do
  let (proof, suffix) ← decodeProofPrefix input
  if suffix = [] then
    some proof
  else
    none

theorem decodeProofExact_encode
    (proof : ProofWire)
    (canonical : proof.Canonical) :
    decodeProofExact proof.encode = some proof := by
  unfold decodeProofExact
  rw [show proof.encode = proof.encode ++ [] by simp]
  rw [decodeProofPrefix_encode proof [] canonical]
  rfl

theorem decodeProofExact_sound
    {input : List Byte}
    {proof : ProofWire}
    (decoded : decodeProofExact input = some proof) :
    proof.Canonical ∧ input = proof.encode := by
  unfold decodeProofExact at decoded
  cases prefixResult : decodeProofPrefix input with
  | none => simp [prefixResult] at decoded
  | some prefixPair =>
      rcases prefixPair with ⟨parsedProof, suffix⟩
      simp [prefixResult] at decoded
      rcases decoded with ⟨suffix_empty, proof_eq⟩
      subst parsedProof
      subst suffix
      simpa using decodeProofPrefix_sound prefixResult

theorem decodeProofExact_rejects_trailing_bytes
    (proof : ProofWire)
    (suffix : List Byte)
    (canonical : proof.Canonical)
    (suffix_nonempty : suffix ≠ []) :
    decodeProofExact (proof.encode ++ suffix) = none := by
  unfold decodeProofExact
  rw [decodeProofPrefix_encode proof suffix canonical]
  simp [suffix_nonempty]

theorem decodeProofExact_rejects_wrong_magic
    (magic : List Byte)
    (payload : List Byte)
    (magic_length : magic.length = 4)
    (wrong_magic : magic ≠ proofMagic) :
    decodeProofExact (magic ++ payload) = none := by
  unfold decodeProofExact decodeProofPrefix
  rw [readFixed_append magic_length]
  simp [wrong_magic]

end SmallWoodProofWire
end HegemonCrypto
