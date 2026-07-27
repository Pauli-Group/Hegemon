import HegemonCrypto.SmallWoodProofWire

set_option maxRecDepth 10000

namespace HegemonCrypto
namespace SmallWoodProofWireExamples

open CanonicalBytes
open SmallWoodProofWire

def zeroBytes (count : Nat) : List Byte :=
  List.replicate count 0

def matrix (rows columns : Nat) (values : List Byte := []) : MatrixWire :=
  { rowCountBytes := encodeLE 2 rows,
    columnCountBytes := encodeLE 2 columns,
    valueBytes := values }

def zeroMatrix : MatrixWire := matrix 0 0

def zeroAuthPaths : AuthPathsWire :=
  { rowCountBytes := encodeLE 2 0,
    pathLengthBytes := [],
    nodeBytes := [] }

def emptyPathAuthPaths : AuthPathsWire :=
  { rowCountBytes := encodeLE 2 1,
    pathLengthBytes := [0],
    nodeBytes := [] }

def zeroPiop : PiopWire :=
  { polynomialHighs := zeroMatrix,
    linearHighs := zeroMatrix }

def zeroDecs : DecsWire :=
  { authPaths := zeroAuthPaths,
    maskingEvaluations := zeroMatrix,
    highCoefficients := zeroMatrix }

def zeroPcs : PcsWire :=
  { randomCombinationTails := zeroMatrix,
    subsetEvaluations := zeroMatrix,
    partialEvaluations := zeroMatrix,
    decs := zeroDecs }

def canonicalMinimalProof : ProofWire :=
  { saltBytes := zeroBytes 32,
    nonceBytes := zeroBytes 4,
    piopHashBytes := zeroBytes 32,
    piop := zeroPiop,
    pcs := zeroPcs,
    openedWitness := .none }

def invalidZeroShapeProof : ProofWire :=
  { canonicalMinimalProof with
      piop := { zeroPiop with polynomialHighs := matrix 1 0 } }

def excessiveRowsProof : ProofWire :=
  { canonicalMinimalProof with
      piop := { zeroPiop with polynomialHighs := matrix 26 1 } }

def noncanonicalFieldProof : ProofWire :=
  { canonicalMinimalProof with
      piop :=
        { zeroPiop with
            polynomialHighs := matrix 1 1 (encodeLE 8 fieldOrder) } }

def emptyAuthPathProof : ProofWire :=
  { canonicalMinimalProof with
      pcs := { zeroPcs with decs := { zeroDecs with authPaths := emptyPathAuthPaths } } }

def wrongMagicBytes : List Byte :=
  [0, 77, 87, 49] ++ proofPayloadCodec.encode canonicalMinimalProof

def trailingBytes : List Byte :=
  canonicalMinimalProof.encode ++ [170]

def invalidOpenedWitnessModeBytes : List Byte :=
  canonicalMinimalProof.encode.dropLast ++ [2]

theorem canonical_minimal_proof_is_canonical :
    canonicalMinimalProof.Canonical := by
  simp [ProofWire.Canonical, proofPayloadCodec, PrefixCodec.xmap,
    PrefixCodec.pair, PrefixCodec.fixed, piopCodec, pcsCodec, decsCodec,
    openedWitnessCodec, matrixCodec, authPathsCodec,
    canonicalMinimalProof, zeroPiop, zeroPcs, zeroDecs, zeroMatrix,
    zeroAuthPaths, zeroBytes, matrix, MatrixWire.Canonical,
    MatrixWire.rowCount, MatrixWire.columnCount, AuthPathsWire.Canonical,
    AuthPathsWire.rowCount, AuthPathsWire.nodeCount,
    OpenedWitnessWire.Canonical, maximumCollectionRows, digestBytes,
    fieldWordsCanonicalB, fieldOrder, encodeLE, decodeLE]

theorem canonical_minimal_proof_roundtrips :
    decodeProofExact canonicalMinimalProof.encode = some canonicalMinimalProof := by
  exact decodeProofExact_encode canonicalMinimalProof canonical_minimal_proof_is_canonical

theorem wrong_magic_rejects :
    decodeProofExact wrongMagicBytes = none := by
  decide

theorem trailing_byte_rejects :
    decodeProofExact trailingBytes = none := by
  decide

theorem zero_nonzero_matrix_shape_rejects :
    decodeProofExact invalidZeroShapeProof.encode = none := by
  decide

theorem excessive_matrix_rows_reject :
    decodeProofExact excessiveRowsProof.encode = none := by
  decide

theorem noncanonical_field_word_rejects :
    decodeProofExact noncanonicalFieldProof.encode = none := by
  decide

theorem empty_auth_path_rejects :
    decodeProofExact emptyAuthPathProof.encode = none := by
  decide

theorem invalid_opened_witness_mode_rejects :
    decodeProofExact invalidOpenedWitnessModeBytes = none := by
  decide

end SmallWoodProofWireExamples
end HegemonCrypto
