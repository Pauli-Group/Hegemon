import Hegemon.Bytes

set_option maxRecDepth 10000

namespace Hegemon
namespace Wallet
namespace NoteCiphertextWire

def chainCiphertextSize : Nat := 579
def mlKemCiphertextLen : Nat := 1568
def cryptoSuiteGamma : Nat := 3

structure NoteCiphertextSummary where
  version : Nat
  cryptoSuite : Nat
  diversifierIndex : Nat
  kemLen : Nat
  notePayloadLen : Nat
  memoPayloadLen : Nat
deriving DecidableEq, Repr

def leValue : List Byte -> Nat
  | [] => 0
  | byteValue :: rest => byte byteValue + 256 * leValue rest

def takeBytes (count : Nat) (input : List Byte) : Option (List Byte × List Byte) :=
  if count <= input.length then
    some (input.take count, input.drop count)
  else
    none

def skipBytes (count : Nat) (input : List Byte) : Option (List Byte) := do
  let (_, rest) ← takeBytes count input
  some rest

def readNat (width : Nat) (input : List Byte) : Option (Nat × List Byte) := do
  let (raw, rest) ← takeBytes width input
  some (leValue raw, rest)

def readU8 : List Byte -> Option (Nat × List Byte) :=
  readNat 1

def readU16 : List Byte -> Option (Nat × List Byte) :=
  readNat 2

def readU32 : List Byte -> Option (Nat × List Byte) :=
  readNat 4

def lastOrZero : List Byte -> Byte
  | [] => 0
  | [value] => value
  | _ :: rest => lastOrZero rest

def parseCompactLen (input : List Byte) : Option (Nat × List Byte) :=
  match input with
  | [] => none
  | first :: rest =>
      let flag := first % 4
      if flag = 0 then
        some (first / 4, rest)
      else if flag = 1 then do
        let (raw, tail) ← readNat 2 input
        let value := raw / 4
        if value < 64 then none else some (value, tail)
      else if flag = 2 then do
        let (raw, tail) ← readNat 4 input
        let value := raw / 4
        if value < 16384 then none else some (value, tail)
      else
        let bytesNeeded := first / 4 + 4
        if bytesNeeded > 8 then
          none
        else if rest.length < bytesNeeded then
          none
        else
          let raw := rest.take bytesNeeded
          let tail := rest.drop bytesNeeded
          let value := leValue raw
          if value < 1073741824 then
            none
          else if lastOrZero raw = 0 then
            none
          else
            some (value, tail)

def parseCryptoNoteCiphertext (input : List Byte) : Option NoteCiphertextSummary := do
  let (version, rest0) ← readU8 input
  let (cryptoSuite, rest1) ← readU16 rest0
  let (diversifierIndex, rest2) ← readU32 rest1
  let (kemLen, rest3) ← readU32 rest2
  if kemLen = mlKemCiphertextLen then
    let rest4 ← skipBytes kemLen rest3
    let (notePayloadLen, rest5) ← readU32 rest4
    let rest6 ← skipBytes notePayloadLen rest5
    let (memoPayloadLen, rest7) ← readU32 rest6
    let rest8 ← skipBytes memoPayloadLen rest7
    match rest8 with
    | [] =>
        some {
          version,
          cryptoSuite,
          diversifierIndex,
          kemLen,
          notePayloadLen,
          memoPayloadLen
        }
    | _ :: _ => none
  else
    none

def parseChainContainer (input : List Byte) : Option NoteCiphertextSummary := do
  let (version, rest0) ← readU8 input
  let (cryptoSuite, rest1) ← readU16 rest0
  let (diversifierIndex, rest2) ← readU32 rest1
  let (notePayloadLen, rest3) ← readU32 rest2
  let rest4 ← skipBytes notePayloadLen rest3
  let (memoPayloadLen, rest5) ← readU32 rest4
  let rest6 ← skipBytes memoPayloadLen rest5
  if cryptoSuite = cryptoSuiteGamma && rest6.all (fun byteValue => byteValue = 0) then
    some {
      version,
      cryptoSuite,
      diversifierIndex,
      kemLen := mlKemCiphertextLen,
      notePayloadLen,
      memoPayloadLen
    }
  else
    none

def parseChainNoteCiphertext (input : List Byte) : Option NoteCiphertextSummary := do
  let (container, rest0) ← takeBytes chainCiphertextSize input
  let summary ← parseChainContainer container
  let (kemLen, rest1) ← parseCompactLen rest0
  if kemLen = mlKemCiphertextLen then
    let rest2 ← skipBytes kemLen rest1
    match rest2 with
    | [] => some summary
    | _ :: _ => none
  else
    none

def sampleNotePayload : List Byte :=
  patternedBytes 5 0x10

def sampleMemoPayload : List Byte :=
  patternedBytes 3 0x80

def sampleKemCiphertext : List Byte :=
  patternedBytes mlKemCiphertextLen 0x40

def cryptoWire (notePayload memoPayload : List Byte) : List Byte :=
  [3]
    ++ u16le cryptoSuiteGamma
    ++ u32le 7
    ++ u32le mlKemCiphertextLen
    ++ sampleKemCiphertext
    ++ u32le notePayload.length
    ++ notePayload
    ++ u32le memoPayload.length
    ++ memoPayload

def validCryptoWire : List Byte :=
  cryptoWire sampleNotePayload sampleMemoPayload

def cryptoTruncatedWire : List Byte :=
  validCryptoWire.take (7 + 4 + mlKemCiphertextLen)

def cryptoTrailingWire : List Byte :=
  validCryptoWire ++ [0x99]

def validChainContainer : List Byte :=
  let headBytes :=
    [3]
      ++ u16le cryptoSuiteGamma
      ++ u32le 7
      ++ u32le sampleNotePayload.length
      ++ sampleNotePayload
      ++ u32le sampleMemoPayload.length
      ++ sampleMemoPayload;
  headBytes ++ List.replicate (chainCiphertextSize - headBytes.length) 0

def chainCompactKemLen : List Byte :=
  u16le (mlKemCiphertextLen * 4 + 1)

def validChainWire : List Byte :=
  validChainContainer ++ chainCompactKemLen ++ sampleKemCiphertext

def chainMemoOverrunContainer : List Byte :=
  let headBytes :=
    [3]
      ++ u16le cryptoSuiteGamma
      ++ u32le 7
      ++ u32le sampleNotePayload.length
      ++ sampleNotePayload
      ++ u32le chainCiphertextSize;
  headBytes ++ List.replicate (chainCiphertextSize - headBytes.length) 0

def chainMemoOverrunWire : List Byte :=
  chainMemoOverrunContainer ++ chainCompactKemLen ++ sampleKemCiphertext

def chainNonzeroPaddingContainer : List Byte :=
  let headBytes :=
    [3]
      ++ u16le cryptoSuiteGamma
      ++ u32le 7
      ++ u32le sampleNotePayload.length
      ++ sampleNotePayload
      ++ u32le sampleMemoPayload.length
      ++ sampleMemoPayload;
  headBytes ++ [0xaa] ++ List.replicate (chainCiphertextSize - headBytes.length - 1) 0

def chainNonzeroPaddingWire : List Byte :=
  chainNonzeroPaddingContainer ++ chainCompactKemLen ++ sampleKemCiphertext

def chainNoncanonicalCompactWire : List Byte :=
  validChainContainer
    ++ u32le (mlKemCiphertextLen * 4 + 2)
    ++ sampleKemCiphertext

def chainTrailingWire : List Byte :=
  validChainWire ++ [0x99]

theorem crypto_valid_accepts :
    parseCryptoNoteCiphertext validCryptoWire =
      some {
        version := 3,
        cryptoSuite := cryptoSuiteGamma,
        diversifierIndex := 7,
        kemLen := mlKemCiphertextLen,
        notePayloadLen := sampleNotePayload.length,
        memoPayloadLen := sampleMemoPayload.length
      } := by
  decide

theorem crypto_truncated_after_kem_rejects :
    parseCryptoNoteCiphertext cryptoTruncatedWire = none := by
  decide

theorem crypto_trailing_byte_rejects :
    parseCryptoNoteCiphertext cryptoTrailingWire = none := by
  decide

theorem chain_valid_accepts :
    parseChainNoteCiphertext validChainWire =
      some {
        version := 3,
        cryptoSuite := cryptoSuiteGamma,
        diversifierIndex := 7,
        kemLen := mlKemCiphertextLen,
        notePayloadLen := sampleNotePayload.length,
        memoPayloadLen := sampleMemoPayload.length
      } := by
  decide

theorem chain_memo_overrun_rejects :
    parseChainNoteCiphertext chainMemoOverrunWire = none := by
  decide

theorem chain_nonzero_padding_rejects :
    parseChainNoteCiphertext chainNonzeroPaddingWire = none := by
  decide

theorem chain_noncanonical_compact_kem_length_rejects :
    parseChainNoteCiphertext chainNoncanonicalCompactWire = none := by
  decide

theorem chain_trailing_byte_rejects :
    parseChainNoteCiphertext chainTrailingWire = none := by
  decide

end NoteCiphertextWire
end Wallet
end Hegemon
