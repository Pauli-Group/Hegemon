import Hegemon.Bytes

set_option maxRecDepth 10000

namespace Hegemon
namespace Wallet
namespace NoteCiphertextWire

def chainCiphertextSize : Nat := 579
def mlKemCiphertextLen : Nat := 1568
def cryptoSuiteGamma : Nat := 3

def chainCompactKemLen : List Byte :=
  u16le (mlKemCiphertextLen * 4 + 1)

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

def parseDaNoteCiphertext (input : List Byte) : Option NoteCiphertextSummary := do
  let (container, rest0) ← takeBytes chainCiphertextSize input
  let summary ← parseChainContainer container
  let rest1 ← skipBytes mlKemCiphertextLen rest0
  match rest1 with
  | [] => some summary
  | _ :: _ => none

def projectChainDaBytes (input : List Byte) : Option (List Byte) := do
  let _summary ← parseChainNoteCiphertext input
  some
    (input.take chainCiphertextSize
      ++ input.drop (chainCiphertextSize + chainCompactKemLen.length))

def bytesBounded (input : List Byte) : Prop :=
  ∀ byteValue, byteValue ∈ input -> byteValue < 256

theorem bytesBounded_drop
    {count : Nat}
    {input : List Byte}
    (bounded : bytesBounded input) :
    bytesBounded (input.drop count) := by
  intro byteValue member
  exact bounded byteValue (List.mem_of_mem_drop member)

theorem takeBytes_some_length
    {count : Nat}
    {input taken rest : List Byte}
    (h : takeBytes count input = some (taken, rest)) :
    input.length = count + rest.length := by
  unfold takeBytes at h
  split at h
  · simp at h
    rcases h with ⟨_, restEq⟩
    rw [← restEq, List.length_drop]
    omega
  · cases h

theorem takeBytes_some_taken_length
    {count : Nat}
    {input taken rest : List Byte}
    (h : takeBytes count input = some (taken, rest)) :
    taken.length = count := by
  unfold takeBytes at h
  split at h
  · simp at h
    rcases h with ⟨takenEq, _⟩
    rw [← takenEq]
    simp
    omega
  · cases h

theorem takeBytes_some_rest_bounded
    {count : Nat}
    {input taken rest : List Byte}
    (bounded : bytesBounded input)
    (h : takeBytes count input = some (taken, rest)) :
    bytesBounded rest := by
  unfold takeBytes at h
  split at h
  · simp at h
    rcases h with ⟨_, restEq⟩
    rw [← restEq]
    exact bytesBounded_drop bounded
  · cases h

theorem skipBytes_some_length
    {count : Nat}
    {input rest : List Byte}
    (h : skipBytes count input = some rest) :
    input.length = count + rest.length := by
  unfold skipBytes at h
  cases takeEq : takeBytes count input with
  | none =>
      simp [takeEq] at h
  | some pair =>
      rcases pair with ⟨taken, tail⟩
      simp [takeEq] at h
      cases h
      exact takeBytes_some_length (taken := taken) takeEq

theorem readNat_some_length
    {width value : Nat}
    {input rest : List Byte}
    (h : readNat width input = some (value, rest)) :
    input.length = width + rest.length := by
  unfold readNat at h
  cases takeEq : takeBytes width input with
  | none =>
      simp [takeEq] at h
  | some pair =>
      rcases pair with ⟨raw, tail⟩
      simp [takeEq] at h
      rcases h with ⟨_, restEq⟩
      rw [← restEq]
      exact takeBytes_some_length (taken := raw) takeEq

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

def validChainWire : List Byte :=
  validChainContainer ++ chainCompactKemLen ++ sampleKemCiphertext

def validChainDaBytes : List Byte :=
  validChainContainer ++ sampleKemCiphertext

def daTruncatedWire : List Byte :=
  validChainDaBytes.take (chainCiphertextSize + mlKemCiphertextLen - 1)

def daTrailingWire : List Byte :=
  validChainDaBytes ++ [0x99]

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

def daMemoOverrunWire : List Byte :=
  chainMemoOverrunContainer ++ sampleKemCiphertext

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

def daNonzeroPaddingWire : List Byte :=
  chainNonzeroPaddingContainer ++ sampleKemCiphertext

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

theorem valid_chain_da_projection :
    projectChainDaBytes validChainWire = some validChainDaBytes := by
  decide

theorem valid_chain_da_projection_length :
    validChainDaBytes.length =
      chainCiphertextSize + mlKemCiphertextLen := by
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

theorem da_valid_accepts :
    parseDaNoteCiphertext validChainDaBytes =
      some {
        version := 3,
        cryptoSuite := cryptoSuiteGamma,
        diversifierIndex := 7,
        kemLen := mlKemCiphertextLen,
        notePayloadLen := sampleNotePayload.length,
        memoPayloadLen := sampleMemoPayload.length
      } := by
  decide

theorem da_memo_overrun_rejects :
    parseDaNoteCiphertext daMemoOverrunWire = none := by
  decide

theorem da_nonzero_padding_rejects :
    parseDaNoteCiphertext daNonzeroPaddingWire = none := by
  decide

theorem da_truncated_kem_rejects :
    parseDaNoteCiphertext daTruncatedWire = none := by
  decide

theorem da_trailing_byte_rejects :
    parseDaNoteCiphertext daTrailingWire = none := by
  decide

theorem chain_noncanonical_compact_kem_length_da_projection_rejects :
    projectChainDaBytes chainNoncanonicalCompactWire = none := by
  decide

theorem chain_trailing_byte_da_projection_rejects :
    projectChainDaBytes chainTrailingWire = none := by
  decide

theorem parsed_crypto_ciphertext_has_fixed_kem_len
    {input : List Byte}
    {summary : NoteCiphertextSummary}
    (parsed : parseCryptoNoteCiphertext input = some summary) :
    summary.kemLen = mlKemCiphertextLen := by
  unfold parseCryptoNoteCiphertext at parsed
  cases readU8Eq : readU8 input with
  | none =>
      simp [readU8Eq] at parsed
  | some versionRest =>
      rcases versionRest with ⟨version, rest0⟩
      simp [readU8Eq] at parsed
      cases readU16Eq : readU16 rest0 with
      | none =>
          simp [readU16Eq] at parsed
      | some suiteRest =>
          rcases suiteRest with ⟨cryptoSuite, rest1⟩
          simp [readU16Eq] at parsed
          cases readDivEq : readU32 rest1 with
          | none =>
              simp [readDivEq] at parsed
          | some diversifierRest =>
              rcases diversifierRest with ⟨diversifierIndex, rest2⟩
              simp [readDivEq] at parsed
              cases readKemEq : readU32 rest2 with
              | none =>
                  simp [readKemEq] at parsed
              | some kemRest =>
                  rcases kemRest with ⟨kemLen, rest3⟩
                  simp [readKemEq] at parsed
                  by_cases kemMatches : kemLen = mlKemCiphertextLen
                  · subst kemLen
                    cases skipKemEq : skipBytes mlKemCiphertextLen rest3 with
                    | none =>
                        simp [skipKemEq] at parsed
                    | some rest4 =>
                        simp [skipKemEq] at parsed
                        cases readNoteEq : readU32 rest4 with
                        | none =>
                            simp [readNoteEq] at parsed
                        | some noteRest =>
                            rcases noteRest with ⟨notePayloadLen, rest5⟩
                            simp [readNoteEq] at parsed
                            cases skipNoteEq : skipBytes notePayloadLen rest5 with
                            | none =>
                                simp [skipNoteEq] at parsed
                            | some rest6 =>
                                simp [skipNoteEq] at parsed
                                cases readMemoEq : readU32 rest6 with
                                | none =>
                                    simp [readMemoEq] at parsed
                                | some memoRest =>
                                    rcases memoRest with ⟨memoPayloadLen, rest7⟩
                                    simp [readMemoEq] at parsed
                                    cases skipMemoEq : skipBytes memoPayloadLen rest7 with
                                    | none =>
                                        simp [skipMemoEq] at parsed
                                    | some rest8 =>
                                        simp [skipMemoEq] at parsed
                                        cases rest8 with
                                        | nil =>
                                            simp at parsed
                                            cases parsed
                                            rfl
                                        | cons _ _ =>
                                            simp at parsed
                  · simp [kemMatches] at parsed

theorem parsed_chain_container_has_gamma_suite_and_fixed_kem
    {input : List Byte}
    {summary : NoteCiphertextSummary}
    (parsed : parseChainContainer input = some summary) :
    summary.cryptoSuite = cryptoSuiteGamma
      ∧ summary.kemLen = mlKemCiphertextLen := by
  unfold parseChainContainer at parsed
  cases readU8Eq : readU8 input with
  | none =>
      simp [readU8Eq] at parsed
  | some versionRest =>
      rcases versionRest with ⟨version, rest0⟩
      simp [readU8Eq] at parsed
      cases readSuiteEq : readU16 rest0 with
      | none =>
          simp [readSuiteEq] at parsed
      | some suiteRest =>
          rcases suiteRest with ⟨cryptoSuite, rest1⟩
          simp [readSuiteEq] at parsed
          cases readDivEq : readU32 rest1 with
          | none =>
              simp [readDivEq] at parsed
          | some diversifierRest =>
              rcases diversifierRest with ⟨diversifierIndex, rest2⟩
              simp [readDivEq] at parsed
              cases readNoteEq : readU32 rest2 with
              | none =>
                  simp [readNoteEq] at parsed
              | some noteRest =>
                  rcases noteRest with ⟨notePayloadLen, rest3⟩
                  simp [readNoteEq] at parsed
                  cases skipNoteEq : skipBytes notePayloadLen rest3 with
                  | none =>
                      simp [skipNoteEq] at parsed
                  | some rest4 =>
                      simp [skipNoteEq] at parsed
                      cases readMemoEq : readU32 rest4 with
                      | none =>
                          simp [readMemoEq] at parsed
                      | some memoRest =>
                          rcases memoRest with ⟨memoPayloadLen, rest5⟩
                          simp [readMemoEq] at parsed
                          cases skipMemoEq : skipBytes memoPayloadLen rest5 with
                          | none =>
                              simp [skipMemoEq] at parsed
                          | some rest6 =>
                              simp [skipMemoEq] at parsed
                              by_cases accepted :
                                  cryptoSuite = cryptoSuiteGamma
                                    ∧ ∀ byteValue, byteValue ∈ rest6 -> byteValue = 0
                              · simp [accepted] at parsed
                                cases parsed.right
                                exact ⟨rfl, rfl⟩
                              · simp [accepted] at parsed

theorem parsed_chain_ciphertext_has_gamma_suite_and_fixed_kem
    {input : List Byte}
    {summary : NoteCiphertextSummary}
    (parsed : parseChainNoteCiphertext input = some summary) :
    summary.cryptoSuite = cryptoSuiteGamma
      ∧ summary.kemLen = mlKemCiphertextLen := by
  unfold parseChainNoteCiphertext at parsed
  cases takeEq : takeBytes chainCiphertextSize input with
  | none =>
      simp [takeEq] at parsed
  | some containerRest =>
      rcases containerRest with ⟨container, rest0⟩
      simp [takeEq] at parsed
      cases parsedContainer : parseChainContainer container with
      | none =>
          simp [parsedContainer] at parsed
      | some containerSummary =>
          simp [parsedContainer] at parsed
          cases compactEq : parseCompactLen rest0 with
          | none =>
              simp [compactEq] at parsed
          | some kemRest =>
              rcases kemRest with ⟨kemLen, rest1⟩
              simp [compactEq] at parsed
              by_cases kemMatches : kemLen = mlKemCiphertextLen
              · subst kemLen
                cases skipKemEq : skipBytes mlKemCiphertextLen rest1 with
                | none =>
                    simp [skipKemEq] at parsed
                | some rest2 =>
                    simp [skipKemEq] at parsed
                    cases rest2 with
                    | nil =>
                        simp at parsed
                        cases parsed
                        exact parsed_chain_container_has_gamma_suite_and_fixed_kem
                          parsedContainer
                    | cons _ _ =>
                        simp at parsed
              · simp [kemMatches] at parsed

theorem parsed_da_ciphertext_has_gamma_suite_and_fixed_kem
    {input : List Byte}
    {summary : NoteCiphertextSummary}
    (parsed : parseDaNoteCiphertext input = some summary) :
    summary.cryptoSuite = cryptoSuiteGamma
      ∧ summary.kemLen = mlKemCiphertextLen := by
  unfold parseDaNoteCiphertext at parsed
  cases takeEq : takeBytes chainCiphertextSize input with
  | none =>
      simp [takeEq] at parsed
  | some containerRest =>
      rcases containerRest with ⟨container, rest0⟩
      simp [takeEq] at parsed
      cases parsedContainer : parseChainContainer container with
      | none =>
          simp [parsedContainer] at parsed
      | some containerSummary =>
          simp [parsedContainer] at parsed
          cases skipKemEq : skipBytes mlKemCiphertextLen rest0 with
          | none =>
              simp [skipKemEq] at parsed
          | some rest1 =>
              simp [skipKemEq] at parsed
              cases rest1 with
              | nil =>
                  simp at parsed
                  cases parsed
                  exact parsed_chain_container_has_gamma_suite_and_fixed_kem
                    parsedContainer
              | cons _ _ =>
                  simp at parsed

theorem bounded_parse_compact_mlkem_consumes_two
    {input rest : List Byte}
    (bounded : bytesBounded input)
    (parsed : parseCompactLen input = some (mlKemCiphertextLen, rest)) :
    input.length = rest.length + 2 := by
  unfold parseCompactLen at parsed
  cases input with
  | nil =>
      simp at parsed
  | cons first tail =>
      have firstBound : first < 256 := bounded first (by simp)
      simp at parsed
      by_cases flag0 : first % 4 = 0
      · have firstDivSmall : first / 4 < 64 := by
          exact Nat.div_lt_of_lt_mul (by omega : first < 4 * 64)
        have impossible : ¬ first / 4 = mlKemCiphertextLen := by
          have lessConst : 64 < mlKemCiphertextLen := by
            decide
          have less : first / 4 < mlKemCiphertextLen :=
            Nat.lt_trans firstDivSmall lessConst
          exact Nat.ne_of_lt less
        simp [flag0, impossible] at parsed
      · simp [flag0] at parsed
        by_cases flag1 : first % 4 = 1
        · simp [flag1] at parsed
          cases readEq : readNat 2 (first :: tail) with
          | none =>
              simp [readEq] at parsed
          | some valueRest =>
              rcases valueRest with ⟨value, tail2⟩
              simp [readEq] at parsed
              rcases parsed with ⟨_largeEnough, _valueEq, restEq⟩
              rw [← restEq]
              have lenEq := readNat_some_length readEq
              omega
        · simp [flag1] at parsed
          by_cases flag2 : first % 4 = 2
          · simp [flag2] at parsed
            cases readEq : readNat 4 (first :: tail) with
            | none =>
                simp [readEq] at parsed
            | some valueRest =>
                rcases valueRest with ⟨value, tail4⟩
                simp [readEq] at parsed
                rcases parsed with ⟨largeEnough, valueEq, _restEq⟩
                unfold mlKemCiphertextLen at valueEq
                omega
          · simp [flag2] at parsed
            unfold mlKemCiphertextLen at parsed
            omega

theorem parsed_chain_ciphertext_has_fixed_wire_length_of_bounded
    {input : List Byte}
    {summary : NoteCiphertextSummary}
    (bounded : bytesBounded input)
    (parsed : parseChainNoteCiphertext input = some summary) :
    input.length =
      chainCiphertextSize + chainCompactKemLen.length + mlKemCiphertextLen := by
  unfold parseChainNoteCiphertext at parsed
  cases takeEq : takeBytes chainCiphertextSize input with
  | none =>
      simp [takeEq] at parsed
  | some containerRest =>
      rcases containerRest with ⟨container, rest0⟩
      have inputLen := takeBytes_some_length takeEq
      have rest0Bounded := takeBytes_some_rest_bounded bounded takeEq
      simp [takeEq] at parsed
      cases containerEq : parseChainContainer container with
      | none =>
          simp [containerEq] at parsed
      | some containerSummary =>
          simp [containerEq] at parsed
          cases compactEq : parseCompactLen rest0 with
          | none =>
              simp [compactEq] at parsed
          | some kemRest =>
              rcases kemRest with ⟨kemLen, rest1⟩
              simp [compactEq] at parsed
              by_cases kemMatches : kemLen = mlKemCiphertextLen
              · subst kemLen
                cases skipEq : skipBytes mlKemCiphertextLen rest1 with
                | none =>
                    simp [skipEq] at parsed
                | some rest2 =>
                    simp [skipEq] at parsed
                    cases rest2 with
                    | nil =>
                        simp at parsed
                        have compactLen :=
                          bounded_parse_compact_mlkem_consumes_two
                            rest0Bounded
                            compactEq
                        have skipLen := skipBytes_some_length skipEq
                        simp at skipLen
                        have compactBytes :
                            chainCompactKemLen.length = 2 := by
                          decide
                        rw [compactBytes]
                        omega
                    | cons _ _ =>
                        simp at parsed
              · simp [kemMatches] at parsed

theorem parsed_chain_ciphertext_has_projected_da_bytes_of_bounded
    {input : List Byte}
    {summary : NoteCiphertextSummary}
    (bounded : bytesBounded input)
    (parsed : parseChainNoteCiphertext input = some summary) :
    ∃ daBytes,
      projectChainDaBytes input = some daBytes
        ∧ daBytes.length = chainCiphertextSize + mlKemCiphertextLen := by
  unfold projectChainDaBytes
  simp [parsed]
  have wireLength :=
    parsed_chain_ciphertext_has_fixed_wire_length_of_bounded
      bounded
      parsed
  have compactBytes :
      chainCompactKemLen.length = 2 := by
    decide
  rw [wireLength, compactBytes]
  omega

end NoteCiphertextWire
end Wallet
end Hegemon
