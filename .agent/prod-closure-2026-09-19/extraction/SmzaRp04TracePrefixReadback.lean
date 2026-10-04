import SmzaRp04TracePrefixes
import SmzaRawRecordedPrefix
import SmzaRawRecordedWrappers

/-! The matrix-role label reads its actual recorded FPP message and the same
complete root subtree used at the earlier DECS-matrix stage. This is a raw
transcript readback theorem, not a supplied equality of execution states. -/
namespace HegemonCrypto.SmallWood.SmzaRp04TracePrefixReadback

open SmzaRp04TracePrefixes SmzaRp04CompleteRawRoleCells
open SmzaRawStageGeometry SmzaRawTraceDepth SmzaRawRecordedPrefix
open SmzaRecordedTracePath V8Smz9CoherentMerkleGeometry
open V8SmzaOnlineParser
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option linter.unusedSimpArgs false
attribute [local irreducible] matrixPrefix openingPrefix rootOracle sourceResponse

/-! Keep the large chronological postprocessors abstract while reducing the
small `Option` decoder spine.  Instantiating these lemmas does not ask the
kernel to normalize `matrixPrefix`, `openingPrefix`, or `recoverSource`. -/

private theorem option_bind_two_postprocess
    {First Second Output : Type*}
    (first : Option First) (second : First → Option Second)
    (postprocess : First → Second → Option Output)
    (firstValue : First) (secondValue : Second)
    (firstRead : first = some firstValue)
    (secondRead : second firstValue = some secondValue) :
    first.bind (fun firstValue =>
      (second firstValue).bind (postprocess firstValue)) =
        postprocess firstValue secondValue := by
  simp only [firstRead, Option.bind_some, secondRead]

private theorem option_bind_four_postprocess
    {First Second Third Fourth Output : Type*}
    (first : Option First) (second : First → Option Second)
    (third : First → Second → Option Third)
    (fourth : First → Second → Third → Option Fourth)
    (postprocess : First → Second → Third → Fourth → Option Output)
    (firstValue : First) (secondValue : Second)
    (thirdValue : Third) (fourthValue : Fourth)
    (firstRead : first = some firstValue)
    (secondRead : second firstValue = some secondValue)
    (thirdRead : third firstValue secondValue = some thirdValue)
    (fourthRead : fourth firstValue secondValue thirdValue = some fourthValue) :
    first.bind (fun firstValue =>
      (second firstValue).bind (fun secondValue =>
        (third firstValue secondValue).bind (fun thirdValue =>
          (fourth firstValue secondValue thirdValue).bind
            (postprocess firstValue secondValue thirdValue)))) =
      postprocess firstValue secondValue thirdValue fourthValue := by
  simp only [firstRead, Option.bind_some, secondRead, thirdRead, fourthRead]

theorem matrix_label_of_recorded_fpp
    (publicWords : List Nat)
    (advice : EarlierTables publicWords .piopMatrix)
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree records)
    (target : V8SmzaOracleParser.RawDigest) (input : V8SmzaOracleParser.RawInput)
    (fpp : V8SmzaOracleParser.Payload)
    (recorded : (input, target) ∈ records)
    (parsed : V8SmzaOracleParser.rawPayload input = some fpp)
    (kind : fpp.kind = .fpp)
    (coefficients : SmzaQ38McaSourceBinding.Coefficients)
    (earlier : advice .decsMatrix (by decide)
      (V8SmzaOracleParser.digestAt fpp.bytes 0) = some coefficients)
    (fuel : Nat) (enough : 26 ≤ fuel) :
    matrixLabel publicWords advice (extract rawOnlineNext records fuel .fpp target) =
      matrixPrefix publicWords
        (rootOracle (extract rawOnlineNext records fuel .root
          (V8SmzaOracleParser.digestAt fpp.bytes 0)))
        (sourceResponse fpp) coefficients := by
  have next : rawOnlineNext .fpp input =
      some [(.root, V8SmzaOracleParser.digestAt fpp.bytes 0)] := by
    simp [rawOnlineNext, parsed, payloadNext, kind]
  have decoded := payload_of_recorded_input records collisionFree .fpp target input fpp
    recorded parsed (by simp [payloadNext, kind]) fuel (by omega)
  rw [kind] at decoded
  have childReadback := recorded_child_is_complete_subtree records collisionFree fuel .fpp
    target input [(.root, V8SmzaOracleParser.digestAt fpp.bytes 0)] 0 .root
    (V8SmzaOracleParser.digestAt fpp.bytes 0) recorded next rfl enough
  rw [← child_eq_subtree] at childReadback
  have reduced :
      matrixLabel publicWords advice (extract rawOnlineNext records fuel .fpp target) =
        matrixPrefix publicWords
          (rootOracle (child (extract rawOnlineNext records fuel .fpp target) 0))
          (sourceResponse fpp) coefficients := by
    unfold matrixLabel
    exact option_bind_two_postprocess
      (payload .fpp (extract rawOnlineNext records fuel .fpp target))
      (fun message => advice .decsMatrix (by decide)
        (V8SmzaOracleParser.digestAt message.bytes 0))
      (fun message earlierCoefficients => matrixPrefix publicWords
        (rootOracle (child (extract rawOnlineNext records fuel .fpp target) 0))
        (sourceResponse message) earlierCoefficients)
      fpp coefficients decoded earlier
  exact reduced.trans (congrArg
    (fun root => matrixPrefix publicWords (rootOracle root)
      (sourceResponse fpp) coefficients)
    childReadback)

theorem opening_label_of_recorded_piop_fpp
    (publicWords : List Nat)
    (advice : EarlierTables publicWords .piopOpening)
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree records)
    (target : V8SmzaOracleParser.RawDigest)
    (piopInput fppInput : V8SmzaOracleParser.RawInput)
    (piop fpp : V8SmzaOracleParser.Payload)
    (piopRecorded : (piopInput, target) ∈ records)
    (fppRecorded : (fppInput, V8SmzaOracleParser.digestAt piop.bytes 0) ∈ records)
    (piopParsed : V8SmzaOracleParser.rawPayload piopInput = some piop)
    (fppParsed : V8SmzaOracleParser.rawPayload fppInput = some fpp)
    (piopKind : piop.kind = .piop) (fppKind : fpp.kind = .fpp)
    (coefficients : SmzaQ38McaSourceBinding.Coefficients)
    (matrix : V8Smz9PiopSoundness.Matrix (SmzaRp04PublicContext.batchingWidth publicWords))
    (earlierCoefficients : advice .decsMatrix (by decide)
      (V8SmzaOracleParser.digestAt fpp.bytes 0) = some coefficients)
    (earlierMatrix : advice .piopMatrix (by decide)
      (V8SmzaOracleParser.digestAt piop.bytes 0) = some matrix)
    (fuel : Nat) (enough : 27 ≤ fuel) :
    openingLabel publicWords advice (extract rawOnlineNext records fuel .piop target) =
      openingPrefix publicWords
        (rootOracle (extract rawOnlineNext records fuel .root
          (V8SmzaOracleParser.digestAt fpp.bytes 0)))
        (sourceResponse fpp) coefficients matrix (piopResponse piop) := by
  have piopNext : rawOnlineNext .piop piopInput =
      some [(.fpp, V8SmzaOracleParser.digestAt piop.bytes 0)] := by
    simp [rawOnlineNext, piopParsed, payloadNext, piopKind]
  have fppNext : rawOnlineNext .fpp fppInput =
      some [(.root, V8SmzaOracleParser.digestAt fpp.bytes 0)] := by
    simp [rawOnlineNext, fppParsed, payloadNext, fppKind]
  have piopDecoded := payload_of_recorded_input records collisionFree .piop target
    piopInput piop piopRecorded piopParsed
    (by simp [payloadNext, piopKind]) fuel (by omega)
  have fppDecoded := payload_of_recorded_input records collisionFree .fpp
    (V8SmzaOracleParser.digestAt piop.bytes 0) fppInput fpp fppRecorded fppParsed
    (by simp [payloadNext, fppKind]) fuel (by omega)
  rw [piopKind] at piopDecoded
  rw [fppKind] at fppDecoded
  have piopChild := recorded_child_is_complete_subtree records collisionFree fuel .piop
    target piopInput [(.fpp, V8SmzaOracleParser.digestAt piop.bytes 0)] 0 .fpp
    (V8SmzaOracleParser.digestAt piop.bytes 0) piopRecorded piopNext rfl enough
  have fppChild := recorded_child_is_complete_subtree records collisionFree fuel .fpp
    (V8SmzaOracleParser.digestAt piop.bytes 0) fppInput
    [(.root, V8SmzaOracleParser.digestAt fpp.bytes 0)] 0 .root
    (V8SmzaOracleParser.digestAt fpp.bytes 0) fppRecorded fppNext rfl
      (by change 26 ≤ fuel; omega)
  rw [← child_eq_subtree] at piopChild fppChild
  have fppAtChild :
      payload .fpp (child (extract rawOnlineNext records fuel .piop target) 0) =
        some fpp := by
    rw [piopChild]
    exact fppDecoded
  have rootAtChild :
      child (child (extract rawOnlineNext records fuel .piop target) 0) 0 =
        extract rawOnlineNext records fuel .root
          (V8SmzaOracleParser.digestAt fpp.bytes 0) := by
    calc
      child (child (extract rawOnlineNext records fuel .piop target) 0) 0 =
          child (extract rawOnlineNext records fuel .fpp
            (V8SmzaOracleParser.digestAt piop.bytes 0)) 0 :=
        congrArg (fun trace => child trace 0) piopChild
      _ = extract rawOnlineNext records fuel .root
          (V8SmzaOracleParser.digestAt fpp.bytes 0) := fppChild
  have reduced :
      openingLabel publicWords advice
          (extract rawOnlineNext records fuel .piop target) =
        openingPrefix publicWords
          (rootOracle
            (child (child (extract rawOnlineNext records fuel .piop target) 0) 0))
          (sourceResponse fpp) coefficients matrix (piopResponse piop) := by
    unfold openingLabel
    exact option_bind_four_postprocess
      (payload .piop (extract rawOnlineNext records fuel .piop target))
      (fun _ => payload .fpp
        (child (extract rawOnlineNext records fuel .piop target) 0))
      (fun _ message => advice .decsMatrix (by decide)
        (V8SmzaOracleParser.digestAt message.bytes 0))
      (fun message _ _ => advice .piopMatrix (by decide)
        (V8SmzaOracleParser.digestAt message.bytes 0))
      (fun piopMessage fppMessage earlierCoefficients earlierMatrix =>
        openingPrefix publicWords
          (rootOracle
            (child (child (extract rawOnlineNext records fuel .piop target) 0) 0))
          (sourceResponse fppMessage) earlierCoefficients earlierMatrix
          (piopResponse piopMessage))
      piop fpp coefficients matrix piopDecoded fppAtChild
      earlierCoefficients earlierMatrix
  exact reduced.trans (congrArg
    (fun root => openingPrefix publicWords (rootOracle root)
      (sourceResponse fpp) coefficients matrix (piopResponse piop))
    rootAtChild)

end
end HegemonCrypto.SmallWood.SmzaRp04TracePrefixReadback
