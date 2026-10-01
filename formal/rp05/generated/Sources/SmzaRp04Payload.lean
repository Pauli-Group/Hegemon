import SmzaQ38McaSourceBindingR2
import HegemonCrypto.SmallWoodRecordedMerkleExtraction
import SmallWoodV8SmzaOracleParserR2
import HegemonCrypto.SmallWoodTranscript

/-! Canonical typed RP04 leaf data, independent of the generated relation. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RecordedClaims

open V8SmzaOracleParser
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.MerkleExtraction

abbrev Rp04Digest := V8SmzaOracleParser.RawDigest
abbrev Rp04Coordinate := Fin SmzaQ38OracleExtraction.decsDomainSize
abbrev Rp04Words := Fin 145 → HegemonCrypto.SmallWoodTranscript.FieldWord

structure Rp04Payload where
  salt : Fin 32 → Fin 256
  index : Rp04Coordinate
  tape : Fin 64 → Fin 256
  words : Rp04Words

instance : CoeFun Rp04Payload (fun _ => Fin 145 → HegemonCrypto.SmallWoodTranscript.FieldWord) :=
  ⟨Rp04Payload.words⟩

abbrev Rp04HashDatabase :=
  Database (HashInput Rp04Payload Rp04Digest) Rp04Digest

end HegemonCrypto.SmallWood.SmzaRp04RecordedClaims
