import SmzaRp05CurrentRawFieldScan
import SmzaRp05CurrentFieldCounterParser
import SmzaRp04RawRoleSampling
import HegemonCrypto.SmallWoodV8Smz9CappedRawSampler

/-! Generic same-oracle bridge from a source scan over a finite counter list
to the corresponding raw-byte field sample. Kept symbolic in both dimensions
so concrete role capacities do not enter parser elaboration. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentRawSampleReadback

open SmzaRp05ExecutableChallengeStage (scan)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open V8Smz9HonestRequestSchedule (NonleafProgram sourceFieldReadLoop sourceDigest)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9HiddenLeafQrom (DigestRegister)
open V8Smz9RawCounterCompiler (parseCounterVector)
open SmzaRp04RawRoleSampling (rawFieldSample)
open V8Smz9CappedRawSampler (RawByteBlock sourceDigestOfByteBlock
  exact_literal_byte_counter_parser)

set_option autoImplicit false
noncomputable section

/-- The scan and raw-role parser consume the same oracle answers at the same
finite key list. The only conversion is the checked byte-digest/register
equivalence at the source-program boundary. -/
theorem source_scan_eq_raw_field_sample {blocks : Nat} (requested : Nat)
    (keys : Fin blocks → RawInput) (oracle : Oracle) :
    scan oracle requested [] (List.ofFn keys) =
      (rawFieldSample blocks requested (fun index => oracle (keys index))).map List.ofFn := by
  let registerOracle : RawInput → DigestRegister := fun key => rawDigestBits (oracle key)
  have reader := SmzaRp05CurrentRawFieldScan.source_field_reader_eq_executable_scan
    requested [] (List.ofFn keys) id oracle
  have reader' : NonleafProgram.interpret registerOracle
      (sourceFieldReadLoop requested [] (List.ofFn keys)) =
      scan oracle requested [] (List.ofFn keys) := by
    exact reader.trans (congrArg (scan oracle requested []) (List.map_id _))
  calc
    scan oracle requested [] (List.ofFn keys) =
        NonleafProgram.interpret registerOracle
          (sourceFieldReadLoop requested [] (List.ofFn keys)) := by
      exact reader'.symm
    _ = parseCounterVector requested
        (fun index => sourceDigest (registerOracle (keys index))) := by
      exact SmzaRp05CurrentFieldCounterParser.source_field_loop_is_counter_parser
        requested keys registerOracle
    _ = parseCounterVector requested
        (fun index => sourceDigestOfByteBlock (oracle (keys index))) := by
      have digestEq :
          (fun index => sourceDigestOfByteBlock (oracle (keys index))) =
            (fun index => sourceDigest (registerOracle (keys index))) := by
        funext index
        have blockEq := congrArg sourceDigestOfByteBlock
          (rawDigestBits.symm_apply_apply (oracle (keys index)))
        exact blockEq.symm.trans
          (SmzaRp05CurrentFieldCounterParser.source_digest_of_raw_bits
            (registerOracle (keys index)))
      rw [digestEq]
    _ = (rawFieldSample blocks requested
          (fun index => oracle (keys index))).map List.ofFn := by
      exact exact_literal_byte_counter_parser requested
        (fun index => oracle (keys index))

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentRawSampleReadback
