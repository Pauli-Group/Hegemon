import Hegemon.Native.NativeBackendAlgebra

open Hegemon.Native.NativeBackendAlgebra

def challengeCaseJson (testCase : ChallengeReductionCase) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ testCase.name ++ "\",\n"
    ++ "      \"raw\": \"" ++ toString testCase.raw ++ "\",\n"
    ++ "      \"expected_reduced\": \""
    ++ toString (reduceActiveFoldChallenge testCase.raw) ++ "\"\n"
    ++ "    }"

def coefficientCaseJson (testCase : CanonicalCoefficientCase) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ testCase.name ++ "\",\n"
    ++ "      \"value\": \"" ++ toString testCase.value ++ "\",\n"
    ++ "      \"expected_canonical\": \""
    ++ toString (canonicalGoldilocksCoefficient testCase.value) ++ "\"\n"
    ++ "    }"

def casesJson {α : Type} (render : α -> String) : List α -> String
  | [] => ""
  | [testCase] => render testCase
  | testCase :: rest => render testCase ++ ",\n" ++ casesJson render rest

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"goldilocks_modulus\": \"" ++ toString goldilocksModulus ++ "\",\n"
    ++ "  \"active_challenge_bits\": " ++ toString activeChallengeBits ++ ",\n"
    ++ "  \"active_challenge_value_count\": \""
    ++ toString activeChallengeValueCount ++ "\",\n"
    ++ "  \"active_fold_challenge_count\": "
    ++ toString activeFoldChallengeCount ++ ",\n"
    ++ "  \"active_ring_degree\": " ++ toString activeRingDegree ++ ",\n"
    ++ "  \"active_digit_bound\": " ++ toString activeDigitBound ++ ",\n"
    ++ "  \"active_matrix_rows\": " ++ toString activeMatrixRows ++ ",\n"
    ++ "  \"active_max_commitment_message_ring_elements\": "
    ++ toString activeMaxCommitmentMessageRingElements ++ ",\n"
    ++ "  \"active_max_claimed_receipt_root_leaves\": "
    ++ toString activeMaxClaimedReceiptRootLeaves ++ ",\n"
    ++ "  \"active_tuple_preimage_bound\": "
    ++ toString activeTuplePreimageBound ++ ",\n"
    ++ "  \"active_transcript_soundness_bits\": "
    ++ toString activeTranscriptSoundnessBits ++ ",\n"
    ++ "  \"active_composition_loss_bits\": "
    ++ toString activeCompositionLossBits ++ ",\n"
    ++ "  \"active_transcript_floor_bits\": "
    ++ toString activeTranscriptFloorBits ++ ",\n"
    ++ "  \"active_ambient_coefficient_dimension\": "
    ++ toString activeAmbientCoefficientDimension ++ ",\n"
    ++ "  \"active_conservative_euclidean_bound\": "
    ++ toString activeConservativeEuclideanBound ++ ",\n"
    ++ "  \"active_live_message_ring_elements\": "
    ++ toString activeLiveMessageRingElements ++ ",\n"
    ++ "  \"active_live_coefficient_dimension\": "
    ++ toString activeLiveCoefficientDimension ++ ",\n"
    ++ "  \"active_live_euclidean_bound\": "
    ++ toString activeLiveEuclideanBound ++ ",\n"
    ++ "  \"challenge_reduction_cases\": [\n"
    ++ casesJson challengeCaseJson challengeReductionCases ++ "\n"
    ++ "  ],\n"
    ++ "  \"canonical_coefficient_cases\": [\n"
    ++ casesJson coefficientCaseJson canonicalCoefficientCases ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
