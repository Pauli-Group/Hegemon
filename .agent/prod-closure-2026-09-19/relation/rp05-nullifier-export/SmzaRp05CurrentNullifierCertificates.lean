import SmzaRp05AuthorizationClosureNullifierSource
import SmzaRp05CurrentDirectionCertificate
import SmzaRp05CurrentInitialCertificate
import SmzaRp05CurrentPublicCertificate
import SmzaRp05Components
import SmzaRp05LocalCertificate
import SmzaRp05ChunkedAcceptedRecurrence
import SmzaRp05SupplyClosureHashCalls
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality

/-! Generated current-RP05 nullifier certificate data from the canonical,
    SHA-512-pinned HGV8RP05 program.  This file certifies finite source
    syntax only; it does not assert production readiness. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentNullifierCertificates
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05NullifierSource
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open HegemonCrypto.SmallWood.SmzaRp05ChunkedAcceptedRecurrence
open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Poseidon2Width16Kernel
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private instance : Inhabited CsrExecutableAttempt :=
  ⟨{ globalIndex := 0, family := 0, localIndex := 0, emission := 0,
      terms := [], targetRoot := 0 }⟩
def sourceSha512Hex : String := "4b0acd4289abd6ae2f0544857fd3fd0177dff45c2bae2a400fbf687e375944ffd4cf62b6d071ec1f29abd9ddce99c7e4e305e214238b0d34e3c64d7b5a0cde97"

/-- All 332 current hash roots on each packed lane imply the exact
    paired reference recurrence. This root-level adapter avoids an
    expanded 332-term `KernelCertificate`. -/
theorem accepted_current_hash_recurrence {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {wireIndex lane : Nat} (wireBound : wireIndex < 332)
    (laneBound : lane < 64) :
    laneField packed lane (hashRow (wireIndex / 166) (wireIndex % 166)) =
      fieldAt referenceExpressions
        (fun n => (publicWords.getD n 0 : Goldilocks))
        (laneField packed lane)
        (hashRootPair (wireIndex / 166) (wireIndex % 166)).2 :=
  accepted_root_recurrence accepted wireBound laneBound

/-- The checked current hash recurrence supplies canonical Nat final words. -/
theorem accepted_current_hash_call_final_eq_kernel
    {publicWords packed : List Nat} (accepted : program.AcceptsPacked publicWords packed)
    {call limb : Nat} (callBound : call < 128) (limbBound : limb < 16) :
    packedWord packed (hashFinalIndex call limb) =
      (Poseidon2Width16Kernel.permutation (packedInitialState packed call)).getD limb 0 :=
  SmzaRp05SupplyClosureHashCalls.current_hash_call_final_eq_kernel accepted callBound limbBound

theorem accepted_current_hash_call_state
    {publicWords packed : List Nat} (accepted : program.AcceptsPacked publicWords packed)
    {call : Nat} (bound : call < 128) :
    Poseidon2Width16Kernel.permutation (packedInitialState packed call) =
      packedFinalState packed call :=
  SmzaRp05SupplyClosureHashCalls.current_hash_call_state accepted bound

def directionRoot (input : Fin 2) (bit : Fin 32) : Nat :=
  match input.val, bit.val with
  | 0, 0 => 841
  | 0, 1 => 843
  | 0, 2 => 845
  | 0, 3 => 847
  | 0, 4 => 849
  | 0, 5 => 851
  | 0, 6 => 853
  | 0, 7 => 855
  | 0, 8 => 857
  | 0, 9 => 859
  | 0, 10 => 861
  | 0, 11 => 863
  | 0, 12 => 865
  | 0, 13 => 867
  | 0, 14 => 869
  | 0, 15 => 871
  | 0, 16 => 873
  | 0, 17 => 875
  | 0, 18 => 877
  | 0, 19 => 879
  | 0, 20 => 881
  | 0, 21 => 883
  | 0, 22 => 885
  | 0, 23 => 887
  | 0, 24 => 889
  | 0, 25 => 891
  | 0, 26 => 893
  | 0, 27 => 895
  | 0, 28 => 897
  | 0, 29 => 899
  | 0, 30 => 901
  | 0, 31 => 903
  | 1, 0 => 918
  | 1, 1 => 920
  | 1, 2 => 922
  | 1, 3 => 924
  | 1, 4 => 926
  | 1, 5 => 928
  | 1, 6 => 930
  | 1, 7 => 932
  | 1, 8 => 934
  | 1, 9 => 936
  | 1, 10 => 938
  | 1, 11 => 940
  | 1, 12 => 942
  | 1, 13 => 944
  | 1, 14 => 946
  | 1, 15 => 948
  | 1, 16 => 950
  | 1, 17 => 952
  | 1, 18 => 954
  | 1, 19 => 956
  | 1, 20 => 958
  | 1, 21 => 960
  | 1, 22 => 962
  | 1, 23 => 964
  | 1, 24 => 966
  | 1, 25 => 968
  | 1, 26 => 970
  | 1, 27 => 972
  | 1, 28 => 974
  | 1, 29 => 976
  | 1, 30 => 978
  | 1, 31 => 980
  | _, _ => 0

def directionCertificate : DirectionCertificate program :=
  SmzaRp05CurrentDirectionCertificate.directionCertificate

def initialAttemptData : Array CsrExecutableAttempt := #[
  { globalIndex := 18255, family := 21, localIndex := 0, emission := 0, terms := [(18148, 1), (6208, 160)], targetRoot := 0 },
  { globalIndex := 18256, family := 21, localIndex := 1, emission := 0, terms := [(18212, 1), (6209, 160)], targetRoot := 0 },
  { globalIndex := 18257, family := 21, localIndex := 2, emission := 0, terms := [(18276, 1), (6210, 160)], targetRoot := 0 },
  { globalIndex := 18258, family := 21, localIndex := 3, emission := 0, terms := [(18340, 1), (6211, 160)], targetRoot := 0 },
  { globalIndex := 18259, family := 21, localIndex := 4, emission := 0, terms := [(18404, 1), (6212, 160)], targetRoot := 0 },
  { globalIndex := 18260, family := 21, localIndex := 5, emission := 0, terms := [(18468, 1)], targetRoot := 0 },
  { globalIndex := 18261, family := 21, localIndex := 6, emission := 0, terms := [(18532, 1)], targetRoot := 0 },
  { globalIndex := 18262, family := 21, localIndex := 7, emission := 0, terms := [(18596, 1), (128, 160), (192, 203), (256, 161), (320, 205), (384, 207), (448, 209), (512, 211), (576, 213), (640, 215), (704, 217), (768, 219), (832, 221), (896, 223), (960, 225), (1024, 227), (1088, 229), (1152, 231), (1216, 233), (1280, 235), (1344, 237), (1408, 239), (1472, 241), (1536, 243), (1600, 245), (1664, 247), (1728, 249), (1792, 251), (1856, 253), (1920, 255), (1984, 257), (2048, 259), (2112, 261)], targetRoot := 0 },
  { globalIndex := 18263, family := 21, localIndex := 8, emission := 0, terms := [(18660, 1)], targetRoot := 542 },
  { globalIndex := 18264, family := 21, localIndex := 9, emission := 0, terms := [(18724, 1)], targetRoot := 543 },
  { globalIndex := 18265, family := 21, localIndex := 10, emission := 0, terms := [(18788, 1)], targetRoot := 540 },
  { globalIndex := 18266, family := 21, localIndex := 11, emission := 0, terms := [(18852, 1)], targetRoot := 0 },
  { globalIndex := 18267, family := 21, localIndex := 12, emission := 0, terms := [(18916, 1)], targetRoot := 0 },
  { globalIndex := 18268, family := 21, localIndex := 13, emission := 0, terms := [(18980, 1)], targetRoot := 0 },
  { globalIndex := 18269, family := 21, localIndex := 14, emission := 0, terms := [(19044, 1)], targetRoot := 0 },
  { globalIndex := 18270, family := 21, localIndex := 15, emission := 0, terms := [(19108, 1)], targetRoot := 541 },
  { globalIndex := 18271, family := 21, localIndex := 16, emission := 0, terms := [(18149, 1), (28772, 160), (18497, 160)], targetRoot := 0 },
  { globalIndex := 18272, family := 21, localIndex := 17, emission := 0, terms := [(18213, 1), (28836, 160), (18561, 160)], targetRoot := 0 },
  { globalIndex := 18273, family := 21, localIndex := 18, emission := 0, terms := [(18277, 1), (28900, 160), (18114, 160), (28737, 262)], targetRoot := 0 },
  { globalIndex := 18274, family := 21, localIndex := 19, emission := 0, terms := [(18341, 1), (28964, 160), (18178, 160), (28801, 262)], targetRoot := 0 },
  { globalIndex := 18275, family := 21, localIndex := 20, emission := 0, terms := [(18405, 1), (29028, 160)], targetRoot := 0 },
  { globalIndex := 18276, family := 21, localIndex := 21, emission := 0, terms := [(18469, 1), (29092, 160)], targetRoot := 0 },
  { globalIndex := 18277, family := 21, localIndex := 22, emission := 0, terms := [(18533, 1), (29156, 160)], targetRoot := 0 },
  { globalIndex := 18278, family := 21, localIndex := 23, emission := 0, terms := [(18597, 1), (29220, 160)], targetRoot := 0 },
  { globalIndex := 18279, family := 21, localIndex := 24, emission := 0, terms := [(18661, 1), (29284, 160)], targetRoot := 0 },
  { globalIndex := 18280, family := 21, localIndex := 25, emission := 0, terms := [(18725, 1), (29348, 160)], targetRoot := 0 },
  { globalIndex := 18281, family := 21, localIndex := 26, emission := 0, terms := [(18789, 1), (29412, 160)], targetRoot := 0 },
  { globalIndex := 18282, family := 21, localIndex := 27, emission := 0, terms := [(18853, 1), (29476, 160)], targetRoot := 1 },
  { globalIndex := 18283, family := 21, localIndex := 28, emission := 0, terms := [(18917, 1), (29540, 160)], targetRoot := 0 },
  { globalIndex := 18284, family := 21, localIndex := 29, emission := 0, terms := [(18981, 1), (29604, 160)], targetRoot := 0 },
  { globalIndex := 18285, family := 21, localIndex := 30, emission := 0, terms := [(19045, 1), (29668, 160)], targetRoot := 0 },
  { globalIndex := 18286, family := 21, localIndex := 31, emission := 0, terms := [(19109, 1), (29732, 160)], targetRoot := 0 },
  { globalIndex := 18287, family := 21, localIndex := 32, emission := 0, terms := [(29769, 1), (6272, 160)], targetRoot := 0 },
  { globalIndex := 18288, family := 21, localIndex := 33, emission := 0, terms := [(29833, 1), (6273, 160)], targetRoot := 0 },
  { globalIndex := 18289, family := 21, localIndex := 34, emission := 0, terms := [(29897, 1), (6274, 160)], targetRoot := 0 },
  { globalIndex := 18290, family := 21, localIndex := 35, emission := 0, terms := [(29961, 1), (6275, 160)], targetRoot := 0 },
  { globalIndex := 18291, family := 21, localIndex := 36, emission := 0, terms := [(30025, 1), (6276, 160)], targetRoot := 0 },
  { globalIndex := 18292, family := 21, localIndex := 37, emission := 0, terms := [(30089, 1)], targetRoot := 0 },
  { globalIndex := 18293, family := 21, localIndex := 38, emission := 0, terms := [(30153, 1)], targetRoot := 0 },
  { globalIndex := 18294, family := 21, localIndex := 39, emission := 0, terms := [(30217, 1), (2304, 160), (2368, 203), (2432, 161), (2496, 205), (2560, 207), (2624, 209), (2688, 211), (2752, 213), (2816, 215), (2880, 217), (2944, 219), (3008, 221), (3072, 223), (3136, 225), (3200, 227), (3264, 229), (3328, 231), (3392, 233), (3456, 235), (3520, 237), (3584, 239), (3648, 241), (3712, 243), (3776, 245), (3840, 247), (3904, 249), (3968, 251), (4032, 253), (4096, 255), (4160, 257), (4224, 259), (4288, 261)], targetRoot := 0 },
  { globalIndex := 18295, family := 21, localIndex := 40, emission := 0, terms := [(30281, 1)], targetRoot := 542 },
  { globalIndex := 18296, family := 21, localIndex := 41, emission := 0, terms := [(30345, 1)], targetRoot := 543 },
  { globalIndex := 18297, family := 21, localIndex := 42, emission := 0, terms := [(30409, 1)], targetRoot := 540 },
  { globalIndex := 18298, family := 21, localIndex := 43, emission := 0, terms := [(30473, 1)], targetRoot := 0 },
  { globalIndex := 18299, family := 21, localIndex := 44, emission := 0, terms := [(30537, 1)], targetRoot := 0 },
  { globalIndex := 18300, family := 21, localIndex := 45, emission := 0, terms := [(30601, 1)], targetRoot := 0 },
  { globalIndex := 18301, family := 21, localIndex := 46, emission := 0, terms := [(30665, 1)], targetRoot := 0 },
  { globalIndex := 18302, family := 21, localIndex := 47, emission := 0, terms := [(30729, 1)], targetRoot := 541 },
  { globalIndex := 18303, family := 21, localIndex := 48, emission := 0, terms := [(29770, 1), (40393, 160), (18534, 160)], targetRoot := 0 },
  { globalIndex := 18304, family := 21, localIndex := 49, emission := 0, terms := [(29834, 1), (40457, 160), (18598, 160)], targetRoot := 0 },
  { globalIndex := 18305, family := 21, localIndex := 50, emission := 0, terms := [(29898, 1), (40521, 160), (18151, 160), (28774, 262)], targetRoot := 0 },
  { globalIndex := 18306, family := 21, localIndex := 51, emission := 0, terms := [(29962, 1), (40585, 160), (18215, 160), (28838, 262)], targetRoot := 0 },
  { globalIndex := 18307, family := 21, localIndex := 52, emission := 0, terms := [(30026, 1), (40649, 160)], targetRoot := 0 },
  { globalIndex := 18308, family := 21, localIndex := 53, emission := 0, terms := [(30090, 1), (40713, 160)], targetRoot := 0 },
  { globalIndex := 18309, family := 21, localIndex := 54, emission := 0, terms := [(30154, 1), (40777, 160)], targetRoot := 0 },
  { globalIndex := 18310, family := 21, localIndex := 55, emission := 0, terms := [(30218, 1), (40841, 160)], targetRoot := 0 },
  { globalIndex := 18311, family := 21, localIndex := 56, emission := 0, terms := [(30282, 1), (40905, 160)], targetRoot := 0 },
  { globalIndex := 18312, family := 21, localIndex := 57, emission := 0, terms := [(30346, 1), (40969, 160)], targetRoot := 0 },
  { globalIndex := 18313, family := 21, localIndex := 58, emission := 0, terms := [(30410, 1), (41033, 160)], targetRoot := 0 },
  { globalIndex := 18314, family := 21, localIndex := 59, emission := 0, terms := [(30474, 1), (41097, 160)], targetRoot := 1 },
  { globalIndex := 18315, family := 21, localIndex := 60, emission := 0, terms := [(30538, 1), (41161, 160)], targetRoot := 0 },
  { globalIndex := 18316, family := 21, localIndex := 61, emission := 0, terms := [(30602, 1), (41225, 160)], targetRoot := 0 },
  { globalIndex := 18317, family := 21, localIndex := 62, emission := 0, terms := [(30666, 1), (41289, 160)], targetRoot := 0 },
  { globalIndex := 18318, family := 21, localIndex := 63, emission := 0, terms := [(30730, 1), (41353, 160)], targetRoot := 0 }
]
def initialAttempt (cell : InitialCell) : CsrExecutableAttempt :=
  initialAttemptData[cell.1.val * 32 + cell.2.1.val * 16 + cell.2.2.val]!

def publicAttemptData : Array CsrExecutableAttempt := #[
  { globalIndex := 18319, family := 22, localIndex := 0, emission := 1, terms := [(28773, 4)], targetRoot := 263 },
  { globalIndex := 18320, family := 22, localIndex := 1, emission := 1, terms := [(28837, 4)], targetRoot := 264 },
  { globalIndex := 18321, family := 22, localIndex := 2, emission := 1, terms := [(28901, 4)], targetRoot := 265 },
  { globalIndex := 18322, family := 22, localIndex := 3, emission := 1, terms := [(28965, 4)], targetRoot := 266 },
  { globalIndex := 18323, family := 22, localIndex := 4, emission := 1, terms := [(29029, 4)], targetRoot := 267 },
  { globalIndex := 18324, family := 22, localIndex := 5, emission := 1, terms := [(29093, 4)], targetRoot := 268 },
  { globalIndex := 18325, family := 22, localIndex := 6, emission := 1, terms := [(29157, 4)], targetRoot := 269 },
  { globalIndex := 18326, family := 22, localIndex := 7, emission := 1, terms := [(40394, 5)], targetRoot := 278 },
  { globalIndex := 18327, family := 22, localIndex := 8, emission := 1, terms := [(40458, 5)], targetRoot := 279 },
  { globalIndex := 18328, family := 22, localIndex := 9, emission := 1, terms := [(40522, 5)], targetRoot := 280 },
  { globalIndex := 18329, family := 22, localIndex := 10, emission := 1, terms := [(40586, 5)], targetRoot := 281 },
  { globalIndex := 18330, family := 22, localIndex := 11, emission := 1, terms := [(40650, 5)], targetRoot := 282 },
  { globalIndex := 18331, family := 22, localIndex := 12, emission := 1, terms := [(40714, 5)], targetRoot := 283 },
  { globalIndex := 18332, family := 22, localIndex := 13, emission := 1, terms := [(40778, 5)], targetRoot := 284 }
]
def publicAttempt (cell : PublicCell) : CsrExecutableAttempt :=
  publicAttemptData[cell.1.val * 7 + cell.2.val]!

def initialConstantNode (cell : InitialCell) : Nat :=
  initialAttempt cell |>.targetRoot

def initialCertificate : InitialCertificate program :=
  SmzaRp05CurrentInitialCertificate.initialCertificate

def publicCertificate : PublicCertificate program :=
  SmzaRp05CurrentPublicCertificate.publicCertificate

/-- Accepted current nullifier initial-state equations and the generated
    332-root adapter determine the full 7-word sponge output. -/
theorem accepted_current_nullifier_digest_of_initial_states
    {publicWords packed : List Nat} (accepted : program.AcceptsPacked publicWords packed)
    (input : Fin 2)
    (firstInitial : packedInitialState packed (nullifierFirstCall input) =
      firstFrame (nullifierPreimage packed input))
    (lastInitial : packedInitialState packed (nullifierLastCall input) =
      lastFrame (nullifierPreimage packed input)
        (packedFinalState packed (nullifierFirstCall input))) :
    liveNullifierDigest packed input =
      (packedFinalState packed (nullifierLastCall input)).take 7 := by
  let inputs := nullifierPreimage packed input
  have shape : inputs.length = 12 := nullifier_preimage_length packed input
  have firstState := accepted_current_hash_call_state accepted
    (call := nullifierFirstCall input) (by fin_cases input <;> decide)
  have lastState := accepted_current_hash_call_state accepted
    (call := nullifierLastCall input) (by fin_cases input <;> decide)
  rw [firstInitial] at firstState
  rw [lastInitial] at lastState
  have firstShape : (packedFinalState packed (nullifierFirstCall input)).length = 16 :=
    by simp [packedFinalState]
  have expanded : poseidon2V8Sponge currentNullifierDomain inputs =
      (poseidon2V8AbsorbBlock currentNullifierDomain inputs 2
        (poseidon2V8AbsorbBlock currentNullifierDomain inputs 2
          poseidon2V8InitialState 0) 1).take 7 := by
    simp [poseidon2V8Sponge, shape, Poseidon2Width16Kernel.rate, digestWords, List.range_succ]
  unfold liveNullifierDigest
  rw [expanded, closure_first_absorb inputs shape, firstState,
    closure_last_absorb inputs _ shape firstShape, lastState]

/-- Full seven-word active public nullifier binding for the exact same
    accepted packed RP05 witness. -/
theorem accepted_current_active_public_nullifier
    {publicWords packed : List Nat} (accepted : program.AcceptsPacked publicWords packed)
    (input : Fin 2) (active : publicWords.getD input.val 0 = 1) (limb : Fin 7) :
    publicWords.getD (4 + input.val * 7 + limb.val) 0 =
      (poseidon2V8Sponge currentNullifierDomain
        (nullifierPreimage packed input)).getD limb.val 0 := by
  obtain ⟨first, last⟩ := closure_nullifier_initial_states
    initialCertificate directionCertificate accepted input
  have copied := closure_active_public_nullifier_word publicCertificate accepted
    input limb active
  have digest := congrArg (fun words : List Nat => words.getD limb.val 0)
    (accepted_current_nullifier_digest_of_initial_states accepted input first last)
  exact copied.trans (by
    simpa [liveNullifierDigest, packedFinalState, packedWord, List.getD_eq_getElem?_getD,
      List.getElem?_take, limb.isLt] using digest.symm)

end HegemonCrypto.SmallWood.SmzaRp05CurrentNullifierCertificates
