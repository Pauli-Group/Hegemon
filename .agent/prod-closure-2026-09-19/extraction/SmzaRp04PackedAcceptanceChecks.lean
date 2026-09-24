import SmzaRp04PackedCanonicalPart00
import SmzaRp04PackedCanonicalPart01
import SmzaRp04PackedCanonicalPart02
import SmzaRp04PackedCanonicalPart03
import SmzaRp04PackedCanonicalPart04
import SmzaRp04PackedCanonicalPart05
import SmzaRp04PackedCoordinatesPart00
import SmzaRp04PackedCoordinatesPart01
import SmzaRp04PackedCoordinatesPart02
import SmzaRp04PackedCoordinatesPart03
import SmzaRp04PackedCoordinatesPart04
import SmzaRp04PackedCoordinatesPart05
import SmzaRp04PackedCoordinatesPart06
import SmzaRp04PackedCoordinatesPart07
import SmzaRp04PackedCoordinatesPart08
import SmzaRp04PackedCoordinatesPart09
import SmzaRp04PackedCoordinatesPart10
import SmzaRp04PackedCoordinatesPart11
import SmzaRp04PackedCoordinatesPart12
import SmzaRp04PackedCoordinatesPart13
import SmzaRp04PackedCoordinatesPart14
import SmzaRp04PackedCoordinatesPart15
import SmzaRp04PackedCoordinatesPart16

namespace HegemonCrypto.SmallWood.SmzaRp04PackedAcceptanceChecks
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp04Components
open HegemonCrypto.SmallWood.SmzaRp04Degree
open HegemonCrypto.SmallWood.SmzaRp04PackedAcceptanceData
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.SmzaRp04PackedCanonicalPart00
open HegemonCrypto.SmallWood.SmzaRp04PackedCanonicalPart01
open HegemonCrypto.SmallWood.SmzaRp04PackedCanonicalPart02
open HegemonCrypto.SmallWood.SmzaRp04PackedCanonicalPart03
open HegemonCrypto.SmallWood.SmzaRp04PackedCanonicalPart04
open HegemonCrypto.SmallWood.SmzaRp04PackedCanonicalPart05
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart00
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart01
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart02
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart03
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart04
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart05
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart06
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart07
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart08
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart09
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart10
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart11
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart12
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart13
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart14
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart15
open HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart16

noncomputable section
set_option maxRecDepth 200000
set_option maxHeartbeats 800000
set_option linter.unusedSimpArgs false

theorem nonlinearChunks_checked :
    checkIndexed_chunks (expressionPredicate true) 0 nonlinearChunks = true := by
  have hprefix00 : (nonlinearChunks00).flatten.length = 1376 :=
    nonlinearChunks00_flatten_length
  have hprefix01 : (nonlinearChunks00 ++ nonlinearChunks01).flatten.length = 2752 := by
    simp only [List.flatten_append, List.length_append,
      nonlinearChunks00_flatten_length, nonlinearChunks01_flatten_length,
      Nat.reduceAdd]
  have hprefix02 : (nonlinearChunks00 ++ nonlinearChunks01 ++ nonlinearChunks02).flatten.length = 4128 := by
    simp only [List.flatten_append, List.length_append,
      nonlinearChunks00_flatten_length, nonlinearChunks01_flatten_length, nonlinearChunks02_flatten_length,
      Nat.reduceAdd]
  have hprefix03 : (nonlinearChunks00 ++ nonlinearChunks01 ++ nonlinearChunks02 ++ nonlinearChunks03).flatten.length = 5504 := by
    simp only [List.flatten_append, List.length_append,
      nonlinearChunks00_flatten_length, nonlinearChunks01_flatten_length, nonlinearChunks02_flatten_length, nonlinearChunks03_flatten_length,
      Nat.reduceAdd]
  have hprefix04 : (nonlinearChunks00 ++ nonlinearChunks01 ++ nonlinearChunks02 ++ nonlinearChunks03 ++ nonlinearChunks04).flatten.length = 6880 := by
    simp only [List.flatten_append, List.length_append,
      nonlinearChunks00_flatten_length, nonlinearChunks01_flatten_length, nonlinearChunks02_flatten_length, nonlinearChunks03_flatten_length, nonlinearChunks04_flatten_length,
      Nat.reduceAdd]
  simp only [nonlinearChunks, checkIndexed_chunks_append,
    nonlinearChunks00_checked, nonlinearChunks01_checked, nonlinearChunks02_checked, nonlinearChunks03_checked, nonlinearChunks04_checked, nonlinearChunks05_checked,
    hprefix00, hprefix01, hprefix02, hprefix03, hprefix04,
    Nat.zero_add, Bool.true_and]

theorem nonlinear_checked :
    checkIndexed (expressionPredicate true) 0 exactNonlinearExpressions = true := by
  have hExpressions : nonlinearChunks.flatten = exactNonlinearExpressions := by
    unfold exactNonlinearExpressions
    apply congrArg List.flatten
    rfl
  rw [← hExpressions, checkIndexed_flatten]
  exact nonlinearChunks_checked

theorem csrExpressionChunk0000_length : exactCsrExpressionsChunk0000.length = 32 := by rfl

theorem csrExpressionChunk0000 :
    checkIndexed (expressionPredicate false) 0 exactCsrExpressionsChunk0000 = true := by
  decide

theorem csrExpressionChunk0001_length : exactCsrExpressionsChunk0001.length = 32 := by rfl

theorem csrExpressionChunk0001 :
    checkIndexed (expressionPredicate false) 32 exactCsrExpressionsChunk0001 = true := by
  decide

theorem csrExpressionChunk0002_length : exactCsrExpressionsChunk0002.length = 32 := by rfl

theorem csrExpressionChunk0002 :
    checkIndexed (expressionPredicate false) 64 exactCsrExpressionsChunk0002 = true := by
  decide

theorem csrExpressionChunk0003_length : exactCsrExpressionsChunk0003.length = 32 := by rfl

theorem csrExpressionChunk0003 :
    checkIndexed (expressionPredicate false) 96 exactCsrExpressionsChunk0003 = true := by
  decide

theorem csrExpressionChunk0004_length : exactCsrExpressionsChunk0004.length = 32 := by rfl

theorem csrExpressionChunk0004 :
    checkIndexed (expressionPredicate false) 128 exactCsrExpressionsChunk0004 = true := by
  decide

theorem csrExpressionChunk0005_length : exactCsrExpressionsChunk0005.length = 32 := by rfl

theorem csrExpressionChunk0005 :
    checkIndexed (expressionPredicate false) 160 exactCsrExpressionsChunk0005 = true := by
  decide

theorem csrExpressionChunk0006_length : exactCsrExpressionsChunk0006.length = 32 := by rfl

theorem csrExpressionChunk0006 :
    checkIndexed (expressionPredicate false) 192 exactCsrExpressionsChunk0006 = true := by
  decide

theorem csrExpressionChunk0007_length : exactCsrExpressionsChunk0007.length = 32 := by rfl

theorem csrExpressionChunk0007 :
    checkIndexed (expressionPredicate false) 224 exactCsrExpressionsChunk0007 = true := by
  decide

theorem csrExpressionChunk0008_length : exactCsrExpressionsChunk0008.length = 32 := by rfl

theorem csrExpressionChunk0008 :
    checkIndexed (expressionPredicate false) 256 exactCsrExpressionsChunk0008 = true := by
  decide

theorem csrExpressionChunk0009_length : exactCsrExpressionsChunk0009.length = 32 := by rfl

theorem csrExpressionChunk0009 :
    checkIndexed (expressionPredicate false) 288 exactCsrExpressionsChunk0009 = true := by
  decide

theorem csrExpressionChunk0010_length : exactCsrExpressionsChunk0010.length = 32 := by rfl

theorem csrExpressionChunk0010 :
    checkIndexed (expressionPredicate false) 320 exactCsrExpressionsChunk0010 = true := by
  decide

theorem csrExpressionChunk0011_length : exactCsrExpressionsChunk0011.length = 32 := by rfl

theorem csrExpressionChunk0011 :
    checkIndexed (expressionPredicate false) 352 exactCsrExpressionsChunk0011 = true := by
  decide

theorem csrExpressionChunk0012_length : exactCsrExpressionsChunk0012.length = 32 := by rfl

theorem csrExpressionChunk0012 :
    checkIndexed (expressionPredicate false) 384 exactCsrExpressionsChunk0012 = true := by
  decide

theorem csrExpressionChunk0013_length : exactCsrExpressionsChunk0013.length = 32 := by rfl

theorem csrExpressionChunk0013 :
    checkIndexed (expressionPredicate false) 416 exactCsrExpressionsChunk0013 = true := by
  decide

theorem csrExpressionChunk0014_length : exactCsrExpressionsChunk0014.length = 32 := by rfl

theorem csrExpressionChunk0014 :
    checkIndexed (expressionPredicate false) 448 exactCsrExpressionsChunk0014 = true := by
  decide

theorem csrExpressionChunk0015_length : exactCsrExpressionsChunk0015.length = 32 := by rfl

theorem csrExpressionChunk0015 :
    checkIndexed (expressionPredicate false) 480 exactCsrExpressionsChunk0015 = true := by
  decide

theorem csrExpressionChunk0016_length : exactCsrExpressionsChunk0016.length = 32 := by rfl

theorem csrExpressionChunk0016 :
    checkIndexed (expressionPredicate false) 512 exactCsrExpressionsChunk0016 = true := by
  decide

theorem csrExpressionChunk0017_length : exactCsrExpressionsChunk0017.length = 20 := by rfl

theorem csrExpressionChunk0017 :
    checkIndexed (expressionPredicate false) 544 exactCsrExpressionsChunk0017 = true := by
  decide

theorem csrExpressionChunks_flatten_length :
    csrExpressionChunks.flatten.length = 564 := by
  simp only [csrExpressionChunks, List.flatten_cons, List.flatten_nil,
    List.length_append, List.length_nil, csrExpressionChunk0000_length, csrExpressionChunk0001_length, csrExpressionChunk0002_length, csrExpressionChunk0003_length, csrExpressionChunk0004_length, csrExpressionChunk0005_length, csrExpressionChunk0006_length, csrExpressionChunk0007_length, csrExpressionChunk0008_length, csrExpressionChunk0009_length, csrExpressionChunk0010_length, csrExpressionChunk0011_length, csrExpressionChunk0012_length, csrExpressionChunk0013_length, csrExpressionChunk0014_length, csrExpressionChunk0015_length, csrExpressionChunk0016_length, csrExpressionChunk0017_length,
    Nat.reduceAdd]

theorem csrExpressions_length : exactCsrExpressions.length = 564 := by
  have hExpressions : csrExpressionChunks.flatten = exactCsrExpressions := by
    unfold exactCsrExpressions
    apply congrArg List.flatten
    rfl
  rw [← hExpressions]
  exact csrExpressionChunks_flatten_length

theorem csrExpressionChunks_checked :
    checkIndexed_chunks (expressionPredicate false) 0 csrExpressionChunks = true := by
  simp only [csrExpressionChunks, checkIndexed_chunks,
    csrExpressionChunk0000_length, csrExpressionChunk0001_length, csrExpressionChunk0002_length, csrExpressionChunk0003_length, csrExpressionChunk0004_length, csrExpressionChunk0005_length, csrExpressionChunk0006_length, csrExpressionChunk0007_length, csrExpressionChunk0008_length, csrExpressionChunk0009_length, csrExpressionChunk0010_length, csrExpressionChunk0011_length, csrExpressionChunk0012_length, csrExpressionChunk0013_length, csrExpressionChunk0014_length, csrExpressionChunk0015_length, csrExpressionChunk0016_length, csrExpressionChunk0000, csrExpressionChunk0001, csrExpressionChunk0002, csrExpressionChunk0003, csrExpressionChunk0004, csrExpressionChunk0005, csrExpressionChunk0006, csrExpressionChunk0007, csrExpressionChunk0008, csrExpressionChunk0009, csrExpressionChunk0010, csrExpressionChunk0011, csrExpressionChunk0012, csrExpressionChunk0013, csrExpressionChunk0014, csrExpressionChunk0015, csrExpressionChunk0016, csrExpressionChunk0017,
    Nat.zero_add, Nat.reduceAdd, Bool.true_and, Bool.and_true]

theorem csrExpressions_checked :
    checkIndexed (expressionPredicate false) 0 exactCsrExpressions = true := by
  have hExpressions : csrExpressionChunks.flatten = exactCsrExpressions := by
    unfold exactCsrExpressions
    apply congrArg List.flatten
    rfl
  rw [← hExpressions, checkIndexed_flatten]
  exact csrExpressionChunks_checked

theorem csrAttemptChunks_coordinates :
    csrAttemptChunks.flatten.all attemptCoordinatesPredicate = true := by
  simp only [csrAttemptChunks, List.flatten_append, List.all_append,
    csrAttemptChunks00_coordinates, csrAttemptChunks01_coordinates, csrAttemptChunks02_coordinates, csrAttemptChunks03_coordinates, csrAttemptChunks04_coordinates, csrAttemptChunks05_coordinates, csrAttemptChunks06_coordinates, csrAttemptChunks07_coordinates, csrAttemptChunks08_coordinates, csrAttemptChunks09_coordinates, csrAttemptChunks10_coordinates, csrAttemptChunks11_coordinates, csrAttemptChunks12_coordinates, csrAttemptChunks13_coordinates, csrAttemptChunks14_coordinates, csrAttemptChunks15_coordinates, csrAttemptChunks16_coordinates,
    Bool.true_and, Bool.and_true]

theorem csrAttempts_coordinates_checked :
    exactCsrAttempts.all attemptCoordinatesPredicate = true := by
  have hAttempts : csrAttemptChunks.flatten = exactCsrAttempts := by
    unfold exactCsrAttempts
    apply congrArg List.flatten
    rfl
  rw [← hAttempts]
  exact csrAttemptChunks_coordinates

theorem csrAttemptPrefixChunks0602_flatten_length :
    csrAttemptPrefixChunks0602.flatten.length = 19264 := by
  simp only [csrAttemptPrefixChunks0602, List.flatten_append,
    List.flatten_cons, List.flatten_nil, List.length_append, List.length_nil,
    csrAttemptChunks00_flatten_length, csrAttemptChunks01_flatten_length, csrAttemptChunks02_flatten_length, csrAttemptChunks03_flatten_length, csrAttemptChunks04_flatten_length, csrAttemptChunks05_flatten_length, csrAttemptChunks06_flatten_length, csrAttemptChunks07_flatten_length, csrAttemptChunks08_flatten_length, csrAttemptChunks09_flatten_length, csrAttemptChunks10_flatten_length, csrAttemptChunks11_flatten_length, csrAttemptChunks12_flatten_length, csrAttemptChunks13_flatten_length, csrAttemptChunks14_flatten_length, csrAttemptChunk0600_length, csrAttemptChunk0601_length, Nat.reduceAdd]

theorem fallback_row : exactCsrAttempts[19295]? =
    some (attempt 19295 45 0 0 [(41528, 1)] 0) := by
  have decomposition : exactCsrAttempts =
      csrAttemptPrefixChunks0602.flatten ++ exactCsrAttemptsChunk0602 ++
        csrAttemptSuffixChunks0603.flatten := by
    unfold exactCsrAttempts
    unfold csrAttemptPrefixChunks0602 csrAttemptSuffixChunks0603
    rfl
  have prefixBound : csrAttemptPrefixChunks0602.flatten.length ≤ 19295 := by
    simpa only [csrAttemptPrefixChunks0602_flatten_length] using
      (show 19264 ≤ 19295 by decide)
  have chunkBound : 31 < exactCsrAttemptsChunk0602.length := by
    simpa only [csrAttemptChunk0602_length] using
      (show 31 < 32 by decide)
  calc
    exactCsrAttempts[19295]? =
        (csrAttemptPrefixChunks0602.flatten ++ exactCsrAttemptsChunk0602 ++
          csrAttemptSuffixChunks0603.flatten)[19295]? := by rw [decomposition]
    _ = (exactCsrAttemptsChunk0602 ++ csrAttemptSuffixChunks0603.flatten)[31]? := by
      rw [List.append_assoc, List.getElem?_append_right prefixBound,
        csrAttemptPrefixChunks0602_flatten_length]
    _ = exactCsrAttemptsChunk0602[31]? :=
      List.getElem?_append_left chunkBound
    _ = some (attempt 19295 45 0 0 [(41528, 1)] 0) :=
      SmzaRp04PackedCoordinatesPart15.fallback_chunk_lookup

end
end HegemonCrypto.SmallWood.SmzaRp04PackedAcceptanceChecks
