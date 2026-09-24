import SmzaRp04PackedAcceptanceData

namespace HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart16
open HegemonCrypto.SmallWood.SmzaRp04Components
open HegemonCrypto.SmallWood.SmzaRp04PackedAcceptanceData

set_option maxRecDepth 200000
set_option maxHeartbeats 800000
set_option linter.unusedSimpArgs false

theorem csrAttemptChunk0640_length : exactCsrAttemptsChunk0640.length = 32 := by rfl

theorem csrAttemptChunk0640_coordinates :
    exactCsrAttemptsChunk0640.all attemptCoordinatesPredicate = true := by
  decide

theorem csrAttemptChunk0641_length : exactCsrAttemptsChunk0641.length = 32 := by rfl

theorem csrAttemptChunk0641_coordinates :
    exactCsrAttemptsChunk0641.all attemptCoordinatesPredicate = true := by
  decide

theorem csrAttemptChunk0642_length : exactCsrAttemptsChunk0642.length = 32 := by rfl

theorem csrAttemptChunk0642_coordinates :
    exactCsrAttemptsChunk0642.all attemptCoordinatesPredicate = true := by
  decide

theorem csrAttemptChunk0643_length : exactCsrAttemptsChunk0643.length = 26 := by rfl

theorem csrAttemptChunk0643_coordinates :
    exactCsrAttemptsChunk0643.all attemptCoordinatesPredicate = true := by
  decide

theorem csrAttemptChunks16_flatten_length :
    csrAttemptChunks16.flatten.length = 122 := by
  simp only [csrAttemptChunks16, List.flatten_cons, List.flatten_nil,
    List.length_append, List.length_nil, csrAttemptChunk0640_length, csrAttemptChunk0641_length, csrAttemptChunk0642_length, csrAttemptChunk0643_length,
    Nat.reduceAdd]

theorem csrAttemptChunks16_coordinates :
    csrAttemptChunks16.flatten.all attemptCoordinatesPredicate = true := by
  simp only [csrAttemptChunks16, List.flatten_cons, List.flatten_nil,
    List.all_append, List.all_nil, csrAttemptChunk0640_coordinates, csrAttemptChunk0641_coordinates, csrAttemptChunk0642_coordinates, csrAttemptChunk0643_coordinates,
    Bool.true_and, Bool.and_true]

end HegemonCrypto.SmallWood.SmzaRp04PackedCoordinatesPart16
