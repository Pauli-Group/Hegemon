import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr39

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr40
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 34, 64, 48, 32, 128, 14, 32, 7, 7, 66, 38, 24, 1, 1, 1, 1, 7, 4, 8, 28, 4, 1, 15, 7, 15, 8, 4, 3, 12, 2, 30, 4, 18, 22, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 20480 84 22 0 [(42344, 1)] 0, attempt 20481 84 23 0 [(42408, 1)] 0, attempt 20482 84 24 0 [(42281, 1)] 0, attempt 20483 84 25 0 [(42345, 1)] 0, attempt 20484 84 26 0 [(42409, 1)] 0, attempt 20485 84 27 0 [(42282, 1)] 0, attempt 20486 84 28 0 [(42346, 1)] 0, attempt 20487 84 29 0 [(42410, 1)] 0, attempt 20488 84 30 0 [(42283, 1)] 0, attempt 20489 84 31 0 [(42347, 1)] 0, attempt 20490 84 32 0 [(42411, 1)] 0, attempt 20491 84 33 0 [(42284, 1)] 0, attempt 20492 84 34 0 [(42348, 1)] 0, attempt 20493 84 35 0 [(42412, 1)] 0, attempt 20494 84 36 0 [(42285, 1)] 0, attempt 20495 84 37 0 [(42349, 1)] 0, attempt 20496 84 38 0 [(42413, 1)] 0, attempt 20497 84 39 0 [(42286, 1)] 0, attempt 20498 84 40 0 [(42350, 1)] 0, attempt 20499 84 41 0 [(42414, 1)] 0, attempt 20500 84 42 0 [(42287, 1)] 0, attempt 20501 84 43 0 [(42351, 1)] 0, attempt 20502 84 44 0 [(42415, 1)] 0, attempt 20503 84 45 0 [(42288, 1)] 0, attempt 20504 84 46 0 [(42352, 1)] 0, attempt 20505 84 47 0 [(42416, 1)] 0, attempt 20506 84 48 0 [(42289, 1)] 0, attempt 20507 84 49 0 [(42353, 1)] 0, attempt 20508 84 50 0 [(42417, 1)] 0, attempt 20509 84 51 0 [(42290, 1)] 0, attempt 20510 84 52 0 [(42354, 1)] 0, attempt 20511 84 53 0 [(42418, 1)] 0]
def counters001 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 34, 64, 48, 32, 128, 14, 32, 7, 7, 66, 38, 24, 1, 1, 1, 1, 7, 4, 8, 28, 4, 1, 15, 7, 15, 8, 4, 3, 12, 2, 30, 4, 18, 54, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 20480
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 20512 84 54 0 [(42291, 1)] 0, attempt 20513 84 55 0 [(42355, 1)] 0, attempt 20514 84 56 0 [(42419, 1)] 0, attempt 20515 84 57 0 [(42292, 1)] 0, attempt 20516 84 58 0 [(42356, 1)] 0, attempt 20517 84 59 0 [(42420, 1)] 0, attempt 20518 84 60 0 [(42293, 1)] 0, attempt 20519 84 61 0 [(42357, 1)] 0, attempt 20520 84 62 0 [(42421, 1)] 0, attempt 20521 84 63 0 [(42294, 1)] 0, attempt 20522 84 64 0 [(42358, 1)] 0, attempt 20523 84 65 0 [(42422, 1)] 0, attempt 20524 84 66 0 [(42295, 1)] 0, attempt 20525 84 67 0 [(42359, 1)] 0, attempt 20526 84 68 0 [(42423, 1)] 0, attempt 20527 84 69 0 [(42296, 1)] 0, attempt 20528 84 70 0 [(42360, 1)] 0, attempt 20529 84 71 0 [(42424, 1)] 0, attempt 20530 84 72 0 [(42297, 1)] 0, attempt 20531 84 73 0 [(42361, 1)] 0, attempt 20532 84 74 0 [(42425, 1)] 0, attempt 20533 84 75 0 [(42298, 1)] 0, attempt 20534 84 76 0 [(42362, 1)] 0, attempt 20535 84 77 0 [(42426, 1)] 0, attempt 20536 84 78 0 [(42299, 1)] 0, attempt 20537 84 79 0 [(42363, 1)] 0, attempt 20538 84 80 0 [(42427, 1)] 0, attempt 20539 84 81 0 [(42300, 1)] 0, attempt 20540 84 82 0 [(42364, 1)] 0, attempt 20541 84 83 0 [(42428, 1)] 0, attempt 20542 84 84 0 [(42301, 1)] 0, attempt 20543 84 85 0 [(42365, 1)] 0]
def counters002 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 34, 64, 48, 32, 128, 14, 32, 7, 7, 66, 38, 24, 1, 1, 1, 1, 7, 4, 8, 28, 4, 1, 15, 7, 15, 8, 4, 3, 12, 2, 30, 4, 18, 86, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 20512
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 20544 84 86 0 [(42429, 1)] 0, attempt 20545 84 87 0 [(42302, 1)] 0, attempt 20546 84 88 0 [(42366, 1)] 0, attempt 20547 84 89 0 [(42430, 1)] 0, attempt 20548 84 90 0 [(42303, 1)] 0, attempt 20549 84 91 0 [(42367, 1)] 0, attempt 20550 84 92 0 [(42431, 1)] 0, attempt 20551 85 0 0 [(42222, 1)] 0, attempt 20552 85 1 0 [(42223, 1)] 0, attempt 20553 85 2 0 [(42224, 1)] 0, attempt 20554 85 3 0 [(42225, 1)] 0, attempt 20555 85 4 0 [(42226, 1)] 0, attempt 20556 85 5 0 [(42227, 1)] 0, attempt 20557 85 6 0 [(42228, 1)] 0, attempt 20558 85 7 0 [(42229, 1)] 0, attempt 20559 85 8 0 [(42230, 1)] 0, attempt 20560 85 9 0 [(42231, 1)] 0, attempt 20561 85 10 0 [(42232, 1)] 0, attempt 20562 85 11 0 [(42233, 1)] 0, attempt 20563 85 12 0 [(42234, 1)] 0, attempt 20564 85 13 0 [(42235, 1)] 0, attempt 20565 85 14 0 [(42236, 1)] 0, attempt 20566 85 15 0 [(42237, 1)] 0, attempt 20567 85 16 0 [(42238, 1)] 0, attempt 20568 85 17 0 [(42239, 1)] 0]
def counters003 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 34, 64, 48, 32, 128, 14, 32, 7, 7, 66, 38, 24, 1, 1, 1, 1, 7, 4, 8, 28, 4, 1, 15, 7, 15, 8, 4, 3, 12, 2, 30, 4, 18, 93, 18]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 20544
        counters002 chunk002 = true ∧ chunk002.length = 25 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def suffix003 : List CsrExecutableAttempt := []
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 20569
      counters003 suffix003 = true := by rfl
theorem suffix003_length : suffix003.length = 0 := by rfl
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters003 := by rfl

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 20544
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 20544 20569 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 20544) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 25 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters003 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 20512
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 20512 20544 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 20512) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 57 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters003 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 20480
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 20480 20512 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 20480) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 89 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters003 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr40
