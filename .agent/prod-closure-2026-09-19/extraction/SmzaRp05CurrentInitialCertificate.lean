import SmzaRp05NullifierSourceBase
import SmzaRp05Components
import SmzaRp05LocalCertificate

/-! Import-light extraction of the concrete current-RP05 initial-state
certificate.  Attempts are selected from their small generated CSR chunks. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentInitialCertificate

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierSource
open _root_.HegemonCrypto.SmallWood.SmzaRp05Components
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex inputDirectionRow hashRowStart
    packingFactor hashRowsPerGroup hashFinalRowOffset rawRowStart)
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
  (nullifierFirstCall inputNullifierKeyRow inputNoteFirstCall)

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 4000000

private def emptyAttempt : CsrExecutableAttempt :=
  { globalIndex := 0, family := 0, localIndex := 0, emission := 0,
    terms := [], targetRoot := 0 }

def initialAttempt (cell : InitialCell) : CsrExecutableAttempt :=
  let n := cell.1.val * 32 + cell.2.1.val * 16 + cell.2.2.val
  if n < 17 then (exactCsrAttemptsChunk0570[n + 15]?).getD emptyAttempt
  else if n < 49 then (exactCsrAttemptsChunk0571[n - 17]?).getD emptyAttempt
  else (exactCsrAttemptsChunk0572[n - 49]?).getD emptyAttempt

def initialPowerNode (bit : Nat) : Nat := match bit with
  | 0 => 160 | 1 => 203 | 2 => 161 | 3 => 205 | 4 => 207
  | 5 => 209 | 6 => 211 | 7 => 213 | 8 => 215 | 9 => 217
  | 10 => 219 | 11 => 221 | 12 => 223 | 13 => 225 | 14 => 227
  | 15 => 229 | 16 => 231 | 17 => 233 | 18 => 235 | 19 => 237
  | 20 => 239 | 21 => 241 | 22 => 243 | 23 => 245 | 24 => 247
  | 25 => 249 | 26 => 251 | 27 => 253 | 28 => 255 | 29 => 257
  | 30 => 259 | 31 => 261 | _ => 0

private theorem chunk570_lift {a : CsrExecutableAttempt}
    (ha : a ∈ exactCsrAttemptsChunk0570) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 570) (by decide)) ha

private theorem chunk571_lift {a : CsrExecutableAttempt}
    (ha : a ∈ exactCsrAttemptsChunk0571) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 571) (by decide)) ha

private theorem chunk572_lift {a : CsrExecutableAttempt}
    (ha : a ∈ exactCsrAttemptsChunk0572) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 572) (by decide)) ha

private theorem initial_attempt_member (cell : InitialCell) :
    initialAttempt cell ∈ program.csrAttempts := by
  change initialAttempt cell ∈ exactCsrAttempts
  rcases cell with ⟨input, block, lane⟩
  fin_cases input <;> fin_cases block <;> fin_cases lane
  all_goals simp [initialAttempt, emptyAttempt]
  all_goals first
  | exact chunk570_lift (by decide)
  | exact chunk571_lift (by decide)
  | exact chunk572_lift (by decide)

def initialConstantNode (cell : InitialCell) : Nat :=
  initialAttempt cell |>.targetRoot

private theorem initial_attempt_terms : ∀ cell,
    (initialAttempt cell).terms = initialTerms 1 160 262 initialPowerNode cell := by
  intro cell
  rcases cell with ⟨input, block, lane⟩
  fin_cases input <;> fin_cases block <;> fin_cases lane
  all_goals
    simp [initialAttempt, emptyAttempt, initialTerms, callOf, initialPowerNode,
      exactCsrAttemptsChunk0570, exactCsrAttemptsChunk0571,
      exactCsrAttemptsChunk0572, hashInitialIndex, hashFinalIndex,
      nullifierFirstCall, inputNullifierKeyRow, inputNoteFirstCall,
      inputDirectionRow, rawIndex, positionTerms, hashRowStart,
      _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      hashRowsPerGroup, hashFinalRowOffset, rawRowStart, List.range_succ]
    rfl

private theorem initial_attempt_target : ∀ cell,
    (initialAttempt cell).targetRoot = initialConstantNode cell := by
  intro cell
  rfl

private theorem initial_constant_realizes (cell : InitialCell) :
    Realizes program.csrExpressions (initialConstantNode cell)
      (.constant (initialConstant cell)) := by
  rcases cell with ⟨input, block, lane⟩
  fin_cases input <;> fin_cases block <;> fin_cases lane
  all_goals
    simp [initialConstantNode, initialAttempt, emptyAttempt,
      exactCsrAttemptsChunk0570, exactCsrAttemptsChunk0571,
      exactCsrAttemptsChunk0572]
    exact Realizes.constant (by decide)

def initialCertificate : InitialCertificate program :=
  { canonical := by apply (checkExpressionProgram_eq_true _ _).mp; decide
    oneNode := 1
    negativeNode := 160
    positiveNode := 262
    powerNode := initialPowerNode
    constantNode := initialConstantNode
    oneRealizes := Realizes.constant (by decide)
    negativeRealizes := Realizes.sub (leftNode := 0) (rightNode := 1)
      (by decide) (by decide) (by decide)
      (Realizes.constant (by decide)) (Realizes.constant (by decide))
    positiveRealizes := Realizes.sub (leftNode := 0) (rightNode := 160)
      (by decide) (by decide) (by decide)
      (Realizes.constant (by decide))
      (Realizes.sub (leftNode := 0) (rightNode := 1)
        (by decide) (by decide) (by decide)
        (Realizes.constant (by decide)) (Realizes.constant (by decide)))
    powerRealizes := by
      intro bit h
      interval_cases bit <;> all_goals first
      | exact Realizes.sub (leftNode := 0) (rightNode := 1)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 2)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 130)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 204)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 206)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 208)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 210)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 212)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 214)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 216)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 218)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 220)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 222)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 224)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 226)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 228)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 230)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 232)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 234)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 236)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 238)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 240)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 242)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 244)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 246)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 248)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 250)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 252)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 254)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 256)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 258)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
      | exact Realizes.sub (leftNode := 0) (rightNode := 260)
          (by decide) (by decide) (by decide)
          (Realizes.constant (by decide)) (Realizes.constant (by decide))
    constantRealizes := initial_constant_realizes
    attempt := initialAttempt
    member := initial_attempt_member
    attemptTerms := initial_attempt_terms
    attemptTarget := initial_attempt_target }

end HegemonCrypto.SmallWood.SmzaRp05CurrentInitialCertificate
