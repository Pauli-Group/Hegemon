import Q38Rp05AdaptiveScheduler
import HegemonCrypto.SmallWoodV8Smz9HonestLeafBatch

/-! Finite-product identity for the actual sequential real leaf compiler.
This is an exact interpreter identity, with no oracle changes, independence
premises about old answers, or distinctness requirement. Source-only. -/
namespace HegemonCrypto.SmallWood.Q38Rp05RealLeafProduct

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestLeafBatch
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 1000000

/-- A generic pointwise eta rule for the constructor used by the sequential
sampler. Keeping the element family opaque here prevents the concrete leaf
input interpreter from being unfolded while transporting its answers. -/
private theorem fin_cons_eta {A : Type} (count : Nat)
    (values : Fin (count + 1) → A) :
    Fin.cons (values 0) (fun index : Fin count => values index.succ) = values := by
  funext index
  exact Fin.cases rfl (fun _ => rfl) index

variable {bound : Nat} {Work : Type} [Fintype Work]
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "OracleInput" => Rp05FullRawInput bound

/-- The literal scheduler samples one tape and reads H at each leaf. Folding
those independent samples into one uniform tape vector preserves its exact
continuation, current answers and original residual state. In particular
`mode` continues unchanged into arbitrary later requests in `next`. -/
theorem real_leaf_batch_product
    (mode : Bool) (count : Nat) (indices : Fin count → LeafIndex)
    (statement : Statement) (salt : SaltBytes)
    (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      MixedProgram OracleInput Work)
    (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode
        (realLeafBatch count indices statement salt data next) oracle state =
      uniformAverage (fun tapes : Fin count → LeafTape =>
        V8Smz9MixedMaskCompiler.run mode
          (next tapes (fun index => oracle (Sum.inl
            (rp05SourceLeafInput statement salt (data index)
              (indices index) (tapes index))))) oracle state) := by
  induction count with
  | zero =>
      simp only [realLeafBatch]
      symm
      calc
        _ = uniformAverage (fun _ : Fin 0 → LeafTape =>
            V8Smz9MixedMaskCompiler.run mode
              (next Fin.elim0 Fin.elim0) oracle state) := by
          apply congrArg uniformAverage
          funext tapes
          have tapeEmpty : tapes = Fin.elim0 := Subsingleton.elim _ _
          have answerEmpty :
              (fun index : Fin 0 => oracle (Sum.inl
                (rp05SourceLeafInput statement salt (data index)
                  (indices index) (tapes index)))) = Fin.elim0 :=
            Subsingleton.elim _ _
          rw [answerEmpty, tapeEmpty]
        _ = _ := uniform_average_const _
  | succ count ih =>
      simp only [realLeafBatch, V8Smz9MixedMaskCompiler.run, uniformSource]
      rw [uniform_average_fin_cons count]
      apply congrArg uniformAverage
      funext tape
      rw [ih]
      apply congrArg uniformAverage
      funext tapes
      let tapeVector : Fin (count + 1) → LeafTape := Fin.cons tape tapes
      let currentAnswer : Fin (count + 1) → DigestRegister := fun index =>
        oracle (Sum.inl (rp05SourceLeafInput statement salt
          (data index) (indices index) (tapeVector index)))
      have answers :
          Fin.cons
              (oracle (Sum.inl (rp05SourceLeafInput statement salt
                (data 0) (indices 0) tape)))
              (fun index : Fin count => oracle (Sum.inl
                (rp05SourceLeafInput statement salt (data index.succ)
                  (indices index.succ) (tapes index)))) = currentAnswer := by
        change Fin.cons (currentAnswer 0)
            (fun index : Fin count => currentAnswer index.succ) = currentAnswer
        exact fin_cons_eta count currentAnswer
      exact congrArg
        (fun answerVector => V8Smz9MixedMaskCompiler.run mode
          (next (Fin.cons tape tapes) answerVector) oracle state)
        answers

end
end HegemonCrypto.SmallWood.Q38Rp05RealLeafProduct
