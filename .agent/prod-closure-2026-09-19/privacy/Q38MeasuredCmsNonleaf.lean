import Q38MeasuredCmsNonleafCore
import Q38ChronologicalStateAlgebra

/-!
The concrete q38 DECS/PIOP chronology layered over the measured-CMS core.

All generic measured-CMS declarations live only in
`Q38MeasuredCmsNonleafCore`; this wrapper imports them and adds the actual
five-by-406 q38 response and RP04 public-context application.
-/
namespace HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf

open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8SmzaChronologicalStateAlgebra
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option linter.unusedSimpArgs false

variable {Other : Type}

/-! The q38 DECS/PIOP split.  This program syntax puts one complete finite
measured branch strictly between the M-to-D and Q-to-T changes of variables.
Unlike the retained `PrefinalShape`, its response-indexed key takes the actual
five-by-406 q38 DECS response. -/

abbrev Q38DecsResponse :=
  HegemonCrypto.SmallWood.V8SmzaMathPrivacy.Decs Goldilocks
abbrev Q38PiopResponse :=
  HegemonCrypto.SmallWood.V8Smz9EagerPrivacy.PiopCoefficients Goldilocks

structure Q38PrefinalShape (Other : Type) where
  build : NonleafProgram Other (DigestRegister × List (List DigestRegister))
  rootKey : DigestRegister → Other
  decs : DigestRegister → NonleafProgram Other (Option (List
    HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord))
  piopKey : DigestRegister → Q38DecsResponse → Other
  piop : DigestRegister → NonleafProgram Other (Option (List
    HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord))

def Q38PrefinalShape.dynamic (shape : Q38PrefinalShape Other)
    (respond : Option (List
      HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord) →
        Q38DecsResponse) :
    NonleafProgram Other (PrefinalResult × Q38DecsResponse) :=
  NonleafProgram.bind shape.build fun built =>
    .read (shape.rootKey built.1) fun firstHash =>
      NonleafProgram.bind (shape.decs firstHash) fun gamma =>
        let reply := respond gamma
        .read (shape.rootKey built.1) fun hashMt =>
          .read (shape.piopKey hashMt reply) fun hashFpp =>
            NonleafProgram.bind (shape.piop hashFpp) fun batching =>
              .done (⟨built.2, hashMt, gamma, hashFpp, batching⟩, reply)

structure DecsStage where
  built : DigestRegister × List (List DigestRegister)
  firstHash : DigestRegister
  decsGamma : Option (List
    HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord)

def decsPrefix (shape : Q38PrefinalShape Other) :
    NonleafProgram Other DecsStage :=
  NonleafProgram.bind shape.build fun built =>
    .read (shape.rootKey built.1) fun firstHash =>
      NonleafProgram.bind (shape.decs firstHash) fun gamma =>
        .done ⟨built, firstHash, gamma⟩

def piopSuffix (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (reply : Q38DecsResponse) : NonleafProgram Other PrefinalResult :=
  .read (shape.rootKey stage.built.1) fun hashMt =>
    .read (shape.piopKey hashMt reply) fun hashFpp =>
      NonleafProgram.bind (shape.piop hashFpp) fun batching =>
        .done ⟨stage.built.2, hashMt, stage.decsGamma, hashFpp, batching⟩

theorem nonleaf_bind_assoc {First Middle Last : Type}
    (program : NonleafProgram Other First)
    (middle : First → NonleafProgram Other Middle)
    (last : Middle → NonleafProgram Other Last) :
    NonleafProgram.bind (NonleafProgram.bind program middle) last =
      NonleafProgram.bind program fun result =>
        NonleafProgram.bind (middle result) last := by
  induction program with
  | done result => rfl
  | read input next ih =>
      simp only [NonleafProgram.bind]
      congr
      funext answer
      exact ih answer

/-- The original adaptive program is definitionally the measured chronology:
finish the DECS prefix, compute D, then execute the D-indexed PIOP suffix. -/
theorem dynamic_eq_decs_then_piop
    (shape : Q38PrefinalShape Other)
    (respond : Option (List
      HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord) →
      Q38DecsResponse) :
    shape.dynamic respond =
      NonleafProgram.bind (decsPrefix shape) fun stage =>
        NonleafProgram.bind (piopSuffix shape stage (respond stage.decsGamma))
          fun result => .done (result, respond stage.decsGamma) := by
  unfold Q38PrefinalShape.dynamic decsPrefix
  rw [nonleaf_bind_assoc]
  apply congrArg (fun continuation => NonleafProgram.bind shape.build continuation)
  funext built
  simp only [NonleafProgram.bind]
  congr
  funext firstHash
  rw [nonleaf_bind_assoc]
  apply congrArg
    (fun continuation => NonleafProgram.bind (shape.decs firstHash) continuation)
  funext gamma
  unfold piopSuffix
  simp only [NonleafProgram.bind]
  congr
  funext hashMt
  congr
  funext hashFpp
  rw [nonleaf_bind_assoc]
  apply congrArg
    (fun continuation => NonleafProgram.bind (shape.piop hashFpp) continuation)
  funext batching
  rfl

/-- Decode the actual PIOP sample from one fixed-width public trace. Invalid
padding maps to the source's existing rejection value `none`. -/
def tracedPiopSample (fuel : Nat) (shape : Q38PrefinalShape Other)
    (stage : DecsStage) (reply : Q38DecsResponse)
    (trace : PublicTrace DigestRegister fuel) :
    Option (List HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord) :=
  (traceResult fuel (piopSuffix shape stage reply) trace).bind
    PrefinalResult.piopGamma

/-- Exact 700-word DECS allocation for q38.  Its dimensions did not change:
five batching polynomials by 140 committed rows. -/
def decodedQ38DecsGamma
    (result : Option (List
      HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord)) :
    Gamma Goldilocks :=
  fun polynomial row =>
    ((HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule.sourceReturnedWords
      700 result).getD (polynomial.val * 140 + row.val) 0).val

/-- Actual RP04 PIOP batching allocation.  The width is `max 773` and the
public retained-row count, rather than the old fixed `max 830` decoder. -/
def decodedRp04PiopGamma (publicValues : List Nat)
    (result : Option (List
      HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord)) :
    Fin 5 → Nat → Goldilocks :=
  let width := HegemonCrypto.SmallWood.SmzaRp04PublicContext.batchingWidth
    publicValues
  fun polynomial row =>
    ((HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule.sourceReturnedWords
      (5 * width) result).getD (polynomial.val * width + row) 0).val

/-- The measured branch is the fixed finite public trace, while its query keys
and RP04 batching sample are computed by the actual q38-response-indexed
`piopSuffix`.  The kernel retains Q, M, D, T and the branch's unnormalised
instrument state. -/
theorem rp04_response_measured_trace_sum
    {Value : Type*} [AddCommMonoid Value]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (publicValues : List Nat)
    (values : WitnessPackingValues Goldilocks)
    (base : HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra.RemainingCoins
      Goldilocks)
    (kernel : Q38DecsResponse → PublicTrace DigestRegister fuel →
      Q38PiopResponse → Q38DecsResponse → Q38PiopResponse → Value) :
    (∑ q, ∑ m, ∑ trace : PublicTrace DigestRegister fuel,
      let reply := V8SmzaMathPrivacy.response
        (decodedQ38DecsGamma stage.decsGamma)
        (rp04PhysicalHeads values base q) base.2.2 m
      kernel reply trace q m
        (rp04ResponseCoefficients
          (HegemonCrypto.SmallWood.SmzaRp04PublicContext.publicParameters
            publicValues (decodedRp04PiopGamma publicValues
              (tracedPiopSample fuel shape stage reply trace)))
          (sourceWitnessPolynomials values base.1) q)) =
    ∑ reply, ∑ trace : PublicTrace DigestRegister fuel, ∑ transcript,
      let q := transcript - rp04UnmaskedResponseCoefficients
        (HegemonCrypto.SmallWood.SmzaRp04PublicContext.publicParameters
          publicValues (decodedRp04PiopGamma publicValues
            (tracedPiopSample fuel shape stage reply trace)))
        (sourceWitnessPolynomials values base.1)
      let m := reply - V8SmzaMathPrivacy.unmasked
        (decodedQ38DecsGamma stage.decsGamma)
        (rp04PhysicalHeads values base q) base.2.2
      kernel reply trace q m transcript := by
  let parameters : Q38DecsResponse → PublicTrace DigestRegister fuel →
      HegemonCrypto.SmallWood.SmzaRp04ProgramPiop.CurrentPublicParameters :=
    fun reply trace =>
      HegemonCrypto.SmallWood.SmzaRp04PublicContext.publicParameters publicValues
        (decodedRp04PiopGamma publicValues
          (tracedPiopSample fuel shape stage reply trace))
  simpa only [parameters] using
    (rp04_response_state_kernel_sum (Value := Value)
      (gamma := decodedQ38DecsGamma stage.decsGamma)
      values base parameters kernel)

end
end HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
