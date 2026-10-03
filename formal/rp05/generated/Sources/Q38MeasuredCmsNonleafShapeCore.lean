import Q38MeasuredCmsNonleafCore
import Hegemon.Transaction.Poseidon2V8SemanticSpecification
import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule
import HegemonCrypto.SmallWoodV8Smz9WholeViewObservation

/-!
# Import-light q38 prefinal PIOP shape

The prefinal-program interface is kept separate from the chronological
algebra proofs so measured-branch accounting can use the same program type
without importing the post-final/compiler chain.
-/
namespace HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf

open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open scoped BigOperators Classical

variable {Other : Type}

abbrev Q38DecsResponse := Fin 5 → Fin 406 → Goldilocks

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

end HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
