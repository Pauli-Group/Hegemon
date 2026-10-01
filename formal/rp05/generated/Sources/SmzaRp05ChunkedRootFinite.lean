import SmzaRp05ChunkedDagRefinement
import SmzaRp05NullifierRootAll
import HegemonCrypto.SmallWoodV8Smz9HashDependencyCertificate

/-! Chunk-backed finite root shape for the 332 RP05/reference Poseidon
recurrences. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ChunkedRootFinite

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def currentRoot (wire : Nat) : Nat :=
  exactNonlinearRoots.getD (459 + wire) 0

def currentRhs (wire : Nat) : Nat :=
  match currentExpressions[currentRoot wire]? with
  | some (.sub _ rhs) => rhs
  | _ => 0

def rootRow (wire : Nat) : Nat :=
  hashRow (wire / 166) (wire % 166)

def RootShape (wire : Nat) : Prop :=
  currentExpressions[currentRoot wire]? =
      some (.sub (124 + rootRow wire) (currentRhs wire)) ∧
  currentExpressions[124 + rootRow wire]? =
      some (.witnessRow (rootRow wire)) ∧
  currentRoot wire ∈ exactNonlinearRoots ∧
  124 + rootRow wire < currentRoot wire ∧
  currentRhs wire < currentRoot wire ∧
  supportedNode (currentRhs wire) ∧
  mappedNode (currentRhs wire) =
    (hashRootPair (wire / 166) (wire % 166)).2

instance (wire : Nat) : Decidable (RootShape wire) := by
  unfold RootShape
  infer_instance

theorem root_shape (wire : Nat) (bound : wire < 332) : RootShape wire := by
  change SmzaRp05NullifierRootChunk00.RootShape wire
  exact SmzaRp05NullifierRootAll.root_shape_all wire bound

end HegemonCrypto.SmallWood.SmzaRp05ChunkedRootFinite
