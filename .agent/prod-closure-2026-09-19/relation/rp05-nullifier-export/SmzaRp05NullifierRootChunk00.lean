import SmzaRp05PairedHashDagData
import HegemonCrypto.SmallWoodV8Smz9HashDependencyCertificate

/-!
Finite root-shape certificate for the first 16 current RP05 Poseidon roots.
The proposition is computed directly from the current component arrays and
the separately generated paired reference-root table.  No acceptance or
production claim is made here.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk00

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

private theorem root_chunk00_checked :
    (List.range 16).all (fun wire => decide (RootShape wire)) = true := by
  decide

/-- Every root-shape fact for wires 0 through 15 follows from the checked
    finite table, without expanding any SourceTerm evaluator tree. -/
theorem root_shape (wire : Nat) (bound : wire < 16) : RootShape wire := by
  have checked := (List.all_eq_true.mp root_chunk00_checked) wire
    (List.mem_range.mpr bound)
  exact decide_eq_true_eq.mp checked

end HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk00
