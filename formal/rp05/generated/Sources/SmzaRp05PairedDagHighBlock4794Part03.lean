import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4842 through 4857. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4842_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4842 + i)) = true := by
  decide

theorem edge_subblock_4842 (node : Nat) (lower : 4842 ≤ node)
    (upper : node < 4858) : directedEdgeCheck node = true :=
  block_sound 4842 16 node edge_part_4842_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part03
