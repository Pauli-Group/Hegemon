import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4826 through 4841. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4826_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4826 + i)) = true := by
  decide

theorem edge_subblock_4826 (node : Nat) (lower : 4826 ≤ node)
    (upper : node < 4842) : directedEdgeCheck node = true :=
  block_sound 4826 16 node edge_part_4826_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part02
