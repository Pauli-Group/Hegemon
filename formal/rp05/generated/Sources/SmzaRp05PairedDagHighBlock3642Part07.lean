import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3754 through 3769. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3754_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3754 + i)) = true := by
  decide

theorem edge_subblock_3754 (node : Nat) (lower : 3754 ≤ node)
    (upper : node < 3770) : directedEdgeCheck node = true :=
  block_sound 3754 16 node edge_part_3754_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part07
