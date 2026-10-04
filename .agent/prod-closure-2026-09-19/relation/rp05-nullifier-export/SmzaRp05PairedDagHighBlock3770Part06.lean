import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3866 through 3881. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3866_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3866 + i)) = true := by
  decide

theorem edge_subblock_3866 (node : Nat) (lower : 3866 ≤ node)
    (upper : node < 3882) : directedEdgeCheck node = true :=
  block_sound 3866 16 node edge_part_3866_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part06
