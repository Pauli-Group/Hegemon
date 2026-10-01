import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4026 through 4041. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4026_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4026 + i)) = true := by
  decide

theorem edge_subblock_4026 (node : Nat) (lower : 4026 ≤ node)
    (upper : node < 4042) : directedEdgeCheck node = true :=
  block_sound 4026 16 node edge_part_4026_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part00
