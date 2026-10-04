import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7194 through 7209. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7194_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7194 + i)) = true := by
  decide

theorem edge_subblock_7194 (node : Nat) (lower : 7194 ≤ node)
    (upper : node < 7210) : directedEdgeCheck node = true :=
  block_sound 7194 16 node edge_part_7194_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part06
