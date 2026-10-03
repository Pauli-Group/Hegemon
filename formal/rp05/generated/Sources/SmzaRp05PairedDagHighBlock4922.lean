import SmzaRp05PairedDagHighBlock4922Part00
import SmzaRp05PairedDagHighBlock4922Part01
import SmzaRp05PairedDagHighBlock4922Part02
import SmzaRp05PairedDagHighBlock4922Part03
import SmzaRp05PairedDagHighBlock4922Part04
import SmzaRp05PairedDagHighBlock4922Part05
import SmzaRp05PairedDagHighBlock4922Part06
import SmzaRp05PairedDagHighBlock4922Part07

/-! Bounded dispatcher for the exact directed-edge interval 4922 through 5049. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_4922 (node : Nat) (lower : 4922 ≤ node)
    (upper : node < 5050) : directedEdgeCheck node = true := by
  by_cases h4938 : node < 4938
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part00.edge_subblock_4922 node lower h4938
  · by_cases h4954 : node < 4954
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part01.edge_subblock_4938 node (Nat.le_of_not_gt h4938) (h4954)
    · by_cases h4970 : node < 4970
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part02.edge_subblock_4954 node (Nat.le_of_not_gt h4954) (h4970)
      · by_cases h4986 : node < 4986
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part03.edge_subblock_4970 node (Nat.le_of_not_gt h4970) (h4986)
        · by_cases h5002 : node < 5002
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part04.edge_subblock_4986 node (Nat.le_of_not_gt h4986) (h5002)
          · by_cases h5018 : node < 5018
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part05.edge_subblock_5002 node (Nat.le_of_not_gt h5002) (h5018)
            · by_cases h5034 : node < 5034
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part06.edge_subblock_5018 node (Nat.le_of_not_gt h5018) (h5034)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part07.edge_subblock_5034 node (Nat.le_of_not_gt h5034) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922
