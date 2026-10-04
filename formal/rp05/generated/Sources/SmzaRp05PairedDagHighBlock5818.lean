import SmzaRp05PairedDagHighBlock5818Part00
import SmzaRp05PairedDagHighBlock5818Part01
import SmzaRp05PairedDagHighBlock5818Part02
import SmzaRp05PairedDagHighBlock5818Part03
import SmzaRp05PairedDagHighBlock5818Part04
import SmzaRp05PairedDagHighBlock5818Part05
import SmzaRp05PairedDagHighBlock5818Part06
import SmzaRp05PairedDagHighBlock5818Part07

/-! Bounded dispatcher for the exact directed-edge interval 5818 through 5945. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_5818 (node : Nat) (lower : 5818 ≤ node)
    (upper : node < 5946) : directedEdgeCheck node = true := by
  by_cases h5834 : node < 5834
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part00.edge_subblock_5818 node lower h5834
  · by_cases h5850 : node < 5850
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part01.edge_subblock_5834 node (Nat.le_of_not_gt h5834) (h5850)
    · by_cases h5866 : node < 5866
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part02.edge_subblock_5850 node (Nat.le_of_not_gt h5850) (h5866)
      · by_cases h5882 : node < 5882
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part03.edge_subblock_5866 node (Nat.le_of_not_gt h5866) (h5882)
        · by_cases h5898 : node < 5898
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part04.edge_subblock_5882 node (Nat.le_of_not_gt h5882) (h5898)
          · by_cases h5914 : node < 5914
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part05.edge_subblock_5898 node (Nat.le_of_not_gt h5898) (h5914)
            · by_cases h5930 : node < 5930
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part06.edge_subblock_5914 node (Nat.le_of_not_gt h5914) (h5930)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part07.edge_subblock_5930 node (Nat.le_of_not_gt h5930) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818
