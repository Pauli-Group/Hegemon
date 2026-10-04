import SmzaRp05PairedDagHighBlock5562Part00
import SmzaRp05PairedDagHighBlock5562Part01
import SmzaRp05PairedDagHighBlock5562Part02
import SmzaRp05PairedDagHighBlock5562Part03
import SmzaRp05PairedDagHighBlock5562Part04
import SmzaRp05PairedDagHighBlock5562Part05
import SmzaRp05PairedDagHighBlock5562Part06
import SmzaRp05PairedDagHighBlock5562Part07

/-! Bounded dispatcher for the exact directed-edge interval 5562 through 5689. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_5562 (node : Nat) (lower : 5562 ≤ node)
    (upper : node < 5690) : directedEdgeCheck node = true := by
  by_cases h5578 : node < 5578
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part00.edge_subblock_5562 node lower h5578
  · by_cases h5594 : node < 5594
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part01.edge_subblock_5578 node (Nat.le_of_not_gt h5578) (h5594)
    · by_cases h5610 : node < 5610
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part02.edge_subblock_5594 node (Nat.le_of_not_gt h5594) (h5610)
      · by_cases h5626 : node < 5626
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part03.edge_subblock_5610 node (Nat.le_of_not_gt h5610) (h5626)
        · by_cases h5642 : node < 5642
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part04.edge_subblock_5626 node (Nat.le_of_not_gt h5626) (h5642)
          · by_cases h5658 : node < 5658
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part05.edge_subblock_5642 node (Nat.le_of_not_gt h5642) (h5658)
            · by_cases h5674 : node < 5674
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part06.edge_subblock_5658 node (Nat.le_of_not_gt h5658) (h5674)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part07.edge_subblock_5674 node (Nat.le_of_not_gt h5674) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562
