import SmzaRp05PairedDagHighBlock5690Part00
import SmzaRp05PairedDagHighBlock5690Part01
import SmzaRp05PairedDagHighBlock5690Part02
import SmzaRp05PairedDagHighBlock5690Part03
import SmzaRp05PairedDagHighBlock5690Part04
import SmzaRp05PairedDagHighBlock5690Part05
import SmzaRp05PairedDagHighBlock5690Part06
import SmzaRp05PairedDagHighBlock5690Part07

/-! Bounded dispatcher for the exact directed-edge interval 5690 through 5817. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_5690 (node : Nat) (lower : 5690 ≤ node)
    (upper : node < 5818) : directedEdgeCheck node = true := by
  by_cases h5706 : node < 5706
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part00.edge_subblock_5690 node lower h5706
  · by_cases h5722 : node < 5722
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part01.edge_subblock_5706 node (Nat.le_of_not_gt h5706) (h5722)
    · by_cases h5738 : node < 5738
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part02.edge_subblock_5722 node (Nat.le_of_not_gt h5722) (h5738)
      · by_cases h5754 : node < 5754
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part03.edge_subblock_5738 node (Nat.le_of_not_gt h5738) (h5754)
        · by_cases h5770 : node < 5770
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part04.edge_subblock_5754 node (Nat.le_of_not_gt h5754) (h5770)
          · by_cases h5786 : node < 5786
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part05.edge_subblock_5770 node (Nat.le_of_not_gt h5770) (h5786)
            · by_cases h5802 : node < 5802
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part06.edge_subblock_5786 node (Nat.le_of_not_gt h5786) (h5802)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part07.edge_subblock_5802 node (Nat.le_of_not_gt h5802) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690
