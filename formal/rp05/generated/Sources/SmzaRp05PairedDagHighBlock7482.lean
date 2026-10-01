import SmzaRp05PairedDagHighBlock7482Part00
import SmzaRp05PairedDagHighBlock7482Part01
import SmzaRp05PairedDagHighBlock7482Part02
import SmzaRp05PairedDagHighBlock7482Part03
import SmzaRp05PairedDagHighBlock7482Part04
import SmzaRp05PairedDagHighBlock7482Part05
import SmzaRp05PairedDagHighBlock7482Part06
import SmzaRp05PairedDagHighBlock7482Part07

/-! Bounded dispatcher for the exact directed-edge interval 7482 through 7609. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_7482 (node : Nat) (lower : 7482 ≤ node)
    (upper : node < 7610) : directedEdgeCheck node = true := by
  by_cases h7498 : node < 7498
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part00.edge_subblock_7482 node lower h7498
  · by_cases h7514 : node < 7514
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part01.edge_subblock_7498 node (Nat.le_of_not_gt h7498) (h7514)
    · by_cases h7530 : node < 7530
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part02.edge_subblock_7514 node (Nat.le_of_not_gt h7514) (h7530)
      · by_cases h7546 : node < 7546
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part03.edge_subblock_7530 node (Nat.le_of_not_gt h7530) (h7546)
        · by_cases h7562 : node < 7562
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part04.edge_subblock_7546 node (Nat.le_of_not_gt h7546) (h7562)
          · by_cases h7578 : node < 7578
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part05.edge_subblock_7562 node (Nat.le_of_not_gt h7562) (h7578)
            · by_cases h7594 : node < 7594
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part06.edge_subblock_7578 node (Nat.le_of_not_gt h7578) (h7594)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part07.edge_subblock_7594 node (Nat.le_of_not_gt h7594) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482
