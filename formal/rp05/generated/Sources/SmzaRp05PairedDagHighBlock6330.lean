import SmzaRp05PairedDagHighBlock6330Part00
import SmzaRp05PairedDagHighBlock6330Part01
import SmzaRp05PairedDagHighBlock6330Part02
import SmzaRp05PairedDagHighBlock6330Part03
import SmzaRp05PairedDagHighBlock6330Part04
import SmzaRp05PairedDagHighBlock6330Part05
import SmzaRp05PairedDagHighBlock6330Part06
import SmzaRp05PairedDagHighBlock6330Part07

/-! Bounded dispatcher for the exact directed-edge interval 6330 through 6457. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_6330 (node : Nat) (lower : 6330 ≤ node)
    (upper : node < 6458) : directedEdgeCheck node = true := by
  by_cases h6346 : node < 6346
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part00.edge_subblock_6330 node lower h6346
  · by_cases h6362 : node < 6362
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part01.edge_subblock_6346 node (Nat.le_of_not_gt h6346) (h6362)
    · by_cases h6378 : node < 6378
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part02.edge_subblock_6362 node (Nat.le_of_not_gt h6362) (h6378)
      · by_cases h6394 : node < 6394
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part03.edge_subblock_6378 node (Nat.le_of_not_gt h6378) (h6394)
        · by_cases h6410 : node < 6410
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part04.edge_subblock_6394 node (Nat.le_of_not_gt h6394) (h6410)
          · by_cases h6426 : node < 6426
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part05.edge_subblock_6410 node (Nat.le_of_not_gt h6410) (h6426)
            · by_cases h6442 : node < 6442
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part06.edge_subblock_6426 node (Nat.le_of_not_gt h6426) (h6442)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part07.edge_subblock_6442 node (Nat.le_of_not_gt h6442) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330
