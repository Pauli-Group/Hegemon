import SmzaRp05PairedDagHighBlock3386Part00
import SmzaRp05PairedDagHighBlock3386Part01
import SmzaRp05PairedDagHighBlock3386Part02
import SmzaRp05PairedDagHighBlock3386Part03
import SmzaRp05PairedDagHighBlock3386Part04
import SmzaRp05PairedDagHighBlock3386Part05
import SmzaRp05PairedDagHighBlock3386Part06
import SmzaRp05PairedDagHighBlock3386Part07

/-! Bounded dispatcher for the exact directed-edge interval 3386 through 3513. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_3386 (node : Nat) (lower : 3386 ≤ node)
    (upper : node < 3514) : directedEdgeCheck node = true := by
  by_cases h3402 : node < 3402
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part00.edge_subblock_3386 node lower h3402
  · by_cases h3418 : node < 3418
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part01.edge_subblock_3402 node (Nat.le_of_not_gt h3402) (h3418)
    · by_cases h3434 : node < 3434
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part02.edge_subblock_3418 node (Nat.le_of_not_gt h3418) (h3434)
      · by_cases h3450 : node < 3450
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part03.edge_subblock_3434 node (Nat.le_of_not_gt h3434) (h3450)
        · by_cases h3466 : node < 3466
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part04.edge_subblock_3450 node (Nat.le_of_not_gt h3450) (h3466)
          · by_cases h3482 : node < 3482
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part05.edge_subblock_3466 node (Nat.le_of_not_gt h3466) (h3482)
            · by_cases h3498 : node < 3498
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part06.edge_subblock_3482 node (Nat.le_of_not_gt h3482) (h3498)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part07.edge_subblock_3498 node (Nat.le_of_not_gt h3498) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386
