import SmzaRp05PairedDagHighBlock7354Part00
import SmzaRp05PairedDagHighBlock7354Part01
import SmzaRp05PairedDagHighBlock7354Part02
import SmzaRp05PairedDagHighBlock7354Part03
import SmzaRp05PairedDagHighBlock7354Part04
import SmzaRp05PairedDagHighBlock7354Part05
import SmzaRp05PairedDagHighBlock7354Part06
import SmzaRp05PairedDagHighBlock7354Part07

/-! Bounded dispatcher for the exact directed-edge interval 7354 through 7481. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_7354 (node : Nat) (lower : 7354 ≤ node)
    (upper : node < 7482) : directedEdgeCheck node = true := by
  by_cases h7370 : node < 7370
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part00.edge_subblock_7354 node lower h7370
  · by_cases h7386 : node < 7386
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part01.edge_subblock_7370 node (Nat.le_of_not_gt h7370) (h7386)
    · by_cases h7402 : node < 7402
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part02.edge_subblock_7386 node (Nat.le_of_not_gt h7386) (h7402)
      · by_cases h7418 : node < 7418
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part03.edge_subblock_7402 node (Nat.le_of_not_gt h7402) (h7418)
        · by_cases h7434 : node < 7434
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part04.edge_subblock_7418 node (Nat.le_of_not_gt h7418) (h7434)
          · by_cases h7450 : node < 7450
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part05.edge_subblock_7434 node (Nat.le_of_not_gt h7434) (h7450)
            · by_cases h7466 : node < 7466
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part06.edge_subblock_7450 node (Nat.le_of_not_gt h7450) (h7466)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part07.edge_subblock_7466 node (Nat.le_of_not_gt h7466) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354
