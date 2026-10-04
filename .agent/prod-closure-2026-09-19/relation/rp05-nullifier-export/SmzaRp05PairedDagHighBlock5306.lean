import SmzaRp05PairedDagHighBlock5306Part00
import SmzaRp05PairedDagHighBlock5306Part01
import SmzaRp05PairedDagHighBlock5306Part02
import SmzaRp05PairedDagHighBlock5306Part03
import SmzaRp05PairedDagHighBlock5306Part04
import SmzaRp05PairedDagHighBlock5306Part05
import SmzaRp05PairedDagHighBlock5306Part06
import SmzaRp05PairedDagHighBlock5306Part07

/-! Bounded dispatcher for the exact directed-edge interval 5306 through 5433. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_5306 (node : Nat) (lower : 5306 ≤ node)
    (upper : node < 5434) : directedEdgeCheck node = true := by
  by_cases h5322 : node < 5322
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part00.edge_subblock_5306 node lower h5322
  · by_cases h5338 : node < 5338
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part01.edge_subblock_5322 node (Nat.le_of_not_gt h5322) (h5338)
    · by_cases h5354 : node < 5354
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part02.edge_subblock_5338 node (Nat.le_of_not_gt h5338) (h5354)
      · by_cases h5370 : node < 5370
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part03.edge_subblock_5354 node (Nat.le_of_not_gt h5354) (h5370)
        · by_cases h5386 : node < 5386
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part04.edge_subblock_5370 node (Nat.le_of_not_gt h5370) (h5386)
          · by_cases h5402 : node < 5402
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part05.edge_subblock_5386 node (Nat.le_of_not_gt h5386) (h5402)
            · by_cases h5418 : node < 5418
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part06.edge_subblock_5402 node (Nat.le_of_not_gt h5402) (h5418)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part07.edge_subblock_5418 node (Nat.le_of_not_gt h5418) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306
