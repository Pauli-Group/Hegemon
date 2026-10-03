import SmzaRp05PairedDagHighBlock5434Part00
import SmzaRp05PairedDagHighBlock5434Part01
import SmzaRp05PairedDagHighBlock5434Part02
import SmzaRp05PairedDagHighBlock5434Part03
import SmzaRp05PairedDagHighBlock5434Part04
import SmzaRp05PairedDagHighBlock5434Part05
import SmzaRp05PairedDagHighBlock5434Part06
import SmzaRp05PairedDagHighBlock5434Part07

/-! Bounded dispatcher for the exact directed-edge interval 5434 through 5561. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_5434 (node : Nat) (lower : 5434 ≤ node)
    (upper : node < 5562) : directedEdgeCheck node = true := by
  by_cases h5450 : node < 5450
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part00.edge_subblock_5434 node lower h5450
  · by_cases h5466 : node < 5466
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part01.edge_subblock_5450 node (Nat.le_of_not_gt h5450) (h5466)
    · by_cases h5482 : node < 5482
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part02.edge_subblock_5466 node (Nat.le_of_not_gt h5466) (h5482)
      · by_cases h5498 : node < 5498
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part03.edge_subblock_5482 node (Nat.le_of_not_gt h5482) (h5498)
        · by_cases h5514 : node < 5514
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part04.edge_subblock_5498 node (Nat.le_of_not_gt h5498) (h5514)
          · by_cases h5530 : node < 5530
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part05.edge_subblock_5514 node (Nat.le_of_not_gt h5514) (h5530)
            · by_cases h5546 : node < 5546
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part06.edge_subblock_5530 node (Nat.le_of_not_gt h5530) (h5546)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part07.edge_subblock_5546 node (Nat.le_of_not_gt h5546) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434
