import SmzaRp05PairedDagHighBlock4410Part00
import SmzaRp05PairedDagHighBlock4410Part01
import SmzaRp05PairedDagHighBlock4410Part02
import SmzaRp05PairedDagHighBlock4410Part03
import SmzaRp05PairedDagHighBlock4410Part04
import SmzaRp05PairedDagHighBlock4410Part05
import SmzaRp05PairedDagHighBlock4410Part06
import SmzaRp05PairedDagHighBlock4410Part07

/-! Bounded dispatcher for the exact directed-edge interval 4410 through 4537. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_4410 (node : Nat) (lower : 4410 ≤ node)
    (upper : node < 4538) : directedEdgeCheck node = true := by
  by_cases h4426 : node < 4426
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part00.edge_subblock_4410 node lower h4426
  · by_cases h4442 : node < 4442
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part01.edge_subblock_4426 node (Nat.le_of_not_gt h4426) (h4442)
    · by_cases h4458 : node < 4458
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part02.edge_subblock_4442 node (Nat.le_of_not_gt h4442) (h4458)
      · by_cases h4474 : node < 4474
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part03.edge_subblock_4458 node (Nat.le_of_not_gt h4458) (h4474)
        · by_cases h4490 : node < 4490
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part04.edge_subblock_4474 node (Nat.le_of_not_gt h4474) (h4490)
          · by_cases h4506 : node < 4506
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part05.edge_subblock_4490 node (Nat.le_of_not_gt h4490) (h4506)
            · by_cases h4522 : node < 4522
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part06.edge_subblock_4506 node (Nat.le_of_not_gt h4506) (h4522)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part07.edge_subblock_4522 node (Nat.le_of_not_gt h4522) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410
