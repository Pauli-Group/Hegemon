import SmzaRp05PairedDagHighBlock4282Part00
import SmzaRp05PairedDagHighBlock4282Part01
import SmzaRp05PairedDagHighBlock4282Part02
import SmzaRp05PairedDagHighBlock4282Part03
import SmzaRp05PairedDagHighBlock4282Part04
import SmzaRp05PairedDagHighBlock4282Part05
import SmzaRp05PairedDagHighBlock4282Part06
import SmzaRp05PairedDagHighBlock4282Part07

/-! Bounded dispatcher for the exact directed-edge interval 4282 through 4409. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_4282 (node : Nat) (lower : 4282 ≤ node)
    (upper : node < 4410) : directedEdgeCheck node = true := by
  by_cases h4298 : node < 4298
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part00.edge_subblock_4282 node lower h4298
  · by_cases h4314 : node < 4314
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part01.edge_subblock_4298 node (Nat.le_of_not_gt h4298) (h4314)
    · by_cases h4330 : node < 4330
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part02.edge_subblock_4314 node (Nat.le_of_not_gt h4314) (h4330)
      · by_cases h4346 : node < 4346
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part03.edge_subblock_4330 node (Nat.le_of_not_gt h4330) (h4346)
        · by_cases h4362 : node < 4362
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part04.edge_subblock_4346 node (Nat.le_of_not_gt h4346) (h4362)
          · by_cases h4378 : node < 4378
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part05.edge_subblock_4362 node (Nat.le_of_not_gt h4362) (h4378)
            · by_cases h4394 : node < 4394
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part06.edge_subblock_4378 node (Nat.le_of_not_gt h4378) (h4394)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part07.edge_subblock_4394 node (Nat.le_of_not_gt h4394) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282
