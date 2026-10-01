import SmzaRp05PairedDagHighBlock6202Part00
import SmzaRp05PairedDagHighBlock6202Part01
import SmzaRp05PairedDagHighBlock6202Part02
import SmzaRp05PairedDagHighBlock6202Part03
import SmzaRp05PairedDagHighBlock6202Part04
import SmzaRp05PairedDagHighBlock6202Part05
import SmzaRp05PairedDagHighBlock6202Part06
import SmzaRp05PairedDagHighBlock6202Part07

/-! Bounded dispatcher for the exact directed-edge interval 6202 through 6329. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_6202 (node : Nat) (lower : 6202 ≤ node)
    (upper : node < 6330) : directedEdgeCheck node = true := by
  by_cases h6218 : node < 6218
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part00.edge_subblock_6202 node lower h6218
  · by_cases h6234 : node < 6234
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part01.edge_subblock_6218 node (Nat.le_of_not_gt h6218) (h6234)
    · by_cases h6250 : node < 6250
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part02.edge_subblock_6234 node (Nat.le_of_not_gt h6234) (h6250)
      · by_cases h6266 : node < 6266
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part03.edge_subblock_6250 node (Nat.le_of_not_gt h6250) (h6266)
        · by_cases h6282 : node < 6282
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part04.edge_subblock_6266 node (Nat.le_of_not_gt h6266) (h6282)
          · by_cases h6298 : node < 6298
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part05.edge_subblock_6282 node (Nat.le_of_not_gt h6282) (h6298)
            · by_cases h6314 : node < 6314
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part06.edge_subblock_6298 node (Nat.le_of_not_gt h6298) (h6314)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part07.edge_subblock_6314 node (Nat.le_of_not_gt h6314) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202
