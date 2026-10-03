import SmzaRp05PairedDagHighBlock7226Part00
import SmzaRp05PairedDagHighBlock7226Part01
import SmzaRp05PairedDagHighBlock7226Part02
import SmzaRp05PairedDagHighBlock7226Part03
import SmzaRp05PairedDagHighBlock7226Part04
import SmzaRp05PairedDagHighBlock7226Part05
import SmzaRp05PairedDagHighBlock7226Part06
import SmzaRp05PairedDagHighBlock7226Part07

/-! Bounded dispatcher for the exact directed-edge interval 7226 through 7353. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_7226 (node : Nat) (lower : 7226 ≤ node)
    (upper : node < 7354) : directedEdgeCheck node = true := by
  by_cases h7242 : node < 7242
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part00.edge_subblock_7226 node lower h7242
  · by_cases h7258 : node < 7258
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part01.edge_subblock_7242 node (Nat.le_of_not_gt h7242) (h7258)
    · by_cases h7274 : node < 7274
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part02.edge_subblock_7258 node (Nat.le_of_not_gt h7258) (h7274)
      · by_cases h7290 : node < 7290
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part03.edge_subblock_7274 node (Nat.le_of_not_gt h7274) (h7290)
        · by_cases h7306 : node < 7306
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part04.edge_subblock_7290 node (Nat.le_of_not_gt h7290) (h7306)
          · by_cases h7322 : node < 7322
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part05.edge_subblock_7306 node (Nat.le_of_not_gt h7306) (h7322)
            · by_cases h7338 : node < 7338
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part06.edge_subblock_7322 node (Nat.le_of_not_gt h7322) (h7338)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part07.edge_subblock_7338 node (Nat.le_of_not_gt h7338) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226
