import SmzaRp05PairedDagHighBlock7098Part00
import SmzaRp05PairedDagHighBlock7098Part01
import SmzaRp05PairedDagHighBlock7098Part02
import SmzaRp05PairedDagHighBlock7098Part03
import SmzaRp05PairedDagHighBlock7098Part04
import SmzaRp05PairedDagHighBlock7098Part05
import SmzaRp05PairedDagHighBlock7098Part06
import SmzaRp05PairedDagHighBlock7098Part07

/-! Bounded dispatcher for the exact directed-edge interval 7098 through 7225. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_7098 (node : Nat) (lower : 7098 ≤ node)
    (upper : node < 7226) : directedEdgeCheck node = true := by
  by_cases h7114 : node < 7114
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part00.edge_subblock_7098 node lower h7114
  · by_cases h7130 : node < 7130
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part01.edge_subblock_7114 node (Nat.le_of_not_gt h7114) (h7130)
    · by_cases h7146 : node < 7146
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part02.edge_subblock_7130 node (Nat.le_of_not_gt h7130) (h7146)
      · by_cases h7162 : node < 7162
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part03.edge_subblock_7146 node (Nat.le_of_not_gt h7146) (h7162)
        · by_cases h7178 : node < 7178
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part04.edge_subblock_7162 node (Nat.le_of_not_gt h7162) (h7178)
          · by_cases h7194 : node < 7194
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part05.edge_subblock_7178 node (Nat.le_of_not_gt h7178) (h7194)
            · by_cases h7210 : node < 7210
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part06.edge_subblock_7194 node (Nat.le_of_not_gt h7194) (h7210)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part07.edge_subblock_7210 node (Nat.le_of_not_gt h7210) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098
