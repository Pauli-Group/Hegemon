import SmzaRp05PairedDagHighBlock4026Part00
import SmzaRp05PairedDagHighBlock4026Part01
import SmzaRp05PairedDagHighBlock4026Part02
import SmzaRp05PairedDagHighBlock4026Part03
import SmzaRp05PairedDagHighBlock4026Part04
import SmzaRp05PairedDagHighBlock4026Part05
import SmzaRp05PairedDagHighBlock4026Part06
import SmzaRp05PairedDagHighBlock4026Part07

/-! Bounded dispatcher for the exact directed-edge interval 4026 through 4153. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_4026 (node : Nat) (lower : 4026 ≤ node)
    (upper : node < 4154) : directedEdgeCheck node = true := by
  by_cases h4042 : node < 4042
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part00.edge_subblock_4026 node lower h4042
  · by_cases h4058 : node < 4058
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part01.edge_subblock_4042 node (Nat.le_of_not_gt h4042) (h4058)
    · by_cases h4074 : node < 4074
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part02.edge_subblock_4058 node (Nat.le_of_not_gt h4058) (h4074)
      · by_cases h4090 : node < 4090
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part03.edge_subblock_4074 node (Nat.le_of_not_gt h4074) (h4090)
        · by_cases h4106 : node < 4106
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part04.edge_subblock_4090 node (Nat.le_of_not_gt h4090) (h4106)
          · by_cases h4122 : node < 4122
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part05.edge_subblock_4106 node (Nat.le_of_not_gt h4106) (h4122)
            · by_cases h4138 : node < 4138
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part06.edge_subblock_4122 node (Nat.le_of_not_gt h4122) (h4138)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part07.edge_subblock_4138 node (Nat.le_of_not_gt h4138) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026
