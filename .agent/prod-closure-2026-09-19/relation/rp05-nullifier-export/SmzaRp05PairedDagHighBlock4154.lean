import SmzaRp05PairedDagHighBlock4154Part00
import SmzaRp05PairedDagHighBlock4154Part01
import SmzaRp05PairedDagHighBlock4154Part02
import SmzaRp05PairedDagHighBlock4154Part03
import SmzaRp05PairedDagHighBlock4154Part04
import SmzaRp05PairedDagHighBlock4154Part05
import SmzaRp05PairedDagHighBlock4154Part06
import SmzaRp05PairedDagHighBlock4154Part07

/-! Bounded dispatcher for the exact directed-edge interval 4154 through 4281. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_4154 (node : Nat) (lower : 4154 ≤ node)
    (upper : node < 4282) : directedEdgeCheck node = true := by
  by_cases h4170 : node < 4170
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part00.edge_subblock_4154 node lower h4170
  · by_cases h4186 : node < 4186
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part01.edge_subblock_4170 node (Nat.le_of_not_gt h4170) (h4186)
    · by_cases h4202 : node < 4202
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part02.edge_subblock_4186 node (Nat.le_of_not_gt h4186) (h4202)
      · by_cases h4218 : node < 4218
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part03.edge_subblock_4202 node (Nat.le_of_not_gt h4202) (h4218)
        · by_cases h4234 : node < 4234
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part04.edge_subblock_4218 node (Nat.le_of_not_gt h4218) (h4234)
          · by_cases h4250 : node < 4250
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part05.edge_subblock_4234 node (Nat.le_of_not_gt h4234) (h4250)
            · by_cases h4266 : node < 4266
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part06.edge_subblock_4250 node (Nat.le_of_not_gt h4250) (h4266)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part07.edge_subblock_4266 node (Nat.le_of_not_gt h4266) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154
