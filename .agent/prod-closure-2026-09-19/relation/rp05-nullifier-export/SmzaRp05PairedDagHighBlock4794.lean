import SmzaRp05PairedDagHighBlock4794Part00
import SmzaRp05PairedDagHighBlock4794Part01
import SmzaRp05PairedDagHighBlock4794Part02
import SmzaRp05PairedDagHighBlock4794Part03
import SmzaRp05PairedDagHighBlock4794Part04
import SmzaRp05PairedDagHighBlock4794Part05
import SmzaRp05PairedDagHighBlock4794Part06
import SmzaRp05PairedDagHighBlock4794Part07

/-! Bounded dispatcher for the exact directed-edge interval 4794 through 4921. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_4794 (node : Nat) (lower : 4794 ≤ node)
    (upper : node < 4922) : directedEdgeCheck node = true := by
  by_cases h4810 : node < 4810
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part00.edge_subblock_4794 node lower h4810
  · by_cases h4826 : node < 4826
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part01.edge_subblock_4810 node (Nat.le_of_not_gt h4810) (h4826)
    · by_cases h4842 : node < 4842
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part02.edge_subblock_4826 node (Nat.le_of_not_gt h4826) (h4842)
      · by_cases h4858 : node < 4858
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part03.edge_subblock_4842 node (Nat.le_of_not_gt h4842) (h4858)
        · by_cases h4874 : node < 4874
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part04.edge_subblock_4858 node (Nat.le_of_not_gt h4858) (h4874)
          · by_cases h4890 : node < 4890
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part05.edge_subblock_4874 node (Nat.le_of_not_gt h4874) (h4890)
            · by_cases h4906 : node < 4906
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part06.edge_subblock_4890 node (Nat.le_of_not_gt h4890) (h4906)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part07.edge_subblock_4906 node (Nat.le_of_not_gt h4906) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794
