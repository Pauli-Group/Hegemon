import SmzaRp05PairedDagHighBlock6842Part00
import SmzaRp05PairedDagHighBlock6842Part01
import SmzaRp05PairedDagHighBlock6842Part02
import SmzaRp05PairedDagHighBlock6842Part03
import SmzaRp05PairedDagHighBlock6842Part04
import SmzaRp05PairedDagHighBlock6842Part05
import SmzaRp05PairedDagHighBlock6842Part06
import SmzaRp05PairedDagHighBlock6842Part07

/-! Bounded dispatcher for the exact directed-edge interval 6842 through 6969. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_6842 (node : Nat) (lower : 6842 ≤ node)
    (upper : node < 6970) : directedEdgeCheck node = true := by
  by_cases h6858 : node < 6858
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part00.edge_subblock_6842 node lower h6858
  · by_cases h6874 : node < 6874
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part01.edge_subblock_6858 node (Nat.le_of_not_gt h6858) (h6874)
    · by_cases h6890 : node < 6890
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part02.edge_subblock_6874 node (Nat.le_of_not_gt h6874) (h6890)
      · by_cases h6906 : node < 6906
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part03.edge_subblock_6890 node (Nat.le_of_not_gt h6890) (h6906)
        · by_cases h6922 : node < 6922
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part04.edge_subblock_6906 node (Nat.le_of_not_gt h6906) (h6922)
          · by_cases h6938 : node < 6938
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part05.edge_subblock_6922 node (Nat.le_of_not_gt h6922) (h6938)
            · by_cases h6954 : node < 6954
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part06.edge_subblock_6938 node (Nat.le_of_not_gt h6938) (h6954)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part07.edge_subblock_6954 node (Nat.le_of_not_gt h6954) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842
