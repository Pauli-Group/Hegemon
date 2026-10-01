import SmzaRp05PairedDagEdgeChunk00
import SmzaRp05PairedDagEdgeChunk01
import SmzaRp05PairedDagEdgeChunk02
import SmzaRp05PairedDagSpecialEdges
import SmzaRp05PairedDagHighChunk00
import SmzaRp05PairedDagHighChunk01
import SmzaRp05PairedDagHighBlock3002
import SmzaRp05PairedDagHighBlock3130
import SmzaRp05PairedDagHighBlock3258
import SmzaRp05PairedDagHighBlock3386
import SmzaRp05PairedDagHighBlock3514
import SmzaRp05PairedDagHighBlock3642
import SmzaRp05PairedDagHighBlock3770
import SmzaRp05PairedDagHighBlock3898
import SmzaRp05PairedDagHighBlock4026
import SmzaRp05PairedDagHighBlock4154
import SmzaRp05PairedDagHighBlock4282
import SmzaRp05PairedDagHighBlock4410
import SmzaRp05PairedDagHighBlock4538
import SmzaRp05PairedDagHighBlock4666
import SmzaRp05PairedDagHighBlock4794
import SmzaRp05PairedDagHighBlock4922
import SmzaRp05PairedDagHighBlock5050
import SmzaRp05PairedDagHighBlock5178
import SmzaRp05PairedDagHighBlock5306
import SmzaRp05PairedDagHighBlock5434
import SmzaRp05PairedDagHighBlock5562
import SmzaRp05PairedDagHighBlock5690
import SmzaRp05PairedDagHighBlock5818
import SmzaRp05PairedDagHighBlock5946
import SmzaRp05PairedDagHighBlock6074
import SmzaRp05PairedDagHighBlock6202
import SmzaRp05PairedDagHighBlock6330
import SmzaRp05PairedDagHighBlock6458
import SmzaRp05PairedDagHighBlock6586
import SmzaRp05PairedDagHighBlock6714
import SmzaRp05PairedDagHighBlock6842
import SmzaRp05PairedDagHighBlock6970
import SmzaRp05PairedDagHighBlock7098
import SmzaRp05PairedDagHighBlock7226
import SmzaRp05PairedDagHighBlock7354
import SmzaRp05PairedDagHighBlock7482
import SmzaRp05PairedDagHighBlock7610
import SmzaRp05PairedDagHighBlock7738
import SmzaRp05PairedDagHighBlock7866
import SmzaRp05PairedDagRootChunk00
import SmzaRp05PairedDagRootChunk01
import SmzaRp05PairedDagRootChunk02

/-! Public finite checker interfaces assembled from bounded exact chunks. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
set_option autoImplicit false

private theorem interval_offset_bound {node offset count : Nat}
    (lower : offset ≤ node) (upper : node < offset + count) :
    node - offset < count := by
  rw [Nat.sub_lt_iff_lt_add lower]
  simpa [Nat.add_comm] using upper

theorem checked_low (node : Nat) (lower : 0 ≤ node) (upper : node < 1000) :
    directedEdgeCheck node = true := by
  by_cases h128 : node < 128
  · have firstUpper : node < 0 + 128 := by simpa using h128
    have firstOffset := interval_offset_bound lower firstUpper
    simpa using
      HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk00.directed_edge_check
        (node - 0) firstOffset
  · by_cases h256 : node < 256
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk01.edge_block_128 node (Nat.le_of_not_gt h128) h256
    · by_cases h384 : node < 384
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk01.edge_block_256 node (Nat.le_of_not_gt h256) h384
      · by_cases h512 : node < 512
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk01.edge_block_384 node (Nat.le_of_not_gt h384) h512
        · by_cases h640 : node < 640
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk01.edge_block_512 node (Nat.le_of_not_gt h512) h640
          · by_cases h768 : node < 768
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk02.edge_block_640 node (Nat.le_of_not_gt h640) h768
            · by_cases h896 : node < 896
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk02.edge_block_768 node (Nat.le_of_not_gt h768) h896
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk02.edge_block_896 node (Nat.le_of_not_gt h896) upper

theorem checked_special_1387 : directedEdgeCheck 1387 = true :=
  HegemonCrypto.SmallWood.SmzaRp05PairedDagSpecialEdges.checked_special_1387
theorem checked_special_1390 : directedEdgeCheck 1390 = true :=
  HegemonCrypto.SmallWood.SmzaRp05PairedDagSpecialEdges.checked_special_1390
theorem checked_special_1393 : directedEdgeCheck 1393 = true :=
  HegemonCrypto.SmallWood.SmzaRp05PairedDagSpecialEdges.checked_special_1393

theorem checked_high (node : Nat) (lower : 1978 ≤ node) (upper : node < 7951) :
    directedEdgeCheck node = true := by
  by_cases h2106 : node < 2106
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk00.edge_block_1978 node lower h2106
  · by_cases h2234 : node < 2234
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk00.edge_block_2106 node (Nat.le_of_not_gt h2106) (h2234)
    · by_cases h2362 : node < 2362
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk00.edge_block_2234 node (Nat.le_of_not_gt h2234) (h2362)
      · by_cases h2490 : node < 2490
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk00.edge_block_2362 node (Nat.le_of_not_gt h2362) (h2490)
        · by_cases h2618 : node < 2618
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk01.edge_block_2490 node (Nat.le_of_not_gt h2490) (h2618)
          · by_cases h2746 : node < 2746
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk01.edge_block_2618 node (Nat.le_of_not_gt h2618) (h2746)
            · by_cases h2874 : node < 2874
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk01.edge_block_2746 node (Nat.le_of_not_gt h2746) (h2874)
              · by_cases h3002 : node < 3002
                · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk01.edge_block_2874 node (Nat.le_of_not_gt h2874) (h3002)
                · by_cases h3130 : node < 3130
                  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3002.edge_block_3002 node (Nat.le_of_not_gt h3002) (h3130)
                  · by_cases h3258 : node < 3258
                    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130.edge_block_3130 node (Nat.le_of_not_gt h3130) (h3258)
                    · by_cases h3386 : node < 3386
                      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258.edge_block_3258 node (Nat.le_of_not_gt h3258) (h3386)
                      · by_cases h3514 : node < 3514
                        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386.edge_block_3386 node (Nat.le_of_not_gt h3386) (h3514)
                        · by_cases h3642 : node < 3642
                          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514.edge_block_3514 node (Nat.le_of_not_gt h3514) (h3642)
                          · by_cases h3770 : node < 3770
                            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642.edge_block_3642 node (Nat.le_of_not_gt h3642) (h3770)
                            · by_cases h3898 : node < 3898
                              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770.edge_block_3770 node (Nat.le_of_not_gt h3770) (h3898)
                              · by_cases h4026 : node < 4026
                                · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898.edge_block_3898 node (Nat.le_of_not_gt h3898) (h4026)
                                · by_cases h4154 : node < 4154
                                  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026.edge_block_4026 node (Nat.le_of_not_gt h4026) (h4154)
                                  · by_cases h4282 : node < 4282
                                    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154.edge_block_4154 node (Nat.le_of_not_gt h4154) (h4282)
                                    · by_cases h4410 : node < 4410
                                      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282.edge_block_4282 node (Nat.le_of_not_gt h4282) (h4410)
                                      · by_cases h4538 : node < 4538
                                        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410.edge_block_4410 node (Nat.le_of_not_gt h4410) (h4538)
                                        · by_cases h4666 : node < 4666
                                          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538.edge_block_4538 node (Nat.le_of_not_gt h4538) (h4666)
                                          · by_cases h4794 : node < 4794
                                            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666.edge_block_4666 node (Nat.le_of_not_gt h4666) (h4794)
                                            · by_cases h4922 : node < 4922
                                              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794.edge_block_4794 node (Nat.le_of_not_gt h4794) (h4922)
                                              · by_cases h5050 : node < 5050
                                                · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922.edge_block_4922 node (Nat.le_of_not_gt h4922) (h5050)
                                                · by_cases h5178 : node < 5178
                                                  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050.edge_block_5050 node (Nat.le_of_not_gt h5050) (h5178)
                                                  · by_cases h5306 : node < 5306
                                                    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178.edge_block_5178 node (Nat.le_of_not_gt h5178) (h5306)
                                                    · by_cases h5434 : node < 5434
                                                      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306.edge_block_5306 node (Nat.le_of_not_gt h5306) (h5434)
                                                      · by_cases h5562 : node < 5562
                                                        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434.edge_block_5434 node (Nat.le_of_not_gt h5434) (h5562)
                                                        · by_cases h5690 : node < 5690
                                                          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562.edge_block_5562 node (Nat.le_of_not_gt h5562) (h5690)
                                                          · by_cases h5818 : node < 5818
                                                            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690.edge_block_5690 node (Nat.le_of_not_gt h5690) (h5818)
                                                            · by_cases h5946 : node < 5946
                                                              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818.edge_block_5818 node (Nat.le_of_not_gt h5818) (h5946)
                                                              · by_cases h6074 : node < 6074
                                                                · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946.edge_block_5946 node (Nat.le_of_not_gt h5946) (h6074)
                                                                · by_cases h6202 : node < 6202
                                                                  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074.edge_block_6074 node (Nat.le_of_not_gt h6074) (h6202)
                                                                  · by_cases h6330 : node < 6330
                                                                    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202.edge_block_6202 node (Nat.le_of_not_gt h6202) (h6330)
                                                                    · by_cases h6458 : node < 6458
                                                                      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330.edge_block_6330 node (Nat.le_of_not_gt h6330) (h6458)
                                                                      · by_cases h6586 : node < 6586
                                                                        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458.edge_block_6458 node (Nat.le_of_not_gt h6458) (h6586)
                                                                        · by_cases h6714 : node < 6714
                                                                          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586.edge_block_6586 node (Nat.le_of_not_gt h6586) (h6714)
                                                                          · by_cases h6842 : node < 6842
                                                                            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714.edge_block_6714 node (Nat.le_of_not_gt h6714) (h6842)
                                                                            · by_cases h6970 : node < 6970
                                                                              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842.edge_block_6842 node (Nat.le_of_not_gt h6842) (h6970)
                                                                              · by_cases h7098 : node < 7098
                                                                                · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970.edge_block_6970 node (Nat.le_of_not_gt h6970) (h7098)
                                                                                · by_cases h7226 : node < 7226
                                                                                  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098.edge_block_7098 node (Nat.le_of_not_gt h7098) (h7226)
                                                                                  · by_cases h7354 : node < 7354
                                                                                    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226.edge_block_7226 node (Nat.le_of_not_gt h7226) (h7354)
                                                                                    · by_cases h7482 : node < 7482
                                                                                      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354.edge_block_7354 node (Nat.le_of_not_gt h7354) (h7482)
                                                                                      · by_cases h7610 : node < 7610
                                                                                        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482.edge_block_7482 node (Nat.le_of_not_gt h7482) (h7610)
                                                                                        · by_cases h7738 : node < 7738
                                                                                          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610.edge_block_7610 node (Nat.le_of_not_gt h7610) (h7738)
                                                                                          · by_cases h7866 : node < 7866
                                                                                            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738.edge_block_7738 node (Nat.le_of_not_gt h7738) (h7866)
                                                                                            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866.edge_block_7866 node (Nat.le_of_not_gt h7866) (upper)

theorem checked_root (wire : Nat) (bound : wire < 332) :
    pairedRootCheck wire = true := by
  by_cases h128 : wire < 128
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk00.paired_root_check_00
      wire (Nat.zero_le _) h128
  · by_cases h256 : wire < 256
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk01.paired_root_check_01
        wire (Nat.le_of_not_gt h128) h256
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk02.paired_root_check_02
        wire (Nat.le_of_not_gt h256) bound

end HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
