import HegemonCrypto.SmallWoodV8Smz9SourceCsrCompositionBase
namespace HegemonCrypto.SmallWood.V8Smz9SourceCsrEarlyComposition
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood
open V8Smz9SourceCsrCompositionBase
open V8Smz9SourceFullTypedCandidate
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem full_candidate_all_19168_early_csr_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 19168) :
    sourceCsrZero statement witness index.val := by
  by_cases part0 : index.val < 15561
  · exact source_csr_replicate statement witness ⟨index.val,by omega⟩
  by_cases part1 : index.val < 15653
  · have zero : sourceCsrZero statement witness (15561+(index.val-15561)) :=
      V8Smz9SourceInactiveRaw92.full_candidate_actual_inactive_raw92_zero statement witness valid ⟨index.val-15561,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part2 : index.val < 15665
  · have zero : sourceCsrZero statement witness (15653+(index.val-15653)) :=
      V8Smz9SourceCipher12.ciphertext_bridge_indexed_zero statement witness ⟨index.val-15653,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part3 : index.val < 15672
  · have zero : sourceCsrZero statement witness (15665+(index.val-15665)) :=
      source_csr_dense7 statement witness ⟨index.val-15665,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part4 : index.val < 15674
  · have zero : sourceCsrZero statement witness (V8Smz9SourceBase7.base7Index (index.val-15672)) :=
      V8Smz9SourceBase7.full_candidate_actual_base7_zero statement witness valid ⟨index.val-15672,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceBase7.base7Index]; split_ifs <;> omega) zero
  by_cases part5 : index.val < 15777
  · have zero : sourceCsrZero statement witness (15674+(index.val-15674)) :=
      V8Smz9SourceDense103.full_candidate_dense_padding103_indexed statement witness ⟨index.val-15674,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part6 : index.val < 15789
  · have zero : sourceCsrZero statement witness (15777+(index.val-15777)) :=
      V8Smz9SourceInputKeyCsr12.full_candidate_actual_all12_input_key_csr_zero statement witness valid ⟨index.val-15777,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part7 : index.val < 15805
  · have zero : sourceCsrZero statement witness (15789+(index.val-15789)) :=
      source_csr_prf16 statement witness valid ⟨index.val-15789,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part8 : index.val < 15810
  · have zero : sourceCsrZero statement witness (V8Smz9SourceBase7.base7Index (index.val-15803)) :=
      V8Smz9SourceBase7.full_candidate_actual_base7_zero statement witness valid ⟨index.val-15803,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceBase7.base7Index]; split_ifs <;> omega) zero
  by_cases part9 : index.val < 15918
  · have zero : sourceCsrZero statement witness (if index.val-15810<108 then 15810+(index.val-15810) else 18346+((index.val-15810)-108)) :=
      source_csr_note216 statement witness valid ⟨index.val-15810,by omega⟩
    exact source_csr_reindex statement witness (by split_ifs <;> omega) zero
  by_cases part10 : index.val < 16942
  · have zero : sourceCsrZero statement witness (15918+(index.val-15918)) :=
      V8Smz9SourceMerkleInitial.typed_all_1024_actual_merkle_initial_csr_zero statement witness valid (typedSourceTail statement witness) (sourceCsrPub statement) ⟨index.val-15918,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part11 : index.val < 17838
  · have zero : sourceCsrZero statement witness (16942+(index.val-16942)) :=
      V8Smz9SourceMerkleCopies.typed_all_896_actual_csr_zero statement witness (typedSourceTail statement witness) (sourceCsrPub statement) ⟨index.val-16942,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part12 : index.val < 18286
  · have zero : sourceCsrZero statement witness (17838+(index.val-17838)) := by
      obtain ⟨entry,found,_,_,zero⟩ :=
        V8Smz9SourceInactiveMerkleRight.full_candidate_actual_inactive_right_all_448_zero
          statement witness valid ⟨index.val-17838,by omega⟩
      unfold sourceCsrZero
      rw [found,Option.map_some,zero]
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part13 : index.val < 18300
  · have zero : sourceCsrZero statement witness (V8Smz9SourcePublicDigest42.publicDigest42Index (index.val-18286)) :=
      V8Smz9SourcePublicDigest42.full_candidate_actual_public_digest42_zero statement witness valid ⟨index.val-18286,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourcePublicDigest42.publicDigest42Index]; split_ifs <;> omega) zero
  by_cases part14 : index.val < 18332
  · have zero : sourceCsrZero statement witness (18300+(index.val-18300)) :=
      V8Smz9SourceNullifier32.full_candidate_actual_nullifier_initial32_zero statement witness valid (sourceCsrPub statement) ⟨index.val-18300,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part15 : index.val < 18346
  · have zero : sourceCsrZero statement witness (V8Smz9SourcePublicDigest42.publicDigest42Index (index.val-18318)) :=
      V8Smz9SourcePublicDigest42.full_candidate_actual_public_digest42_zero statement witness valid ⟨index.val-18318,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourcePublicDigest42.publicDigest42Index]; split_ifs <;> omega) zero
  by_cases part16 : index.val < 18454
  · have zero : sourceCsrZero statement witness (if index.val-18238<108 then 15810+(index.val-18238) else 18346+((index.val-18238)-108)) :=
      source_csr_note216 statement witness valid ⟨index.val-18238,by omega⟩
    exact source_csr_reindex statement witness (by split_ifs <;> omega) zero
  by_cases part17 : index.val < 18468
  · have zero : sourceCsrZero statement witness (V8Smz9SourcePublicDigest42.publicDigest42Index (index.val-18426)) :=
      V8Smz9SourcePublicDigest42.full_candidate_actual_public_digest42_zero statement witness valid ⟨index.val-18426,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourcePublicDigest42.publicDigest42Index]; split_ifs <;> omega) zero
  by_cases part18 : index.val < 18708
  · have zero : sourceCsrZero statement witness (V8Smz9SourceInitial288.initial288GlobalIndex ⟨index.val-18468,by omega⟩) :=
      source_csr_initial288 statement witness valid ⟨index.val-18468,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceInitial288.initial288GlobalIndex]; split_ifs <;> omega) zero
  by_cases part19 : index.val < 18715
  · have zero : sourceCsrZero statement witness (18708+(index.val-18708)) :=
      V8Smz9SourceAuthDigestCsr.full_candidate_actual_digest_csr_zero statement witness .statement ⟨index.val-18708,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part20 : index.val < 18779
  · have zero : sourceCsrZero statement witness (18715+(index.val-18715)) :=
      V8Smz9SourcePolicyInitial.typed_all_64_actual_policy_initial_csr_zero statement witness valid (typedSourceTail statement witness) (sourceCsrPub statement) ⟨index.val-18715,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part21 : index.val < 18971
  · have zero : sourceCsrZero statement witness (18779+(index.val-18779)) :=
      V8Smz9SourceInlinePolicy192.full_candidate_inline_policy192_indexed statement witness (sourceCsrPub statement) ⟨index.val-18779,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part22 : index.val < 19019
  · have zero : sourceCsrZero statement witness (V8Smz9SourceAuthInitial128.authInitial128Index (index.val-18971)) :=
      V8Smz9SourceAuthInitial128.full_candidate_actual_all128_auth_initial_zero statement witness valid (sourceCsrPub statement) ⟨index.val-18971,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceAuthInitial128.authInitial128Index]; split_ifs <;> omega) zero
  by_cases part23 : index.val < 19026
  · have zero : sourceCsrZero statement witness (19019+(index.val-19019)) :=
      V8Smz9SourceAuthDigestCsr.full_candidate_actual_digest_csr_zero statement witness .current ⟨index.val-19019,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part24 : index.val < 19074
  · have zero : sourceCsrZero statement witness (V8Smz9SourceAuthInitial128.authInitial128Index (index.val-18978)) :=
      V8Smz9SourceAuthInitial128.full_candidate_actual_all128_auth_initial_zero statement witness valid (sourceCsrPub statement) ⟨index.val-18978,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceAuthInitial128.authInitial128Index]; split_ifs <;> omega) zero
  by_cases part25 : index.val < 19081
  · have zero : sourceCsrZero statement witness (19074+(index.val-19074)) :=
      V8Smz9SourceAuthDigestCsr.full_candidate_actual_digest_csr_zero statement witness .next ⟨index.val-19074,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part26 : index.val < 19113
  · have zero : sourceCsrZero statement witness (V8Smz9SourceAuthInitial128.authInitial128Index (index.val-18985)) :=
      V8Smz9SourceAuthInitial128.full_candidate_actual_all128_auth_initial_zero statement witness valid (sourceCsrPub statement) ⟨index.val-18985,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceAuthInitial128.authInitial128Index]; split_ifs <;> omega) zero
  by_cases part27 : index.val < 19120
  · have zero : sourceCsrZero statement witness (19113+(index.val-19113)) :=
      V8Smz9SourceAuthDigestCsr.full_candidate_actual_digest_csr_zero statement witness .valueLock ⟨index.val-19113,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part28 : index.val < 19168
  · have zero : sourceCsrZero statement witness (V8Smz9SourceInitial288.initial288GlobalIndex ⟨index.val-18880,by omega⟩) :=
      source_csr_initial288 statement witness valid ⟨index.val-18880,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceInitial288.initial288GlobalIndex]; split_ifs <;> omega) zero
  omega

end
end HegemonCrypto.SmallWood.V8Smz9SourceCsrEarlyComposition
