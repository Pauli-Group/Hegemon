import HegemonCrypto.SmallWoodV8Smz9SourceCsrCompositionBase
namespace HegemonCrypto.SmallWood.V8Smz9SourceCsrMiddleComposition
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood
open V8Smz9SourceCsrCompositionBase
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem full_candidate_middle1152_csr_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (global : Nat)
    (lower : 19168 ≤ global) (upper : global < 20320) :
    sourceCsrZero statement witness global := by
  by_cases part0 : global < 19262
  · have zero : sourceCsrZero statement witness (19168+(global-19168)) :=
      V8Smz9SourceLiveCsrRoots.full_candidate_actual_simple_live_csr_zero statement witness valid .disabled (by decide) ⟨global-19168,by change global-19168<94; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part1 : global < 19280
  · have zero : sourceCsrZero statement witness (19262+(global-19262)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .compatibilityCopy ⟨global-19262,by change global-19262<18; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part2 : global < 19298
  · have zero : sourceCsrZero statement witness (19280+(global-19280)) :=
      V8Smz9SourceLiveCsrRoots.full_candidate_actual_simple_live_csr_zero statement witness valid .compatibility (by decide) ⟨global-19280,by change global-19280<18; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part3 : global < 19306
  · have zero : sourceCsrZero statement witness (19298+(global-19298)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .sourcePadding ⟨global-19298,by change global-19298<8; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part4 : global < 19313
  · have zero : sourceCsrZero statement witness (19306+(global-19306)) :=
      V8Smz9SourceLiveCsrRoots.full_candidate_actual_simple_live_csr_zero statement witness valid .issuer (by decide) ⟨global-19306,by change global-19306<7; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part5 : global < 19320
  · have zero : sourceCsrZero statement witness (19313+(global-19313)) :=
      V8Smz9SourceLiveCsrRoots.full_candidate_actual_simple_live_csr_zero statement witness valid .burn (by decide) ⟨global-19313,by change global-19313<7; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part6 : global < 19322
  · have zero : sourceCsrZero statement witness (19320+(global-19320)) :=
      V8Smz9SourceLiveCsrRoots.full_candidate_actual_simple_live_csr_zero statement witness valid .scalar (by decide) ⟨global-19320,by change global-19320<2; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part7 : global < 19325
  · have zero : sourceCsrZero statement witness (19322+(global-19322)) :=
      V8Smz9SourceLiveCsrRoots.full_candidate_actual_simple_live_csr_zero statement witness valid .direction (by decide) ⟨global-19322,by change global-19322<3; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part8 : global < 19329
  · have zero : sourceCsrZero statement witness (19325+(global-19325)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .booleanCopy ⟨global-19325,by change global-19325<4; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part9 : global < 19333
  · have zero : sourceCsrZero statement witness (19329+(global-19329)) :=
      V8Smz9SourceLiveCsrRoots.full_candidate_actual_simple_live_csr_zero statement witness valid .assetBits (by decide) ⟨global-19329,by change global-19329<4; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part10 : global < 19344
  · have zero : sourceCsrZero statement witness (19333+(global-19333)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .booleanPadding ⟨global-19333,by change global-19333<11; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part11 : global < 19554
  · have zero : sourceCsrZero statement witness (19344+(global-19344)) :=
      V8Smz9SourceLiveRoleCsrRoots.full_actual_live_role_csr_zero statement witness valid ⟨global-19344,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part12 : global < 19588
  · have zero : sourceCsrZero statement witness (19554+(global-19554)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .roleUnit ⟨global-19554,by change global-19554<34; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part13 : global < 19792
  · have zero : sourceCsrZero statement witness (19588+(global-19588)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .roleLimbs ⟨global-19588,by change global-19588<204; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part14 : global < 19826
  · have zero : sourceCsrZero statement witness (19792+(global-19792)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .roleSelector ⟨global-19792,by change global-19792<34; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part15 : global < 19860
  · have zero : sourceCsrZero statement witness (19826+(global-19826)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .roleInverse ⟨global-19826,by change global-19826<34; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part16 : global < 19972
  · have zero : sourceCsrZero statement witness (19860+(global-19860)) :=
      V8Smz9SourceStableConfig112.full_candidate_actual_config112_zero statement witness valid (sourceCsrPub statement) ⟨global-19860,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part17 : global < 20004
  · have zero : sourceCsrZero statement witness (19972+(global-19972)) :=
      V8Smz9SourceStableLeaf32.full_candidate_actual_leaf32_zero statement witness valid ⟨global-19972,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part18 : global < 20132
  · have zero : sourceCsrZero statement witness (20004+(global-20004)) :=
      V8Smz9SourceStablePath128.full_candidate_actual_path128_zero statement witness valid ⟨global-20004,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part19 : global < 20146
  · have zero : sourceCsrZero statement witness (V8Smz9SourceStableOutput28.stableOutputGlobal (global-20132)) :=
      V8Smz9SourceStableOutput28.full_candidate_actual_output28_zero statement witness valid ⟨global-20132,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceStableOutput28.stableOutputGlobal]; split_ifs <;> omega) zero
  by_cases part20 : global < 20178
  · have zero : sourceCsrZero statement witness (20146+(global-20146)) :=
      V8Smz9SourceStableIssuer32.full_candidate_actual_issuer32_zero statement witness valid ⟨global-20146,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part21 : global < 20192
  · have zero : sourceCsrZero statement witness (V8Smz9SourceStableOutput28.stableOutputGlobal (global-20164)) :=
      V8Smz9SourceStableOutput28.full_candidate_actual_output28_zero statement witness valid ⟨global-20164,by omega⟩
    exact source_csr_reindex statement witness (by dsimp only [V8Smz9SourceStableOutput28.stableOutputGlobal]; split_ifs <;> omega) zero
  by_cases part22 : global < 20258
  · have zero : sourceCsrZero statement witness (20192+(global-20192)) :=
      V8Smz9SourceStableRange66.full_candidate_actual_range66_zero statement witness valid ⟨global-20192,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part23 : global < 20296
  · have zero : sourceCsrZero statement witness (20258+(global-20258)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness .rangePadding ⟨global-20258,by change global-20258<38; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  by_cases part24 : global < 20320
  · have zero : sourceCsrZero statement witness (20296+(global-20296)) :=
      V8Smz9SourceStablePadding24.full_candidate_actual_padding24_zero statement witness valid ⟨global-20296,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  omega

theorem full_candidate_last111_csr_zero
    (statement : V8PublicStatement) (witness : V8Witness) (global : Nat)
    (lower : 20494 ≤ global) (upper : global < 20605) :
    sourceCsrZero statement witness global := by
  by_cases multiplication : global < 20587
  · have zero : sourceCsrZero statement witness (20494+(global-20494)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness
        .multiplicationPadding ⟨global-20494,by change global-20494<93; omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  · have zero : sourceCsrZero statement witness (20587+(global-20587)) :=
      V8Smz9SourceTailCsrRoots.full_candidate_actual_tail_csr_zero statement witness
        .numericPadding ⟨global-20587,by change global-20587<18; omega⟩
    exact source_csr_reindex statement witness (by omega) zero

end
end HegemonCrypto.SmallWood.V8Smz9SourceCsrMiddleComposition

