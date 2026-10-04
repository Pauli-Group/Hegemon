import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityGenerated
import Mathlib.Data.List.GetD

namespace HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable

open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

inductive LiveCsrFamily where
  | disabled | compatibility | issuer | burn | scalar | direction | assetBits | roles
deriving DecidableEq, Repr

def liveCsrFamilies : List LiveCsrFamily :=
  [.disabled,.compatibility,.issuer,.burn,.scalar,.direction,.assetBits,.roles]

def LiveCsrFamily.number : LiveCsrFamily → Nat
  | .disabled => 36
  | .compatibility => 38
  | .issuer => 40
  | .burn => 41
  | .scalar => 42
  | .direction => 43
  | .assetBits => 45
  | .roles => 47

def LiveCsrFamily.start : LiveCsrFamily → Nat
  | .disabled => 19168
  | .compatibility => 19280
  | .issuer => 19306
  | .burn => 19313
  | .scalar => 19320
  | .direction => 19322
  | .assetBits => 19329
  | .roles => 19344

def LiveCsrFamily.count : LiveCsrFamily → Nat
  | .disabled => 94
  | .compatibility => 18
  | .issuer => 7
  | .burn => 7
  | .scalar => 2
  | .direction => 3
  | .assetBits => 4
  | .roles => 210

def roleCommitmentStart (role : Nat) : Nat := [6,24,31,38,48].getD role 0
def rolePair (role : Nat) : Nat × Nat :=
  [(0,1),(0,2),(0,3),(0,4),(1,2),(1,3),(1,4),(2,3),(2,4),(3,4)].getD (role - 5) (0,0)

def liveRoleExtraTerms (role limb : Nat) : List (Nat × Nat) :=
  if role < 5 then [(41408 + roleCommitmentStart role + limb,320)]
  else if role < 15 then
    [(41408 + roleCommitmentStart (rolePair role).1 + limb,320),
     (41408 + roleCommitmentStart (rolePair role).2 + limb,322)]
  else if role = 15 then [(41491 + limb,323)]
  else if role = 16 then []
  else if role = 17 ∨ role = 18 then [(41425 + (role - 17),if limb = 0 then 323 else 0)]
  else if role = 19 then [(41408,if limb = 0 then 320 else 0)]
  else if role = 20 then []
  else if role = 21 then
    if limb < 4 then [(41520 + limb,339),(41524 + limb,340)] else []
  else if role = 22 ∨ role = 23 then
    [((138 + 7 * (role - 22) + limb) * 64,158),
     (5952,if limb = 0 then 265 else 0),(6016,if limb = 0 then 265 else 0)]
  else
    (if limb < 5 then [((196 + 5 * (role - 24) + limb) * 64,158)] else []) ++
    ((List.range (6 - (role - 24))).map fun offset =>
      ((176 + (role - 24) + offset) * 64,if limb = 0 then 265 else 0))

def liveRoleTarget (role limb : Nat) : Nat :=
  if role < 15 then if limb = 0 then 307 else 0
  else if role = 15 then if limb = 0 then 308 else 0
  else if role = 16 then if limb = 0 then 325 else 0
  else if role = 17 ∨ role = 18 then if limb = 0 then 308 else 0
  else if role = 19 then if limb = 0 then 307 else 0
  else if role = 20 then 327 + limb
  else if role = 21 then if limb = 0 then 338 else 0
  else if limb = 0 then 1 else 0

def expectedLiveCsrAttempt (family : LiveCsrFamily) (index : Nat) : CsrExecutableAttempt :=
  let terms := match family with
    | .disabled => [(41408 + index,307)]
    | .compatibility => [(41502 + index,1)]
    | .issuer => [(41491 + index,308)]
    | .burn => [(41528,1)]
    | .scalar => [(41408 + index,1)]
    | .direction => [(42112 + index,1)]
    | .assetBits => [(42119 + index,1)]
    | .roles => (41536 + index / 7 + 64 * (index % 7),1) ::
        liveRoleExtraTerms (index / 7) (index % 7)
  let target := match family with
    | .burn => 309 + index
    | .scalar => 88 + index
    | .direction => [306,304,305].getD index 0
    | .assetBits => 316 + index
    | .roles => liveRoleTarget (index / 7) (index % 7)
    | _ => 0
  let emission := if family = .disabled ∨ family = .issuer then 1 else 0
  attempt (family.start + index) family.number index emission terms target

def expectedLiveCsrChunk (family : LiveCsrFamily) (index : Nat) : List CsrExecutableAttempt :=
  csrChunks037.getD ((family.start + index) / 32 - 592) []

private theorem member_disabled_0 (index : Fin 14) :
    expectedLiveCsrAttempt .disabled (0 + index.val) ∈ expectedLiveCsrChunk .disabled (0 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .disabled (0 + i.val) ∈ expectedLiveCsrChunk .disabled (0 + i.val) := by decide
  exact checked index

private theorem member_disabled_14 (index : Fin 14) :
    expectedLiveCsrAttempt .disabled (14 + index.val) ∈ expectedLiveCsrChunk .disabled (14 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .disabled (14 + i.val) ∈ expectedLiveCsrChunk .disabled (14 + i.val) := by decide
  exact checked index

private theorem member_disabled_28 (index : Fin 14) :
    expectedLiveCsrAttempt .disabled (28 + index.val) ∈ expectedLiveCsrChunk .disabled (28 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .disabled (28 + i.val) ∈ expectedLiveCsrChunk .disabled (28 + i.val) := by decide
  exact checked index

private theorem member_disabled_42 (index : Fin 14) :
    expectedLiveCsrAttempt .disabled (42 + index.val) ∈ expectedLiveCsrChunk .disabled (42 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .disabled (42 + i.val) ∈ expectedLiveCsrChunk .disabled (42 + i.val) := by decide
  exact checked index

private theorem member_disabled_56 (index : Fin 14) :
    expectedLiveCsrAttempt .disabled (56 + index.val) ∈ expectedLiveCsrChunk .disabled (56 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .disabled (56 + i.val) ∈ expectedLiveCsrChunk .disabled (56 + i.val) := by decide
  exact checked index

private theorem member_disabled_70 (index : Fin 14) :
    expectedLiveCsrAttempt .disabled (70 + index.val) ∈ expectedLiveCsrChunk .disabled (70 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .disabled (70 + i.val) ∈ expectedLiveCsrChunk .disabled (70 + i.val) := by decide
  exact checked index

private theorem member_disabled_84 (index : Fin 10) :
    expectedLiveCsrAttempt .disabled (84 + index.val) ∈ expectedLiveCsrChunk .disabled (84 + index.val) := by
  have checked : ∀ i : Fin 10,
      expectedLiveCsrAttempt .disabled (84 + i.val) ∈ expectedLiveCsrChunk .disabled (84 + i.val) := by decide
  exact checked index

private theorem member_compatibility_0 (index : Fin 14) :
    expectedLiveCsrAttempt .compatibility (0 + index.val) ∈ expectedLiveCsrChunk .compatibility (0 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .compatibility (0 + i.val) ∈ expectedLiveCsrChunk .compatibility (0 + i.val) := by decide
  exact checked index

private theorem member_compatibility_14 (index : Fin 4) :
    expectedLiveCsrAttempt .compatibility (14 + index.val) ∈ expectedLiveCsrChunk .compatibility (14 + index.val) := by
  have checked : ∀ i : Fin 4,
      expectedLiveCsrAttempt .compatibility (14 + i.val) ∈ expectedLiveCsrChunk .compatibility (14 + i.val) := by decide
  exact checked index

private theorem member_issuer_0 (index : Fin 7) :
    expectedLiveCsrAttempt .issuer (0 + index.val) ∈ expectedLiveCsrChunk .issuer (0 + index.val) := by
  have checked : ∀ i : Fin 7,
      expectedLiveCsrAttempt .issuer (0 + i.val) ∈ expectedLiveCsrChunk .issuer (0 + i.val) := by decide
  exact checked index

private theorem member_burn_0 (index : Fin 7) :
    expectedLiveCsrAttempt .burn (0 + index.val) ∈ expectedLiveCsrChunk .burn (0 + index.val) := by
  have checked : ∀ i : Fin 7,
      expectedLiveCsrAttempt .burn (0 + i.val) ∈ expectedLiveCsrChunk .burn (0 + i.val) := by decide
  exact checked index

private theorem member_scalar_0 (index : Fin 2) :
    expectedLiveCsrAttempt .scalar (0 + index.val) ∈ expectedLiveCsrChunk .scalar (0 + index.val) := by
  have checked : ∀ i : Fin 2,
      expectedLiveCsrAttempt .scalar (0 + i.val) ∈ expectedLiveCsrChunk .scalar (0 + i.val) := by decide
  exact checked index

private theorem member_direction_0 (index : Fin 3) :
    expectedLiveCsrAttempt .direction (0 + index.val) ∈ expectedLiveCsrChunk .direction (0 + index.val) := by
  have checked : ∀ i : Fin 3,
      expectedLiveCsrAttempt .direction (0 + i.val) ∈ expectedLiveCsrChunk .direction (0 + i.val) := by decide
  exact checked index

private theorem member_assetBits_0 (index : Fin 4) :
    expectedLiveCsrAttempt .assetBits (0 + index.val) ∈ expectedLiveCsrChunk .assetBits (0 + index.val) := by
  have checked : ∀ i : Fin 4,
      expectedLiveCsrAttempt .assetBits (0 + i.val) ∈ expectedLiveCsrChunk .assetBits (0 + i.val) := by decide
  exact checked index

private theorem member_roles_0 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (0 + index.val) ∈ expectedLiveCsrChunk .roles (0 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (0 + i.val) ∈ expectedLiveCsrChunk .roles (0 + i.val) := by decide
  exact checked index

private theorem member_roles_14 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (14 + index.val) ∈ expectedLiveCsrChunk .roles (14 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (14 + i.val) ∈ expectedLiveCsrChunk .roles (14 + i.val) := by decide
  exact checked index

private theorem member_roles_28 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (28 + index.val) ∈ expectedLiveCsrChunk .roles (28 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (28 + i.val) ∈ expectedLiveCsrChunk .roles (28 + i.val) := by decide
  exact checked index

private theorem member_roles_42 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (42 + index.val) ∈ expectedLiveCsrChunk .roles (42 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (42 + i.val) ∈ expectedLiveCsrChunk .roles (42 + i.val) := by decide
  exact checked index

private theorem member_roles_56 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (56 + index.val) ∈ expectedLiveCsrChunk .roles (56 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (56 + i.val) ∈ expectedLiveCsrChunk .roles (56 + i.val) := by decide
  exact checked index

private theorem member_roles_70 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (70 + index.val) ∈ expectedLiveCsrChunk .roles (70 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (70 + i.val) ∈ expectedLiveCsrChunk .roles (70 + i.val) := by decide
  exact checked index

private theorem member_roles_84 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (84 + index.val) ∈ expectedLiveCsrChunk .roles (84 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (84 + i.val) ∈ expectedLiveCsrChunk .roles (84 + i.val) := by decide
  exact checked index

private theorem member_roles_98 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (98 + index.val) ∈ expectedLiveCsrChunk .roles (98 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (98 + i.val) ∈ expectedLiveCsrChunk .roles (98 + i.val) := by decide
  exact checked index

private theorem member_roles_112 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (112 + index.val) ∈ expectedLiveCsrChunk .roles (112 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (112 + i.val) ∈ expectedLiveCsrChunk .roles (112 + i.val) := by decide
  exact checked index

private theorem member_roles_126 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (126 + index.val) ∈ expectedLiveCsrChunk .roles (126 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (126 + i.val) ∈ expectedLiveCsrChunk .roles (126 + i.val) := by decide
  exact checked index

private theorem member_roles_140 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (140 + index.val) ∈ expectedLiveCsrChunk .roles (140 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (140 + i.val) ∈ expectedLiveCsrChunk .roles (140 + i.val) := by decide
  exact checked index

private theorem member_roles_154 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (154 + index.val) ∈ expectedLiveCsrChunk .roles (154 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (154 + i.val) ∈ expectedLiveCsrChunk .roles (154 + i.val) := by decide
  exact checked index

private theorem member_roles_168 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (168 + index.val) ∈ expectedLiveCsrChunk .roles (168 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (168 + i.val) ∈ expectedLiveCsrChunk .roles (168 + i.val) := by decide
  exact checked index

private theorem member_roles_182 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (182 + index.val) ∈ expectedLiveCsrChunk .roles (182 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (182 + i.val) ∈ expectedLiveCsrChunk .roles (182 + i.val) := by decide
  exact checked index

private theorem member_roles_196 (index : Fin 14) :
    expectedLiveCsrAttempt .roles (196 + index.val) ∈ expectedLiveCsrChunk .roles (196 + index.val) := by
  have checked : ∀ i : Fin 14,
      expectedLiveCsrAttempt .roles (196 + i.val) ∈ expectedLiveCsrChunk .roles (196 + i.val) := by decide
  exact checked index

theorem expected_live_csr_chunk_member (family : LiveCsrFamily) (index : Fin family.count) :
    expectedLiveCsrAttempt family index.val ∈ expectedLiveCsrChunk family index.val := by
  cases family with
  | disabled =>
      by_cases below14 : index.val < 14
      · have chunkProof := member_disabled_0 ⟨index.val - 0,by have bound : index.val < 94 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      by_cases below28 : index.val < 28
      · have chunkProof := member_disabled_14 ⟨index.val - 14,by have bound : index.val < 94 := index.isLt; omega⟩
        simpa only [show 14 + (index.val - 14) = index.val by omega] using chunkProof
      by_cases below42 : index.val < 42
      · have chunkProof := member_disabled_28 ⟨index.val - 28,by have bound : index.val < 94 := index.isLt; omega⟩
        simpa only [show 28 + (index.val - 28) = index.val by omega] using chunkProof
      by_cases below56 : index.val < 56
      · have chunkProof := member_disabled_42 ⟨index.val - 42,by have bound : index.val < 94 := index.isLt; omega⟩
        simpa only [show 42 + (index.val - 42) = index.val by omega] using chunkProof
      by_cases below70 : index.val < 70
      · have chunkProof := member_disabled_56 ⟨index.val - 56,by have bound : index.val < 94 := index.isLt; omega⟩
        simpa only [show 56 + (index.val - 56) = index.val by omega] using chunkProof
      by_cases below84 : index.val < 84
      · have chunkProof := member_disabled_70 ⟨index.val - 70,by have bound : index.val < 94 := index.isLt; omega⟩
        simpa only [show 70 + (index.val - 70) = index.val by omega] using chunkProof
      have chunkProof := member_disabled_84 ⟨index.val - 84,by have bound : index.val < 94 := index.isLt; omega⟩
      simpa only [show 84 + (index.val - 84) = index.val by omega] using chunkProof
  | compatibility =>
      by_cases below14 : index.val < 14
      · have chunkProof := member_compatibility_0 ⟨index.val - 0,by have bound : index.val < 18 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      have chunkProof := member_compatibility_14 ⟨index.val - 14,by have bound : index.val < 18 := index.isLt; omega⟩
      simpa only [show 14 + (index.val - 14) = index.val by omega] using chunkProof
  | issuer =>
      simpa only [Nat.zero_add] using member_issuer_0 index
  | burn =>
      simpa only [Nat.zero_add] using member_burn_0 index
  | scalar =>
      simpa only [Nat.zero_add] using member_scalar_0 index
  | direction =>
      simpa only [Nat.zero_add] using member_direction_0 index
  | assetBits =>
      simpa only [Nat.zero_add] using member_assetBits_0 index
  | roles =>
      by_cases below14 : index.val < 14
      · have chunkProof := member_roles_0 ⟨index.val - 0,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      by_cases below28 : index.val < 28
      · have chunkProof := member_roles_14 ⟨index.val - 14,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 14 + (index.val - 14) = index.val by omega] using chunkProof
      by_cases below42 : index.val < 42
      · have chunkProof := member_roles_28 ⟨index.val - 28,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 28 + (index.val - 28) = index.val by omega] using chunkProof
      by_cases below56 : index.val < 56
      · have chunkProof := member_roles_42 ⟨index.val - 42,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 42 + (index.val - 42) = index.val by omega] using chunkProof
      by_cases below70 : index.val < 70
      · have chunkProof := member_roles_56 ⟨index.val - 56,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 56 + (index.val - 56) = index.val by omega] using chunkProof
      by_cases below84 : index.val < 84
      · have chunkProof := member_roles_70 ⟨index.val - 70,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 70 + (index.val - 70) = index.val by omega] using chunkProof
      by_cases below98 : index.val < 98
      · have chunkProof := member_roles_84 ⟨index.val - 84,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 84 + (index.val - 84) = index.val by omega] using chunkProof
      by_cases below112 : index.val < 112
      · have chunkProof := member_roles_98 ⟨index.val - 98,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 98 + (index.val - 98) = index.val by omega] using chunkProof
      by_cases below126 : index.val < 126
      · have chunkProof := member_roles_112 ⟨index.val - 112,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 112 + (index.val - 112) = index.val by omega] using chunkProof
      by_cases below140 : index.val < 140
      · have chunkProof := member_roles_126 ⟨index.val - 126,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 126 + (index.val - 126) = index.val by omega] using chunkProof
      by_cases below154 : index.val < 154
      · have chunkProof := member_roles_140 ⟨index.val - 140,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 140 + (index.val - 140) = index.val by omega] using chunkProof
      by_cases below168 : index.val < 168
      · have chunkProof := member_roles_154 ⟨index.val - 154,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 154 + (index.val - 154) = index.val by omega] using chunkProof
      by_cases below182 : index.val < 182
      · have chunkProof := member_roles_168 ⟨index.val - 168,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 168 + (index.val - 168) = index.val by omega] using chunkProof
      by_cases below196 : index.val < 196
      · have chunkProof := member_roles_182 ⟨index.val - 182,by have bound : index.val < 210 := index.isLt; omega⟩
        simpa only [show 182 + (index.val - 182) = index.val by omega] using chunkProof
      have chunkProof := member_roles_196 ⟨index.val - 196,by have bound : index.val < 210 := index.isLt; omega⟩
      simpa only [show 196 + (index.val - 196) = index.val by omega] using chunkProof


end HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
