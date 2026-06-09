import Hegemon.Bytes

namespace Hegemon
namespace Bridge
namespace HeaderMmrTranscript

def parentDomain : List Byte :=
  asciiBytes "hegemon.header-mmr.node-v2"

def rootDomain : List Byte :=
  asciiBytes "hegemon.header-mmr.root-v2"

structure ParentInput where
  level : Nat
  left : List Byte
  right : List Byte
deriving DecidableEq, Repr

structure RootInput where
  leafCount : Nat
  peaks : List (List Byte)
deriving DecidableEq, Repr

def parentPreimage (input : ParentInput) : List Byte :=
  parentDomain ++ u32le input.level ++ input.left ++ input.right

def flattenPeaks (peaks : List (List Byte)) : List Byte :=
  peaks.foldl (fun acc peak => acc ++ peak) []

def rootPreimage (input : RootInput) : List Byte :=
  rootDomain ++ u64le input.leafCount ++ u32le input.peaks.length ++ flattenPeaks input.peaks

def sampleParent : ParentInput :=
  {
    level := 2,
    left := patternedBytes 32 4,
    right := patternedBytes 32 5
  }

def maxLevelParent : ParentInput :=
  {
    level := 4294967295,
    left := patternedBytes 32 6,
    right := patternedBytes 32 7
  }

def emptyRoot : RootInput :=
  {
    leafCount := 0,
    peaks := []
  }

def twoPeakRoot : RootInput :=
  {
    leafCount := 6,
    peaks := [patternedBytes 32 8, patternedBytes 32 9]
  }

def reversedTwoPeakRoot : RootInput :=
  {
    leafCount := 6,
    peaks := [patternedBytes 32 9, patternedBytes 32 8]
  }

theorem parent_domain_bytes :
    parentDomain =
      [104, 101, 103, 101, 109, 111, 110, 46, 104, 101, 97, 100, 101,
       114, 45, 109, 109, 114, 46, 110, 111, 100, 101, 45, 118, 50] := by
  decide

theorem root_domain_bytes :
    rootDomain =
      [104, 101, 103, 101, 109, 111, 110, 46, 104, 101, 97, 100, 101,
       114, 45, 109, 109, 114, 46, 114, 111, 111, 116, 45, 118, 50] := by
  decide

theorem sample_parent_length :
    (parentPreimage sampleParent).length = 94 := by
  decide

theorem sample_parent_hex :
    hexBytes (parentPreimage sampleParent) =
      "0x686567656d6f6e2e6865616465722d6d6d722e6e6f64652d7632020000000415263748596a7b8c9daebfd0e1f2031425364758697a8b9cadbecfe0f1021305162738495a6b7c8d9eafc0d1e2f30415263748596a7b8c9daebfd0e1f20314" := by
  set_option maxRecDepth 5000 in
  decide

theorem max_level_parent_hex :
    hexBytes (parentPreimage maxLevelParent) =
      "0x686567656d6f6e2e6865616465722d6d6d722e6e6f64652d7632ffffffff061728394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f304150718293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f40516" := by
  set_option maxRecDepth 5000 in
  decide

theorem empty_root_length :
    (rootPreimage emptyRoot).length = 38 := by
  decide

theorem empty_root_hex :
    hexBytes (rootPreimage emptyRoot) =
      "0x686567656d6f6e2e6865616465722d6d6d722e726f6f742d7632000000000000000000000000" := by
  decide

theorem two_peak_root_length :
    (rootPreimage twoPeakRoot).length = 102 := by
  decide

theorem two_peak_root_hex :
    hexBytes (rootPreimage twoPeakRoot) =
      "0x686567656d6f6e2e6865616465722d6d6d722e726f6f742d763206000000000000000200000008192a3b4c5d6e7f90a1b2c3d4e5f60718293a4b5c6d7e8fa0b1c2d3e4f50617091a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f90a1b2c3d4e5f60718" := by
  set_option maxRecDepth 6000 in
  decide

theorem reversed_two_peak_root_hex :
    hexBytes (rootPreimage reversedTwoPeakRoot) =
      "0x686567656d6f6e2e6865616465722d6d6d722e726f6f742d7632060000000000000002000000091a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f90a1b2c3d4e5f6071808192a3b4c5d6e7f90a1b2c3d4e5f60718293a4b5c6d7e8fa0b1c2d3e4f50617" := by
  set_option maxRecDepth 6000 in
  decide

theorem root_order_binds_peak_sequence :
    rootPreimage twoPeakRoot ≠ rootPreimage reversedTwoPeakRoot := by
  decide

end HeaderMmrTranscript
end Bridge
end Hegemon
