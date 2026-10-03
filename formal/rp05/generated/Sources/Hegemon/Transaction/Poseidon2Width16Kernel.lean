import Hegemon.Transaction.NoteCommitmentInputs

namespace Hegemon
namespace Transaction
namespace Poseidon2Width16Kernel

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

/-!
Executable Lean mirror of the source-owned width-16 Poseidon2 permutation used by fresh
transaction relations.  This module deliberately contains no V8 relation geometry, compiler
status, relation identifier, or production-authority bit.  Those belong to the separate compiled
relation refinement and can only be fixed after the source table is final.

The definitions below mirror `circuits/transaction-core/src/poseidon2_width16.rs`: Goldilocks
arithmetic, the `M4 ⊗ P4` external layer, the checked-in internal diagonal, four initial external
rounds, twenty-two internal rounds, four terminal external rounds, and the exact 150 pre-S-box
wires consumed by the compressed constraint kernel.
-/

def fieldModulus : Nat := NoteCommitmentInputs.fieldModulus
def width : Nat := 16
def rate : Nat := 8
def capacity : Nat := 8
def digestWidth : Nat := 7
def externalRoundsPerHalf : Nat := 4
def internalRounds : Nat := 22
def permutationSteps : Nat := 31
def sboxWiresPerCall : Nat :=
  externalRoundsPerHalf * 2 * width + internalRounds

def parameterSetId : String := "hegemon-p2w16-v1-114a4e7eb2684d29"
def parameterSetSha256 : String :=
  "114a4e7eb2684d293d13d306a756b03fc734f19edbfb80a07126ab1b2ad9e529"

def fieldValue (value : Nat) : Nat := value % fieldModulus

def fieldAdd (left right : Nat) : Nat :=
  (left + right) % fieldModulus

def fieldMul (left right : Nat) : Nat :=
  (left * right) % fieldModulus

def sbox (value : Nat) : Nat :=
  let value2 := fieldMul value value
  let value4 := fieldMul value2 value2
  let value6 := fieldMul value4 value2
  fieldMul value6 value

def internalMatrixDiagonal : List Nat :=
  [ 0xde9b91a467d6afc0,
    0xc5f16b9c76a9be17,
    0x0ab0fef2d540ac55,
    0x3001d27009d05773,
    0xed23b1f906d3d9eb,
    0x5ce73743cba97054,
    0x1c3bab944af4ba24,
    0x2faa105854dbafae,
    0x53ffb3ae6d421a10,
    0xbcda9df8884ba396,
    0xfc1273e4a31807bb,
    0xc77952573d5142c0,
    0x56683339a819b85e,
    0x328fcbd8f0ddc8eb,
    0xb5101e303fce9cb7,
    0x774487b8c40089bb ]

def externalRoundConstantsInitial : List (List Nat) :=
  [ [ 0x15ebea3fc73397c3, 0xd73cd9fbfe8e275c, 0x8c096bfce77f6c26,
      0x4e128f68b53d8fea, 0x29b779a36b2763f6, 0xfe2adc6fb65acd08,
      0x8d2520e725ad0955, 0x1c2392b214624d2a, 0x37482118206dcc6e,
      0x2f829bed19be019a, 0x2fe298cb6f8159b0, 0x2bbad982deccdbbf,
      0xbad568b8cc60a81e, 0xb86a814265baad10, 0xbec2005513b3acb3,
      0x6bf89b59a07c2a94 ],
    [ 0xa25deeb835e230f5, 0x3c5bad8512b8b12a, 0x7230f73c3cb7a4f2,
      0xa70c87f095c74d0f, 0x6b7606b830bb2e80, 0x6cd467cfc4f24274,
      0xfeed794df42a9b0a, 0x8cf7cf6163b7dbd3, 0x9a6e9dda597175a0,
      0xaa52295a684faf7b, 0x017b811cc3589d8d, 0x55bfb699b6181648,
      0xc2ccaf71501c2421, 0x1707950327596402, 0xdd2fcdcd42a8229f,
      0x8b9d7d5b27778a21 ],
    [ 0xac9a05525f9cf512, 0x2ba125c58627b5e8, 0xc74e91250a8147a5,
      0xa3e64b640d5bb384, 0xf53047d18d1f9292, 0xbaaeddacae3a6374,
      0xf2d0914a808b3db1, 0x18af1a3742bfa3b0, 0x9a621ef50c55bdb8,
      0xc615f4d1cc5466f3, 0xb7fbac19a35cf793, 0xd2b1a15ba517e46d,
      0x4a290c4d7fd26f6f, 0x4f0cf1bb1770c4c4, 0x548345386cd377f5,
      0x33978d2789fddd42 ],
    [ 0xab78c59deb77e211, 0xc485b2a933d2be7f, 0xbde3792c00c03c53,
      0xab4cefe8f893d247, 0xc5c0e752eab7f85f, 0xdbf5a76f893bafea,
      0xa91f6003e3d984de, 0x099539077f311e87, 0x097ec52232f9559e,
      0x53641bdf8991e48c, 0x2afe9711d5ed9d7c, 0xa7b13d3661b5d117,
      0x5a0e243fe7af6556, 0x1076fae8932d5f00, 0x9b53a83d434934e3,
      0xed3fd595a3c0344a ] ]

def internalRoundConstants : List Nat :=
  [ 0x28eff4b01103d100,
    0x60400ca3e2685a45,
    0x1c8636beb3389b84,
    0xac1332b60e13eff0,
    0x2adafcc364e20f87,
    0x79ffc2b14054ea0b,
    0x3f98e4c0908f0a05,
    0xcdb230bc4e8a06c4,
    0x1bcaf7705b152a74,
    0xd9bca249a82a7470,
    0x91e24af19bf82551,
    0xa62b43ba5cb78858,
    0xb4898117472e797f,
    0xb3228bca606cdaa0,
    0x844461051bca39c9,
    0xf3411581f6617d68,
    0xf7fd50646782b533,
    0x6ca664253c18fb48,
    0x2d2fcdec0886a08f,
    0x29da00dd799b575e,
    0x47d966cc3b6e1e93,
    0xde884e9a17ced59e ]

def externalRoundConstantsTerminal : List (List Nat) :=
  [ [ 0xdacf46dc1c31a045, 0x5d2e3c121eb387f2, 0x51f8b0658b124499,
      0x1e7dbd1daa72167d, 0x8275015a25c55b88, 0xe8521c24ac7a70b3,
      0x6521d121c40b3f67, 0xac12de797de135b0, 0xafa28ead79f6ed6a,
      0x685174a7a8d26f0b, 0xeff92a08d35d9874, 0x3058734b76dd123a,
      0xfa55dcfba429f79c, 0x559294d4324c7728, 0x7a770f53012dc178,
      0xedd8f7c408f3883b ],
    [ 0x39b533cf8d795fa5, 0x160ef9de243a8c0a, 0x431d52da6215fe3f,
      0x54c51a2a2ef6d528, 0x9b13892b46ff9d16, 0x263c46fcee210289,
      0xb738c96d25aabdc4, 0x5c33a5203996d38f, 0x2626496e7c98d8dd,
      0xc669e0a52785903a, 0xaecde726c8ae1f47, 0x039343ef3a81e999,
      0x2615ceaf044a54f9, 0x7e41e834662b66e1, 0x4ca5fd4895335783,
      0x64b334d02916f2b0 ],
    [ 0x87268837389a6981, 0x034b75bcb20a6274, 0x58e658296cc2cd6e,
      0xe2d0f759acc31df4, 0x81a652e435093e20, 0x0b72b6e0172eaf47,
      0x4aec43cec577d66d, 0xde78365b028a84e6, 0x444e19569adc0ee4,
      0x942b2451fa40d1da, 0xe24506623ea5bd6c, 0x082854bf2ef7c743,
      0x69dbbc566f59d62e, 0x248c38d02a7b5cb2, 0x4f4e8f8c09d15edb,
      0xd96682f188d310cf ],
    [ 0x6f9a25d56818b54c, 0xb6cefed606546cd9, 0x5bc07523da38a67b,
      0x7df5a3c35b8111cf, 0xaaa2cc5d4db34bb0, 0x9e673ff22a4653f8,
      0xbd8b278d60739c62, 0xe10d20f6925b8815, 0xf6c87b91dd4da2bf,
      0xfed623e2f71b6f1a, 0xa0f02fa52a94d0d3, 0xbb5794711b39fa16,
      0xd3b94fba9d005c7f, 0x15a26e89fad946c9, 0xf3cb87db8a67cf49,
      0x400d2bf56aa2a577 ] ]

theorem parameter_tables_have_exact_shape :
    internalMatrixDiagonal.length = width
      ∧ externalRoundConstantsInitial.length = externalRoundsPerHalf
      ∧ externalRoundConstantsInitial.map (fun constants => constants.length) =
        List.replicate externalRoundsPerHalf width
      ∧ internalRoundConstants.length = internalRounds
      ∧ externalRoundConstantsTerminal.length = externalRoundsPerHalf
      ∧ externalRoundConstantsTerminal.map (fun constants => constants.length) =
        List.replicate externalRoundsPerHalf width
      ∧ sboxWiresPerCall = 150 := by
  decide

def applyMds4 (input : List Nat) : List Nat :=
  let x0 := fieldValue (input.getD 0 0)
  let x1 := fieldValue (input.getD 1 0)
  let x2 := fieldValue (input.getD 2 0)
  let x3 := fieldValue (input.getD 3 0)
  let t01 := fieldAdd x0 x1
  let t23 := fieldAdd x2 x3
  let t0123 := fieldAdd t01 t23
  let t01123 := fieldAdd t0123 x1
  let t01233 := fieldAdd t0123 x3
  [ fieldAdd t01123 t01,
    fieldAdd t01123 (fieldAdd x2 x2),
    fieldAdd t01233 t23,
    fieldAdd t01233 (fieldAdd x0 x0) ]

@[simp] theorem apply_mds4_length (input : List Nat) :
    (applyMds4 input).length = 4 := by
  simp [applyMds4]

/-- The `P4` factor: add each four-lane chunk sum to every lane in that chunk. -/
def applyP4Chunks (state : List Nat) : List Nat :=
  (List.range width).map fun index =>
    let chunkStart := (index / 4) * 4
    let chunkSum := (List.range 4).foldl
      (fun sum offset => fieldAdd sum (state.getD (chunkStart + offset) 0)) 0
    fieldAdd (state.getD index 0) chunkSum

@[simp] theorem apply_p4_chunks_length (state : List Nat) :
    (applyP4Chunks state).length = width := by
  simp [applyP4Chunks]

/-- Exact source orientation `M4 ⊗ P4`: P4 chunks followed by strided M4 columns. -/
def externalLinearLayer (state : List Nat) : List Nat :=
  let p4 := applyP4Chunks state
  (List.range width).map fun index =>
    let column := index % 4
    let row := index / 4
    (applyMds4
      [ p4.getD column 0,
        p4.getD (column + 4) 0,
        p4.getD (column + 8) 0,
        p4.getD (column + 12) 0 ]).getD row 0

@[simp] theorem external_linear_layer_length (state : List Nat) :
    (externalLinearLayer state).length = width := by
  simp [externalLinearLayer]

def internalLinearLayer (state : List Nat) : List Nat :=
  let sum := state.foldl fieldAdd 0
  (List.range width).map fun lane =>
    fieldAdd
      (fieldMul (state.getD lane 0) (internalMatrixDiagonal.getD lane 0))
      sum

@[simp] theorem internal_linear_layer_length (state : List Nat) :
    (internalLinearLayer state).length = width := by
  simp [internalLinearLayer]

def externalRound (state roundConstants : List Nat) : List Nat :=
  externalLinearLayer <| (List.range width).map fun lane =>
    sbox (fieldAdd (state.getD lane 0) (roundConstants.getD lane 0))

@[simp] theorem external_round_length (state roundConstants : List Nat) :
    (externalRound state roundConstants).length = width := by
  simp [externalRound]

def internalRound (state : List Nat) (roundConstant : Nat) : List Nat :=
  let replaced := state.set 0 (sbox (fieldAdd (state.getD 0 0) roundConstant))
  internalLinearLayer replaced

@[simp] theorem internal_round_length (state : List Nat) (roundConstant : Nat) :
    (internalRound state roundConstant).length = width := by
  simp [internalRound]

def permutation (state : List Nat) : List Nat :=
  let afterInitialLinear := externalLinearLayer state
  let afterInitialExternal :=
    externalRoundConstantsInitial.foldl externalRound afterInitialLinear
  let afterInternal := internalRoundConstants.foldl internalRound afterInitialExternal
  externalRoundConstantsTerminal.foldl externalRound afterInternal

structure CompressedTrace where
  wires : List Nat
  finalState : List Nat
deriving DecidableEq, Repr

def externalRoundWires (state roundConstants : List Nat) : List Nat :=
  (List.range width).map fun lane =>
    fieldAdd (state.getD lane 0) (roundConstants.getD lane 0)

def internalRoundWire (state : List Nat) (roundConstant : Nat) : Nat :=
  fieldAdd (state.getD 0 0) roundConstant

def traceExternalRounds :
    List (List Nat) → List Nat → CompressedTrace
  | [], state => { wires := [], finalState := state }
  | constants :: rounds, state =>
      let tail := traceExternalRounds rounds (externalRound state constants)
      { wires := externalRoundWires state constants ++ tail.wires
        finalState := tail.finalState }

def traceInternalRounds : List Nat → List Nat → CompressedTrace
  | [], state => { wires := [], finalState := state }
  | constant :: rounds, state =>
      let tail := traceInternalRounds rounds (internalRound state constant)
      { wires := internalRoundWire state constant :: tail.wires
        finalState := tail.finalState }

@[simp] theorem trace_external_rounds_final_state
    (rounds : List (List Nat)) (state : List Nat) :
    (traceExternalRounds rounds state).finalState =
      rounds.foldl externalRound state := by
  induction rounds generalizing state with
  | nil => rfl
  | cons round rounds inductionHypothesis =>
      simp only [traceExternalRounds, List.foldl_cons]
      exact inductionHypothesis _

@[simp] theorem trace_internal_rounds_final_state
    (rounds state : List Nat) :
    (traceInternalRounds rounds state).finalState =
      rounds.foldl internalRound state := by
  induction rounds generalizing state with
  | nil => rfl
  | cons round rounds inductionHypothesis =>
      simp only [traceInternalRounds, List.foldl_cons]
      exact inductionHypothesis _

@[simp] theorem external_round_wires_length
    (state constants : List Nat) :
    (externalRoundWires state constants).length = width := by
  simp [externalRoundWires]

@[simp] theorem trace_external_rounds_wire_count
    (rounds : List (List Nat)) (state : List Nat) :
    (traceExternalRounds rounds state).wires.length = rounds.length * width := by
  induction rounds generalizing state with
  | nil => rfl
  | cons round rounds inductionHypothesis =>
      simp [traceExternalRounds, inductionHypothesis, Nat.add_mul]
      omega

@[simp] theorem trace_internal_rounds_wire_count
    (rounds state : List Nat) :
    (traceInternalRounds rounds state).wires.length = rounds.length := by
  induction rounds generalizing state with
  | nil => rfl
  | cons round rounds inductionHypothesis =>
      simp [traceInternalRounds, inductionHypothesis]

def compressedTrace (initialState : List Nat) : CompressedTrace :=
  let afterInitialLinear := externalLinearLayer initialState
  let initialExternal :=
    traceExternalRounds externalRoundConstantsInitial afterInitialLinear
  let internal :=
    traceInternalRounds internalRoundConstants initialExternal.finalState
  let terminalExternal :=
    traceExternalRounds externalRoundConstantsTerminal internal.finalState
  { wires := initialExternal.wires ++ internal.wires ++ terminalExternal.wires
    finalState := terminalExternal.finalState }

theorem compressed_trace_final_state (initialState : List Nat) :
    (compressedTrace initialState).finalState = permutation initialState := by
  simp [compressedTrace, permutation]

theorem compressed_trace_has_exact_wire_count (initialState : List Nat) :
    (compressedTrace initialState).wires.length = 150 := by
  simp [compressedTrace, parameter_tables_have_exact_shape, width,
    externalRoundsPerHalf, internalRounds]

theorem zero_state_permutation_known_answer :
    permutation (List.replicate width 0) =
      [ 0x60cffc11a095a4f6, 0x72899c1ee607ed14, 0x4df3cc4d6b1bc564,
        0xc26fe27ff58ae926, 0x3c3a59baedec60ba, 0x544b7efa6912a7f0,
        0x0f58443dbbc8f508, 0x92600a0875753918, 0x993899e6b1a4dc23,
        0x176443ed0f40bb61, 0x51329b9a5bef1845, 0x1a62243a788d4043,
        0xcbad6a50e2aba4cf, 0x30d6ea344ca06272, 0x342acb06b825e707,
        0xe8e5df50ae88b3b8 ] := by
  decide

theorem sequential_state_permutation_known_answer :
    permutation (List.range width) =
      [ 0x7bdb37f65a141f74, 0xf5a78c9512b524b0, 0x1f2ea94d2f967151,
        0xc7ca3a38b3d8c985, 0x33e53f18cad64aab, 0xd7c3457e364739ff,
        0x56ad9901f86041c5, 0xb1a8d11b7e155500, 0xdc4da8ca70b05416,
        0xb7a617bf235972f9, 0x648b548bec007bb6, 0x9e0f57c272b5d85a,
        0xe5a5534d13edc45f, 0x29e908ddebe00774, 0x36da1da2302878d5,
        0x34a03056f44029ce ] := by
  decide

end Poseidon2Width16Kernel
end Transaction
end Hegemon
