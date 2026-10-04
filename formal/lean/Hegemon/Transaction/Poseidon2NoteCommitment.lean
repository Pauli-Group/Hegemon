import Hegemon.Transaction.NoteCommitmentInputs

namespace Hegemon
namespace Transaction
namespace Poseidon2NoteCommitment

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

/-!
Executable Lean mirror of the deployed Goldilocks Poseidon2 transaction sponge.

The constants and round schedule mirror `circuits/transaction-core/src/poseidon2.rs` and
`circuits/transaction-core/src/poseidon2_constants.rs`. Cross-language known-answer vectors
generated from this module are checked against `hashing_pq::note_commitment` in Rust.
-/

def fieldModulus : Nat := NoteCommitmentInputs.fieldModulus
def poseidon2Width : Nat := 12
def poseidon2Rate : Nat := 6
def poseidon2ExternalRounds : Nat := 4
def poseidon2InternalRounds : Nat := 22
def noteDomainTag : Nat := NoteCommitmentInputs.noteDomainTag

def fieldValue (value : Nat) : Nat := value % fieldModulus

def fieldAdd (left right : Nat) : Nat :=
  (left + right) % fieldModulus

def fieldMul (left right : Nat) : Nat :=
  (left * right) % fieldModulus

def poseidon2Sbox (value : Nat) : Nat :=
  let value2 := fieldMul value value
  let value4 := fieldMul value2 value2
  let value6 := fieldMul value4 value2
  fieldMul value6 value

def internalMatrixDiagonal : List Nat :=
  [ 0xc3b6c08e23ba9300,
    0xd84b5de94a324fb6,
    0x0d0c371c5b35b84f,
    0x7964f570e7188037,
    0x5daf18bbd996604b,
    0x6743bc47b9595257,
    0x5528b9362c59bb70,
    0xac45e25b7127b68b,
    0xa2077d7dfbb606b5,
    0xf3faac6faee378ae,
    0x0c6388b51545e883,
    0xd27dbb6944917b60 ]

def externalRoundConstantsInitial : List (List Nat) :=
  [ [ 0x7914ff869d09bdc3,
      0xb03ee00cfebfb05b,
      0x375eb98de727052d,
      0xdd8d1543e04114c3,
      0xfb0767ab77ed1f7a,
      0x542cc730c3972c50,
      0xa825a62cfe711418,
      0xe47f81105525816a,
      0xeb5c7dcde6c3738a,
      0x6b8104926185e10e,
      0xa06eee93a6045fb8,
      0xbd87e85188445457 ],
    [ 0xb1b6960dc01581f4,
      0x1115e21368af8891,
      0x14d94244202b4d15,
      0x92e83baa9d07f0ef,
      0x1966581757bdfb99,
      0x1902430824b960d7,
      0xcb327f95f40eaecd,
      0xe5fafddec3c17c1f,
      0x92421473488f71bd,
      0x2168f2b2f622ae51,
      0xd191e8bda72fe558,
      0x31ae6876405abab5 ],
    [ 0xf39272caff95caab,
      0x44bf5ad3597e99f6,
      0xcc2ba812e2327d54,
      0x6bd5380bf8ed35d8,
      0x8473d71f7750b0ba,
      0xea023aa925dee3a0,
      0xea08e2de3aa450e0,
      0xf49b8ee36da12b44,
      0x2ef5f3f207eba00c,
      0x827abbd7733372f4,
      0xf04714126b1385ab,
      0x37800dcceb8107e2 ],
    [ 0xe85ff87c7c8f77a6,
      0xb8268cefb3261610,
      0x14d0bb9f7604547f,
      0x788cf96ecb430dde,
      0x3cbe69615ba2e1d0,
      0x55ae1c01d4262c04,
      0x7429dc16119c28f6,
      0xcda93b327917418b,
      0x2497a9225c187b37,
      0x91ac79167a6f377e,
      0xa5effac16d7668a3,
      0xd78a26ce76d4d811 ] ]

def externalRoundConstantsTerminal : List (List Nat) :=
  [ [ 0x5e0497fa4c4f1682,
      0x547d0d0b9b99a7e3,
      0xd229d5678cced1de,
      0xc12e48a54ac5022e,
      0xc00d4ab46ef4d7b2,
      0xb4645340a95b0b6a,
      0xbb06f800d2bd2524,
      0x596b284ffd64c009,
      0x885736fcd5b663bf,
      0x7fbe08c4afe0a5cd,
      0x0c2b541d80c5d2aa,
      0x0685f06c8e1189d3 ],
    [ 0xbf0934418bc86dc0,
      0x345243ffbec349d4,
      0xa9332c45ff7c7d82,
      0xb8cc956e50dd0450,
      0xbfe62fe64e38ae9c,
      0x8583d2cd534f1b9b,
      0x04520d21cc10efed,
      0x99e81987be9932a3,
      0xf0d3a301a33955e0,
      0x5a5dbcbf1df5522b,
      0x0c13e879a2360261,
      0x094a1123513e9ba3 ],
    [ 0x858d9ad9c453649d,
      0xfdce777f1dbb0ff9,
      0x24194bbf7e6ee44f,
      0x15a6a88ce9f441a5,
      0x55a03ae2f62e843c,
      0x515c6e41f49d9b3d,
      0x431ba02861d0f884,
      0xeefd245429d11dd9,
      0x831f1811991a26a4,
      0x2269f8805c3d40c2,
      0x6c8a794a8943b2a9,
      0x2298bd8b15776de9 ],
    [ 0x959639a90173c751,
      0x65b6244a78e84c2b,
      0x8a04fc785b1407be,
      0x68e27a5a1cde026f,
      0xa408bb722d770889,
      0x804491c567e5f3d5,
      0xcbc7d07164231f8b,
      0x3441ffec6f80800d,
      0x190b7cc675a4192a,
      0x8944fdce36a23877,
      0xe2a24e1ce229fb4d,
      0xffcb89b9e9a6e223 ] ]

def internalRoundConstants : List Nat :=
  [ 0xc0929f33e2853d1b,
    0xd87c59fd9506f59c,
    0x9b8986da30c5661d,
    0xacb45c9caf8f9bab,
    0x4f64d87fd0164596,
    0x04bddf3342d684d9,
    0xcaa3498150fc3e3b,
    0x5ddd38a00e26563b,
    0x5105844dcef0279d,
    0x63f9e1ff40676ef7,
    0x64bb32f2134ce6ba,
    0xa2a96bba1042ab02,
    0x17f6c4815e81af65,
    0x6b49fe48b8e0cc07,
    0x2e5e3d70d8fe257d,
    0xd4bed28c49c172e9,
    0xcfb25a871027d329,
    0xb62ad38bb2bf0f3b,
    0xdfe40c70f2c288dc,
    0x2fbb65b92fa854d9,
    0xb0fe72a89100504b,
    0xfec87ab0375b5da0 ]

theorem poseidon2_constant_tables_have_deployed_shape :
    internalMatrixDiagonal.length = poseidon2Width
      ∧ externalRoundConstantsInitial.length = poseidon2ExternalRounds
      ∧ externalRoundConstantsInitial.map (fun constants => constants.length) =
        List.replicate poseidon2ExternalRounds poseidon2Width
      ∧ internalRoundConstants.length = poseidon2InternalRounds
      ∧ externalRoundConstantsTerminal.length = poseidon2ExternalRounds
      ∧ externalRoundConstantsTerminal.map (fun constants => constants.length) =
        List.replicate poseidon2ExternalRounds poseidon2Width := by
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

@[simp] theorem applyMds4_length (input : List Nat) :
    (applyMds4 input).length = 4 := by
  simp [applyMds4]

def mdsLight (state : List Nat) : List Nat :=
  let mixed :=
    applyMds4 (state.take 4)
      ++ applyMds4 ((state.drop 4).take 4)
      ++ applyMds4 ((state.drop 8).take 4)
  let columnSums := (List.range 4).map fun column =>
    fieldAdd (mixed.getD column 0)
      (fieldAdd (mixed.getD (column + 4) 0) (mixed.getD (column + 8) 0))
  (List.range poseidon2Width).map fun index =>
    fieldAdd (mixed.getD index 0) (columnSums.getD (index % 4) 0)

@[simp] theorem mdsLight_length (state : List Nat) :
    (mdsLight state).length = poseidon2Width := by
  simp [mdsLight]

def externalRound (state roundConstants : List Nat) : List Nat :=
  mdsLight <| (List.range poseidon2Width).map fun index =>
    poseidon2Sbox (fieldAdd (state.getD index 0) (roundConstants.getD index 0))

@[simp] theorem externalRound_length (state roundConstants : List Nat) :
    (externalRound state roundConstants).length = poseidon2Width := by
  simp [externalRound]

def internalRound (state : List Nat) (roundConstant : Nat) : List Nat :=
  let sboxed := state.set 0 (poseidon2Sbox (fieldAdd (state.getD 0 0) roundConstant))
  let sum := sboxed.foldl fieldAdd 0
  (List.range poseidon2Width).map fun index =>
    fieldAdd
      (fieldMul (sboxed.getD index 0) (internalMatrixDiagonal.getD index 0))
      sum

@[simp] theorem internalRound_length (state : List Nat) (roundConstant : Nat) :
    (internalRound state roundConstant).length = poseidon2Width := by
  simp [internalRound]

theorem foldl_externalRound_length
    (rounds : List (List Nat))
    (state : List Nat)
    (stateWidth : state.length = poseidon2Width) :
    (rounds.foldl externalRound state).length = poseidon2Width := by
  induction rounds generalizing state with
  | nil => simpa
  | cons round tail inductionHypothesis =>
      apply inductionHypothesis
      exact externalRound_length state round

theorem foldl_internalRound_length
    (rounds : List Nat)
    (state : List Nat)
    (stateWidth : state.length = poseidon2Width) :
    (rounds.foldl internalRound state).length = poseidon2Width := by
  induction rounds generalizing state with
  | nil => simpa
  | cons round tail inductionHypothesis =>
      apply inductionHypothesis
      exact internalRound_length state round

def poseidon2Permutation (state : List Nat) : List Nat :=
  let afterInitialMds := mdsLight state
  let afterInitialExternal := externalRoundConstantsInitial.foldl externalRound afterInitialMds
  let afterInternal := internalRoundConstants.foldl internalRound afterInitialExternal
  externalRoundConstantsTerminal.foldl externalRound afterInternal

@[simp] theorem poseidon2Permutation_length (state : List Nat) :
    (poseidon2Permutation state).length = poseidon2Width := by
  simp only [poseidon2Permutation]
  apply foldl_externalRound_length
  apply foldl_internalRound_length
  apply foldl_externalRound_length
  exact mdsLight_length state

theorem poseidon2_zero_state_permutation_known_answer :
    poseidon2Permutation (List.replicate poseidon2Width 0) =
      [ 0x55fca8bcb7c2650b, 0xc82c35dd3c63e660, 0x6a752db9d25f4fb7,
        0xfdd20701a3c96ccd, 0x0cdb74cc5f0dacf9, 0xe43b9de64fdbb0eb,
        0x8953eb71b3e847f8, 0x7d86ed20878d820b, 0x1db9a1390ba5f835,
        0x541d5ab92f915289, 0xe1b57440527a2050, 0x69dc653889078efa ] := by
  decide

def initialSpongeState (domainTag : Nat) : List Nat :=
  (List.range poseidon2Width).map fun index =>
    if index = 0 then fieldValue domainTag
    else if index = poseidon2Width - 1 then 1
    else 0

@[simp] theorem initialSpongeState_length (domainTag : Nat) :
    (initialSpongeState domainTag).length = poseidon2Width := by
  simp [initialSpongeState]

def absorbChunk (inputs : List Nat) (state : List Nat) (chunk : Nat) : List Nat :=
  let absorbed := (List.range poseidon2Width).map fun index =>
    let inputIndex := chunk * poseidon2Rate + index
    if index < poseidon2Rate && inputIndex < inputs.length then
      fieldAdd (state.getD index 0) (inputs.getD inputIndex 0)
    else
      state.getD index 0
  poseidon2Permutation absorbed

@[simp] theorem absorbChunk_length (inputs state : List Nat) (chunk : Nat) :
    (absorbChunk inputs state chunk).length = poseidon2Width := by
  simp [absorbChunk]

theorem foldl_absorbChunk_length
    (inputs : List Nat)
    (chunks : List Nat)
    (state : List Nat)
    (stateWidth : state.length = poseidon2Width) :
    (chunks.foldl (absorbChunk inputs) state).length = poseidon2Width := by
  induction chunks generalizing state with
  | nil => simpa
  | cons chunk tail inductionHypothesis =>
      apply inductionHypothesis
      exact absorbChunk_length inputs state chunk

def deployedPoseidon2PermutationCount (inputs : List Nat) : Nat :=
  (inputs.length + poseidon2Rate - 1) / poseidon2Rate

def deployedPoseidon2Sponge (domainTag : Nat) (inputs : List Nat) : List Nat :=
  let chunkCount := deployedPoseidon2PermutationCount inputs
  let finalState := (List.range chunkCount).foldl (absorbChunk inputs)
    (initialSpongeState domainTag)
  finalState.take poseidon2Rate

@[simp] theorem deployedPoseidon2Sponge_length (domainTag : Nat) (inputs : List Nat) :
    (deployedPoseidon2Sponge domainTag inputs).length = poseidon2Rate := by
  simp [deployedPoseidon2Sponge, foldl_absorbChunk_length,
    poseidon2Rate, poseidon2Width]

theorem eighteen_word_preimage_uses_three_poseidon2_permutations
    (inputs : List Nat)
    (inputWidth : inputs.length = 18) :
    deployedPoseidon2PermutationCount inputs = 3 := by
  simp [deployedPoseidon2PermutationCount, inputWidth, poseidon2Rate]

theorem eighteen_word_note_preimage_produces_six_digest_limbs
    (inputs : List Nat)
    (_inputWidth : inputs.length = 18) :
    (deployedPoseidon2Sponge noteDomainTag inputs).length = 6 := by
  exact deployedPoseidon2Sponge_length noteDomainTag inputs

theorem poseidon2_zero_note_commitment_known_answer :
    deployedPoseidon2Sponge noteDomainTag (List.replicate 18 0) =
      [ 0xf217be6cb41e33e5, 0x788c0d453bfad2f9, 0xa4e7713bd1e4118b,
        0xb41c7110cb9c015a, 0xab495e710c67d3bb, 0xfae74866b9731d67 ] := by
  decide

theorem poseidon2_sequential_note_commitment_known_answer :
    deployedPoseidon2Sponge noteDomainTag (List.range 18) =
      [ 0x57152e6d432635e1, 0xf687c2d7f57cdee3, 0x4fac7066750c3d3a,
        0x363c23b1d7109c1b, 0x63d694dcc2c9cd2b, 0xb895af2eb8f22c85 ] := by
  decide

def deployedNoteCommitmentDigest (inputs : List Nat) : List Nat :=
  deployedPoseidon2Sponge noteDomainTag inputs

end Poseidon2NoteCommitment
end Transaction
end Hegemon
