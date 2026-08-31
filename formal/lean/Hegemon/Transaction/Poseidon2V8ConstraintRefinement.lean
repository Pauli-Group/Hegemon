import Hegemon.Transaction.Poseidon2V8RelationProgram

namespace Hegemon
namespace Transaction
namespace Poseidon2V8ConstraintRefinement

open Poseidon2Width16Kernel

universe u v

/-!
Formal boundary for the fresh V8 width-16 constraint layout.

Unlike `Poseidon2ConstraintRefinement`, which describes the historical width-12 relation, this
module fixes only the source-derived V8 facts now present in
`smallwood_poseidon2_v8_hash_constraints.rs` and `smallwood_poseidon2_v8_semantics.rs`: a
120-word statement, 125 live permutation calls padded to 128 lanes, two 64-lane groups, 150
pre-S-box wires and 166 equations per group, a 364-row hash kernel at relation row 283, and a
686-row candidate layout.

The source adapter now constructs its linear table directly from the statement-independent
`HGV8RP03` CSR program and executes the relation-id-bound nonlinear expression DAG in every one
of the 64 packed lanes.  Its 852,305-byte transcript, SHA-512 known answer, exact linear-count
range, and maximum constraint union are frozen.  This closes the universal source-program
specialization boundary for every canonical statement and packed witness, rather than only for
known-answer vectors.  What remains absent is a verified-compiler or machine-code theorem tying
an arbitrary production binary to this source predicate, plus a theorem equating the executable
program with the higher-level transaction semantic target.  Neither source refinement nor the
hash-kernel theorem is production authority.
-/

def semanticTargetId : String :=
  "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2"
def hashKernelSourceModule : String :=
  "circuits/transaction/src/smallwood_poseidon2_v8_hash_constraints.rs"
def relationCompilerSourceModule : String :=
  "circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs"

def publicStatementWordCount : Nat := 120
def relationBindingLimbCount : Nat := 7
def packingFactor : Nat := 64
def relationConstraintDegree : Nat := 8

def liveHashCallCount : Nat := 125
def paddedHashCallCount : Nat := 128
def dummyHashCallCount : Nat := 3
def hashGroupCount : Nat := 2
def hashRowsPerGroup : Nat :=
  Poseidon2Width16Kernel.width + Poseidon2Width16Kernel.sboxWiresPerCall +
    Poseidon2Width16Kernel.width
def hashConstraintsPerGroup : Nat :=
  Poseidon2Width16Kernel.sboxWiresPerCall + Poseidon2Width16Kernel.width
def hashRowCount : Nat := hashGroupCount * hashRowsPerGroup
def hashConstraintCount : Nat := hashGroupCount * hashConstraintsPerGroup
def dummyZeroLinearConstraintCount : Nat :=
  dummyHashCallCount * Poseidon2Width16Kernel.width

def rawRowStart : Nat := 0
def rawRowCount : Nat := 247
def denseRangeRowStart : Nat := 247
def denseRangeRowCount : Nat := 5
def inlineRowStart : Nat := 252
def inlineRowCount : Nat := 31
def hashRowStart : Nat := 283
def stableRowStart : Nat := 647
def stableRowCount : Nat := 39
def relationRowCount : Nat := 686
def proofGeometryColumnCount : Nat := 368
def packedWitnessWordCount : Nat := relationRowCount * packingFactor
def nonlinearIdentityCount : Nat := 830
def minimumStatementLinearConstraintCount : Nat := 19899
def maximumStatementLinearConstraintCount : Nat := 20473
def enginePiopGammaWidth : Nat :=
  max nonlinearIdentityCount maximumStatementLinearConstraintCount
def maximumSummedIdentityUnionCount : Nat :=
  nonlinearIdentityCount + maximumStatementLinearConstraintCount

theorem source_derived_v8_geometry_is_exact :
    publicStatementWordCount = 120
      ∧ relationBindingLimbCount = 7
      ∧ Poseidon2Width16Kernel.width = 16
      ∧ Poseidon2Width16Kernel.sboxWiresPerCall = 150
      ∧ liveHashCallCount = 125
      ∧ paddedHashCallCount = 128
      ∧ dummyHashCallCount = 3
      ∧ hashGroupCount = 2
      ∧ hashRowsPerGroup = 182
      ∧ hashConstraintsPerGroup = 166
      ∧ hashRowCount = 364
      ∧ hashConstraintCount = 332
      ∧ dummyZeroLinearConstraintCount = 48
      ∧ rawRowStart = 0
      ∧ rawRowStart + rawRowCount = denseRangeRowStart
      ∧ denseRangeRowStart + denseRangeRowCount = inlineRowStart
      ∧ inlineRowStart + inlineRowCount = hashRowStart
      ∧ hashRowStart + hashRowCount = stableRowStart
      ∧ stableRowStart + stableRowCount = relationRowCount
      ∧ relationRowCount = 686
      ∧ proofGeometryColumnCount = 368
      ∧ nonlinearIdentityCount = 830
      ∧ minimumStatementLinearConstraintCount = 19899
      ∧ maximumStatementLinearConstraintCount = 20473
      ∧ enginePiopGammaWidth = 20473
      ∧ maximumSummedIdentityUnionCount = 21303
      ∧ packingFactor = 64
      ∧ packedWitnessWordCount = 43904
      ∧ relationConstraintDegree = 8 := by
  decide

structure CallRoleRange where
  name : String
  start : Nat
  stop : Nat
deriving DecidableEq, Repr

def callRoleTable : List CallRoleRange :=
  [ { name := "transaction_prf", start := 0, stop := 1 },
    { name := "input_0_note", start := 1, stop := 4 },
    { name := "input_0_merkle", start := 4, stop := 36 },
    { name := "input_0_nullifier", start := 36, stop := 37 },
    { name := "input_1_note", start := 37, stop := 40 },
    { name := "input_1_merkle", start := 40, stop := 72 },
    { name := "input_1_nullifier", start := 72, stop := 73 },
    { name := "output_0_note", start := 73, stop := 76 },
    { name := "output_1_note", start := 76, stop := 79 },
    { name := "action_intent", start := 79, stop := 94 },
    { name := "authorization_policy", start := 94, stop := 98 },
    { name := "authorization_current", start := 98, stop := 101 },
    { name := "authorization_next", start := 101, stop := 104 },
    { name := "authorization_value_lock", start := 104, stop := 106 },
    { name := "stable_config_chunks", start := 106, stop := 110 },
    { name := "stable_config_tree", start := 110, stop := 113 },
    { name := "stable_state_leaves", start := 113, stop := 115 },
    { name := "stable_authenticated_paths", start := 115, stop := 123 },
    { name := "stable_issuer_commitment", start := 123, stop := 124 },
    { name := "stable_issuer_authorization", start := 124, stop := 125 } ]

theorem call_role_table_is_the_exact_gap_free_partition :
    callRoleTable.length = 20
      ∧ callRoleTable.map (fun role => role.start) =
        [0, 1, 4, 36, 37, 40, 72, 73, 76, 79,
          94, 98, 101, 104, 106, 110, 113, 115, 123, 124]
      ∧ callRoleTable.map (fun role => role.stop) =
        [1, 4, 36, 37, 40, 72, 73, 76, 79, 94,
          98, 101, 104, 106, 110, 113, 115, 123, 124, 125]
      ∧ (callRoleTable.map (fun role => role.stop - role.start)).sum =
        liveHashCallCount := by
  decide

def hashCallGroup (call : Nat) : Nat := call / packingFactor
def hashCallLane (call : Nat) : Nat := call % packingFactor
def hashGroupLocalRowStart (group : Nat) : Nat := group * hashRowsPerGroup

def hashInitialLocalRow (group stateLane : Nat) : Nat :=
  hashGroupLocalRowStart group + stateLane

def hashSboxWireLocalRow (group wire : Nat) : Nat :=
  hashGroupLocalRowStart group + Poseidon2Width16Kernel.width + wire

def hashFinalLocalRow (group stateLane : Nat) : Nat :=
  hashGroupLocalRowStart group + Poseidon2Width16Kernel.width +
    Poseidon2Width16Kernel.sboxWiresPerCall + stateLane

def hashInitialRelationRow (group stateLane : Nat) : Nat :=
  hashRowStart + hashInitialLocalRow group stateLane

def hashSboxWireRelationRow (group wire : Nat) : Nat :=
  hashRowStart + hashSboxWireLocalRow group wire

def hashFinalRelationRow (group stateLane : Nat) : Nat :=
  hashRowStart + hashFinalLocalRow group stateLane

def packedWitnessIndex (row lane : Nat) : Nat := row * packingFactor + lane

def hashCallInitialWitnessIndex (call stateLane : Nat) : Nat :=
  packedWitnessIndex
    (hashInitialRelationRow (hashCallGroup call) stateLane)
    (hashCallLane call)

def hashCallFinalWitnessIndex (call stateLane : Nat) : Nat :=
  packedWitnessIndex
    (hashFinalRelationRow (hashCallGroup call) stateLane)
    (hashCallLane call)

theorem source_row_index_examples_are_exact :
    hashCallInitialWitnessIndex 0 0 = 18112
      ∧ hashCallInitialWitnessIndex 63 15 = 19135
      ∧ hashCallInitialWitnessIndex 64 0 = 29760
      ∧ hashCallInitialWitnessIndex 125 0 = 29821
      ∧ hashCallInitialWitnessIndex 127 15 = 30783
      ∧ hashCallFinalWitnessIndex 124 15 = 41404 := by
  decide

def packedHashValue
    (packedRows : List (List Nat)) (localRow lane : Nat) : Nat :=
  (packedRows.getD localRow []).getD lane 0

def groupInitialState
    (packedRows : List (List Nat)) (group lane : Nat) : List Nat :=
  (List.range Poseidon2Width16Kernel.width).map fun stateLane =>
    packedHashValue packedRows (hashInitialLocalRow group stateLane) lane

def groupSboxWires
    (packedRows : List (List Nat)) (group lane : Nat) : List Nat :=
  (List.range Poseidon2Width16Kernel.sboxWiresPerCall).map fun wire =>
    packedHashValue packedRows (hashSboxWireLocalRow group wire) lane

def groupFinalState
    (packedRows : List (List Nat)) (group lane : Nat) : List Nat :=
  (List.range Poseidon2Width16Kernel.width).map fun stateLane =>
    packedHashValue packedRows (hashFinalLocalRow group stateLane) lane

@[simp] theorem group_initial_state_length
    (packedRows : List (List Nat)) (group lane : Nat) :
    (groupInitialState packedRows group lane).length = 16 := by
  simp [groupInitialState, Poseidon2Width16Kernel.width]

@[simp] theorem group_sbox_wires_length
    (packedRows : List (List Nat)) (group lane : Nat) :
    (groupSboxWires packedRows group lane).length = 150 := by
  simp [groupSboxWires, Poseidon2Width16Kernel.sboxWiresPerCall,
    Poseidon2Width16Kernel.externalRoundsPerHalf,
    Poseidon2Width16Kernel.internalRounds, Poseidon2Width16Kernel.width]

@[simp] theorem group_final_state_length
    (packedRows : List (List Nat)) (group lane : Nat) :
    (groupFinalState packedRows group lane).length = 16 := by
  simp [groupFinalState, Poseidon2Width16Kernel.width]

/-- Semantic meaning of one accepted 166-equation source kernel slice. -/
structure HashGroupTraceMatches
    (packedRows : List (List Nat)) (group lane : Nat) : Prop where
  exactSboxWires :
    groupSboxWires packedRows group lane =
      (Poseidon2Width16Kernel.compressedTrace
        (groupInitialState packedRows group lane)).wires
  exactFinalState :
    groupFinalState packedRows group lane =
      (Poseidon2Width16Kernel.compressedTrace
        (groupInitialState packedRows group lane)).finalState

theorem hash_group_trace_matches_implies_width16_permutation
    {packedRows : List (List Nat)} {group lane : Nat}
    (traceMatches : HashGroupTraceMatches packedRows group lane) :
    groupFinalState packedRows group lane =
      Poseidon2Width16Kernel.permutation
        (groupInitialState packedRows group lane) := by
  rw [traceMatches.exactFinalState,
    Poseidon2Width16Kernel.compressed_trace_final_state]

def PackedHashRowsCanonical (packedRows : List (List Nat)) : Prop :=
  packedRows.length = hashRowCount
    ∧ ∀ row, row ∈ packedRows →
      row.length = packingFactor
        ∧ ∀ value, value ∈ row → value < Poseidon2Width16Kernel.fieldModulus

def DummyHashStartsZero (packedRows : List (List Nat)) : Prop :=
  ∀ call, liveHashCallCount ≤ call → call < paddedHashCallCount →
    ∀ stateLane, stateLane < Poseidon2Width16Kernel.width →
      packedHashValue packedRows
          (hashInitialLocalRow (hashCallGroup call) stateLane)
          (hashCallLane call) = 0

structure LeanHashKernelAccepted (packedRows : List (List Nat)) : Prop where
  canonical : PackedHashRowsCanonical packedRows
  traceMatches :
    ∀ group, group < hashGroupCount →
      ∀ lane, lane < packingFactor →
        HashGroupTraceMatches packedRows group lane
  dummyStartsZero : DummyHashStartsZero packedRows

/-!
The next structure is the universal Rust-to-Lean hash-kernel boundary.  Known-answer and mutation
vectors can falsify drift, but they do not construct this universal equivalence.  A release receipt
must supply it for the exact production verifier predicate.
-/
structure RustLeanHashKernelRefinementReceipt where
  sourceModule : String
  sourceModuleExact : sourceModule = hashKernelSourceModule
  parameterId : String
  parameterIdExact : parameterId = Poseidon2Width16Kernel.parameterSetId
  rustAccepts : List (List Nat) → Bool
  rustAcceptsIffLeanKernel :
    ∀ packedRows,
      rustAccepts packedRows = true ↔ LeanHashKernelAccepted packedRows

inductive CheckedInCompilerCoverage where
  | hashKernelOnly
  | executableRelationUnbound
  | sourceExecutableProgramBound
  | fullRelation
deriving DecidableEq, Repr

/-- The Rust source adapter is program-derived; compiled-machine and semantic refinement remain. -/
def checkedInCompilerCoverage : CheckedInCompilerCoverage := .sourceExecutableProgramBound

theorem checked_in_source_executable_program_is_bound :
    checkedInCompilerCoverage = .sourceExecutableProgramBound := by
  rfl

theorem checked_in_full_relation_receipt_is_not_complete :
    checkedInCompilerCoverage ≠ .fullRelation := by
  decide

/--
Source-level acceptance used by the program-derived Rust adapter.  Its definition deliberately
mentions the pinned interpreter once: all 64 nonlinear lanes and the exact CSR attempt program
are part of the same universal predicate.
-/
def sourceExecutableAdapterAccepts
    (components : Poseidon2V8RelationProgram.RelationProgramComponents)
    (publicWords packedWitness : List Nat) : Prop :=
  components.AcceptsPacked publicWords packedWitness

theorem source_executable_adapter_refines_pinned_program_for_all_inputs
    (components : Poseidon2V8RelationProgram.RelationProgramComponents)
    (publicWords packedWitness : List Nat) :
    sourceExecutableAdapterAccepts components publicWords packedWitness ↔
      components.AcceptsPacked publicWords packedWitness := by
  rfl

theorem source_executable_adapter_checks_all_64_lanes
    {components : Poseidon2V8RelationProgram.RelationProgramComponents}
    {publicWords packedWitness : List Nat}
    (accepted : sourceExecutableAdapterAccepts components publicWords packedWitness)
    {lane : Nat} (laneBound : lane < packingFactor) :
    components.nonlinearExecutable.Accepts publicWords
      (Poseidon2V8RelationProgram.packedWitnessLaneRows packedWitness lane) := by
  exact Poseidon2V8RelationProgram.accepted_packed_program_checks_every_nonlinear_lane
    accepted laneBound

/--
Required universal bridge from the executable, statement-specialized Rust CSR builder to the
statement-independent executable CSR program committed by `HGV8RP03`.
-/
structure RustExecutableCsrProgramRefinementReceipt
    (Statement : Type u)
    (components : Poseidon2V8RelationProgram.RelationProgramComponents) where
  acceptedStatement : Statement → Prop
  publicStatementWords : Statement → List Nat
  publicStatementWordsExact :
    ∀ statement, (publicStatementWords statement).length = publicStatementWordCount
  descriptorReplayAccepts : Statement → Bool
  emittedLinearConstraintCount : Statement → Nat
  rustCsrAccepts : Statement → List Nat → Bool
  descriptorReplayAcceptsIffAccepted :
    ∀ statement, descriptorReplayAccepts statement = true ↔ acceptedStatement statement
  /-- Exact ordered program bytes consumed by every source-builder run. -/
  builderProgramBytes : Statement → List Nat
  builderProgramBytesExact :
    ∀ statement, acceptedStatement statement →
      builderProgramBytes statement =
        Poseidon2V8RelationProgram.encodeCsrExecutableProgram
          components.csrExpressions components.csrAttempts
  /-- Universal acceptance equivalence, not a finite fixture or mutation-test claim. -/
  rustCsrAcceptsIffExecutableProgram :
    ∀ statement packedWitness,
      acceptedStatement statement →
      (rustCsrAccepts statement packedWitness = true ↔
        Poseidon2V8RelationProgram.csrExecutableProgramAccepts
          components.csrExpressions components.csrAttempts
          (publicStatementWords statement) packedWitness)
  acceptedLinearCountInExactRange :
    ∀ statement, acceptedStatement statement →
      minimumStatementLinearConstraintCount ≤ emittedLinearConstraintCount statement ∧
        emittedLinearConstraintCount statement ≤ maximumStatementLinearConstraintCount
  minimumLinearCountWitness :
    ∃ statement, acceptedStatement statement ∧
      emittedLinearConstraintCount statement = minimumStatementLinearConstraintCount
  maximumLinearCountWitness :
    ∃ statement, acceptedStatement statement ∧
      emittedLinearConstraintCount statement = maximumStatementLinearConstraintCount

/-!
Receipt required before the 120-word semantic target may be identified with an accepted compiled
relation.  The frozen program identity is data; this receipt additionally requires universal
acceptance equivalence for the exact executable nonlinear and CSR interpreters.  KATs and mutation
tests can falsify drift, but cannot replace either equivalence.
-/
structure FullRelationCompilerRefinementReceipt
    (Statement : Type u) (Witness : Type v) where
  compilerSourceModule : String
  compilerSourceModuleExact : compilerSourceModule = relationCompilerSourceModule
  compilerCoverageExact : checkedInCompilerCoverage = .fullRelation
  hashKernel : RustLeanHashKernelRefinementReceipt
  programComponents : Poseidon2V8RelationProgram.RelationProgramComponents
  programComponentsCanonical : programComponents.Canonical
  executableCsrProgramRefinement :
    RustExecutableCsrProgramRefinementReceipt Statement programComponents
  programBytes : List Nat
  programBytesNonempty : programBytes ≠ []
  programBytesCanonical : ∀ byte, byte ∈ programBytes → byte < 256
  programBytesExact :
    programBytes = Poseidon2V8RelationProgram.canonicalProgramTranscript programComponents
  programBytesExactLength :
    programBytes.length = Poseidon2V8RelationProgram.canonicalProgramTranscriptBytes
  programSha512 : List Nat
  programSha512ExactLength : programSha512.length = 64
  programSha512Canonical : ∀ byte, byte ∈ programSha512 → byte < 256
  programSha512Exact :
    programSha512 = Poseidon2V8RelationProgram.canonicalProgramSha512
  productionSha512 : List Nat → List Nat
  productionSha512Name : String
  productionSha512NameExact : productionSha512Name = "SHA-512"
  programSha512RecomputedFromExactProgramBytes :
    productionSha512 programBytes = programSha512
  exactRelationRows : Nat
  exactRelationRowsBound : exactRelationRows = relationRowCount
  exactProofGeometryColumns : Nat
  exactProofGeometryColumnsBound :
    exactProofGeometryColumns = proofGeometryColumnCount
  exactNonlinearIdentityCount : Nat
  exactNonlinearIdentityCountBound :
    exactNonlinearIdentityCount = nonlinearIdentityCount
  minimumStatementLinearConstraintCount : Nat
  minimumStatementLinearConstraintCountBound :
    minimumStatementLinearConstraintCount =
      Poseidon2V8ConstraintRefinement.minimumStatementLinearConstraintCount
  maximumStatementLinearConstraintCount : Nat
  maximumStatementLinearConstraintCountBound :
    maximumStatementLinearConstraintCount =
      Poseidon2V8ConstraintRefinement.maximumStatementLinearConstraintCount
  exactEnginePiopGammaWidth : Nat
  enginePiopGammaWidthBound :
    exactEnginePiopGammaWidth =
      max exactNonlinearIdentityCount maximumStatementLinearConstraintCount
  maximumSummedIdentityUnionCount : Nat
  maximumSummedIdentityUnionCountBound :
    maximumSummedIdentityUnionCount =
      exactNonlinearIdentityCount + maximumStatementLinearConstraintCount
  publicStatementWords : Statement → List Nat
  publicStatementWordsExact :
    ∀ statement, (publicStatementWords statement).length = publicStatementWordCount
  publicStatementWordsMatchCsrRefinement :
    publicStatementWords = executableCsrProgramRefinement.publicStatementWords
  bindingLimbs : Statement → List Nat
  bindingLimbsExact :
    ∀ statement, (bindingLimbs statement).length = relationBindingLimbCount
  semanticTarget : Statement → Witness → Prop
  packedWitness : Witness → List Nat
  packedWitnessExact :
    ∀ witness, (packedWitness witness).length = packedWitnessWordCount
  compiledAccepts : Statement → Witness → Bool
  /-- Exact Rust acceptance equals the interpreter of the relation-id-bound program. -/
  compiledAcceptsIffExecutableProgram :
    ∀ statement witness,
      compiledAccepts statement witness = true ↔
        programComponents.AcceptsPacked
          (publicStatementWords statement) (packedWitness witness)
  /-- Specification adequacy remains a separate equality from executable refinement. -/
  compiledAcceptsIffSemanticTarget :
    ∀ statement witness,
      compiledAccepts statement witness = true ↔ semanticTarget statement witness

theorem full_relation_compiler_receipt_is_unavailable_from_checked_in_status
    (Statement : Type u) (Witness : Type v) :
    ¬ Nonempty (FullRelationCompilerRefinementReceipt Statement Witness) := by
  intro evidence
  rcases evidence with ⟨receipt⟩
  exact checked_in_full_relation_receipt_is_not_complete receipt.compilerCoverageExact

end Poseidon2V8ConstraintRefinement
end Transaction
end Hegemon
