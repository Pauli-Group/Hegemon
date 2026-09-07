import Hegemon.Transaction.Poseidon2Width16Kernel

namespace Hegemon
namespace Transaction
namespace Poseidon2V8RelationProgram

/-!
Canonical, statement-independent transcript for the executable V8 relation program.

The native `HGV8TX02` leaf carries 48 relation-id bytes.  Those bytes are the first 48 bytes of
SHA-512 over this exact transcript.  The SHA-512 input begins with the eight-byte `HGV8RP03`
magic, a little-endian grammar version and section count, followed by nine ordered, tagged,
length-delimited sections.  Statement *descriptors* occur in the transcript; statement values do
not.  Changing a transaction therefore cannot change the relation id.

This module fixes the encoding, required V8 shape, and source-recomputed program digest KAT.  It
defines an interpreter for the exact expression and CSR grammar, including all 64 packed witness
lanes.  The Rust source adapter is constructed directly from this program grammar; a compiled
machine-code equivalence theorem, semantic-target adequacy theorem, and production authority
remain separate boundaries.
-/

def transcriptMagic : List Nat := [72, 71, 86, 56, 82, 80, 48, 51] -- `HGV8RP03`
def transcriptGrammar : Nat := 3
def transcriptHashName : String := "SHA-512"
def transcriptDigestBytes : Nat := 64
def nativeRelationIdBytes : Nat := 48
def transcriptSectionCount : Nat := 9
def publicStatementWordCount : Nat := 120
def relationRowCount : Nat := 686
def packingFactor : Nat := 64
def packedWitnessWordCount : Nat := 43904

/-!
Source-recomputed known-answer identity for the current `HGV8RP03`-format program. These constants were frozen only after the
shared executable expression IR, the 86-family compiler cursor, all nine transcript sections, and
formula-level mutation tests agreed. They identify a program artifact; they do not by themselves
assert universal Rust/Lean semantic refinement or production authority.
-/
def canonicalProgramArtifactAvailable : Bool := true
def canonicalProgramTranscriptBytes : Nat := 853429
def canonicalProgramSha512Hex : String :=
  "180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d22" ++
  "39e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84"
def canonicalProgramSha512 : List Nat :=
  [ 24, 15, 202, 80, 55, 111, 117, 115, 202, 206, 223, 181, 70, 90, 11, 77,
    107, 245, 198, 22, 55, 21, 32, 53, 166, 130, 210, 16, 56, 1, 109, 34,
    57, 226, 248, 181, 6, 5, 243, 107, 170, 99, 80, 56, 52, 141, 201, 132,
    25, 125, 109, 242, 147, 71, 225, 126, 17, 80, 194, 79, 247, 55, 222, 132 ]
def canonicalNativeRelationIdHex : String :=
  "180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d22" ++
  "39e2f8b50605f36baa635038348dc984"

def publicIdentityOpcode : Nat := 0x0201
def publicRangeOpcode : Nat := 0x0202
def intentZeroRangeOpcode : Nat := 0x0203
def domainOrMarkerOpcode : Nat := 0x0204
def compilerNormalizationOpcode : Nat := 0x0205
def nonlinearIdentityOpcode : Nat := 0x0401
def linearCsrFamilyOpcode : Nat := 0x0501
def spongeCallOpcode : Nat := 0x0601
def compress14CallOpcode : Nat := 0x0602
def bindingDescriptorOpcodeStart : Nat := 0x0701
def bindingDescriptorOpcodeStop : Nat := 0x0800
def expressionConstantOpcode : Nat := 0x01
def expressionPublicOpcode : Nat := 0x02
def expressionWitnessRowOpcode : Nat := 0x03
def expressionAddOpcode : Nat := 0x10
def expressionSubOpcode : Nat := 0x11
def expressionMulOpcode : Nat := 0x12
def expressionNegOpcode : Nat := 0x13
def expressionInverseOpcode : Nat := 0x14
def expressionSelectEqualOpcode : Nat := 0x15
def expressionBitOpcode : Nat := 0x16
def exactBindingDescriptorOpcodes : List Nat :=
  (List.range 8).map fun index => bindingDescriptorOpcodeStart + index
def exactPublicDescriptorOpcodes : List Nat :=
  [publicIdentityOpcode] ++ List.replicate 28 publicRangeOpcode ++
    List.replicate 4 intentZeroRangeOpcode ++ List.replicate 22 domainOrMarkerOpcode ++
    [compilerNormalizationOpcode]

def u16le (value : Nat) : List Nat :=
  [value % 256, (value / 256) % 256]

def u32le (value : Nat) : List Nat :=
  [value % 256, (value / 256) % 256,
    (value / 65536) % 256, (value / 16777216) % 256]

def u64le (value : Nat) : List Nat :=
  [value % 256, (value / 256) % 256,
    (value / 65536) % 256, (value / 16777216) % 256,
    (value / 4294967296) % 256, (value / 1099511627776) % 256,
    (value / 281474976710656) % 256, (value / 72057594037927936) % 256]

def asciiBytes (value : String) : List Nat :=
  value.toList.map Char.toNat

def encodeBlob (bytes : List Nat) : List Nat :=
  u32le bytes.length ++ bytes

structure ProgramDescriptor where
  opcode : Nat
  words : List Nat
  label : String
deriving DecidableEq, Repr

/--
Stable descriptor encoding: opcode, word count, u64 words, then one length-prefixed ASCII label.
Compound compiler labels join their ordered fields with byte zero; the outer u32 length makes the
separator unambiguous.
-/
def encodeDescriptor (descriptor : ProgramDescriptor) : List Nat :=
  u16le descriptor.opcode ++ u16le descriptor.words.length ++
    descriptor.words.flatMap u64le ++ encodeBlob (asciiBytes descriptor.label)

def encodeDescriptors (descriptors : List ProgramDescriptor) : List Nat :=
  u32le descriptors.length ++ descriptors.flatMap encodeDescriptor

inductive FieldExpression where
  | constant (value : Nat)
  | publicWord (index : Nat)
  | witnessRow (index : Nat)
  | add (left right : Nat)
  | sub (left right : Nat)
  | mul (left right : Nat)
  | neg (value : Nat)
  | inverse (value : Nat)
  | selectEqual (left right equal notEqual : Nat)
  | bit (value bit : Nat)
deriving DecidableEq, Repr

def encodeFieldExpression : FieldExpression → List Nat
  | .constant value => [expressionConstantOpcode] ++ u64le value
  | .publicWord index => [expressionPublicOpcode] ++ u16le index
  | .witnessRow index => [expressionWitnessRowOpcode] ++ u16le index
  | .add left right => [expressionAddOpcode] ++ u32le left ++ u32le right
  | .sub left right => [expressionSubOpcode] ++ u32le left ++ u32le right
  | .mul left right => [expressionMulOpcode] ++ u32le left ++ u32le right
  | .neg value => [expressionNegOpcode] ++ u32le value
  | .inverse value => [expressionInverseOpcode] ++ u32le value
  | .selectEqual left right equal notEqual =>
      [expressionSelectEqualOpcode] ++ u32le left ++ u32le right ++
        u32le equal ++ u32le notEqual
  | .bit value bitIndex => [expressionBitOpcode] ++ u32le value ++ [bitIndex % 256]

def FieldExpression.CanonicalAt
    (allowWitnessRows : Bool) (node : Nat) : FieldExpression → Prop
  | .constant value => value < 18446744069414584321
  | .publicWord index => index < publicStatementWordCount
  | .witnessRow index => allowWitnessRows = true ∧ index < 686
  | .add left right | .sub left right | .mul left right =>
      left < node ∧ right < node
  | .neg value | .inverse value => value < node
  | .selectEqual left right equal notEqual =>
      left < node ∧ right < node ∧ equal < node ∧ notEqual < node
  | .bit value bitIndex => value < node ∧ bitIndex < 64

structure ExpressionProgram where
  expressions : List FieldExpression
  roots : List Nat
deriving DecidableEq, Repr

def encodeExpressionProgram (program : ExpressionProgram) : List Nat :=
  u32le program.expressions.length ++ program.expressions.flatMap encodeFieldExpression ++
    u32le program.roots.length ++ program.roots.flatMap u32le

def ExpressionProgram.Canonical
    (program : ExpressionProgram) (allowWitnessRows : Bool) : Prop :=
  (∀ node expression, program.expressions[node]? = some expression →
      FieldExpression.CanonicalAt allowWitnessRows node expression) ∧
    ∀ root, root ∈ program.roots → root < program.expressions.length

structure CsrExecutableAttempt where
  globalIndex : Nat
  family : Nat
  localIndex : Nat
  emission : Nat
  terms : List (Nat × Nat)
  targetRoot : Nat
deriving DecidableEq, Repr

def encodeCsrExecutableAttempt (attempt : CsrExecutableAttempt) : List Nat :=
  u32le attempt.globalIndex ++ u16le attempt.family ++ u32le attempt.localIndex ++
    [attempt.emission % 256] ++ u16le attempt.terms.length ++
    attempt.terms.flatMap (fun term => u32le term.1 ++ u32le term.2) ++
    u32le attempt.targetRoot

def CsrExecutableAttempt.Canonical
    (expressionCount globalIndex : Nat) (attempt : CsrExecutableAttempt) : Prop :=
  attempt.globalIndex = globalIndex ∧ attempt.family < 86 ∧
    attempt.emission ≤ 1 ∧
    (∀ term, term ∈ attempt.terms → term.1 < packedWitnessWordCount ∧
      term.2 < expressionCount) ∧
    attempt.targetRoot < expressionCount

def encodeCsrExecutableProgram
    (expressions : List FieldExpression) (attempts : List CsrExecutableAttempt) : List Nat :=
  encodeBlob (encodeExpressionProgram { expressions, roots := [] }) ++
    u32le attempts.length ++ attempts.flatMap encodeCsrExecutableAttempt

structure RelationProgramComponents where
  /-- Exact ordered u64 geometry/version words. -/
  geometryWords : List Nat
  /-- Public map, relation version, semantic target, and domain descriptors. -/
  publicMapVersionDomain : List ProgramDescriptor
  /-- The 32-byte canonical Poseidon2 parameter-set manifest digest. -/
  poseidonParameterManifestDigest : List Nat
  /-- All nonlinear identities in evaluator order. -/
  nonlinearIdentities : List ProgramDescriptor
  /--
  Ordered compact CSR compiler families.  Their opcodes and words describe selectors, repeated
  index/coefficient shapes, and symbolic public targets; specializing a statement instantiates
  those targets but never changes this program.
  -/
  linearCsrCompilerFamilies : List ProgramDescriptor
  /-- Hash schedule and exact call-role descriptors. -/
  hashScheduleAndCallRoles : List ProgramDescriptor
  /-- Seven-limb relation binding and verifier-input descriptors. -/
  bindingDescriptors : List ProgramDescriptor
  /-- Exact shared executable nonlinear expression DAG and its 830 ordered roots. -/
  nonlinearExecutable : ExpressionProgram
  /-- Exact public-only expression DAG used by all 20,605 attempted CSR identities. -/
  csrExpressions : List FieldExpression
  /-- Every attempted CSR identity before statement specialization and normalized zero deletion. -/
  csrAttempts : List CsrExecutableAttempt
deriving DecidableEq, Repr

def nulSeparator : String := String.singleton (Char.ofNat 0)

def exactBindingDescriptors : List ProgramDescriptor :=
  [ { opcode := 0x0701, words := [8, 7, 1, 10, 2, 6, 4],
      label := "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2" ++
        nulSeparator ++ "SMZ9" },
    { opcode := 0x0702, words := [120, 18446744069414584321],
      label := "HGV8TX02.statement[0,120)->verifier.public[0,120);canonical-goldilocks" },
    { opcode := 0x0703, words := [7, 87, 94],
      label := "relation.binding[0,7)=expected-action-intent=call[93].final[0,7)" },
    { opcode := 0x0704, words := [0, 247, 247, 5, 252, 31, 283, 364, 647, 39, 686],
      label := "rows=raw[0,247);dense[247,252);inline[252,283);hash[283,647);stable[647,686)" },
    { opcode := 0x0705, words := [125, 128, 16, 48],
      label := "calls[125,128).initial[0,16)=0" },
    { opcode := 0x0706, words := [0], label := "auxiliary-witness-words=0" },
    { opcode := 0x0707,
      words := [64, 8, 830, 19935, 20509, 21339, 5, 6, 2, 23, 20, 5],
      label := "DirectPacked64Poseidon2V8Sha512Smz9" ++ nulSeparator ++
        "Sha512Poseidon2V8Smz9" ++ nulSeparator ++ "rho5-open6-beta2-N23-q20-eta5" },
    { opcode := 0x0708, words := [64, 48],
      label := "SHA-512" ++ nulSeparator ++ "HGV8RP03-canonical-executable-program-prefix[0,48)" } ]

def requiredGeometryWords : List Nat :=
  [ 18446744069414584321, -- Goldilocks modulus
    16, 8, 8, 7, 7, 8, 22, -- width/rate/capacity/digest/alpha/full/internal rounds
    120, 7, -- public statement and relation-binding limbs
    0, 247, 247, 5, 252, 31, -- raw/dense/inline partitions
    283, 364, 647, 39, 686, -- hash/stable/final row geometry
    64, 8, -- packing and maximum relation degree
    125, 128, 3, 2, -- live/padded/dummy calls and groups
    150, 182, 166, 332, -- S-box wires, rows and identities per group, hash identities
    830, 19935, 20509, 21339, -- nonlinear, min/max linear, summed union maximum
    368, 43904 ] -- proof columns and packed witness words

def poseidonParameterSetSha256 : List Nat :=
  [ 0x11, 0x4a, 0x4e, 0x7e, 0xb2, 0x68, 0x4d, 0x29,
    0x3d, 0x13, 0xd3, 0x06, 0xa7, 0x56, 0xb0, 0x3f,
    0xc7, 0x34, 0xf1, 0x9e, 0xdb, 0xfb, 0x80, 0xa0,
    0x71, 0x26, 0xab, 0x1b, 0x2a, 0xd9, 0xe5, 0x29 ]

def geometryPayload (components : RelationProgramComponents) : List Nat :=
  components.geometryWords.flatMap u64le

structure ProgramSection where
  tag : Nat
  itemCount : Nat
  payload : List Nat
deriving DecidableEq, Repr

/-- Section header is `u16 tag || u32 item_count || u64 payload_bytes`. -/
def encodeSection (entry : ProgramSection) : List Nat :=
  u16le entry.tag ++ u32le entry.itemCount ++ u64le entry.payload.length ++ entry.payload

def sections (components : RelationProgramComponents) : List ProgramSection :=
  [ { tag := 1, itemCount := components.geometryWords.length,
      payload := geometryPayload components },
    { tag := 2, itemCount := components.publicMapVersionDomain.length,
      payload := encodeDescriptors components.publicMapVersionDomain },
    { tag := 3, itemCount := 1,
      payload := components.poseidonParameterManifestDigest },
    { tag := 4, itemCount := components.nonlinearIdentities.length,
      payload := encodeDescriptors components.nonlinearIdentities },
    { tag := 5, itemCount := components.linearCsrCompilerFamilies.length,
      payload := encodeDescriptors components.linearCsrCompilerFamilies },
    { tag := 6, itemCount := components.hashScheduleAndCallRoles.length,
      payload := encodeDescriptors components.hashScheduleAndCallRoles },
    { tag := 7, itemCount := components.bindingDescriptors.length,
      payload := encodeDescriptors components.bindingDescriptors },
    { tag := 8, itemCount := components.nonlinearExecutable.roots.length,
      payload := encodeExpressionProgram components.nonlinearExecutable },
    { tag := 9, itemCount := components.csrAttempts.length,
      payload := encodeCsrExecutableProgram components.csrExpressions components.csrAttempts } ]

def canonicalProgramTranscript (components : RelationProgramComponents) : List Nat :=
  transcriptMagic ++ u16le transcriptGrammar ++ u16le transcriptSectionCount ++
    (sections components).flatMap encodeSection

def fieldModulus : Nat := 18446744069414584321
def fieldNormalize (value : Nat) : Nat := value % fieldModulus
def fieldAdd (left right : Nat) : Nat := fieldNormalize (left + right)
def fieldSub (left right : Nat) : Nat := fieldNormalize (left + fieldModulus - right)
def fieldMul (left right : Nat) : Nat := fieldNormalize (left * right)
def fieldInverse (value : Nat) : Nat :=
  if fieldNormalize value = 0 then 0
  else fieldNormalize (value ^ (fieldModulus - 2))

def evalFieldExpression
    (publicWords rows values : List Nat) : FieldExpression → Option Nat
  | .constant value => some (fieldNormalize value)
  | .publicWord index => publicWords[index]?.map fieldNormalize
  | .witnessRow index => rows[index]?.map fieldNormalize
  | .add left right => do
      let leftValue ← values[left]?
      let rightValue ← values[right]?
      some (fieldAdd leftValue rightValue)
  | .sub left right => do
      let leftValue ← values[left]?
      let rightValue ← values[right]?
      some (fieldSub leftValue rightValue)
  | .mul left right => do
      let leftValue ← values[left]?
      let rightValue ← values[right]?
      some (fieldMul leftValue rightValue)
  | .neg value => do
      let resolved ← values[value]?
      some (fieldSub 0 resolved)
  | .inverse value => do
      let resolved ← values[value]?
      some (fieldInverse resolved)
  | .selectEqual left right equal notEqual => do
      let leftValue ← values[left]?
      let rightValue ← values[right]?
      if leftValue = rightValue then values[equal]? else values[notEqual]?
  | .bit value bitIndex => do
      let resolved ← values[value]?
      some ((resolved / (2 ^ bitIndex)) % 2)

def evalExpressionNodes
    (publicWords rows : List Nat) (expressions : List FieldExpression) : Option (List Nat) :=
  let rec go (remaining : List FieldExpression) (values : List Nat) : Option (List Nat) :=
    match remaining with
    | [] => some values
    | expression :: tail => do
        let value ← evalFieldExpression publicWords rows values expression
        go tail (values ++ [value])
  go expressions []

def ExpressionProgram.EvaluatesTo
    (program : ExpressionProgram) (publicWords rows roots : List Nat) : Prop :=
  ∃ values,
    evalExpressionNodes publicWords rows program.expressions = some values ∧
      program.roots.map (fun root => values[root]?) = roots.map some

def ExpressionProgram.Accepts
    (program : ExpressionProgram) (publicWords rows : List Nat) : Prop :=
  program.EvaluatesTo publicWords rows (List.replicate program.roots.length 0)

def evalCsrTerms
    (expressionValues witness : List Nat) : List (Nat × Nat) → Option Nat
  | [] => some 0
  | (witnessIndex, coefficientRoot) :: tail => do
      let coefficient ← expressionValues[coefficientRoot]?
      let witnessValue ← witness[witnessIndex]?
      let rest ← evalCsrTerms expressionValues witness tail
      some (fieldAdd (fieldMul coefficient witnessValue) rest)

def CsrExecutableAttempt.Accepts
    (attempt : CsrExecutableAttempt) (expressionValues witness : List Nat) : Prop :=
  ∃ left target,
    evalCsrTerms expressionValues witness attempt.terms = some left ∧
      expressionValues[attempt.targetRoot]? = some target ∧ left = target

def csrExecutableProgramAccepts
    (expressions : List FieldExpression) (attempts : List CsrExecutableAttempt)
    (publicWords witness : List Nat) : Prop :=
  ∃ expressionValues,
    evalExpressionNodes publicWords [] expressions = some expressionValues ∧
      ∀ attempt, attempt ∈ attempts → attempt.Accepts expressionValues witness

def RelationProgramComponents.Accepts
    (components : RelationProgramComponents)
    (publicWords witnessRows packedWitness : List Nat) : Prop :=
  components.nonlinearExecutable.Accepts publicWords witnessRows ∧
    csrExecutableProgramAccepts components.csrExpressions components.csrAttempts
      publicWords packedWitness

/-- The 686 row scalars consumed by one packed lane of the Rust nonlinear interpreter. -/
def packedWitnessLaneRows (packedWitness : List Nat) (lane : Nat) : List Nat :=
  (List.range relationRowCount).map fun row =>
    packedWitness.getD (row * packingFactor + lane) 0

def CanonicalPublicWords (publicWords : List Nat) : Prop :=
  publicWords.length = publicStatementWordCount ∧
    ∀ word, word ∈ publicWords → word < fieldModulus

def CanonicalPackedWitness (packedWitness : List Nat) : Prop :=
  packedWitness.length = packedWitnessWordCount ∧
    ∀ word, word ∈ packedWitness → word < fieldModulus

/--
Exact source-adapter acceptance over the packed 686-by-64 witness.  Unlike `Accepts`, which is a
single-lane helper retained for older receipt types, this predicate checks the relation-id-bound
nonlinear program in every lane and the statement-specialized CSR program over the full packed
witness.
-/
def RelationProgramComponents.AcceptsPacked
    (components : RelationProgramComponents)
    (publicWords packedWitness : List Nat) : Prop :=
  CanonicalPublicWords publicWords ∧ CanonicalPackedWitness packedWitness ∧
    (∀ lane, lane < packingFactor →
      components.nonlinearExecutable.Accepts publicWords
        (packedWitnessLaneRows packedWitness lane)) ∧
    csrExecutableProgramAccepts components.csrExpressions components.csrAttempts
      publicWords packedWitness

theorem packed_witness_lane_rows_have_exact_relation_length
    (packedWitness : List Nat) (lane : Nat) :
    (packedWitnessLaneRows packedWitness lane).length = relationRowCount := by
  simp [packedWitnessLaneRows]

theorem packed_witness_lane_index_is_in_exact_rectangle
    {row lane : Nat} (rowBound : row < relationRowCount)
    (laneBound : lane < packingFactor) :
    row * packingFactor + lane < packedWitnessWordCount := by
  simp [relationRowCount, packingFactor, packedWitnessWordCount] at rowBound laneBound ⊢
  omega

theorem accepted_packed_program_checks_every_nonlinear_lane
    {components : RelationProgramComponents} {publicWords packedWitness : List Nat}
    (accepted : components.AcceptsPacked publicWords packedWitness)
    {lane : Nat} (laneBound : lane < packingFactor) :
    components.nonlinearExecutable.Accepts publicWords
      (packedWitnessLaneRows packedWitness lane) :=
  accepted.2.2.1 lane laneBound

theorem accepted_packed_program_checks_exact_csr
    {components : RelationProgramComponents} {publicWords packedWitness : List Nat}
    (accepted : components.AcceptsPacked publicWords packedWitness) :
    csrExecutableProgramAccepts components.csrExpressions components.csrAttempts
      publicWords packedWitness :=
  accepted.2.2.2

/-- Native leaf identity derived from an externally computed canonical 64-byte SHA-512 result. -/
def nativeRelationId (programSha512 : List Nat) : List Nat :=
  programSha512.take nativeRelationIdBytes

def descriptorCanonical (descriptor : ProgramDescriptor) : Prop :=
  descriptor.opcode < 65536 ∧ descriptor.words.length < 65536 ∧
    (∀ word, word ∈ descriptor.words → word < 18446744073709551616) ∧
    (∀ byte, byte ∈ asciiBytes descriptor.label → byte < 128)

/-- Exact source-artifact preconditions before hashing or constructing a refinement receipt. -/
def RelationProgramComponents.Canonical
    (components : RelationProgramComponents) : Prop :=
    components.geometryWords = requiredGeometryWords ∧
    components.poseidonParameterManifestDigest = poseidonParameterSetSha256 ∧
    components.nonlinearIdentities.length = 830 ∧
    components.linearCsrCompilerFamilies.length = 86 ∧
    components.hashScheduleAndCallRoles.length = 125 ∧
    components.nonlinearExecutable.expressions.length = 8271 ∧
    components.nonlinearExecutable.roots.length = 830 ∧
    components.nonlinearExecutable.Canonical true ∧
    components.csrExpressions.length = 565 ∧
    ({ expressions := components.csrExpressions, roots := [] } : ExpressionProgram).Canonical false ∧
    components.csrAttempts.length = 20605 ∧
    (∀ global attempt, components.csrAttempts[global]? = some attempt →
      attempt.Canonical components.csrExpressions.length global ∧
        attempt.localIndex =
          ((components.csrAttempts.take global).filter
            (fun prior => prior.family = attempt.family)).length ∧
        (components.linearCsrCompilerFamilies[attempt.family]?).map
            (fun descriptor => descriptor.words[2]?) = some (some attempt.emission)) ∧
    components.publicMapVersionDomain.map (fun descriptor => descriptor.opcode) =
      exactPublicDescriptorOpcodes ∧
    components.bindingDescriptors = exactBindingDescriptors ∧
    (∀ descriptor, descriptor ∈ components.publicMapVersionDomain →
      descriptor.opcode ∈
        [publicIdentityOpcode, publicRangeOpcode, intentZeroRangeOpcode,
          domainOrMarkerOpcode, compilerNormalizationOpcode]) ∧
    (∀ descriptor, descriptor ∈ components.nonlinearIdentities →
      descriptor.opcode = nonlinearIdentityOpcode) ∧
    (∀ descriptor, descriptor ∈ components.linearCsrCompilerFamilies →
      descriptor.opcode = linearCsrFamilyOpcode) ∧
    (∀ descriptor, descriptor ∈ components.hashScheduleAndCallRoles →
      descriptor.opcode = spongeCallOpcode ∨ descriptor.opcode = compress14CallOpcode) ∧
    (∀ descriptor, descriptor ∈ components.bindingDescriptors →
      bindingDescriptorOpcodeStart ≤ descriptor.opcode ∧
        descriptor.opcode < bindingDescriptorOpcodeStop) ∧
    (∀ descriptor,
      descriptor ∈ components.publicMapVersionDomain ∨
        descriptor ∈ components.nonlinearIdentities ∨
        descriptor ∈ components.linearCsrCompilerFamilies ∨
        descriptor ∈ components.hashScheduleAndCallRoles ∨
        descriptor ∈ components.bindingDescriptors →
      descriptorCanonical descriptor)

theorem transcript_framing_is_exact :
    transcriptMagic = [72, 71, 86, 56, 82, 80, 48, 51] ∧
      transcriptMagic.length = 8 ∧ transcriptGrammar = 3 ∧
      transcriptSectionCount = 9 ∧ transcriptDigestBytes = 64 ∧
      nativeRelationIdBytes = 48 := by
  decide

theorem canonical_program_identity_widths_are_exact :
    canonicalProgramArtifactAvailable = true ∧
      canonicalProgramTranscriptBytes = 853429 ∧
      canonicalProgramSha512.length = transcriptDigestBytes ∧
      (nativeRelationId canonicalProgramSha512).length = nativeRelationIdBytes ∧
      nativeRelationId canonicalProgramSha512 = canonicalProgramSha512.take 48 := by
  decide

theorem required_v8_geometry_is_exact :
    requiredGeometryWords.length = 37 ∧
      requiredGeometryWords[20]? = some 686 ∧
      requiredGeometryWords[31]? = some 830 ∧
      requiredGeometryWords[32]? = some 19935 ∧
      requiredGeometryWords[33]? = some 20509 ∧
      requiredGeometryWords[34]? = some 21339 ∧
      requiredGeometryWords[35]? = some 368 := by
  simp [requiredGeometryWords]

theorem native_relation_id_has_exact_length
    (programSha512 : List Nat) (digestLength : programSha512.length = 64) :
    (nativeRelationId programSha512).length = 48 := by
  simp [nativeRelationId, nativeRelationIdBytes, digestLength]

end Poseidon2V8RelationProgram
end Transaction
end Hegemon
