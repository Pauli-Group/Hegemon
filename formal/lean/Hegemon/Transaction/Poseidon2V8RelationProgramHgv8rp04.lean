import Hegemon.Transaction.Poseidon2V8RelationProgram

namespace Hegemon
namespace Transaction
namespace Poseidon2V8RelationProgramHgv8rp04

open Poseidon2V8RelationProgram

/-!
Canonical, statement-independent transcript for the executable V8 relation program.

The native `HGV8TX02` leaf carries 48 relation-id bytes.  Those bytes are the first 48 bytes of
SHA-512 over this exact transcript.  The SHA-512 input begins with the eight-byte `HGV8RP04`
magic, a little-endian grammar version and section count, followed by nine ordered, tagged,
length-delimited sections.  Statement *descriptors* occur in the transcript; statement values do
not.  Changing a transaction therefore cannot change the relation id.

This module fixes the encoding, required V8 shape, and source-recomputed program digest KAT.  It
defines an interpreter for the exact expression and CSR grammar, including all 64 packed witness
lanes.  The Rust source adapter is constructed directly from this program grammar; a compiled
machine-code equivalence theorem, semantic-target adequacy theorem, and production authority
remain separate boundaries.
-/

def transcriptMagic : List Nat := [72, 71, 86, 56, 82, 80, 48, 52] -- `HGV8RP04`
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
Source-recomputed known-answer identity for the current `HGV8RP04`-format program. These constants were frozen only after the
shared executable expression IR, the 92-family compiler cursor, all nine transcript sections, and
formula-level mutation tests agreed. They identify a program artifact; they do not by themselves
assert universal Rust/Lean semantic refinement or production authority.
-/
def canonicalProgramArtifactAvailable : Bool := true
def canonicalProgramTranscriptBytes : Nat := 843715
def canonicalProgramSha512Hex : String :=
  "580ee045ad26fe3f385185717107b7d669ef024a710f0525530d7c600b3dcecdc96963a01f327166dea78e9b93edb2097efb62adb101c6ce0518f6e7169848e6"
def canonicalProgramSha512 : List Nat :=
  [ 88, 14, 224, 69, 173, 38, 254, 63, 56, 81, 133, 113, 113, 7, 183, 214, 105, 239, 2, 74, 113, 15, 5, 37, 83, 13, 124, 96, 11, 61, 206, 205, 201, 105, 99, 160, 31, 50, 113, 102, 222, 167, 142, 155, 147, 237, 178, 9, 126, 251, 98, 173, 177, 1, 198, 206, 5, 24, 246, 231, 22, 152, 72, 230 ]
def canonicalNativeRelationIdHex : String :=
  "580ee045ad26fe3f385185717107b7d669ef024a710f0525530d7c600b3dcecdc96963a01f327166dea78e9b93edb209"

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
    List.replicate 4 intentZeroRangeOpcode ++ List.replicate 24 domainOrMarkerOpcode ++
    [compilerNormalizationOpcode]

def nulSeparator : String := String.singleton (Char.ofNat 0)

def exactBindingDescriptors : List ProgramDescriptor :=
  [ { opcode := 0x0701, words := [8, 7, 1, 10, 2, 6, 4],
      label := "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v3" ++
        nulSeparator ++ "SMZ9" },
    { opcode := 0x0702, words := [120, 18446744069414584321],
      label := "HGV8TX02.statement[0,120)->verifier.public[0,120);canonical-goldilocks" },
    { opcode := 0x0703, words := [7, 87, 94],
      label := "relation.binding[0,7)=expected-action-intent=call[95].final[0,7)" },
    { opcode := 0x0704, words := [0, 247, 247, 5, 252, 31, 283, 364, 647, 39, 686],
      label := "rows=raw[0,247);dense[247,252);inline[252,283);hash[283,647);stable[647,686)" },
    { opcode := 0x0705, words := [128, 128, 16, 0],
      label := "calls[128,128).initial[0,16)=0" },
    { opcode := 0x0706, words := [0], label := "auxiliary-witness-words=0" },
    { opcode := 0x0707,
      words := [64, 8, 773, 19838, 20510, 21283, 5, 6, 2, 23, 20, 5],
      label := "DirectPacked64Poseidon2V8Sha512Smz9" ++ nulSeparator ++
        "Sha512Poseidon2V8Smz9" ++ nulSeparator ++ "rho5-open6-beta2-N23-q20-eta5" },
    { opcode := 0x0708, words := [64, 48],
      label := "SHA-512" ++ nulSeparator ++ "HGV8RP04-canonical-executable-program-prefix[0,48)" } ]

def requiredGeometryWords : List Nat :=
  [ 18446744069414584321, -- Goldilocks modulus
    16, 8, 8, 7, 7, 8, 22, -- width/rate/capacity/digest/alpha/full/internal rounds
    120, 7, -- public statement and relation-binding limbs
    0, 247, 247, 5, 252, 31, -- raw/dense/inline partitions
    283, 364, 647, 39, 686, -- hash/stable/final row geometry
    64, 8, -- packing and maximum relation degree
    128, 128, 0, 2, -- live/padded/dummy calls and groups
    150, 182, 166, 332, -- S-box wires, rows and identities per group, hash identities
    773, 19838, 20510, 21283, -- nonlinear, min/max linear, summed union maximum
    368, 43904 ] -- proof columns and packed witness words

def poseidonParameterSetSha256 : List Nat :=
  [ 0x11, 0x4a, 0x4e, 0x7e, 0xb2, 0x68, 0x4d, 0x29,
    0x3d, 0x13, 0xd3, 0x06, 0xa7, 0x56, 0xb0, 0x3f,
    0xc7, 0x34, 0xf1, 0x9e, 0xdb, 0xfb, 0x80, 0xa0,
    0x71, 0x26, 0xab, 0x1b, 0x2a, 0xd9, 0xe5, 0x29 ]

def canonicalProgramTranscript (components : RelationProgramComponents) : List Nat :=
  transcriptMagic ++ u16le transcriptGrammar ++ u16le transcriptSectionCount ++
    (sections components).flatMap encodeSection

def nativeRelationId (programSha512 : List Nat) : List Nat :=
  programSha512.take nativeRelationIdBytes

def descriptorCanonical (descriptor : ProgramDescriptor) : Prop :=
  descriptor.opcode < 65536 ∧ descriptor.words.length < 65536 ∧
    (∀ word, word ∈ descriptor.words → word < 18446744073709551616) ∧
    (∀ byte, byte ∈ asciiBytes descriptor.label → byte < 128)

/-- Same generic CSR grammar, with this candidate's exact family bound. -/
def csrAttemptCanonical
    (expressionCount globalIndex : Nat) (attempt : CsrExecutableAttempt) : Prop :=
  attempt.globalIndex = globalIndex ∧ attempt.family < 92 ∧
    attempt.emission ≤ 1 ∧
    (∀ term, term ∈ attempt.terms → term.1 < packedWitnessWordCount ∧
      term.2 < expressionCount) ∧
    attempt.targetRoot < expressionCount

/-- Exact source-artifact preconditions before hashing or constructing a refinement receipt. -/
def candidateCanonical
    (components : RelationProgramComponents) : Prop :=
    components.geometryWords = requiredGeometryWords ∧
    components.poseidonParameterManifestDigest = poseidonParameterSetSha256 ∧
    components.nonlinearIdentities.length = 773 ∧
    components.linearCsrCompilerFamilies.length = 92 ∧
    components.hashScheduleAndCallRoles.length = 128 ∧
    components.nonlinearExecutable.expressions.length = 8130 ∧
    components.nonlinearExecutable.roots.length = 773 ∧
    components.nonlinearExecutable.Canonical true ∧
    components.csrExpressions.length = 564 ∧
    ({ expressions := components.csrExpressions, roots := [] } : ExpressionProgram).Canonical false ∧
    components.csrAttempts.length = 20602 ∧
    (∀ global attempt, components.csrAttempts[global]? = some attempt →
      csrAttemptCanonical components.csrExpressions.length global attempt ∧
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
    transcriptMagic = [72, 71, 86, 56, 82, 80, 48, 52] ∧
      transcriptMagic.length = 8 ∧ transcriptGrammar = 3 ∧
      transcriptSectionCount = 9 ∧ transcriptDigestBytes = 64 ∧
      nativeRelationIdBytes = 48 := by
  decide

theorem canonical_program_identity_widths_are_exact :
    canonicalProgramArtifactAvailable = true ∧
      canonicalProgramTranscriptBytes = 843715 ∧
      canonicalProgramSha512.length = transcriptDigestBytes ∧
      (nativeRelationId canonicalProgramSha512).length = nativeRelationIdBytes ∧
      nativeRelationId canonicalProgramSha512 = canonicalProgramSha512.take 48 := by
  decide

theorem required_v8_geometry_is_exact :
    requiredGeometryWords.length = 37 ∧
      requiredGeometryWords[20]? = some 686 ∧
      requiredGeometryWords[31]? = some 773 ∧
      requiredGeometryWords[32]? = some 19838 ∧
      requiredGeometryWords[33]? = some 20510 ∧
      requiredGeometryWords[34]? = some 21283 ∧
      requiredGeometryWords[35]? = some 368 := by
  simp [requiredGeometryWords]

theorem native_relation_id_has_exact_length
    (programSha512 : List Nat) (digestLength : programSha512.length = 64) :
    (nativeRelationId programSha512).length = 48 := by
  simp [nativeRelationId, nativeRelationIdBytes, digestLength]

end Poseidon2V8RelationProgramHgv8rp04
end Transaction
end Hegemon
