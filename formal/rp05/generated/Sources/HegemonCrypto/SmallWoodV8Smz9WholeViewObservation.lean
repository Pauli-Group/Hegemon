import HegemonCrypto.SmallWoodV8Smz9RuntimeRandomness
import HegemonCrypto.SmallWoodSha512Xof

/-!
# Executable internal whole-view audit records for SMZ9

This module defines a source-shaped internal audit record for the honest SMZ9
verifier replay and the strict whole-view simulator replay.  Unlike the older
`Smz9WholeView`, that record retains the raw `u64` SHA-512 keys, the complete
program table, the ordered query trace, both verifier results, the Merkle
program histogram, and mode-specific coin accounting.  Those internal fields
are not an adversary-visible transcript.

The constructors below are deterministic validators, not security receipts.
They parse the actual `SMZ9` proof wire and derive every field available from
those bytes.  Data which the proof does not carry -- public statement and
binded-data bytes, verifier trace internals, ordered raw-oracle queries, and
runtime draw ledgers -- is explicit input and is checked against the exact
source grammar wherever the checked-in model permits.  In particular, no
refinement currently derives the two public-context byte strings from the Rust
`statement` adapter and `binded_data` argument.  A universal Rust-to-Lean
execution-trace refinement is still absent.  The fixtures below use the
minimal parser vector; they do not enforce the production matrix dimensions or
execute the Rust verifier.

No distribution, coupling, indistinguishability, QROM, or production claim is
stated here.
-/

namespace HegemonCrypto.SmallWood.V8Smz9WholeViewObservation

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWoodProofWire
open HegemonCrypto.SmallWoodSmz9ProofWire
open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.SmallWood.Sha512Xof
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness

set_option maxHeartbeats 0
set_option maxRecDepth 100000

abbrev RawWord := Nat
abbrev FieldWord := Fin fieldModulus
abbrev Sha512Digest := { bytes : List Byte // bytes.length = 64 }
abbrev ConcreteRawOracle := List Byte → Sha512Digest

def rawWordCardinality : Nat := 2 ^ 64
def smz9MerkleDepth : Nat := 23
def smz9OpenedLeaves : Nat := 20
def smz9CommittedEvaluationCount : Nat := 140
def smz9MaskingEvaluationCount : Nat := 5
def smz9FinalPiopInputWordCount : Nat :=
  SmallWoodTranscript.digestWordCount +
    V8Smz9ZeroKnowledge.nonlinearMaskPolynomialCount *
      (V8Smz9ZeroKnowledge.nonlinearMaskPolynomialDegree + 1) +
    V8Smz9ZeroKnowledge.linearMaskPolynomialCount *
      V8Smz9ZeroKnowledge.linearMaskPolynomialDegree

/-- SMZ9's refined wire carries no auxiliary witness words in either view. -/
def smz9RawWitnessWordsConsumed : Nat := 0

def smz9ProfileDomain : List Byte :=
  [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119,
    111, 111, 100, 46, 112, 111, 115, 101, 105, 100, 111, 110, 50, 45,
    118, 56, 46, 115, 109, 122, 57, 46, 115, 104, 97, 53, 49, 50, 46,
    112, 114, 111, 102, 105, 108, 101, 46, 118, 49]

def strictZkMerkleLeafDomain : List Byte :=
  [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119,
    111, 111, 100, 46, 115, 116, 114, 105, 99, 116, 45, 122, 107, 46,
    109, 101, 114, 107, 108, 101, 45, 108, 101, 97, 102, 46, 118, 49]

/-- Exact `SMALLWOOD_XOF_DOMAIN` bytes from `smallwood_engine.rs`. -/
def fieldXofDomain : List Byte :=
  [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119,
    111, 111, 100, 46, 102, 54, 52, 45, 120, 111, 102, 46, 118, 49]

/-- Exact `SMALLWOOD_COMPRESS2_DOMAIN` bytes from `smallwood_engine.rs`. -/
def compress2Domain : List Byte :=
  [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119,
    111, 111, 100, 46, 102, 54, 52, 45, 99, 111, 109, 112, 114, 101,
    115, 115, 50, 46, 118, 49]

/-- Every raw SHA-512 role registered by the shared engine dispatch. -/
def engineRawSha512RoleDomains : List (List Byte) :=
  [fieldXofDomain, compress2Domain, decsFixedSamplingDomain, piopInputDomain,
    piopTranscriptDomain, decsOpeningDomain, merkleLeafDomain,
    strictZkMerkleLeafDomain, merkleNodeDomain, merkleRootDomain,
    decsCoefficientDomain, piopCoefficientDomain, piopOpeningDomain,
    decsQueryDomain]

/--
Exact reachable role domains in an SMZ9 verifier replay.  The refined wire
always takes the strict-leaf branch, and the SHA-512 backend always takes the
fixed no-grinding DECS sampler, so the generic leaf and legacy DECS-query roles
are deliberately absent.  The engine-only XOF/compress roles are not called by
the verifier path either.
-/
def smz9VerifierRawSha512RoleDomains : List (List Byte) :=
  [decsFixedSamplingDomain, piopInputDomain, piopTranscriptDomain,
    decsOpeningDomain, strictZkMerkleLeafDomain, merkleNodeDomain,
    merkleRootDomain, decsCoefficientDomain, piopCoefficientDomain,
    piopOpeningDomain]

theorem exact_source_constants :
    smz9FinalPiopInputWordCount = 3113 ∧
      smz9RawWitnessWordsConsumed = 0 ∧
      smz9ProfileDomain.length = 53 ∧
      strictZkMerkleLeafDomain.length = 42 ∧
      fieldXofDomain.length = 28 ∧
      compress2Domain.length = 34 ∧
      engineRawSha512RoleDomains.length = 14 ∧
      engineRawSha512RoleDomains.Nodup ∧
      smz9VerifierRawSha512RoleDomains.length = 10 ∧
      smz9VerifierRawSha512RoleDomains.Nodup ∧
      ∀ domain ∈ smz9VerifierRawSha512RoleDomains,
        domain ∈ engineRawSha512RoleDomains := by
  decide

def digestOfBytes? (bytes : List Byte) : Option Sha512Digest :=
  if exact : bytes.length = 64 then some ⟨bytes, exact⟩ else none

def Sha512Digest.zero : Sha512Digest :=
  ⟨List.replicate 64 0, by simp⟩

def Sha512Digest.rawWords (digest : Sha512Digest) : List RawWord :=
  (List.range 8).map fun index =>
    decodeLE ((digest.val.drop (index * 8)).take 8)

def bytesToRawWords? (bytes : List Byte) : Option (List RawWord) :=
  if _aligned : bytes.length % 8 = 0 then
    some ((List.range (bytes.length / 8)).map fun index =>
      decodeLE ((bytes.drop (index * 8)).take 8))
  else
    none

structure RawSha512OracleKey where
  profileDomain : Option (List Byte)
  roleDomain : List Byte
  words : List RawWord
  counter : RawWord
deriving DecidableEq, Repr

def RawSha512OracleKey.Canonical (key : RawSha512OracleKey) : Prop :=
  key.profileDomain = some smz9ProfileDomain ∧
    key.roleDomain ∈ smz9VerifierRawSha512RoleDomains ∧
    key.words.Forall (fun word => word < rawWordCardinality) ∧
    key.counter < rawWordCardinality

instance (key : RawSha512OracleKey) : Decidable key.Canonical := by
  unfold RawSha512OracleKey.Canonical
  infer_instance

/-- Exact preimage consumed by `concrete_smallwood_sha512_oracle_query_v1`. -/
def RawSha512OracleKey.preimage (key : RawSha512OracleKey) : List Byte :=
  (match key.profileDomain with
    | none => []
    | some domain => encodeLE 8 domain.length ++ domain) ++
  encodeLE 8 key.roleDomain.length ++ key.roleDomain ++
  encodeLE 8 key.words.length ++
  (key.words.map (encodeLE 8)).flatten ++
  encodeLE 8 key.counter

inductive OracleProgramKind where
  | lazyMerkle
  | finalPiop
deriving DecidableEq, Repr

structure RawSha512OracleProgram where
  key : RawSha512OracleKey
  output : Sha512Digest
  kind : OracleProgramKind
deriving DecidableEq

structure RawSha512OracleQuery where
  key : RawSha512OracleKey
  output : Sha512Digest
  programmedKind : Option OracleProgramKind
deriving DecidableEq

structure OracleReplayReceipt where
  programCount : Nat
  queryCount : Nat
  finalPiopProgramHits : Nat
  lazyMerkleProgramHits : Nat
deriving DecidableEq, Repr

structure OracleReplayResult where
  receipt : OracleReplayReceipt
  verifierAccepts : Bool
deriving DecidableEq, Repr

inductive ProgrammedMerkleInput where
  | strictZkLeaf
      (tape : Sha512Digest)
      (committedEvaluations : List FieldWord)
      (maskingEvaluations : List FieldWord)
  | merkleNode (left right : Sha512Digest)
deriving DecidableEq

structure ProgrammedMerkleNode where
  level : Nat
  nodeIndex : Nat
  input : ProgrammedMerkleInput
  digest : Sha512Digest
deriving DecidableEq

structure ProgrammedMerkleHistogram where
  levelCounts : List Nat
  strictLeafPrograms : Nat
  internalNodePrograms : Nat
  totalPrograms : Nat
deriving DecidableEq, Repr

structure HonestCoinLedgerInput where
  fieldCandidateWords : Nat
  fieldRejections : Nat
  successfulGetrandomFillCalls : Nat
  sourceBytes : Nat
deriving DecidableEq, Repr

structure HonestCoinLedger where
  fieldCandidateWords : Nat
  fieldRejections : Nat
  acceptedFieldWords : Nat
  saltBytes : Nat
  fullLeafTapeCoins512 : Nat
  leafTapeBytesEach : Nat
  successfulGetrandomFillCalls : Nat
  sourceBytes : Nat
deriving DecidableEq, Repr

structure SimulatorCoinLedger where
  canonicalFieldCoins : Nat
  openedLeafTapeCoins512 : Nat
  programmedLeafInputCoins512 : Nat
  programmedInternalInputCoins1024 : Nat
  programmedOutputCoins512 : Nat
  finalOutputCoins512 : Nat
  allSuppliedCoinsConsumed : Bool
deriving DecidableEq, Repr

inductive WholeViewCoinLedger where
  | honest (ledger : HonestCoinLedger)
  | simulator (ledger : SimulatorCoinLedger)
deriving DecidableEq, Repr

/--
An internal carrier for the three verifier audit components consumed below.  `Payload`
may hold the remaining fields of Rust `SmallwoodVerifierTraceV1`, but it is
not inspected and deliberately unvalidated here; only the final PIOP input, DECS leaf
indexes, and acceptance bit have executable checks in this module.  The
simulator constructor requires the two payload values to agree but does not
establish what either value means.
-/
structure VerifierTrace (Payload : Type) where
  payload : Payload
  piopTranscriptWords : List RawWord
  decsLeafIndexes : List Nat
  accepts : Bool
deriving DecidableEq

inductive ObservationOrigin where
  | honest
  | simulator
deriving DecidableEq, Repr

/--
The complete internal audit record.  It intentionally retains simulator-only
state and must not itself be treated as an adversary-visible observation.
-/
structure Smz9WholeViewObservation (VerifierPayload : Type) where
  origin : ObservationOrigin
  /-- Explicit public context; Rust statement-serialization refinement is absent. -/
  publicStatementBytes : List Byte
  /-- Explicit public context; Rust `binded_data` refinement is absent. -/
  bindedDataBytes : List Byte
  proofBytes : List Byte
  decodedProof : SmallWoodSmz9ProofWire.ProofWire
  authenticationPaths : List (List Sha512Digest)
  openedLeafTapes : List Sha512Digest
  verifierTrace : VerifierTrace VerifierPayload
  concreteVerifierTrace : VerifierTrace VerifierPayload
  programmedMerkleNodes : List ProgrammedMerkleNode
  programmedFinalPiopInputWords : List RawWord
  programmedFinalPiopOutput : Option Sha512Digest
  oracleProgramTable : List RawSha512OracleProgram
  priorSha512Queries : List RawSha512OracleKey
  orderedOracleQueryTrace : List RawSha512OracleQuery
  replay : OracleReplayResult
  programmedMerkleHistogram : ProgrammedMerkleHistogram
  coinLedger : WholeViewCoinLedger
  rawWitnessWordsConsumed : Nat
  concreteSha512Accepts : Bool
deriving DecidableEq

/--
The minimal static result exposed by one verifier call in this model.  It
deliberately excludes origin, decoded wire state,
oracle programs and prior queries, ordered execution traces, verifier-trace
internals, concrete-replay diagnostics, replay receipts, histograms, and coin
ledgers.  The single acceptance bit is the active replay outcome, not the
counterfactual concrete-SHA-512 diagnostic.

This projection is not a complete ROM/QROM adversary view, distribution, or
privacy claim: an oracle adversary also observes and controls an interactive
query interface.  In particular, the public-context bytes are copied from
explicit inputs because their Rust provenance has not been refined into Lean.
-/
structure StaticVerifierObservation where
  publicStatementBytes : List Byte
  bindedDataBytes : List Byte
  proofBytes : List Byte
  verifierAccepts : Bool
deriving DecidableEq, Repr

/-- Deterministically erase every internal audit field. -/
def Smz9WholeViewObservation.toStaticVerifierObservation
    {VerifierPayload : Type}
    (observation : Smz9WholeViewObservation VerifierPayload) :
    StaticVerifierObservation :=
  { publicStatementBytes := observation.publicStatementBytes
    bindedDataBytes := observation.bindedDataBytes
    proofBytes := observation.proofBytes
    verifierAccepts := observation.replay.verifierAccepts }

@[simp] theorem toStaticVerifierObservation_publicStatementBytes
    {VerifierPayload : Type}
    (observation : Smz9WholeViewObservation VerifierPayload) :
    observation.toStaticVerifierObservation.publicStatementBytes =
      observation.publicStatementBytes := rfl

@[simp] theorem toStaticVerifierObservation_bindedDataBytes
    {VerifierPayload : Type}
    (observation : Smz9WholeViewObservation VerifierPayload) :
    observation.toStaticVerifierObservation.bindedDataBytes = observation.bindedDataBytes := rfl

@[simp] theorem toStaticVerifierObservation_proofBytes
    {VerifierPayload : Type}
    (observation : Smz9WholeViewObservation VerifierPayload) :
    observation.toStaticVerifierObservation.proofBytes = observation.proofBytes := rfl

@[simp] theorem toStaticVerifierObservation_verifierAccepts
    {VerifierPayload : Type}
    (observation : Smz9WholeViewObservation VerifierPayload) :
    observation.toStaticVerifierObservation.verifierAccepts =
      observation.replay.verifierAccepts := rfl

theorem toStaticVerifierObservation_eq_iff
    {VerifierPayload : Type}
    (left right : Smz9WholeViewObservation VerifierPayload) :
    left.toStaticVerifierObservation = right.toStaticVerifierObservation ↔
      left.publicStatementBytes = right.publicStatementBytes ∧
      left.bindedDataBytes = right.bindedDataBytes ∧
      left.proofBytes = right.proofBytes ∧
      left.replay.verifierAccepts = right.replay.verifierAccepts := by
  constructor
  · intro equality
    exact ⟨congrArg StaticVerifierObservation.publicStatementBytes equality,
      congrArg StaticVerifierObservation.bindedDataBytes equality,
      congrArg StaticVerifierObservation.proofBytes equality,
      congrArg StaticVerifierObservation.verifierAccepts equality⟩
  · rintro ⟨statementEquality, bindedDataEquality, proofEquality, acceptEquality⟩
    cases left
    cases right
    simp_all [Smz9WholeViewObservation.toStaticVerifierObservation]

/-! ## Wire-derived authentication paths -/

def decodeDigestList : Nat → List Byte → Option (List Sha512Digest × List Byte)
  | 0, bytes => some ([], bytes)
  | count + 1, bytes => do
      let (headBytes, rest) ← readFixed 64 bytes
      let head ← digestOfBytes? headBytes
      let (tail, suffix) ← decodeDigestList count rest
      some (head :: tail, suffix)

def splitDigestPaths : List Byte → List Sha512Digest → Option (List (List Sha512Digest))
  | [], digests => if digests = [] then some [] else none
  | lengthByte :: lengths, digests => do
      if lengthByte.val ≤ digests.length then
        let head := digests.take lengthByte.val
        let tail ← splitDigestPaths lengths (digests.drop lengthByte.val)
        some (head :: tail)
      else
        none

def decodeAuthenticationPaths
    (proof : SmallWoodSmz9ProofWire.ProofWire) : Option (List (List Sha512Digest)) := do
  let auth := proof.pcs.decs.authPaths
  let (digests, suffix) ← decodeDigestList auth.nodeCount auth.nodeBytes
  if suffix = [] then splitDigestPaths auth.pathLengthBytes digests else none

def decodeOpenedLeafTapes
    (proof : SmallWoodSmz9ProofWire.ProofWire) : Option (List Sha512Digest) := do
  let (digests, suffix) ← decodeDigestList smz9OpenedLeaves proof.pcs.decs.leafTapeBytes
  if suffix = [] then some digests else none

/-! ## Exact compact-path positions -/

structure ExpectedProgram where
  level : Nat
  nodeIndex : Nat
  digest : Sha512Digest
deriving DecidableEq

def ExpectedProgram.samePosition (left right : ExpectedProgram) : Bool :=
  left.level == right.level && left.nodeIndex == right.nodeIndex

def insertExpectedProgram
    (entry : ExpectedProgram)
    (entries : List ExpectedProgram) : Option (List ExpectedProgram) :=
  match entries.find? fun candidate => candidate.samePosition entry with
  | none => some (entries ++ [entry])
  | some existing => if existing.digest = entry.digest then some entries else none

def consumeCompactLevel
    (level : Nat)
    (openedAtLevel : List Nat) :
    List Nat → List (List Sha512Digest) → List ExpectedProgram →
      Option (List (List Sha512Digest) × List ExpectedProgram)
  | [], [], programs => some ([], programs)
  | index :: indices, path :: paths, programs => do
      let sibling := if index % 2 = 0 then index + 1 else index - 1
      let (remainingPath, updatedPrograms) ←
        if sibling ∈ openedAtLevel then
          some (path, programs)
        else
          match path with
          | [] => none
          | digest :: remaining => do
              let inserted ← insertExpectedProgram ⟨level, sibling, digest⟩ programs
              some (remaining, inserted)
      let (remainingPaths, finalPrograms) ←
        consumeCompactLevel level openedAtLevel indices paths updatedPrograms
      some (remainingPath :: remainingPaths, finalPrograms)
  | _, _, _ => none

def extractExpectedProgramsAux :
    Nat → Nat → List Nat → List (List Sha512Digest) →
      List ExpectedProgram → Option (List ExpectedProgram)
  | 0, _, _, paths, programs =>
      if paths.all List.isEmpty then some programs else none
  | remaining + 1, level, indices, paths, programs => do
      let (remainingPaths, updatedPrograms) ←
        consumeCompactLevel level indices indices paths programs
      extractExpectedProgramsAux remaining (level + 1)
        (indices.map fun index => index / 2) remainingPaths updatedPrograms

def extractExpectedPrograms
    (leafIndexes : List Nat)
    (paths : List (List Sha512Digest)) : Option (List ExpectedProgram) := do
  if leafIndexes.length = smz9OpenedLeaves ∧
      paths.length = smz9OpenedLeaves ∧
      leafIndexes.all (fun index => index < 2 ^ smz9MerkleDepth) ∧
      leafIndexes.Nodup then
    extractExpectedProgramsAux smz9MerkleDepth 0 leafIndexes paths []
  else
    none

def merklePositionLt (left right : ProgrammedMerkleNode) : Bool :=
  left.level < right.level ||
    (left.level == right.level && left.nodeIndex < right.nodeIndex)

def merklePositionsStrictlyIncreasing : List ProgrammedMerkleNode → Bool
  | [] | [_] => true
  | left :: right :: rest =>
      merklePositionLt left right &&
        merklePositionsStrictlyIncreasing (right :: rest)

def nodeMatchesExpected (node : ProgrammedMerkleNode) (expected : ExpectedProgram) : Bool :=
  node.level == expected.level && node.nodeIndex == expected.nodeIndex &&
    node.digest == expected.digest

def nodesMatchExpected
    (nodes : List ProgrammedMerkleNode)
    (expected : List ExpectedProgram) : Bool :=
  nodes.length == expected.length &&
    expected.all fun entry => nodes.any fun node => nodeMatchesExpected node entry

/-! ## Program table, trace, histogram, and ledger derivation -/

def fieldWordAsRaw (word : FieldWord) : RawWord := word.val

def rawKey
    (roleDomain : List Byte)
    (words : List RawWord)
    (counter : RawWord := 0) : RawSha512OracleKey :=
  { profileDomain := some smz9ProfileDomain, roleDomain, words, counter }

def programmedMerkleProgram
    (proof : SmallWoodSmz9ProofWire.ProofWire)
    (node : ProgrammedMerkleNode) : Option RawSha512OracleProgram := do
  if node.level < smz9MerkleDepth ∧
      node.nodeIndex < 2 ^ (smz9MerkleDepth - node.level) then
    let saltWords ← bytesToRawWords? proof.saltBytes
    match node.level, node.input with
    | 0, .strictZkLeaf tape committed masking =>
        if committed.length = smz9CommittedEvaluationCount ∧
            masking.length = smz9MaskingEvaluationCount then
          let words := saltWords ++ [node.nodeIndex] ++ tape.rawWords ++
            [committed.length] ++ committed.map fieldWordAsRaw ++
            [masking.length] ++ masking.map fieldWordAsRaw
          some ⟨rawKey strictZkMerkleLeafDomain words, node.digest, .lazyMerkle⟩
        else none
    | _level + 1, .merkleNode left right =>
        some ⟨rawKey merkleNodeDomain (left.rawWords ++ right.rawWords),
          node.digest, .lazyMerkle⟩
    | _, _ => none
  else
    none

def finalPiopProgram
    (inputWords : List RawWord)
    (output : Sha512Digest) : RawSha512OracleProgram :=
  ⟨rawKey piopTranscriptDomain inputWords, output, .finalPiop⟩

def buildProgramTable
    (proof : SmallWoodSmz9ProofWire.ProofWire)
    (nodes : List ProgrammedMerkleNode)
    (finalPiopInputWords : List RawWord)
    (finalPiopOutput : Sha512Digest) : Option (List RawSha512OracleProgram) := do
  let merklePrograms ← nodes.mapM (programmedMerkleProgram proof)
  let table := merklePrograms ++ [finalPiopProgram finalPiopInputWords finalPiopOutput]
  if table.Pairwise fun left right => left.key ≠ right.key then some table else none

def histogram (nodes : List ProgrammedMerkleNode) : ProgrammedMerkleHistogram :=
  let leafCount := nodes.countP fun node => node.level = 0
  let internalCount := nodes.length - leafCount
  { levelCounts := (List.range smz9MerkleDepth).map fun level =>
      nodes.countP fun node => node.level = level
    strictLeafPrograms := leafCount
    internalNodePrograms := internalCount
    totalPrograms := nodes.length }

def lookupProgram
    (table : List RawSha512OracleProgram)
    (key : RawSha512OracleKey) : Option RawSha512OracleProgram :=
  table.find? fun program => program.key = key

def queryConsistent
    (oracle : ConcreteRawOracle)
    (table : List RawSha512OracleProgram)
    (query : RawSha512OracleQuery) : Bool :=
  match lookupProgram table query.key with
  | some program =>
      query.programmedKind == some program.kind && query.output == program.output
  | none =>
      query.programmedKind == none && query.output == oracle query.key.preimage

def replayReceipt
    (table : List RawSha512OracleProgram)
    (queries : List RawSha512OracleQuery) : OracleReplayReceipt :=
  { programCount := table.length
    queryCount := queries.length
    finalPiopProgramHits := queries.countP fun query =>
      query.programmedKind = some .finalPiop
    lazyMerkleProgramHits := queries.countP fun query =>
      query.programmedKind = some .lazyMerkle }

def natStrictlyIncreasing : List Nat → Bool
  | [] | [_] => true
  | left :: right :: rest => left < right && natStrictlyIncreasing (right :: rest)

def traceShapeValid {Payload : Type} (trace : VerifierTrace Payload) : Bool :=
  trace.piopTranscriptWords.length == smz9FinalPiopInputWordCount &&
    trace.piopTranscriptWords.all (fun word => word < rawWordCardinality) &&
    trace.decsLeafIndexes.length == smz9OpenedLeaves &&
    trace.decsLeafIndexes.all (fun index => index < 2 ^ smz9MerkleDepth) &&
    natStrictlyIncreasing trace.decsLeafIndexes

def honestMinimumFieldFillCalls : Nat := 901
def honestLeafTapeFillCalls : Nat := 2048
def honestMinimumGetrandomFillCalls : Nat :=
  1 + honestMinimumFieldFillCalls + honestLeafTapeFillCalls

theorem exact_honest_fill_call_constants :
    honestMinimumFieldFillCalls = 901 ∧
      honestLeafTapeFillCalls = 2048 ∧
      honestMinimumGetrandomFillCalls = 2950 := by
  decide

def honestCoinLedger?
    (input : HonestCoinLedgerInput) : Option HonestCoinLedger :=
  if input.fieldCandidateWords = honestAlgebraicFieldCoinCount + input.fieldRejections ∧
      honestMinimumGetrandomFillCalls ≤ input.successfulGetrandomFillCalls ∧
      input.successfulGetrandomFillCalls ≤
        honestMinimumGetrandomFillCalls + input.fieldRejections ∧
      input.sourceBytes = honestSaltBytes + 8 * input.fieldCandidateWords + honestLeafTapeBytes then
    some
      { fieldCandidateWords := input.fieldCandidateWords
        fieldRejections := input.fieldRejections
        acceptedFieldWords := honestAlgebraicFieldCoinCount
        saltBytes := honestSaltBytes
        fullLeafTapeCoins512 := honestLeafTapeCount
        leafTapeBytesEach := honestLeafTapeBytesEach
        successfulGetrandomFillCalls := input.successfulGetrandomFillCalls
        sourceBytes := input.sourceBytes }
  else
    none

/-!
The strict simulator supplies the 12,201 honest algebraic coordinates plus
the 20-by-5 opened DECS mask evaluations which are derived, rather than
independently sampled, in the honest prover.
-/
def simulatorBaseFieldCoins : Nat :=
  honestAlgebraicFieldCoinCount +
    smz9OpenedLeaves * smz9MaskingEvaluationCount
def simulatorHiddenLeafFieldCoins : Nat :=
  smz9CommittedEvaluationCount + smz9MaskingEvaluationCount

theorem exact_simulator_coin_constants :
    simulatorBaseFieldCoins = 12301 ∧ simulatorHiddenLeafFieldCoins = 145 := by
  decide

def simulatorCoinLedgerValid
    (ledger : SimulatorCoinLedger)
    (nodes : List ProgrammedMerkleNode)
    (nodeHistogram : ProgrammedMerkleHistogram) : Bool :=
  ledger.canonicalFieldCoins ==
      simulatorBaseFieldCoins + simulatorHiddenLeafFieldCoins * nodeHistogram.strictLeafPrograms &&
    ledger.openedLeafTapeCoins512 == smz9OpenedLeaves &&
    ledger.programmedLeafInputCoins512 == nodeHistogram.strictLeafPrograms &&
    ledger.programmedInternalInputCoins1024 == nodeHistogram.internalNodePrograms &&
    ledger.programmedOutputCoins512 == nodes.length &&
    ledger.finalOutputCoins512 == 1 && ledger.allSuppliedCoinsConsumed

def inputDigestList (nodes : List ProgrammedMerkleNode) : List Sha512Digest :=
  nodes.flatMap fun node =>
    match node.input with
    | .strictZkLeaf tape _ _ => [tape]
    | .merkleNode left right => [left, right]

/--
Executable analogue of the typed-input reuse checks in
`validate_smallwood_strict_whole_view_coin_shapes_v1`.  This predicate does
not by itself prove that Rust executions refine the Lean digest lists or that
the accepted values were sampled independently.
-/
def allInputDigestsFresh
    (openedTapes : List Sha512Digest)
    (nodes : List ProgrammedMerkleNode) : Bool :=
  let inputs := openedTapes ++ inputDigestList nodes
  decide inputs.Nodup

/-! ## Honest and simulator constructors -/

structure HonestViewInput (VerifierPayload : Type) where
  /-- Explicit bytes; no Rust statement-adapter serialization refinement is claimed. -/
  publicStatementBytes : List Byte
  /-- Explicit bytes; no refinement from Rust `binded_data` is claimed. -/
  bindedDataBytes : List Byte
  proofBytes : List Byte
  verifierTrace : VerifierTrace VerifierPayload
  orderedOracleQueryTrace : List RawSha512OracleQuery
  coinLedger : HonestCoinLedgerInput

structure SimulatorViewInput (VerifierPayload : Type) where
  /-- Explicit bytes; no Rust statement-adapter serialization refinement is claimed. -/
  publicStatementBytes : List Byte
  /-- Explicit bytes; no refinement from Rust `binded_data` is claimed. -/
  bindedDataBytes : List Byte
  proofBytes : List Byte
  verifierTrace : VerifierTrace VerifierPayload
  concreteVerifierTrace : VerifierTrace VerifierPayload
  programmedMerkleNodes : List ProgrammedMerkleNode
  recordedMerkleHistogram : ProgrammedMerkleHistogram
  programmedFinalPiopInputWords : List RawWord
  programmedFinalPiopOutput : Sha512Digest
  priorSha512Queries : List RawSha512OracleKey
  orderedOracleQueryTrace : List RawSha512OracleQuery
  recordedReplayReceipt : OracleReplayReceipt
  coinLedger : SimulatorCoinLedger
  concreteSha512Accepts : Bool

def honestWholeView?
    {VerifierPayload : Type}
    (oracle : ConcreteRawOracle)
    (input : HonestViewInput VerifierPayload) :
    Option (Smz9WholeViewObservation VerifierPayload) := do
  let proof ← SmallWoodSmz9ProofWire.decodeProofExact input.proofBytes
  let paths ← decodeAuthenticationPaths proof
  let openedTapes ← decodeOpenedLeafTapes proof
  let ledger ← honestCoinLedger? input.coinLedger
  if traceShapeValid input.verifierTrace ∧
      input.orderedOracleQueryTrace.all (fun query =>
        decide query.key.Canonical && queryConsistent oracle [] query) then
    let receipt := replayReceipt [] input.orderedOracleQueryTrace
    some
      { origin := .honest
        publicStatementBytes := input.publicStatementBytes
        bindedDataBytes := input.bindedDataBytes
        proofBytes := input.proofBytes
        decodedProof := proof
        authenticationPaths := paths
        openedLeafTapes := openedTapes
        verifierTrace := input.verifierTrace
        concreteVerifierTrace := input.verifierTrace
        programmedMerkleNodes := []
        programmedFinalPiopInputWords := []
        programmedFinalPiopOutput := none
        oracleProgramTable := []
        priorSha512Queries := []
        orderedOracleQueryTrace := input.orderedOracleQueryTrace
        replay := ⟨receipt, input.verifierTrace.accepts⟩
        programmedMerkleHistogram := histogram []
        coinLedger := .honest ledger
        rawWitnessWordsConsumed := smz9RawWitnessWordsConsumed
        concreteSha512Accepts := input.verifierTrace.accepts }
  else
    none

def proofPiopDigest?
    (proof : SmallWoodSmz9ProofWire.ProofWire) : Option Sha512Digest :=
  digestOfBytes? proof.piopHashBytes

/--
Cheap invariants implied by a successful full rebuild.  Checking these first
does not replace the source-shaped checks below; it makes malformed external
trace records fail before parsing a large proof.
-/
def simulatorInputEnvelopeValid
    {VerifierPayload : Type}
    (input : SimulatorViewInput VerifierPayload) : Bool :=
  input.recordedReplayReceipt.programCount == input.programmedMerkleNodes.length + 1 &&
    input.recordedReplayReceipt.queryCount == input.orderedOracleQueryTrace.length &&
    input.coinLedger.programmedOutputCoins512 == input.programmedMerkleNodes.length &&
    decide input.priorSha512Queries.Nodup

def simulatorWholeViewAfterEnvelope?
    {VerifierPayload : Type}
    [DecidableEq VerifierPayload]
    (oracle : ConcreteRawOracle)
    (input : SimulatorViewInput VerifierPayload) :
    Option (Smz9WholeViewObservation VerifierPayload) := do
  let proof ← SmallWoodSmz9ProofWire.decodeProofExact input.proofBytes
  let paths ← decodeAuthenticationPaths proof
  let openedTapes ← decodeOpenedLeafTapes proof
  let proofPiopDigest ← proofPiopDigest? proof
  let expectedPrograms ← extractExpectedPrograms
    input.concreteVerifierTrace.decsLeafIndexes paths
  let table ← buildProgramTable proof input.programmedMerkleNodes
    input.programmedFinalPiopInputWords input.programmedFinalPiopOutput
  let rebuiltHistogram := histogram input.programmedMerkleNodes
  let rebuiltReceipt := replayReceipt table input.orderedOracleQueryTrace
  if traceShapeValid input.verifierTrace ∧
      traceShapeValid input.concreteVerifierTrace ∧
      input.verifierTrace.payload = input.concreteVerifierTrace.payload ∧
      input.verifierTrace.piopTranscriptWords =
        input.concreteVerifierTrace.piopTranscriptWords ∧
      input.verifierTrace.decsLeafIndexes =
        input.concreteVerifierTrace.decsLeafIndexes ∧
      input.programmedFinalPiopInputWords =
        input.concreteVerifierTrace.piopTranscriptWords ∧
      input.programmedFinalPiopOutput = proofPiopDigest ∧
      merklePositionsStrictlyIncreasing input.programmedMerkleNodes ∧
      nodesMatchExpected input.programmedMerkleNodes expectedPrograms ∧
      allInputDigestsFresh openedTapes input.programmedMerkleNodes ∧
      table.all (fun program => decide program.key.Canonical) ∧
      rebuiltHistogram = input.recordedMerkleHistogram ∧
      simulatorCoinLedgerValid input.coinLedger input.programmedMerkleNodes rebuiltHistogram ∧
      input.priorSha512Queries.all (fun key => decide key.Canonical) ∧
      input.priorSha512Queries.Nodup ∧
      input.priorSha512Queries.all (fun key => (lookupProgram table key).isNone) ∧
      input.orderedOracleQueryTrace.all (fun query =>
        decide query.key.Canonical && queryConsistent oracle table query) ∧
      rebuiltReceipt = input.recordedReplayReceipt ∧
      rebuiltReceipt.finalPiopProgramHits = 1 ∧
      rebuiltReceipt.lazyMerkleProgramHits = 0 ∧
      input.verifierTrace.accepts = true ∧
      input.concreteSha512Accepts = input.concreteVerifierTrace.accepts then
    some
      { origin := .simulator
        publicStatementBytes := input.publicStatementBytes
        bindedDataBytes := input.bindedDataBytes
        proofBytes := input.proofBytes
        decodedProof := proof
        authenticationPaths := paths
        openedLeafTapes := openedTapes
        verifierTrace := input.verifierTrace
        concreteVerifierTrace := input.concreteVerifierTrace
        programmedMerkleNodes := input.programmedMerkleNodes
        programmedFinalPiopInputWords := input.programmedFinalPiopInputWords
        programmedFinalPiopOutput := some input.programmedFinalPiopOutput
        oracleProgramTable := table
        priorSha512Queries := input.priorSha512Queries
        orderedOracleQueryTrace := input.orderedOracleQueryTrace
        replay := ⟨rebuiltReceipt, input.verifierTrace.accepts⟩
        programmedMerkleHistogram := rebuiltHistogram
        coinLedger := .simulator input.coinLedger
        rawWitnessWordsConsumed := smz9RawWitnessWordsConsumed
        concreteSha512Accepts := input.concreteSha512Accepts }
  else
    none

def simulatorWholeView?
    {VerifierPayload : Type}
    [DecidableEq VerifierPayload]
    (oracle : ConcreteRawOracle)
    (input : SimulatorViewInput VerifierPayload) :
    Option (Smz9WholeViewObservation VerifierPayload) :=
  if simulatorInputEnvelopeValid input then
    simulatorWholeViewAfterEnvelope? oracle input
  else
    none

/-! ## Source binding and executable regression fixtures -/

def rustSimulatorViewSource : String :=
  "transaction_circuit::smallwood_engine::SmallwoodStrictZkWholeViewSimulationV1"

def rustSimulatorConstructorSource : String :=
  "transaction_circuit::smallwood_engine::simulate_smallwood_strict_whole_view_v1"

def rustVerifierTraceSource : String :=
  "transaction_circuit::smallwood_engine::SmallwoodVerifierTraceV1"

def missingRustToLeanTraceRefinement : String :=
  "No universal refinement yet maps the Rust statement adapter or binded_data argument to the explicit public-context bytes, or maps the full verifier trace payload or execution-derived ordered SHA-512 overlay events into this Lean internal audit record; all remain explicit checked inputs."

theorem source_binding_names_are_exact :
    rustSimulatorViewSource =
        "transaction_circuit::smallwood_engine::SmallwoodStrictZkWholeViewSimulationV1" ∧
      rustSimulatorConstructorSource =
        "transaction_circuit::smallwood_engine::simulate_smallwood_strict_whole_view_v1" ∧
      rustVerifierTraceSource =
        "transaction_circuit::smallwood_engine::SmallwoodVerifierTraceV1" := by
  exact ⟨rfl, rfl, rfl⟩

namespace Examples

def zeroOracle : ConcreteRawOracle := fun _ => Sha512Digest.zero

def canonicalLeafIndexes : List Nat := List.range smz9OpenedLeaves

def honestTrace : VerifierTrace Unit :=
  { payload := ()
    piopTranscriptWords := List.replicate smz9FinalPiopInputWordCount 7
    decsLeafIndexes := canonicalLeafIndexes
    accepts := false }

def honestLedgerInput : HonestCoinLedgerInput :=
  { fieldCandidateWords := honestAlgebraicFieldCoinCount
    fieldRejections := 0
    successfulGetrandomFillCalls := 2950
    sourceBytes := honestSaltBytes + 8 * honestAlgebraicFieldCoinCount + honestLeafTapeBytes }

def publicStatementBytesFixture : List Byte := [83, 77, 90, 57]

def bindedDataBytesFixture : List Byte := [72, 71, 86, 56, 82, 80, 48, 51]

def staticVerifierFixture (proofBytes : List Byte) (accepts : Bool) :
    StaticVerifierObservation :=
  { publicStatementBytes := publicStatementBytesFixture
    bindedDataBytes := bindedDataBytesFixture
    proofBytes
    verifierAccepts := accepts }

def honestInput : HonestViewInput Unit :=
  { publicStatementBytes := publicStatementBytesFixture
    bindedDataBytes := bindedDataBytesFixture
    proofBytes := SmallWoodSmz9ProofWire.Examples.canonicalMinimalProof.encode
    verifierTrace := honestTrace
    orderedOracleQueryTrace :=
      [{ key := rawKey piopInputDomain []
         output := Sha512Digest.zero
         programmedKind := none }]
    coinLedger := honestLedgerInput }

theorem honest_constructor_parses_wire_and_derives_empty_program_surface :
    ∃ observation, honestWholeView? zeroOracle honestInput = some observation ∧
      observation.origin = .honest ∧
      observation.toStaticVerifierObservation =
        staticVerifierFixture honestInput.proofBytes honestInput.verifierTrace.accepts ∧
      observation.proofBytes = honestInput.proofBytes ∧
      observation.authenticationPaths.length = smz9OpenedLeaves ∧
      observation.programmedMerkleNodes = [] ∧
      observation.oracleProgramTable = [] ∧
      observation.replay.receipt.programCount = 0 ∧
      observation.replay.receipt.queryCount = 1 ∧
      observation.programmedMerkleHistogram.totalPrograms = 0 ∧
      observation.rawWitnessWordsConsumed = 0 := by
  decide

def invalidHonestInput : HonestViewInput Unit :=
  { honestInput with
    proofBytes := SmallWoodSmz9ProofWire.Examples.trailingBytes }

theorem honest_constructor_rejects_noncanonical_wire :
    honestWholeView? zeroOracle invalidHonestInput = none := by
  decide

def impossibleHonestCallLedger : HonestCoinLedgerInput :=
  { honestLedgerInput with successfulGetrandomFillCalls := 2951 }

def impossibleHonestCallLedgerRegression : Bool :=
  (honestCoinLedger? impossibleHonestCallLedger).isNone

def taggedDigest (tag : Nat) : Sha512Digest :=
  ⟨encodeLE 8 tag ++ List.replicate 56 0, by simp [encodeLE_length]⟩

def simulatorAuthPaths : AuthPathsWire :=
  { rowCountBytes := encodeLE 2 smz9OpenedLeaves
    pathLengthBytes := List.replicate 16 18 ++ List.replicate 4 20
    nodeBytes := List.replicate (368 * 64) 0 }

def simulatorOpenedLeafTapes : List Sha512Digest :=
  (List.range smz9OpenedLeaves).map fun index => taggedDigest (100 + index)

def simulatorProof : SmallWoodSmz9ProofWire.ProofWire :=
  let base := SmallWoodSmz9ProofWire.Examples.makeProof simulatorAuthPaths
  { base with
    pcs :=
      { base.pcs with
        decs :=
          { base.pcs.decs with
            leafTapeBytes := (simulatorOpenedLeafTapes.map Subtype.val).flatten } } }

def simulatorProgramPositions : List (Nat × Nat) :=
  [(2, 5), (3, 3), (5, 1), (6, 1), (7, 1), (8, 1), (9, 1),
    (10, 1), (11, 1), (12, 1), (13, 1), (14, 1), (15, 1),
    (16, 1), (17, 1), (18, 1), (19, 1), (20, 1), (21, 1), (22, 1)]

def programNodesFromPositions : Nat → List (Nat × Nat) → List ProgrammedMerkleNode
  | _, [] => []
  | ordinal, (level, nodeIndex) :: positions =>
      { level, nodeIndex
        input := .merkleNode
          (taggedDigest (1000 + 2 * ordinal))
          (taggedDigest (1001 + 2 * ordinal))
        digest := Sha512Digest.zero } ::
      programNodesFromPositions (ordinal + 1) positions

def simulatorProgramNodes : List ProgrammedMerkleNode :=
  programNodesFromPositions 0 simulatorProgramPositions

def simulatorConcreteTrace : VerifierTrace Unit :=
  { payload := ()
    piopTranscriptWords := List.replicate smz9FinalPiopInputWordCount 8
    decsLeafIndexes := canonicalLeafIndexes
    accepts := false }

def simulatorProgrammedTrace : VerifierTrace Unit :=
  { simulatorConcreteTrace with accepts := true }

def simulatorFinalProgram : RawSha512OracleProgram :=
  finalPiopProgram simulatorConcreteTrace.piopTranscriptWords Sha512Digest.zero

def simulatorQueryTrace : List RawSha512OracleQuery :=
  [{ key := simulatorFinalProgram.key
     output := simulatorFinalProgram.output
     programmedKind := some .finalPiop }]

def simulatorRecordedReceipt : OracleReplayReceipt :=
  { programCount := simulatorProgramNodes.length + 1
    queryCount := 1
    finalPiopProgramHits := 1
    lazyMerkleProgramHits := 0 }

def simulatorLedger : SimulatorCoinLedger :=
  { canonicalFieldCoins := simulatorBaseFieldCoins
    openedLeafTapeCoins512 := smz9OpenedLeaves
    programmedLeafInputCoins512 := 0
    programmedInternalInputCoins1024 := simulatorProgramNodes.length
    programmedOutputCoins512 := simulatorProgramNodes.length
    finalOutputCoins512 := 1
    allSuppliedCoinsConsumed := true }

def simulatorInput : SimulatorViewInput Unit :=
  { publicStatementBytes := publicStatementBytesFixture
    bindedDataBytes := bindedDataBytesFixture
    proofBytes := simulatorProof.encode
    verifierTrace := simulatorProgrammedTrace
    concreteVerifierTrace := simulatorConcreteTrace
    programmedMerkleNodes := simulatorProgramNodes
    recordedMerkleHistogram := histogram simulatorProgramNodes
    programmedFinalPiopInputWords := simulatorConcreteTrace.piopTranscriptWords
    programmedFinalPiopOutput := Sha512Digest.zero
    priorSha512Queries := []
    orderedOracleQueryTrace := simulatorQueryTrace
    recordedReplayReceipt := simulatorRecordedReceipt
    coinLedger := simulatorLedger
    concreteSha512Accepts := false }

def simulatorConstructorRegression : Bool :=
  (simulatorWholeView? zeroOracle simulatorInput).isSome

set_option maxRecDepth 1000000 in
theorem simulator_constructor_regression_passes :
    simulatorConstructorRegression = true := by
  decide

def simulatorSurfaceRegression : Bool :=
  match simulatorWholeView? zeroOracle simulatorInput with
  | none => false
  | some observation =>
      observation.origin == .simulator &&
        decide (observation.toStaticVerifierObservation =
          staticVerifierFixture simulatorInput.proofBytes simulatorInput.verifierTrace.accepts) &&
        observation.authenticationPaths.length == smz9OpenedLeaves &&
        observation.openedLeafTapes.length == smz9OpenedLeaves &&
        observation.programmedMerkleNodes == simulatorProgramNodes &&
        observation.oracleProgramTable.length == simulatorProgramNodes.length + 1 &&
        observation.orderedOracleQueryTrace == simulatorQueryTrace &&
        observation.replay.receipt == simulatorRecordedReceipt &&
        observation.programmedMerkleHistogram == histogram simulatorProgramNodes &&
        observation.coinLedger == .simulator simulatorLedger &&
        observation.rawWitnessWordsConsumed == smz9RawWitnessWordsConsumed

def wrongReceiptSimulatorInput : SimulatorViewInput Unit :=
  { simulatorInput with
    recordedReplayReceipt :=
      { simulatorRecordedReceipt with queryCount := 2 } }

def forgedReplayCountRegression : Bool :=
  (simulatorWholeView? zeroOracle wrongReceiptSimulatorInput).isNone

theorem forged_replay_count_regression_passes :
    forgedReplayCountRegression = true := by
  decide

def duplicatePriorKeySimulatorInput : SimulatorViewInput Unit :=
  { simulatorInput with
    priorSha512Queries :=
      [rawKey piopInputDomain [], rawKey piopInputDomain []] }

def duplicatePriorKeyRegression : Bool :=
  (simulatorWholeView? zeroOracle duplicatePriorKeySimulatorInput).isNone

theorem duplicate_prior_key_regression_passes :
    duplicatePriorKeyRegression = true := by
  decide

def wrongLedgerSimulatorInput : SimulatorViewInput Unit :=
  { simulatorInput with
    coinLedger :=
      { simulatorLedger with programmedOutputCoins512 := 19 } }

def forgedCoinLedgerRegression : Bool :=
  (simulatorWholeView? zeroOracle wrongLedgerSimulatorInput).isNone

theorem forged_coin_ledger_regression_passes :
    forgedCoinLedgerRegression = true := by
  decide

theorem impossible_honest_call_ledger_regression_passes :
    impossibleHonestCallLedgerRegression = true := by
  decide

/-! These guards are executable regressions, not cryptographic theorems. -/

#guard simulatorConstructorRegression
#guard simulatorSurfaceRegression
#guard forgedReplayCountRegression
#guard duplicatePriorKeyRegression
#guard forgedCoinLedgerRegression
#guard impossibleHonestCallLedgerRegression

end Examples

end HegemonCrypto.SmallWood.V8Smz9WholeViewObservation
