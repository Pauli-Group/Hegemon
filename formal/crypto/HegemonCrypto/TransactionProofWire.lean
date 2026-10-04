import HegemonCrypto.SmallWoodCandidateWire

namespace HegemonCrypto
namespace TransactionProofWire

open CanonicalBytes
open SmallWoodCandidateWire

def bytesCodec : PrefixCodec CountedWire := countedCodec 1

def digest48Codec : PrefixCodec CountedWire :=
  PrefixCodec.refine bytesCodec fun wire => wire.count = 48

def bytes48VectorCodec : PrefixCodec CountedWire :=
  PrefixCodec.refine bytesCodec fun wire => wire.payloadBytes.length % 48 = 0

def balanceSlotsCodec : PrefixCodec CountedWire := countedCodec 24
def vectorU64Codec : PrefixCodec CountedWire := countedCodec 8

def boolCodec : PrefixCodec (List Byte) :=
  PrefixCodec.refine (PrefixCodec.fixed 1) fun bytes => decodeLE bytes <= 1

structure StablecoinWire where
  enabledBytes : List Byte
  assetIdBytes : List Byte
  policyHash : CountedWire
  oracleCommitment : CountedWire
  attestationCommitment : CountedWire
  issuanceDeltaBytes : List Byte
  policyVersionBytes : List Byte
deriving DecidableEq, Repr

def stablecoinCodec : PrefixCodec StablecoinWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair boolCodec
      (PrefixCodec.pair (PrefixCodec.fixed 8)
        (PrefixCodec.pair digest48Codec
          (PrefixCodec.pair digest48Codec
            (PrefixCodec.pair digest48Codec
              (PrefixCodec.pair (PrefixCodec.fixed 16)
                (PrefixCodec.fixed 4)))))))
    (fun value =>
      { enabledBytes := value.1,
        assetIdBytes := value.2.1,
        policyHash := value.2.2.1,
        oracleCommitment := value.2.2.2.1,
        attestationCommitment := value.2.2.2.2.1,
        issuanceDeltaBytes := value.2.2.2.2.2.1,
        policyVersionBytes := value.2.2.2.2.2.2 })
    (fun wire =>
      (wire.enabledBytes,
        (wire.assetIdBytes,
          (wire.policyHash,
            (wire.oracleCommitment,
              (wire.attestationCommitment,
                (wire.issuanceDeltaBytes, wire.policyVersionBytes)))))))
    (by
      intro value
      rcases value with ⟨enabled, asset, policy, oracle, attestation,
        issuance, version⟩
      rfl)
    (by intro value; cases value; rfl)

structure PublicCollectionsWire where
  merkleRoot : CountedWire
  nullifiers : CountedWire
  commitments : CountedWire
  ciphertextHashes : CountedWire
  balanceSlots : CountedWire
deriving DecidableEq, Repr

def publicCollectionsCodec : PrefixCodec PublicCollectionsWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair digest48Codec
      (PrefixCodec.pair bytes48VectorCodec
        (PrefixCodec.pair bytes48VectorCodec
          (PrefixCodec.pair bytes48VectorCodec balanceSlotsCodec))))
    (fun value =>
      { merkleRoot := value.1,
        nullifiers := value.2.1,
        commitments := value.2.2.1,
        ciphertextHashes := value.2.2.2.1,
        balanceSlots := value.2.2.2.2 })
    (fun wire =>
      (wire.merkleRoot,
        (wire.nullifiers,
          (wire.commitments, (wire.ciphertextHashes, wire.balanceSlots)))))
    (by
      intro value
      rcases value with ⟨merkle, nullifiers, commitments, ciphertexts, slots⟩
      rfl)
    (by intro value; cases value; rfl)

structure PublicTailWire where
  nativeFeeBytes : List Byte
  valueBalanceBytes : List Byte
  stablecoin : StablecoinWire
  balanceTag : CountedWire
  circuitVersionBytes : List Byte
  cryptoSuiteBytes : List Byte
deriving DecidableEq, Repr

def publicTailCodec : PrefixCodec PublicTailWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair (PrefixCodec.fixed 8)
      (PrefixCodec.pair (PrefixCodec.fixed 16)
        (PrefixCodec.pair stablecoinCodec
          (PrefixCodec.pair digest48Codec
            (PrefixCodec.pair (PrefixCodec.fixed 2)
              (PrefixCodec.fixed 2))))))
    (fun value =>
      { nativeFeeBytes := value.1,
        valueBalanceBytes := value.2.1,
        stablecoin := value.2.2.1,
        balanceTag := value.2.2.2.1,
        circuitVersionBytes := value.2.2.2.2.1,
        cryptoSuiteBytes := value.2.2.2.2.2 })
    (fun wire =>
      (wire.nativeFeeBytes,
        (wire.valueBalanceBytes,
          (wire.stablecoin,
            (wire.balanceTag,
              (wire.circuitVersionBytes, wire.cryptoSuiteBytes))))))
    (by
      intro value
      rcases value with ⟨fee, balance, stablecoin, tag, circuit, crypto⟩
      rfl)
    (by intro value; cases value; rfl)

structure TransactionPublicInputsWire where
  collections : PublicCollectionsWire
  tail : PublicTailWire
deriving DecidableEq, Repr

def transactionPublicInputsCodec : PrefixCodec TransactionPublicInputsWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair publicCollectionsCodec publicTailCodec)
    (fun value => { collections := value.1, tail := value.2 })
    (fun wire => (wire.collections, wire.tail))
    (by intro value; cases value; rfl)
    (by intro value; cases value; rfl)

structure StarkCoreWire where
  inputFlags : CountedWire
  outputFlags : CountedWire
  feeBytes : List Byte
  valueBalanceSignBytes : List Byte
  valueBalanceMagnitudeBytes : List Byte
  merkleRoot : CountedWire
  balanceSlotAssetIds : CountedWire
deriving DecidableEq, Repr

def starkCoreCodec : PrefixCodec StarkCoreWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair bytesCodec
      (PrefixCodec.pair bytesCodec
        (PrefixCodec.pair (PrefixCodec.fixed 8)
          (PrefixCodec.pair (PrefixCodec.fixed 1)
            (PrefixCodec.pair (PrefixCodec.fixed 8)
              (PrefixCodec.pair digest48Codec vectorU64Codec))))))
    (fun value =>
      { inputFlags := value.1,
        outputFlags := value.2.1,
        feeBytes := value.2.2.1,
        valueBalanceSignBytes := value.2.2.2.1,
        valueBalanceMagnitudeBytes := value.2.2.2.2.1,
        merkleRoot := value.2.2.2.2.2.1,
        balanceSlotAssetIds := value.2.2.2.2.2.2 })
    (fun wire =>
      (wire.inputFlags,
        (wire.outputFlags,
          (wire.feeBytes,
            (wire.valueBalanceSignBytes,
              (wire.valueBalanceMagnitudeBytes,
                (wire.merkleRoot, wire.balanceSlotAssetIds)))))))
    (by
      intro value
      rcases value with ⟨inputs, outputs, fee, sign, magnitude, root, assets⟩
      rfl)
    (by intro value; cases value; rfl)

structure StarkStablecoinWire where
  enabledBytes : List Byte
  assetIdBytes : List Byte
  policyVersionBytes : List Byte
  issuanceSignBytes : List Byte
  issuanceMagnitudeBytes : List Byte
  policyHash : CountedWire
  oracleCommitment : CountedWire
  attestationCommitment : CountedWire
deriving DecidableEq, Repr

def starkStablecoinCodec : PrefixCodec StarkStablecoinWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair (PrefixCodec.fixed 1)
      (PrefixCodec.pair (PrefixCodec.fixed 8)
        (PrefixCodec.pair (PrefixCodec.fixed 4)
          (PrefixCodec.pair (PrefixCodec.fixed 1)
            (PrefixCodec.pair (PrefixCodec.fixed 8)
              (PrefixCodec.pair digest48Codec
                (PrefixCodec.pair digest48Codec digest48Codec)))))))
    (fun value =>
      { enabledBytes := value.1,
        assetIdBytes := value.2.1,
        policyVersionBytes := value.2.2.1,
        issuanceSignBytes := value.2.2.2.1,
        issuanceMagnitudeBytes := value.2.2.2.2.1,
        policyHash := value.2.2.2.2.2.1,
        oracleCommitment := value.2.2.2.2.2.2.1,
        attestationCommitment := value.2.2.2.2.2.2.2 })
    (fun wire =>
      (wire.enabledBytes,
        (wire.assetIdBytes,
          (wire.policyVersionBytes,
            (wire.issuanceSignBytes,
              (wire.issuanceMagnitudeBytes,
                (wire.policyHash,
                  (wire.oracleCommitment, wire.attestationCommitment))))))))
    (by
      intro value
      rcases value with ⟨enabled, asset, version, sign, magnitude, policy,
        oracle, attestation⟩
      rfl)
    (by intro value; cases value; rfl)

structure SerializedStarkInputsWire where
  core : StarkCoreWire
  stablecoin : StarkStablecoinWire
deriving DecidableEq, Repr

def serializedStarkInputsCodec : PrefixCodec SerializedStarkInputsWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair starkCoreCodec starkStablecoinCodec)
    (fun value => { core := value.1, stablecoin := value.2 })
    (fun wire => (wire.core, wire.stablecoin))
    (by intro value; cases value; rfl)
    (by intro value; cases value; rfl)

def backendCodec : PrefixCodec (List Byte) :=
  PrefixCodec.refine (PrefixCodec.fixed 4) fun bytes => decodeLE bytes <= 1

structure ProofWrapperWire where
  publicInputs : TransactionPublicInputsWire
  nullifiers : CountedWire
  commitments : CountedWire
  balanceSlots : CountedWire
  backendBytes : List Byte
  proofBytes : CountedWire
  serializedStarkInputs : Option SerializedStarkInputsWire
deriving DecidableEq, Repr

def transactionProofCodec : PrefixCodec ProofWrapperWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair transactionPublicInputsCodec
      (PrefixCodec.pair bytes48VectorCodec
        (PrefixCodec.pair bytes48VectorCodec
          (PrefixCodec.pair balanceSlotsCodec
            (PrefixCodec.pair backendCodec
              (PrefixCodec.pair bytesCodec
                (PrefixCodec.option serializedStarkInputsCodec)))))))
    (fun value =>
      { publicInputs := value.1,
        nullifiers := value.2.1,
        commitments := value.2.2.1,
        balanceSlots := value.2.2.2.1,
        backendBytes := value.2.2.2.2.1,
        proofBytes := value.2.2.2.2.2.1,
        serializedStarkInputs := value.2.2.2.2.2.2 })
    (fun wire =>
      (wire.publicInputs,
        (wire.nullifiers,
          (wire.commitments,
            (wire.balanceSlots,
              (wire.backendBytes,
                (wire.proofBytes, wire.serializedStarkInputs)))))))
    (by
      intro value
      rcases value with ⟨publicInputs, nullifiers, commitments, balanceSlots,
        backend, proof, starkInputs⟩
      rfl)
    (by intro value; cases value; rfl)

namespace ProofWrapperWire

def encode (wire : ProofWrapperWire) : List Byte :=
  transactionProofCodec.encode wire

def Canonical (wire : ProofWrapperWire) : Prop :=
  transactionProofCodec.canonical wire

end ProofWrapperWire

def decodeTransactionProofPrefix
    (input : List Byte) : Option (ProofWrapperWire × List Byte) :=
  transactionProofCodec.decode input

def decodeTransactionProofExact (input : List Byte) : Option ProofWrapperWire := do
  let (wire, suffix) ← decodeTransactionProofPrefix input
  if suffix = [] then some wire else none

theorem decodeTransactionProofExact_encode
    (wire : ProofWrapperWire)
    (canonical : wire.Canonical) :
    decodeTransactionProofExact wire.encode = some wire := by
  unfold decodeTransactionProofExact decodeTransactionProofPrefix
  change transactionProofCodec.canonical wire at canonical
  rw [show wire.encode = transactionProofCodec.encode wire ++ [] by simp [ProofWrapperWire.encode]]
  rw [transactionProofCodec.decode_encode wire [] canonical]
  rfl

theorem decodeTransactionProofExact_sound
    {input : List Byte}
    {wire : ProofWrapperWire}
    (decoded : decodeTransactionProofExact input = some wire) :
    wire.Canonical ∧ input = wire.encode := by
  unfold decodeTransactionProofExact decodeTransactionProofPrefix at decoded
  cases prefixResult : transactionProofCodec.decode input with
  | none => simp [prefixResult] at decoded
  | some prefixPair =>
      rcases prefixPair with ⟨parsedWire, suffix⟩
      simp [prefixResult] at decoded
      rcases decoded with ⟨suffix_empty, wire_eq⟩
      subst parsedWire
      subst suffix
      simpa [ProofWrapperWire.Canonical, ProofWrapperWire.encode] using
        transactionProofCodec.decode_sound prefixResult

theorem decodeTransactionProofExact_rejects_trailing_bytes
    (wire : ProofWrapperWire)
    (suffix : List Byte)
    (canonical : wire.Canonical)
    (suffix_nonempty : suffix ≠ []) :
    decodeTransactionProofExact (wire.encode ++ suffix) = none := by
  unfold decodeTransactionProofExact decodeTransactionProofPrefix
  change transactionProofCodec.canonical wire at canonical
  change
    (do
      let (parsedWire, rest) ←
        transactionProofCodec.decode (transactionProofCodec.encode wire ++ suffix)
      if rest = [] then some parsedWire else none) = none
  rw [transactionProofCodec.decode_encode wire suffix canonical]
  simp [suffix_nonempty]

structure ActiveAcceptedProofWire where
  wrapper : ProofWrapperWire
  backendProof : SmallWoodCandidateWire.ActiveProofArtifact
deriving DecidableEq, Repr

namespace ActiveAcceptedProofWire

def activeCircuitVersion : Nat := 4
def activeCryptoSuite : Nat := 3

def encode (artifact : ActiveAcceptedProofWire) : List Byte :=
  artifact.wrapper.encode

def Canonical (artifact : ActiveAcceptedProofWire) : Prop :=
  artifact.wrapper.Canonical
    ∧ decodeLE artifact.wrapper.publicInputs.tail.circuitVersionBytes =
      activeCircuitVersion
    ∧ decodeLE artifact.wrapper.publicInputs.tail.cryptoSuiteBytes =
      activeCryptoSuite
    ∧ decodeLE artifact.wrapper.backendBytes = 1
    ∧ artifact.wrapper.serializedStarkInputs.isSome
    ∧ artifact.backendProof.Canonical
    ∧ artifact.wrapper.proofBytes.payloadBytes = artifact.backendProof.encode

end ActiveAcceptedProofWire

def decodeActiveAcceptedProofWireExact
    (input : List Byte) : Option ActiveAcceptedProofWire := do
  let wrapper ← decodeTransactionProofExact input
  if decodeLE wrapper.publicInputs.tail.circuitVersionBytes =
      ActiveAcceptedProofWire.activeCircuitVersion then
    if decodeLE wrapper.publicInputs.tail.cryptoSuiteBytes =
        ActiveAcceptedProofWire.activeCryptoSuite then
      if decodeLE wrapper.backendBytes = 1 then
        if wrapper.serializedStarkInputs.isSome then
          let backendProof ←
            SmallWoodCandidateWire.decodeActiveProofArtifactExact
              wrapper.proofBytes.payloadBytes
          some { wrapper, backendProof }
        else
          none
      else
        none
    else
      none
  else
    none

theorem decodeActiveAcceptedProofWireExact_encode
    (artifact : ActiveAcceptedProofWire)
    (canonical : artifact.Canonical) :
    decodeActiveAcceptedProofWireExact artifact.encode = some artifact := by
  rcases canonical with
    ⟨wrapperCanonical, circuitActive, cryptoActive, backendActive,
      starkPresent, backendCanonical, proof_bytes_eq⟩
  unfold decodeActiveAcceptedProofWireExact ActiveAcceptedProofWire.encode
  rw [decodeTransactionProofExact_encode artifact.wrapper wrapperCanonical]
  simp [circuitActive, cryptoActive, backendActive, starkPresent]
  rw [proof_bytes_eq]
  rw [SmallWoodCandidateWire.decodeActiveProofArtifactExact_encode
    artifact.backendProof backendCanonical]
  rfl

theorem decodeActiveAcceptedProofWireExact_sound
    {input : List Byte}
    {artifact : ActiveAcceptedProofWire}
    (decoded : decodeActiveAcceptedProofWireExact input = some artifact) :
    artifact.Canonical ∧ input = artifact.encode := by
  unfold decodeActiveAcceptedProofWireExact at decoded
  cases wrapperResult : decodeTransactionProofExact input with
  | none => simp [wrapperResult] at decoded
  | some wrapper =>
      simp [wrapperResult] at decoded
      rcases decoded with
        ⟨circuitActive, cryptoActive, backendActive, starkPresent, decoded⟩
      cases backendResult :
          SmallWoodCandidateWire.decodeActiveProofArtifactExact
            wrapper.proofBytes.payloadBytes with
      | none => simp [backendResult] at decoded
      | some backendProof =>
          simp [backendResult] at decoded
          subst artifact
          rcases decodeTransactionProofExact_sound wrapperResult with
            ⟨wrapperCanonical, input_eq⟩
          rcases SmallWoodCandidateWire.decodeActiveProofArtifactExact_sound
            backendResult with
            ⟨backendCanonical, proof_bytes_eq⟩
          constructor
          · exact
              ⟨wrapperCanonical, circuitActive, cryptoActive, backendActive,
                starkPresent, backendCanonical, proof_bytes_eq⟩
          · exact input_eq

end TransactionProofWire
end HegemonCrypto
