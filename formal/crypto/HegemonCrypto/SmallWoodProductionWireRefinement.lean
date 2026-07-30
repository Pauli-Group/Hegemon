import HegemonCrypto.SmallWoodNativeDecsReconstruction
import HegemonCrypto.SmallWoodNativePcsMessageReconstruction
import HegemonCrypto.SmallWoodNativePiopReconstruction
import HegemonCrypto.SmallWoodProofWire

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Active `SMW2` proof-field refinement

This module interprets every field-valued matrix and compact authentication path in the canonical
`SMW2` parser output. The interpretation is total, while `ProofWireRepresents` fixes the exact
active dimensions and values required by the production verifier. This is the byte-to-algebra
boundary used by production acceptance; no proof-derived algebraic object is left unconstrained.
-/

namespace HegemonCrypto.SmallWood.ProductionWireRefinement

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.CompactMerkleExtraction
open HegemonCrypto.SmallWood.NativeDecsReconstruction
open HegemonCrypto.SmallWood.NativeLvcsReconstruction
open HegemonCrypto.SmallWood.NativePcsMessageReconstruction
open HegemonCrypto.SmallWood.NativePiopReconstruction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.Sha512Xof
open HegemonCrypto.SmallWoodProofWire
open HegemonCrypto.SmallWoodTranscript

def canonicalFieldWordAt
    (bytes : List Byte)
    (index : Nat) : FieldWord :=
  ⟨decodeLE ((bytes.drop (index * 8)).take 8) % fieldOrder,
    Nat.mod_lt _ (by
      unfold fieldOrder
      decide)⟩

def canonicalWordAt
    (bytes : List Byte)
    (index : Nat) : Word :=
  ⟨decodeLE ((bytes.drop (index * 8)).take 8) % (2 ^ 64),
    Nat.mod_lt _ (by positivity)⟩

def matrixFieldWordAt
    (wire : MatrixWire)
    (row column : Nat) : FieldWord :=
  canonicalFieldWordAt wire.valueBytes
    (row * wire.columnCount + column)

def MatrixWireRepresents
    (wire : MatrixWire)
    (rows columns : Nat)
    (values : Fin rows -> Fin columns -> FieldWord) : Prop :=
  wire.rowCount = rows
    ∧ wire.columnCount = columns
    ∧ ∀ row column,
      matrixFieldWordAt wire row.val column.val = values row column

def authPathPrefixNodes
    (wire : AuthPathsWire)
    (opening : Nat) : Nat :=
  ((wire.pathLengthBytes.take opening).map Fin.val).sum

def authPathNodeWordAt
    (wire : AuthPathsWire)
    (opening node : Nat)
    (word : Fin digestWordCount) : Word :=
  canonicalWordAt wire.nodeBytes
    ((authPathPrefixNodes wire opening + node) * digestWordCount + word.val)

def AuthPathsWireRepresents
    (wire : AuthPathsWire)
    (paths : ProductionCompactPaths) : Prop :=
  wire.rowCount = decsOpenedEvaluations
    ∧ ∀ opening : OpeningIndex,
      (wire.pathLengthBytes.getD opening.val 0).val =
          (paths opening).length
        ∧ ∀ node (nodeBound : node < (paths opening).length),
          ∀ word : Fin digestWordCount,
            authPathNodeWordAt wire opening.val node word =
              (paths opening).get ⟨node, nodeBound⟩ word

def OpenedWitnessWireRepresents
    (wire : OpenedWitnessWire)
    (rowScalars : NativeOpenedRowScalars) : Prop :=
  ∃ matrix wordCountBytes limbCountBytes wordBytes,
    wire = .rowScalars matrix wordCountBytes limbCountBytes wordBytes
      ∧ MatrixWireRepresents matrix openedEvaluations polynomialCount rowScalars
      ∧ decodeLE wordCountBytes = 0
      ∧ decodeLE limbCountBytes = 0
      ∧ wordBytes = []

structure ProductionProofWireData where
  rowScalars : NativeOpenedRowScalars
  partialEvaluations : NativePartialEvaluations
  combinationTails : NativePcsCombinationTails
  subsetEvaluations : NativeSubsetEvaluations
  maskingEvaluations : NativeMaskingRows
  decsHighCoefficients : NativeDecsHighCoefficients
  nonlinearHighCoefficients : NativeNonlinearHighCoefficients
  linearHighCoefficients : NativeLinearHighCoefficients
  paths : ProductionCompactPaths

def openedWitnessRowScalars : OpenedWitnessWire -> NativeOpenedRowScalars
  | .none => fun _ _ => 0
  | .rowScalars matrix _ _ _ =>
      fun row column => matrixFieldWordAt matrix row.val column.val

def proofWireNonlinearHigh
    (proof : ProofWire) : NativeNonlinearHighCoefficients :=
  fun row column =>
    matrixFieldWordAt proof.piop.polynomialHighs row.val column.val

def proofWireLinearHigh
    (proof : ProofWire) : NativeLinearHighCoefficients :=
  fun row column =>
    matrixFieldWordAt proof.piop.linearHighs row.val column.val

def proofWireCombinationTails
    (proof : ProofWire) : NativePcsCombinationTails :=
  fun row column =>
    matrixFieldWordAt proof.pcs.randomCombinationTails row.val column.val

def proofWireSubsetEvaluations
    (proof : ProofWire) : NativeSubsetEvaluations :=
  fun row column =>
    matrixFieldWordAt proof.pcs.subsetEvaluations row.val column.val

def proofWirePartialEvaluations
    (proof : ProofWire) : NativePartialEvaluations :=
  fun row column =>
    matrixFieldWordAt proof.pcs.partialEvaluations row.val column.val

def proofWireMaskingEvaluations
    (proof : ProofWire) : NativeMaskingRows :=
  fun row column =>
    matrixFieldWordAt proof.pcs.decs.maskingEvaluations row.val column.val

def proofWireDecsHigh
    (proof : ProofWire) : NativeDecsHighCoefficients :=
  fun row column =>
    matrixFieldWordAt proof.pcs.decs.highCoefficients row.val column.val

def proofWireAuthPathLength
    (wire : AuthPathsWire)
    (opening : OpeningIndex) : Nat :=
  (wire.pathLengthBytes.getD opening.val 0).val

def proofWireAuthPaths
    (wire : AuthPathsWire) : ProductionCompactPaths :=
  fun opening =>
    List.ofFn fun node : Fin (proofWireAuthPathLength wire opening) =>
      fun word =>
        authPathNodeWordAt wire opening.val node.val word

/--
The typed proof data is a total deterministic projection of the canonical parser output. A
successful verifier still has to prove the active shapes and every algebraic/hash check, but no
algebraic value can be chosen independently from the bytes.
-/
def productionProofWireData
    (proof : ProofWire) : ProductionProofWireData :=
  { rowScalars := openedWitnessRowScalars proof.openedWitness
    partialEvaluations := proofWirePartialEvaluations proof
    combinationTails := proofWireCombinationTails proof
    subsetEvaluations := proofWireSubsetEvaluations proof
    maskingEvaluations := proofWireMaskingEvaluations proof
    decsHighCoefficients := proofWireDecsHigh proof
    nonlinearHighCoefficients := proofWireNonlinearHigh proof
    linearHighCoefficients := proofWireLinearHigh proof
    paths := proofWireAuthPaths proof.pcs.decs.authPaths }

def ProofWireRepresents
    (proof : ProofWire)
    (data : ProductionProofWireData) : Prop :=
  MatrixWireRepresents proof.piop.polynomialHighs
      rho NativeNonlinearHighCount data.nonlinearHighCoefficients
    ∧ MatrixWireRepresents proof.piop.linearHighs
      rho NativeLinearHighCount data.linearHighCoefficients
    ∧ MatrixWireRepresents proof.pcs.randomCombinationTails
      openedCombinationCount decsOpenedEvaluations data.combinationTails
    ∧ MatrixWireRepresents proof.pcs.subsetEvaluations
      decsOpenedEvaluations (lvcsRowCount - openedCombinationCount)
      data.subsetEvaluations
    ∧ MatrixWireRepresents proof.pcs.partialEvaluations
      openedEvaluations (unstackedColumnCount - polynomialCount)
      data.partialEvaluations
    ∧ AuthPathsWireRepresents proof.pcs.decs.authPaths data.paths
    ∧ MatrixWireRepresents proof.pcs.decs.maskingEvaluations
      decsOpenedEvaluations decsEta data.maskingEvaluations
    ∧ MatrixWireRepresents proof.pcs.decs.highCoefficients
      decsEta NativeDecsHighCount data.decsHighCoefficients
    ∧ OpenedWitnessWireRepresents proof.openedWitness data.rowScalars

/--
All active wire-shape checks made by the production verifier, stated against the unique typed
projection of those same bytes.
-/
def ActiveProofWireShape (proof : ProofWire) : Prop :=
  ProofWireRepresents proof (productionProofWireData proof)

/-- Every active matrix dimension is fixed by the production profile. -/
theorem proof_wire_represents_active_dimensions
    {proof : ProofWire}
    {data : ProductionProofWireData}
    (represents : ProofWireRepresents proof data) :
    proof.piop.polynomialHighs.rowCount = 5
      ∧ proof.piop.polynomialHighs.columnCount = 476
      ∧ proof.piop.linearHighs.rowCount = 5
      ∧ proof.piop.linearHighs.columnCount = 126
      ∧ proof.pcs.randomCombinationTails.rowCount = 35
      ∧ proof.pcs.randomCombinationTails.columnCount = 20
      ∧ proof.pcs.subsetEvaluations.rowCount = 20
      ∧ proof.pcs.subsetEvaluations.columnCount = 448
      ∧ proof.pcs.partialEvaluations.rowCount = 5
      ∧ proof.pcs.partialEvaluations.columnCount = 40
      ∧ proof.pcs.decs.maskingEvaluations.rowCount = 20
      ∧ proof.pcs.decs.maskingEvaluations.columnCount = 33
      ∧ proof.pcs.decs.highCoefficients.rowCount = 33
      ∧ proof.pcs.decs.highCoefficients.columnCount = 107 := by
  rcases represents with
    ⟨nonlinear, linear, tails, subset, partialEvaluations, _paths,
      masking, decsHigh, _opened⟩
  exact
    ⟨nonlinear.1.trans (by decide),
      nonlinear.2.1.trans (by decide),
      linear.1.trans (by decide),
      linear.2.1.trans (by decide),
      tails.1.trans (by decide),
      tails.2.1.trans (by decide),
      subset.1.trans (by decide),
      subset.2.1.trans (by decide),
      partialEvaluations.1.trans (by decide),
      partialEvaluations.2.1.trans (by decide),
      masking.1.trans (by decide),
      masking.2.1.trans (by decide),
      decsHigh.1.trans (by decide),
      decsHigh.2.1.trans (by decide)⟩

end HegemonCrypto.SmallWood.ProductionWireRefinement
