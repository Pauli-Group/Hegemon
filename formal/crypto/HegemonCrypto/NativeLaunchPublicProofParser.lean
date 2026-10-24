import HegemonCrypto.NativeLaunchPublicProofView
import HegemonCrypto.SmallWoodProofWire

/-! Actual prefix-parser construction for complete native raw wire carriers.
No SMZ9 magic/count codec is used. Typed View-to-wire conversion remains separate. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 10000
namespace HegemonCrypto.NativeLaunchPublicProofParser
open CanonicalBytes SmallWoodProofWire
open SmallWood.NativeLaunchRelationModelResponse (Branch queryCount)
open NativeLaunchPublicProofView (Config ShapeGuard dims magic)

def nativeAuthGuard (b : Branch) (paths : AuthPathsWire) : Prop :=
  paths.rowCount = queryCount b ∧ ∀ x ∈ paths.pathLengthBytes, x.val ≤ 23
instance (b : Branch) : DecidablePred (nativeAuthGuard b) := fun p => by
  unfold nativeAuthGuard
  infer_instance

def nativeAuthCodec (b : Branch) : PrefixCodec AuthPathsWire :=
  PrefixCodec.refine SmallWoodProofWire.authPathsCodec (nativeAuthGuard b)

def EmptyAux : OpenedWitnessWire → Prop
  | .none => False
  | .rowScalars _ words limbs bytes => decodeLE words = 0 ∧ decodeLE limbs = 0 ∧ bytes = []
instance : DecidablePred EmptyAux := fun p => by cases p <;> unfold EmptyAux <;> infer_instance

def emptyAuxCodec : PrefixCodec OpenedWitnessWire := PrefixCodec.refine openedWitnessCodec EmptyAux

structure DecsWire where
  authPaths : AuthPathsWire
  leafTapeBytes : List Byte
  maskingEvaluations : MatrixWire
  highCoefficients : MatrixWire
deriving DecidableEq, Repr

def decsCodec (b : Branch) : PrefixCodec DecsWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair (nativeAuthCodec b)
      (PrefixCodec.pair (PrefixCodec.fixed (queryCount b * 64))
        (PrefixCodec.pair matrixCodec matrixCodec)))
    (fun value =>
      { authPaths := value.1, leafTapeBytes := value.2.1,
        maskingEvaluations := value.2.2.1, highCoefficients := value.2.2.2 })
    (fun decs =>
      (decs.authPaths, (decs.leafTapeBytes,
        (decs.maskingEvaluations, decs.highCoefficients))))
    (by intro value; rcases value with ⟨auth, tapes, masking, high⟩; rfl)
    (by intro value; cases value; rfl)

structure PcsWire where
  randomCombinationTails : MatrixWire
  subsetEvaluations : MatrixWire
  partialEvaluations : MatrixWire
  decs : DecsWire
deriving DecidableEq, Repr

def pcsCodec (b : Branch) : PrefixCodec PcsWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair matrixCodec
      (PrefixCodec.pair matrixCodec (PrefixCodec.pair matrixCodec (decsCodec b))))
    (fun value =>
      { randomCombinationTails := value.1, subsetEvaluations := value.2.1,
        partialEvaluations := value.2.2.1, decs := value.2.2.2 })
    (fun pcs =>
      (pcs.randomCombinationTails,
        (pcs.subsetEvaluations, (pcs.partialEvaluations, pcs.decs))))
    (by intro value; rcases value with ⟨rcombi, subset, partialMatrix, decs⟩; rfl)
    (by intro value; cases value; rfl)

structure ProofWire where
  saltBytes : List Byte
  nonceBytes : List Byte
  piopHashBytes : List Byte
  piop : PiopWire
  pcs : PcsWire
  openedWitness : OpenedWitnessWire
deriving DecidableEq, Repr

def proofPayloadCodec (b : Branch) : PrefixCodec ProofWire :=
  PrefixCodec.xmap
    (PrefixCodec.pair (PrefixCodec.fixed 32)
      (PrefixCodec.pair (PrefixCodec.fixed 4)
        (PrefixCodec.pair (PrefixCodec.fixed digestBytes)
          (PrefixCodec.pair piopCodec
            (PrefixCodec.pair (pcsCodec b) emptyAuxCodec)))))
    (fun value =>
      { saltBytes := value.1, nonceBytes := value.2.1, piopHashBytes := value.2.2.1,
        piop := value.2.2.2.1, pcs := value.2.2.2.2.1,
        openedWitness := value.2.2.2.2.2 })
    (fun proof =>
      (proof.saltBytes, (proof.nonceBytes,
        (proof.piopHashBytes, (proof.piop, (proof.pcs, proof.openedWitness))))))
    (by
      intro value
      rcases value with ⟨salt, nonce, hash, piop, pcs, opened⟩
      rfl)
    (by intro value; cases value; rfl)


def matrixShape (shape : Nat × Nat) (m : MatrixWire) : Prop :=
  m.rowCount = shape.1 ∧ m.columnCount = shape.2

def exactShape (b : Branch) (c : Config) (w : ProofWire) : Prop :=
  matrixShape (dims b c 0) w.piop.polynomialHighs ∧
  matrixShape (dims b c 1) w.piop.linearHighs ∧
  matrixShape (dims b c 2) w.pcs.randomCombinationTails ∧
  matrixShape (dims b c 3) w.pcs.subsetEvaluations ∧
  matrixShape (dims b c 4) w.pcs.partialEvaluations ∧
  matrixShape (dims b c 5) w.pcs.decs.maskingEvaluations ∧
  matrixShape (dims b c 6) w.pcs.decs.highCoefficients ∧
  match w.openedWitness with
  | .none => False
  | .rowScalars rows _ _ _ => matrixShape (dims b c 7) rows

instance (b : Branch) (c : Config) : DecidablePred (exactShape b c) := fun w => by
  unfold exactShape matrixShape
  cases w.openedWitness <;> infer_instance

instance (b : Branch) (c : Config) : Decidable (ShapeGuard b c) := by
  unfold ShapeGuard
  infer_instance

/-- SourceConfig guard remains explicit and is checked along with all raw matrices. -/
def guardedPayload (b : Branch) (c : Config) : PrefixCodec ProofWire :=
  PrefixCodec.refine (proofPayloadCodec b) (fun w => ShapeGuard b c ∧ exactShape b c w)

def encode (b : Branch) (w : ProofWire) : List Byte := magic b ++ (proofPayloadCodec b).encode w

def decodePrefix (b : Branch) (c : Config) (input : List Byte) : Option (ProofWire × List Byte) := do
  let (tag, rest) ← readFixed 4 input
  if tag = magic b then (guardedPayload b c).decode rest else none

def maximumBytes : Branch → Nat | .rp06 => 164113 | _ => 2097152

/-- Cap checked before any variable matrix/path allocation; all input consumed. -/
def decodeExact (b : Branch) (c : Config) (input : List Byte) : Option ProofWire :=
  if input.length ≤ maximumBytes b then do
    let (proof, suffix) ← decodePrefix b c input
    if suffix = [] then some proof else none
  else none

theorem magic_length (b : Branch) : (magic b).length = 4 := by cases b <;> rfl

theorem decode_prefix_encode (b : Branch) (c : Config) (w : ProofWire) (suffix : List Byte)
    (canonical : (guardedPayload b c).canonical w) :
    decodePrefix b c (encode b w ++ suffix) = some (w, suffix) := by
  unfold decodePrefix encode
  rw [List.append_assoc, readFixed_append (magic_length b)]
  simp
  exact (guardedPayload b c).decode_encode w suffix canonical

theorem decode_exact_encode (b : Branch) (c : Config) (w : ProofWire)
    (canonical : (guardedPayload b c).canonical w)
    (withinCap : (encode b w).length ≤ maximumBytes b) :
    decodeExact b c (encode b w) = some w := by
  have roundtrip := decode_prefix_encode b c w [] canonical
  simp only [List.append_nil] at roundtrip
  simp [decodeExact, withinCap, roundtrip]

theorem prefix_sound {b : Branch} {c : Config} {input suffix : List Byte} {w : ProofWire}
    (decoded : decodePrefix b c input = some (w, suffix)) :
    (guardedPayload b c).canonical w ∧ input = encode b w ++ suffix := by
  unfold decodePrefix at decoded
  cases result : readFixed 4 input with
  | none => simp [result] at decoded
  | some pair =>
    rcases pair with ⟨tag, rest⟩
    simp [result] at decoded
    rcases decoded with ⟨tagEq, decoded⟩
    obtain ⟨canonical, restEq⟩ := (guardedPayload b c).decode_sound decoded
    obtain ⟨_, inputEq⟩ := readFixed_sound result
    subst tag
    exact ⟨canonical, by simp [encode, inputEq, restEq, guardedPayload, PrefixCodec.refine, List.append_assoc]⟩

theorem exact_sound {b : Branch} {c : Config} {input : List Byte} {w : ProofWire}
    (decoded : decodeExact b c input = some w) :
    input.length ≤ maximumBytes b ∧ (guardedPayload b c).canonical w ∧ input = encode b w := by
  unfold decodeExact at decoded
  split at decoded
  · next cap =>
    cases result : decodePrefix b c input with
    | none => simp [result] at decoded
    | some pair =>
      rcases pair with ⟨found, suffix⟩
      simp [result] at decoded
      rcases decoded with ⟨empty, same⟩
      subst found
      subst suffix
      obtain ⟨canon, raw⟩ := prefix_sound result
      exact ⟨cap, canon, by simpa using raw⟩
  · contradiction

end HegemonCrypto.NativeLaunchPublicProofParser
