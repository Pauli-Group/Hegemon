import SmzaRawRecordedWrappers

/-! A canonical recorded leaf path fixes the extracted oracle cell directly.
This uses the accepted raw payload, not a second whole-program encoding
refinement or an assumed equality between two extracted matrices. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawRootReadback

open SmzaRp04TracePrefixes SmzaRp04TracePrefixReadback
open SmzaRecordedTracePath SmzaRawRecordedPrefix SmzaRawStageGeometry
open V8Smz9CoherentMerkleGeometry V8SmzaOnlineParser
open scoped Classical

noncomputable section
set_option autoImplicit false
attribute [local irreducible] extract rawOnlineNext
attribute [local irreducible] payload descend child fieldWordAt

def indexPath (coordinate : SmzaQ38McaSourceBinding.Position) : Nat → List Nat
  | 0 => []
  | depth + 1 =>
      (if coordinate.val.testBit depth then 1 else 0) :: indexPath coordinate depth

theorem index_path_length (coordinate : SmzaQ38McaSourceBinding.Position)
    (depth : Nat) : (indexPath coordinate depth).length = depth := by
  induction depth with
  | zero => rfl
  | succ depth ih => simp only [indexPath, List.length_cons, ih]

theorem descend_eq_subtree (coordinate : SmzaQ38McaSourceBinding.Position)
    (depth : Nat) (trace : SmzaRp04TracePrefixes.Trace) :
    descend coordinate depth trace = subtree (indexPath coordinate depth) trace := by
  induction depth generalizing trace with
  | zero => simp only [descend, indexPath, subtree]
  | succ depth ih =>
      rw [descend, indexPath, subtree_cons, ← child_eq_subtree, ih]

theorem payload_of_read_path
    (path : List Nat) (trace : SmzaRp04TracePrefixes.Trace)
    (input : V8SmzaOracleParser.RawInput) (parsed : V8SmzaOracleParser.Payload)
    (readback : readPath path trace = some input)
    (parse : V8SmzaOracleParser.rawPayload input = some parsed) :
    payload parsed.kind (subtree path trace) = some parsed := by
  induction path generalizing trace with
  | nil =>
      cases trace with
      | missing => cases readback
      | budget => cases readback
      | record actual children =>
          have same : actual = input := Option.some.inj readback
          subst actual
          simp [subtree, payload, parse]
  | cons index rest ih =>
      cases trace with
      | missing => cases readback
      | budget => cases readback
      | record actual children =>
          simp only [readPath] at readback
          cases selected : children[index]? with
          | none => simp [selected] at readback
          | some childTrace =>
              have below : readPath rest childTrace = some input := by
                simpa only [selected, Option.bind_some] using readback
              simpa only [subtree, selected, Option.getD_some] using ih childTrace below

private theorem root_oracle_of_payload
    (trace : SmzaRp04TracePrefixes.Trace)
    (coordinate : SmzaQ38McaSourceBinding.Position) (row : Fin 145)
    (leaf : V8SmzaOracleParser.Payload)
    (readback : payload .leaf (descend coordinate 23 (child trace 0)) = some leaf)
    (index : V8SmzaOracleParser.wordAt leaf.bytes 4 = coordinate.val)
    (dataCount : V8SmzaOracleParser.wordAt leaf.bytes 13 = 140)
    (maskCount : V8SmzaOracleParser.wordAt leaf.bytes 154 = 5) :
    rootOracle trace coordinate row = fieldWordAt leaf.bytes
      (if row.val < 140 then 14 + row.val else 155 + (row.val - 140)) := by
  unfold rootOracle
  rw [readback]
  exact if_pos ⟨index, dataCount, maskCount⟩

/-- The same MSB-first branch path as the verifier is used. A record at an
unrelated branch cannot satisfy this theorem merely by carrying the same index. -/
theorem root_oracle_cell_of_recorded_path
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree records)
    (root : V8SmzaOracleParser.RawDigest)
    (coordinate : SmzaQ38McaSourceBinding.Position) (row : Fin 145)
    (input : V8SmzaOracleParser.RawInput) (leaf : V8SmzaOracleParser.Payload)
    (recorded : RecordedPath rawOnlineNext records .root root
      (0 :: indexPath coordinate 23) input)
    (parsed : V8SmzaOracleParser.rawPayload input = some leaf)
    (kind : leaf.kind = .leaf)
    (index : V8SmzaOracleParser.wordAt leaf.bytes 4 = coordinate.val)
    (dataCount : V8SmzaOracleParser.wordAt leaf.bytes 13 = 140)
    (maskCount : V8SmzaOracleParser.wordAt leaf.bytes 154 = 5)
    (fuel : Nat) (enough : 25 ≤ fuel) :
    rootOracle (extract rawOnlineNext records fuel .root root) coordinate row =
      fieldWordAt leaf.bytes
        (if row.val < 140 then 14 + row.val else 155 + (row.val - 140)) := by
  have pathRead := recorded_path_readback rawOnlineNext records collisionFree
    .root root (0 :: indexPath coordinate 23) input recorded fuel
    (by simp only [List.length_cons, index_path_length]; omega)
  have payloadRead := payload_of_read_path (0 :: indexPath coordinate 23)
    (extract rawOnlineNext records fuel .root root) input leaf pathRead parsed
  rw [kind, subtree_cons, ← child_eq_subtree, ← descend_eq_subtree] at payloadRead
  exact root_oracle_of_payload _ coordinate row leaf payloadRead index dataCount maskCount

end
end HegemonCrypto.SmallWood.SmzaRp04RawRootReadback
