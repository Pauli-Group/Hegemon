import SmzaRp05ExecutablePcsClosureStatement

/-!
# Deterministic PCS stage evidence extracted from the assembled execution

The stage record below is constructed from successful PCS execution. It is
never a verifier argument. It preserves every intermediate's provenance in
the same decoded proof and oracle, including the pending state returned by
the source-shaped q38 sampler. Its row-construction equation can be passed
directly to the checked LVCS coordinate-equation theorem. The response
construction equation exposes the actual decoded-high polynomial restore.

This does not construct an AcceptedFailureWitness without its other semantic
inputs: fresh statement, extraction failure, a common measured database,
BEFORE records and their collision-free reconstruction are still necessary.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureStages

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program Oracle Input ask)
open SmzaRp05ExecutableChallengeStage (PostMerkle)
open SmzaRp05PcsWireProjection (DecodedMiddleWire)
open SmzaRp05PcsWireProjection (fieldWordsToGoldilocks)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05ExecutablePcsClosure
  (pcsProgram queryProgram widths deltas nativeFiveMcaGate406 currentTwelveLvcsGate406)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false

structure PcsStages (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : DecodedMiddleWire) (decs : DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest)) (oracle : Oracle)
    (hashFpp : RawDigest) (finalPending : Bool) where
  heads : List (List Goldilocks)
  openingInput : RawInput
  openingDigest : RawDigest
  indexes : List Nat
  sampledPending : Bool
  decsPoints : List Goldilocks
  rows : List (List Goldilocks)
  merkleInput : Input
  post : PostMerkle
  hashProgram : Program RawDigest
  headsBuilt : SmzaRp05PcsWireProjection.reconstructedHeadsAll wire.pcs points
    wire.rowScalars 64 widths deltas 2 368 = some heads
  openingBuilt : SmzaRp05PcsWireProjection.decsOpeningInput hPiop 12 368 38
    heads wire.pcs.rcombiTails = some openingInput
  openingRead : (ask openingInput).eval oracle = some openingDigest
  queryExecuted : (queryProgram pending openingDigest).eval oracle =
    some (indexes, sampledPending)
  pointsBuilt : SmzaRp05DecsPointProjection.fieldPoints 406 indexes = some decsPoints
  rowsBuilt : SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields wire.pcs
    points decsPoints wire.rowScalars 64 widths deltas 2 368 140 38 = some rows
  inputBuilt : SmzaRp05PcsMerklePayload.makeMerkleInput salt binding sampledPending
    indexes rows decs.maskingEvals tapes paths = some merkleInput
  postExecuted : (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns merkleInput).eval
    oracle = some post
  responseBuilt : SmzaRp05DecsResponseProjection.hashFppProgram post.root decs
    (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
    (SmzaRp05PcsHashFppMiddle.gammaRows post)
    (decsPoints.map SmzaRp05ExecutableRestore.toWord)
    140 368 statementBinding = some hashProgram
  hashExecuted : hashProgram.eval oracle = some hashFpp
  pendingReturned : finalPending = post.pending

attribute [local irreducible]
  SmzaRp05PcsWireProjection.reconstructedHeadsAll
  SmzaRp05PcsWireProjection.decsOpeningInput
  SmzaRp05DecsPointProjection.fieldPoints
  SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
  SmzaRp05PcsMerklePayload.makeMerkleInput
  SmzaRp05ExecutableChallengeStage.postMerkleProgram
  SmzaRp05DecsResponseProjection.hashFppProgram
  queryProgram

theorem pcs_execution_has_stages (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : DecodedMiddleWire) (decs : DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest)) (oracle : Oracle)
    (hashFpp : RawDigest) (finalPending : Bool)
    (executed : (pcsProgram ns pending hPiop wire decs points salt binding
      statementBinding tapes paths).eval oracle = some (hashFpp, finalPending)) :
    Nonempty (PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending) := by
  cases headsBuilt : SmzaRp05PcsWireProjection.reconstructedHeadsAll wire.pcs points
      wire.rowScalars 64 widths deltas 2 368 with
  | none =>
      simp only [pcsProgram, headsBuilt, Program.eval] at executed
      cases executed
  | some heads =>
      simp only [pcsProgram, headsBuilt] at executed
      cases openingBuilt : SmzaRp05PcsWireProjection.decsOpeningInput hPiop 12 368 38
          heads wire.pcs.rcombiTails with
      | none =>
          simp only [openingBuilt, Program.eval] at executed
          cases executed
      | some openingInput =>
          simp only [openingBuilt] at executed
          obtain ⟨openingDigest, openingRead, afterOpening⟩ :=
            SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
              (ask openingInput) _ (hashFpp, finalPending) executed
          obtain ⟨queryPair, queryExecuted, afterQuery⟩ :=
            SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
              (queryProgram pending openingDigest) _ (hashFpp, finalPending) afterOpening
          rcases queryPair with ⟨indexes, sampledPending⟩
          cases pointsBuilt : SmzaRp05DecsPointProjection.fieldPoints 406 indexes with
          | none =>
              simp only [pointsBuilt, Program.eval] at afterQuery
              cases afterQuery
          | some decsPoints =>
              simp only [pointsBuilt] at afterQuery
              cases rowsBuilt : SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
                  wire.pcs points decsPoints wire.rowScalars 64 widths deltas
                  2 368 140 38 with
              | none =>
                  simp only [rowsBuilt, Program.eval] at afterQuery
                  cases afterQuery
              | some rows =>
                  simp only [rowsBuilt] at afterQuery
                  cases lvcsGate : currentTwelveLvcsGate406 heads
                      (wire.pcs.rcombiTails.map fieldWordsToGoldilocks)
                      points decsPoints rows with
                  | false =>
                      simp only [lvcsGate] at afterQuery
                      cases afterQuery
                  | true =>
                      simp only [lvcsGate] at afterQuery
                      cases inputBuilt : SmzaRp05PcsMerklePayload.makeMerkleInput
                          salt binding sampledPending indexes rows decs.maskingEvals
                          tapes paths with
                      | none =>
                          simp only [inputBuilt] at afterQuery
                          cases afterQuery
                      | some merkleInput =>
                          simp only [inputBuilt] at afterQuery
                          obtain ⟨post, postExecuted, afterMerkle⟩ :=
                            SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
                              (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns
                                merkleInput) _ (hashFpp, finalPending) afterQuery
                          cases responseBuilt :
                              SmzaRp05DecsResponseProjection.hashFppProgram post.root decs
                                (rows.map fun row =>
                                  row.map SmzaRp05ExecutableRestore.toWord)
                                (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                                140 368 statementBinding with
                          | none =>
                              simp only [responseBuilt, Program.eval] at afterMerkle
                              cases afterMerkle
                          | some hashProgram =>
                              simp only [responseBuilt] at afterMerkle
                              cases restorationBuilt :
                                  SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
                                    (rows.map fun row =>
                                      row.map SmzaRp05ExecutableRestore.toWord)
                                    (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                    (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                                    140 368 with
                              | none =>
                                  simp only [restorationBuilt, Program.eval] at afterMerkle
                                  cases afterMerkle
                              | some polynomials =>
                                  cases mcaGate : nativeFiveMcaGate406 salt tapes indexes
                                      (rows.map fun row =>
                                        row.map SmzaRp05ExecutableRestore.toWord)
                                      (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                      decs.maskingEvals
                                      (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                                      polynomials with
                                  | false =>
                                      simp only [restorationBuilt, mcaGate] at afterMerkle
                                      cases afterMerkle
                                  | true =>
                                      simp only [restorationBuilt, mcaGate] at afterMerkle
                                      obtain ⟨digest, hashExecuted, returned⟩ :=
                                        SmzaRp05FinalProgramMiddleExecution.program_bind_success
                                          oracle hashProgram _ (hashFpp, finalPending)
                                          afterMerkle
                                      have pairEqual :
                                          (digest, post.pending) = (hashFpp, finalPending) :=
                                        Option.some.inj returned
                                      have digestEqual : digest = hashFpp :=
                                        congrArg Prod.fst pairEqual
                                      have pendingEqual : post.pending = finalPending :=
                                        congrArg Prod.snd pairEqual
                                      subst digest
                                      exact ⟨⟨heads, openingInput, openingDigest, indexes,
                                        sampledPending, decsPoints, rows, merkleInput, post,
                                        hashProgram, headsBuilt, openingBuilt, openingRead,
                                        queryExecuted, pointsBuilt, rowsBuilt, inputBuilt,
                                        postExecuted, responseBuilt, hashExecuted,
                                        pendingEqual.symm⟩⟩

end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureStages
