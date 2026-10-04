import HegemonCrypto.SmallWoodV8Smz9SourceLifetime

/-! Explicit public input/control flow for a full source lifetime. The public
syntax contains no witness or admission proof. A simulator can consume this
erased interface directly; no valid witness is chosen from public inputs. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourcePublicErasure

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9SourceLifetime
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

structure PublicRequestData (bound : Nat) where
  statement : V8PublicStatement
  publicValues : List Nat
  statementBinding : List Nat
  bindingFits : 15704 + 8 * statementBinding.length ≤ bound
  salt : V8Smz9EagerOracleGame.SaltBytes
  retainedRows : Nat
  rowBound : retainedRows ≤ 20605

def publicRequest {bound : Nat} (request : SourceRequestData bound) : PublicRequestData bound where
  statement := request.statement
  publicValues := request.publicValues
  statementBinding := request.statementBinding
  bindingFits := request.bindingFits
  salt := request.salt
  retainedRows := request.retainedRows
  rowBound := request.rowBound

inductive PublicLifetime (bound : Nat) (Work : Type) [Fintype Work] : Nat → Nat → Type 1 where
  | finish {queries requests : Nat}
      (event : Finset (QueryBasis (FullRawInput bound) DigestRegister Work)) :
      PublicLifetime bound Work queries requests
  | gate {queries requests : Nat}
      (operation : GameGate (Input := FullRawInput bound) (Work := Work))
      (next : PublicLifetime bound Work queries requests) : PublicLifetime bound Work queries requests
  | quantumQuery {queries requests : Nat}
      (next : PublicLifetime bound Work queries requests) : PublicLifetime bound Work (queries + 1) requests
  | honestRead {queries requests : Nat} (input : FullRawInput bound)
      (next : DigestRegister → PublicLifetime bound Work queries requests) :
      PublicLifetime bound Work (queries + 1) requests
  | instrument {queries requests count : Nat}
      (operation : Instrument (FullRawInput bound) Work count)
      (next : Fin count → PublicLifetime bound Work queries requests) : PublicLifetime bound Work queries requests
  | random {queries requests : Nat} (source : RandomSource)
      (next : source.Coins → PublicLifetime bound Work queries requests) : PublicLifetime bound Work queries requests
  | sourceRequest {queries requests : Nat} (request : PublicRequestData bound)
      (next : ByteResult → PublicLifetime bound Work queries requests) :
      PublicLifetime bound Work (16790291 + queries) (requests + 1)

variable {bound : Nat} {Work : Type} [Fintype Work]

def eraseSource : {queries requests : Nat} → Lifetime bound Work queries requests →
    PublicLifetime bound Work queries requests
  | _, _, .finish event => .finish event
  | _, _, .gate operation next => .gate operation (eraseSource next)
  | _, _, .quantumQuery next => .quantumQuery (eraseSource next)
  | _, _, .honestRead input next => .honestRead input (fun answer => eraseSource (next answer))
  | _, _, .instrument operation next => .instrument operation (fun outcome => eraseSource (next outcome))
  | _, _, .random source next => .random source (fun coins => eraseSource (next coins))
  | _, _, .sourceRequest request next =>
      .sourceRequest (publicRequest request) (fun bytes => eraseSource (next bytes))

/-- Public control flow agrees at every possible classical outcome. The two
admitted witnesses and their domain proofs may differ at each request. -/
inductive PubliclyEquivalent : {queries requests : Nat} →
    Lifetime bound Work queries requests → Lifetime bound Work queries requests → Prop where
  | finish {queries requests : Nat}
      (event : Finset (QueryBasis (FullRawInput bound) DigestRegister Work)) :
      PubliclyEquivalent (.finish (queries := queries) (requests := requests) event) (.finish event)
  | gate {queries requests : Nat} {left right : Lifetime bound Work queries requests}
      (operation : GameGate (Input := FullRawInput bound) (Work := Work))
      (next : PubliclyEquivalent left right) : PubliclyEquivalent (.gate operation left) (.gate operation right)
  | quantumQuery {queries requests : Nat} {left right : Lifetime bound Work queries requests}
      (next : PubliclyEquivalent left right) : PubliclyEquivalent (.quantumQuery left) (.quantumQuery right)
  | honestRead {queries requests : Nat}
      {left right : DigestRegister → Lifetime bound Work queries requests}
      (input : FullRawInput bound) (next : ∀ answer, PubliclyEquivalent (left answer) (right answer)) :
      PubliclyEquivalent (.honestRead input left) (.honestRead input right)
  | instrument {queries requests count : Nat}
      {left right : Fin count → Lifetime bound Work queries requests}
      (operation : Instrument (FullRawInput bound) Work count)
      (next : ∀ outcome, PubliclyEquivalent (left outcome) (right outcome)) :
      PubliclyEquivalent (.instrument operation left) (.instrument operation right)
  | random {queries requests : Nat} (source : RandomSource)
      {left right : source.Coins → Lifetime bound Work queries requests}
      (next : ∀ coins, PubliclyEquivalent (left coins) (right coins)) :
      PubliclyEquivalent (.random source left) (.random source right)
  | sourceRequest {queries requests : Nat}
      {left right : ByteResult → Lifetime bound Work queries requests}
      (leftRequest rightRequest : SourceRequestData bound)
      (same : publicRequest leftRequest = publicRequest rightRequest)
      (next : ∀ bytes, PubliclyEquivalent (left bytes) (right bytes)) :
      PubliclyEquivalent (.sourceRequest leftRequest left) (.sourceRequest rightRequest right)

theorem public_erasure_eq_of_publicly_equivalent {queries requests : Nat}
    {left right : Lifetime bound Work queries requests} (related : PubliclyEquivalent left right) :
    eraseSource left = eraseSource right := by
  induction related with
  | finish event => rfl
  | gate operation next ih => exact congrArg (PublicLifetime.gate operation) ih
  | quantumQuery next ih => exact congrArg PublicLifetime.quantumQuery ih
  | honestRead input next ih => exact congrArg (PublicLifetime.honestRead input) (funext ih)
  | instrument operation next ih => exact congrArg (PublicLifetime.instrument operation) (funext ih)
  | random source next ih => exact congrArg (PublicLifetime.random source) (funext ih)
  | sourceRequest leftRequest rightRequest same next ih =>
      simp only [eraseSource, same]
      exact congrArg (PublicLifetime.sourceRequest (publicRequest rightRequest)) (funext ih)

end
end HegemonCrypto.SmallWood.V8Smz9SourcePublicErasure
