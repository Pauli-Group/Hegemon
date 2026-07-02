namespace Hegemon
namespace Native
namespace CoinbaseActionPayloadAdmission

inductive CoinbasePayloadReject where
  | amountZero
  | commitmentMismatch
  | commitmentZero
  | ciphertextTooLarge
  | ciphertextHashMismatch
  | ciphertextSizeMismatch
deriving DecidableEq, Repr

structure CoinbasePayloadInput where
  amountNonzero : Bool
  commitmentMatches : Bool
  commitmentNonzero : Bool
  ciphertextBytes : Nat
  maxCiphertextBytes : Nat
  ciphertextHashMatches : Bool
  ciphertextSizeMatches : Bool
deriving DecidableEq, Repr

def evaluateCoinbasePayload
    (input : CoinbasePayloadInput) : Except CoinbasePayloadReject Unit :=
  if input.amountNonzero = false then
    Except.error CoinbasePayloadReject.amountZero
  else if input.commitmentMatches = false then
    Except.error CoinbasePayloadReject.commitmentMismatch
  else if input.commitmentNonzero = false then
    Except.error CoinbasePayloadReject.commitmentZero
  else if input.ciphertextBytes > input.maxCiphertextBytes then
    Except.error CoinbasePayloadReject.ciphertextTooLarge
  else if input.ciphertextHashMatches = false then
    Except.error CoinbasePayloadReject.ciphertextHashMismatch
  else if input.ciphertextSizeMatches = false then
    Except.error CoinbasePayloadReject.ciphertextSizeMismatch
  else
    Except.ok ()

def coinbasePayloadAccepts (input : CoinbasePayloadInput) : Bool :=
  match evaluateCoinbasePayload input with
  | Except.ok _ => true
  | Except.error _ => false

def coinbasePayloadRejection
    (input : CoinbasePayloadInput) : Option CoinbasePayloadReject :=
  match evaluateCoinbasePayload input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def coinbasePayloadPreconditions (input : CoinbasePayloadInput) : Bool :=
  if input.amountNonzero = false then
    false
  else if input.commitmentMatches = false then
    false
  else if input.commitmentNonzero = false then
    false
  else if input.ciphertextBytes > input.maxCiphertextBytes then
    false
  else if input.ciphertextHashMatches = false then
    false
  else if input.ciphertextSizeMatches = false then
    false
  else
    true

theorem accepts_iff_payload_preconditions (input : CoinbasePayloadInput) :
    coinbasePayloadAccepts input = coinbasePayloadPreconditions input := by
  cases input with
  | mk amountNonzero commitmentMatches commitmentNonzero ciphertextBytes
      maxCiphertextBytes ciphertextHashMatches ciphertextSizeMatches =>
      unfold coinbasePayloadAccepts coinbasePayloadPreconditions evaluateCoinbasePayload
      by_cases tooLarge : ciphertextBytes > maxCiphertextBytes
      · cases amountNonzero <;> cases commitmentMatches <;> cases commitmentNonzero <;>
          cases ciphertextHashMatches <;> cases ciphertextSizeMatches <;>
          simp [tooLarge]
      · cases amountNonzero <;> cases commitmentMatches <;> cases commitmentNonzero <;>
          cases ciphertextHashMatches <;> cases ciphertextSizeMatches <;>
          simp [tooLarge]

def validCoinbasePayload : CoinbasePayloadInput :=
  {
    amountNonzero := true,
    commitmentMatches := true,
    commitmentNonzero := true,
    ciphertextBytes := 611,
    maxCiphertextBytes := 2147,
    ciphertextHashMatches := true,
    ciphertextSizeMatches := true
  }

theorem valid_coinbase_payload_accepts :
    evaluateCoinbasePayload validCoinbasePayload = Except.ok () := by
  rfl

theorem exact_ciphertext_limit_accepts :
    evaluateCoinbasePayload
      { validCoinbasePayload with
        ciphertextBytes := validCoinbasePayload.maxCiphertextBytes } =
      Except.ok () := by
  rfl

theorem amount_zero_rejects
    {input : CoinbasePayloadInput}
    (zero : input.amountNonzero = false) :
    evaluateCoinbasePayload input =
      Except.error CoinbasePayloadReject.amountZero := by
  unfold evaluateCoinbasePayload
  simp [zero]

theorem commitment_mismatch_rejects
    {input : CoinbasePayloadInput}
    (amount : input.amountNonzero = true)
    (mismatch : input.commitmentMatches = false) :
    evaluateCoinbasePayload input =
      Except.error CoinbasePayloadReject.commitmentMismatch := by
  unfold evaluateCoinbasePayload
  simp [amount, mismatch]

theorem commitment_zero_rejects
    {input : CoinbasePayloadInput}
    (amount : input.amountNonzero = true)
    (commitmentMatches : input.commitmentMatches = true)
    (zero : input.commitmentNonzero = false) :
    evaluateCoinbasePayload input =
      Except.error CoinbasePayloadReject.commitmentZero := by
  unfold evaluateCoinbasePayload
  simp [amount, commitmentMatches, zero]

theorem ciphertext_too_large_rejects
    {input : CoinbasePayloadInput}
    (amount : input.amountNonzero = true)
    (commitmentMatches : input.commitmentMatches = true)
    (commitmentNonzero : input.commitmentNonzero = true)
    (tooLarge : input.ciphertextBytes > input.maxCiphertextBytes) :
    evaluateCoinbasePayload input =
      Except.error CoinbasePayloadReject.ciphertextTooLarge := by
  unfold evaluateCoinbasePayload
  simp [amount, commitmentMatches, commitmentNonzero, tooLarge]

theorem ciphertext_hash_mismatch_rejects
    {input : CoinbasePayloadInput}
    (amount : input.amountNonzero = true)
    (commitmentMatches : input.commitmentMatches = true)
    (commitmentNonzero : input.commitmentNonzero = true)
    (ciphertextInBounds : ¬ input.ciphertextBytes > input.maxCiphertextBytes)
    (mismatch : input.ciphertextHashMatches = false) :
    evaluateCoinbasePayload input =
      Except.error CoinbasePayloadReject.ciphertextHashMismatch := by
  unfold evaluateCoinbasePayload
  simp [
    amount,
    commitmentMatches,
    commitmentNonzero,
    ciphertextInBounds,
    mismatch
  ]

theorem ciphertext_size_mismatch_rejects
    {input : CoinbasePayloadInput}
    (amount : input.amountNonzero = true)
    (commitmentMatches : input.commitmentMatches = true)
    (commitmentNonzero : input.commitmentNonzero = true)
    (ciphertextInBounds : ¬ input.ciphertextBytes > input.maxCiphertextBytes)
    (hashes : input.ciphertextHashMatches = true)
    (mismatch : input.ciphertextSizeMatches = false) :
    evaluateCoinbasePayload input =
      Except.error CoinbasePayloadReject.ciphertextSizeMismatch := by
  unfold evaluateCoinbasePayload
  simp [
    amount,
    commitmentMatches,
    commitmentNonzero,
    ciphertextInBounds,
    hashes,
    mismatch
  ]

theorem amount_zero_precedes_commitment_mismatch :
    evaluateCoinbasePayload
      { validCoinbasePayload with
        amountNonzero := false,
        commitmentMatches := false } =
      Except.error CoinbasePayloadReject.amountZero := by
  rfl

theorem commitment_mismatch_precedes_zero_commitment :
    evaluateCoinbasePayload
      { validCoinbasePayload with
        commitmentMatches := false,
        commitmentNonzero := false } =
      Except.error CoinbasePayloadReject.commitmentMismatch := by
  rfl

theorem ciphertext_too_large_precedes_hash_mismatch :
    evaluateCoinbasePayload
      { validCoinbasePayload with
        ciphertextBytes := validCoinbasePayload.maxCiphertextBytes + 1,
        ciphertextHashMatches := false } =
      Except.error CoinbasePayloadReject.ciphertextTooLarge := by
  rfl

end CoinbaseActionPayloadAdmission
end Native
end Hegemon
