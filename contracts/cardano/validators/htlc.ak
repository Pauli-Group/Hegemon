use aiken/builtin.{length_of_bytearray, sha2_256}
use aiken/collection/list
use aiken/interval
use cardano/transaction.{OutputReference, Transaction}

pub type Terms {
  hashlock: ByteArray,
  claimant: ByteArray,
  refundee: ByteArray,
  expiry: Int,
}
pub type Action {
  Claim { preimage: ByteArray }
  Refund
}
pub fn authorized(terms: Terms, action: Action, tx: Transaction) -> Bool {
  when action is {
    Claim { preimage } -> and {
      length_of_bytearray(preimage) == 32,
      sha2_256(preimage) == terms.hashlock,
      list.has(tx.extra_signatories, terms.claimant),
      interval.is_entirely_before(tx.validity_range, terms.expiry),
    }
    Refund -> and {
      list.has(tx.extra_signatories, terms.refundee),
      interval.is_entirely_after(tx.validity_range, terms.expiry - 1),
    }
  }
}
validator htlc {
  spend(datum: Option<Terms>, action: Action, _own_ref: OutputReference, tx: Transaction) {
    expect Some(terms) = datum
    authorized(terms, action, tx)
  }
  else(_) { fail }
}

fn terms() -> Terms {
  Terms {
    hashlock: sha2_256(#"0000000000000000000000000000000000000000000000000000000000000001"),
    claimant: #"11111111111111111111111111111111111111111111111111111111",
    refundee: #"22222222222222222222222222222222222222222222222222222222",
    expiry: 1000,
  }
}
fn context(signer: ByteArray, lower: Int, upper: Int) -> Transaction {
  Transaction { ..transaction.placeholder, extra_signatories: [signer], validity_range: interval.between(lower, upper) }
}
test claim_before_expiry() {
  let t = terms()
  authorized(t, Claim { preimage: #"0000000000000000000000000000000000000000000000000000000000000001" }, context(t.claimant, 0, 999))
}
test wrong_secret_rejected() {
  let t = terms()
  !authorized(t, Claim { preimage: #"0000000000000000000000000000000000000000000000000000000000000002" }, context(t.claimant, 0, 999))
}
test short_secret_rejected() {
  let t = terms()
  !authorized(t, Claim { preimage: #"01" }, context(t.claimant, 0, 999))
}
test unauthorized_claim_rejected() {
  let t = terms()
  !authorized(t, Claim { preimage: #"0000000000000000000000000000000000000000000000000000000000000001" }, context(t.refundee, 0, 999))
}
test inclusive_expiry_claim_rejected() {
  let t = terms()
  !authorized(t, Claim { preimage: #"0000000000000000000000000000000000000000000000000000000000000001" }, context(t.claimant, 0, 1000))
}
test crossing_expiry_claim_rejected() {
  let t = terms()
  !authorized(t, Claim { preimage: #"0000000000000000000000000000000000000000000000000000000000000001" }, context(t.claimant, 999, 1001))
}
test unbounded_claim_rejected() {
  let t = terms()
  let tx = Transaction { ..transaction.placeholder, extra_signatories: [t.claimant] }
  !authorized(t, Claim { preimage: #"0000000000000000000000000000000000000000000000000000000000000001" }, tx)
}
test early_refund_rejected() {
  let t = terms()
  !authorized(t, Refund, context(t.refundee, 999, 1001))
}
test refund_at_expiry() {
  let t = terms()
  authorized(t, Refund, context(t.refundee, 1000, 1001))
}
test unauthorized_refund_rejected() {
  let t = terms()
  !authorized(t, Refund, context(t.claimant, 1000, 1001))
}
