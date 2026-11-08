# Native supply accounting

The `supply_digest` returned by `hegemon_consensusStatus` and
`hegemon_latestBlock` is the same unsigned 128-bit counter committed in the
PoW header. Its existing name and arithmetic are consensus data. It measures
gross fee-inclusive coinbase accounting, not circulating supply.

## Header and RPC counter

For the historical per-block native HGN route, a block with coinbase advances the counter by
its scheduled subsidy plus the checked total of included transfer fees. A block
without coinbase leaves it unchanged. Replay reconstructs this value and
requires exact equality with the header; reward or counter overflow rejects.

    next_digest = parent_digest + subsidy(height) + included_fees  # coinbase present
    next_digest = parent_digest                                   # no coinbase

For example, a parent counter of 100 HGN, a subsidy of 5 HGN and fees of 0.1 HGN
give a new counter of 105.1 HGN. Transfers have already removed the 0.1 HGN fee
from their input/output value balance, and coinbase returns it to the miner.
Only the 5 HGN subsidy is newly issued in that example. Spending and recycling
existing fees can increase the counter repeatedly, including after subsidies
end. A value above 21M in `supply_digest` therefore does not, by itself,
demonstrate more than 21M spendable HGN or a monetary-cap violation.

Explorers and RPC consumers should label this field **supply digest** or
**gross coinbase accounting**, retain exact integer atoms (100,000,000 per HGN),
and not use it as circulating supply or compare it directly with `MAX_SUPPLY`.
There is no new RPC metric introduced by this documentation. Redefining the
existing header value would require a separately reviewed consensus change,
matching replay and formal/vector updates, and explicit identity/activation
handling.

## Schedule, actual issuance and spendable value

These quantities have different meanings:

- `scheduled_subsidy(height)` is the cumulative subsidy schedule through that
  height. It is a ceiling: an omitted coinbase does not mint its scheduled
  subsidy, and later blocks do not recover that forfeited allocation.
- Actual subsidy issuance counts subsidies included in accepted coinbases.
  Current HGN has no separate native burn action. Included fees are recycled
  value, not additional issuance. If coinbase is omitted, its subsidy and fees
  are forfeited; unclaimed fees reduce existing spendable value. Subsidy issuance
  alone therefore does not measure the net change in note value.
- Spendable wealth additionally depends on accepted transfer conservation,
  unspent-note history and reward maturity. It is not a wallet's available
  balance, a schedule prefix or the fee-inclusive header counter.

The current schedule uses height-based 2,100,000-block epochs and an initial
5 HGN subsidy. Each epoch receives the difference between consecutive remaining
scheduled budgets; differences of integer floor prefixes distribute that epoch's
atoms exactly across its slots. This avoids losing division dust. Height zero
issues nothing. The 60-second target is a timing target, not a timestamp-based
epoch selector. The selected network starts from an empty note tree; genesis
allocations and optional burn/tail-emission proposals in older tokenomics
material do not alter this source-owned policy.

The reward split assigns `floor(subsidy / 5)` to the configured funding recipient
and the remainder plus all fees to the miner. The source requires 120-block
reward maturity. These statements describe the current implementation; mainnet
identity and release authority remain separately qualified.

## Combined treasury migration candidate

The combined upgrade keeps the historical per-block rules below its selected
activation height H. Production H remains unset during preparation. At active
heights, reconstruct the same gross counter from the actual coinbase-note values:

    next_digest = parent_digest + sum(created_coinbase_note_values)

That sum includes recycled fees when the miner claims its note. It excludes
pending treasury entitlement until a treasury note is actually created. Each
accepted active height accrues `floor(subsidy(height) / 5)` independently of the
miner claiming its own reward. A positive payout at H+59 and every 60 blocks
thereafter is mandatory, including when the miner forfeits its note. Omissions
below H are never re-accrued. Miner subsidy remainder and all fees stay per block;
120-block maturity begins at each note's actual creation height.

The historical per-block supply theorems do not by themselves describe this
transition. The separate
[batch accounting model](../formal/lean/Hegemon/Consensus/TreasuryBatchSupply.lean)
and generated native-helper vectors distinguish pending entitlement, actual
coinbase issuance and the legacy inactive branch. They are local model/vector
and source-guard evidence, with full Rust/chain refinement and production
activation outside their scope. Genuine proof-bearing lifecycle and exact
release-artifact qualification remain required.

## Evidence and limits

[Native replay](../node/src/native/block_flow.rs) implements
`expected_native_supply_from_parts` and compares the reconstructed digest with
the header. [The subsidy helpers](../consensus/src/reward.rs) implement the
schedule and expose `scheduled_subsidy`. [The reward split](../protocol/shielded-pool/src/poseidon2_v8_coinbase.rs)
preserves subsidy-plus-fee total while fixing the funding allocation.

[The Lean accounting model](../formal/lean/Hegemon/Consensus/Supply.lean) treats
the fee-inclusive digest separately from the scheduled prefix.
[NativeMonetaryCap](../formal/crypto/HegemonCrypto/NativeMonetaryCap.lean) proves
the exact epoch-budget issuance result and that coinbase outputs minus fees
leave the subsidy. It explicitly excludes circulating-wealth/history
conservation, arbitrary Rust/compiler refinement and release authority.
The conditional initialized-history conservation endpoint and its cryptographic
assumptions are described in [the security policy](../SECURITY.md). Passing an
accounting/vector check is not an end-to-end proof of current compiled-node
security.
