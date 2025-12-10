## 1. Parameter Summary

Hegemon’s monetary policy is defined in *time* rather than raw block height, so that changing the block time target does not change the overall shape of the supply curve.

Core parameters:

* `t_block` – target block time in seconds (e.g. 5, 10, 15, 60, …)
* `S_max` – asymptotic maximum supply (e.g. 21,000,000 HEG)
* `Y_epoch` – duration of one issuance epoch in years (e.g. 4 years)
* `T_year` – number of seconds in a year (fixed at 31,536,000 = 365 × 24 × 3,600)
* `α_m` – fraction of block reward paid to miners (0–1)
* `α_f` – fraction of block reward paid to protocol treasury/foundation (0–1)
* `α_c` – fraction of block reward paid to community/ecosystem pools (0–1)
* `β_burn` – fraction of transaction fees that are burned (0–1)

With the constraint:

```text
α_m + α_f + α_c = 1
```

Hegemon exposes **only a shielded pool**: all minted HEG enter circulation as shielded outputs; there is no transparent pool.

---

## 2. Monetary Policy

### 2.1 Epochs and emission shape

Issuance follows a geometric “halving every `Y_epoch` years” schedule, similar in shape to Bitcoin / Zcash but parameterized by the block time.

Define:

```text
T_epoch = Y_epoch × T_year             (seconds per epoch)
blocks_per_year = T_year / t_block
blocks_per_epoch = T_epoch / t_block   (expected blocks in one epoch)
```

Let `R0` be the initial block reward during epoch 0, and let epoch index `k = 0, 1, 2, …`.

Block reward per epoch:

```text
R(k) = R0 / 2^k      for k = 0, 1, 2, …
```

With an infinite sequence of halvings, the total minted supply converges to:

```text
S_total = 2 × R0 × blocks_per_epoch
```

To make `S_total` equal to the design cap `S_max`, Hegemon sets:

```text
R0 = S_max / (2 × blocks_per_epoch)
   = S_max / (2 × Y_epoch × blocks_per_year)
   = (S_max × t_block) / (2 × Y_epoch × T_year)
```

So the **initial block reward is an explicit function of the chosen block time**:

```text
R0(t_block) = (S_max × t_block) / (2 × Y_epoch × 31,536,000)
```

Once `t_block` is fixed for mainnet, `R0` is fixed and the emission schedule is fully determined.

---

### 2.2 Epoch selection (time‑based)

Consensus determines the current epoch based on block timestamps and the configured genesis time.

Let:

* `t_genesis` – genesis time (UNIX timestamp)
* `t_block_timestamp` – median‑time or validated timestamp for the block

Define:

```text
time_since_genesis = max(0, t_block_timestamp − t_genesis)
epoch_index k = floor(time_since_genesis / T_epoch)
```

The consensus block subsidy for a block in epoch `k` is:

```text
BlockSubsidy(k) = R(k) = R0 / 2^k
```

> **Note:** If you prefer height‑based epochs, you can replace the above with:
>
> ```text
> blocks_per_epoch = T_epoch / t_block   (computed once at genesis)
> k = floor(height / blocks_per_epoch)
> ```
>
> and keep the rest of the math identical. The important part is that `blocks_per_epoch` is derived from `t_block`, not hard‑coded for a debug value like 5 seconds.

---

### 2.3 Optional tail emission (parameterized)

To support a tail emission instead of a pure hard cap, define:

* `K_tail` – epoch index at which halving stops and tail emission begins
* `R_tail` – tail emission block reward (constant)

Then:

```text
R(k) = {
    R0 / 2^k          if 0 ≤ k < K_tail
    R_tail            if k ≥ K_tail
}
```

* For a **strict hard cap**, set `R_tail = 0`.
* For a **low, perpetual inflation rate**, choose `R_tail > 0` such that:

  ```text
  annual_tail_issuance ≈ R_tail × blocks_per_year
  tail_inflation_rate ≈ annual_tail_issuance / circulating_supply
  ```

`R_tail` can be treated as a governance parameter; tokenomics remain parameterized by `t_block` via `blocks_per_year`.

---

## 3. Reward Distribution

For each block, the total subsidy from §2 is split between miners, the treasury, and community pools according to fixed fractions `α_m`, `α_f`, and `α_c`.

Given epoch index `k`:

```text
TotalSubsidy(k) = R(k)

MinerReward(k)    = α_m × TotalSubsidy(k)
TreasuryReward(k) = α_f × TotalSubsidy(k)
CommunityReward(k)= α_c × TotalSubsidy(k)
```

All three outputs are paid **directly into the shielded pool**. In practice that means:

* The coinbase transaction creates shielded outputs:

  * One or more outputs to miner‑controlled shielded addresses
  * One output to the treasury shielded address
  * One output to a community/grants shielded address (or contract controller)

No transparent outputs are permitted in coinbase transactions.

---

## 4. Fees and Burns

Hegemon may implement a simple “all fees to miners” model, or a base‑fee‑plus‑burn model. Both can be written in a parameterized way.

Let:

* `Fee_total` – total transaction fees paid by all transactions in the block
* `β_burn` – fraction of `Fee_total` that is burned (0 ≤ β_burn ≤ 1)

Then:

```text
FeeBurned       = β_burn × Fee_total
FeeToMiners     = (1 − β_burn) × Fee_total
```

The miner’s total compensation per block in epoch `k` is:

```text
MinerComp(k) = MinerReward(k) + FeeToMiners
             = α_m × R(k) + (1 − β_burn) × Fee_total
```

If an EIP‑1559‑style mechanism is used, you can further decompose:

* `Fee_total = BaseFee_burned + PriorityFees_to_miners`
* with `BaseFee_burned` determined algorithmically per block.

From a tokenomics standpoint, the key configurable parameter is `β_burn`, which controls how much of the fee revenue is turned into a **negative issuance (burn)** versus directed to miners as additional security budget.

All burned fees are removed from the shielded supply via protocol rules; total supply accounting must include both minted subsidies and burnt fees.

---

## 5. Genesis Distribution (Parameterized)

Genesis allocations are defined abstractly as a set of shielded outputs, each with an amount and optional vesting schedule.

Let the genesis distribution be a list:

```text
GenesisAllocations = { (addr_i, amount_i, vesting_schedule_i) } for i = 1..N
```

Subject to:

```text
sum_i(amount_i) = S_genesis ≤ S_max
```

Where:

* `addr_i` – shielded address for allocation `i`
* `amount_i` – allocated HEG amount
* `vesting_schedule_i` – optional vesting conditions (time‑locked spendability, cliffs, linear vesting, etc.)

Common patterns that can be expressed through this:

* Team & advisor allocations with 3–4 year vesting
* Foundation/treasury allocation with time‑locked tranches
* Early investor allocations with defined cliffs and linear vesting
* Community/airdrop allocations, if any

Genesis allocations are the only place where HEG can appear without coming from the emission schedule; the sum of:

```text
GenesisSupply
+ MintedSubsidies (all epochs)
− BurnedFees
```

must never exceed `S_max` if `R_tail = 0`, and must follow the configured tail‑emission curve when `R_tail > 0`.

All of this is enforced at the protocol level within the shielded value‑balance rules.

---

## 6. Privacy & Pool Design

Hegemon is a **fully shielded** system:

* There is exactly **one** global pool of value: the shielded pool.
* All:

  * Genesis allocations
  * Block subsidies (miner, treasury, community)
  * Transaction outputs
    are shielded outputs.

There is **no transparent pool** and no transparent addresses. This has the following tokenomics implications:

1. **Uniform privacy incentives**

   * There is no economic distinction between “transparent” and “shielded” balances; all value contributes to the anonymity set by construction.

2. **Supply auditability**

   * Even though balances and flows are private, total supply is enforced via:

     * Explicit constraints on minted subsidies from §2
     * Explicit counting of burns from §4
     * Shielded value‑balance checks at the protocol level.

3. **Coinbase behavior**

   * Coinbase transactions must directly create shielded outputs. Any special‑case logic (e.g., multi‑recipient coinbase, vesting) is implemented through shielded addresses and/or time‑locks, not via transparent UTXOs.

---

## 7. Example Instantiation (for later)

Once you decide concrete values, you can instantiate the above by choosing:

* `t_block_mainnet`  (e.g. 10 s or 15 s)
* `S_max`            (e.g. 21,000,000 HEG)
* `Y_epoch`          (e.g. 4 years)
* `α_m`, `α_f`, `α_c` (e.g. 0.8 / 0.1 / 0.1)
* `β_burn`           (e.g. 0.0 at launch, or 0.5 for a base‑fee burn)
* Optional: `K_tail`, `R_tail` if you want a tail emission

Then you compute:

```text
R0 = (S_max × t_block_mainnet) / (2 × Y_epoch × 31,536,000)
blocks_per_epoch = (Y_epoch × 31,536,000) / t_block_mainnet
```

…and publish a short table showing supply over time (e.g. after 4, 8, 12, 16 years) derived from this schedule.

---

## 8. Current implementation snapshot

The runtime now implements the parameterized tokenomics model described above:

* **Time-normalized block rewards** – The pallet computes rewards using the formula `R0 = (S_MAX × T_BLOCK_SECONDS) / (2 × Y_EPOCH × T_YEAR)`. With a 60-second target block time, the initial reward is approximately **4.98 HEG per block**. Halving occurs every `BLOCKS_PER_EPOCH = 2,102,400 blocks` (4 years at 1-minute blocks). [pallets/coinbase/src/lib.rs]

* **Multi-party reward distribution** – Each coinbase is split according to configurable shares:
  - `MinerShare` (α_m = 80%): paid to the miner who found the block
  - `TreasuryShare` (α_f = 10%): paid to the protocol treasury account
  - `CommunityShare` (α_c = 10%): paid to a community/ecosystem pool account
  
  The shares are configured via `Permill` types in `runtime/src/lib.rs` and can be adjusted via governance. [pallets/coinbase/src/lib.rs, runtime/src/lib.rs]

* **Fee burning support** – The fee model pallet now supports a `BurnShare` parameter (β_burn) that controls what fraction of transaction fees are burned. At launch this is set to 0% (all fees go to the fee collector), but can be increased to implement EIP-1559-style fee burning. Burned fees are tracked in `TotalBurned` storage and emitted via `FeeBurned` events. [pallets/fee-model/src/lib.rs]

* **Tail emission support** – The pallet includes `K_TAIL` and `R_TAIL` constants for optional perpetual tail emission after a configurable number of epochs. Currently set to 0 for a strict 21M hard cap, but can be enabled to provide low, perpetual security rewards. [pallets/coinbase/src/lib.rs]

* **Target block time** – Consensus now targets a **60-second block time** (`TARGET_BLOCK_TIME_MS = 60_000`). Genesis difficulty is set to `20,040,000` (12× the previous 5-second value) to maintain the same hash rate requirement per block. Retarget interval is `10 blocks` (10 minutes between adjustments). [pallets/difficulty/src/lib.rs, node/src/substrate/service.rs]

### Calculated values for mainnet

| Parameter | Value |
|-----------|-------|
| `t_block` | 60 seconds |
| `S_max` | 21,000,000 HEG |
| `Y_epoch` | 4 years |
| `R0` (initial reward) | ~4.98 HEG/block |
| `blocks_per_epoch` | 2,102,400 |
| `α_m` (miner share) | 80% |
| `α_f` (treasury share) | 10% |
| `α_c` (community share) | 10% |
| `β_burn` (fee burn) | 0% (adjustable) |
| `K_tail` | 0 (no tail emission) |
| `GENESIS_DIFFICULTY` | 20,040,000 |
