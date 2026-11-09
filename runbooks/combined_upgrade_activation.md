# Combined pre-mainnet upgrade candidate

The candidate composes the timestamp-admission repair, one-hour ASERT,
24-bit mining version rolling and exact 60-block treasury payouts on the existing
pre-mainnet identity. The user selected **H18,660** for release **v0.11.4** and
authorized publication followed by deployment on hegemon-dev, then hegemon-ovh.
Complete final exact-source and artifact checks before publication or rollout.
The user will make the Discord announcement after rollout. Test receipts retain
their technical evidence scope and do not stand in for operational receipts.

The disposable Development rehearsal activates all three scheduled rules at
H120, preserves legacy rules through H119, and pays its first complete batch at
H179. Treasury accrual includes every accepted active height even when a miner
forfeits its own reward. The treasury note matures 120 blocks after creation;
the first ordinary spend can be included at H299. Miner rewards and fees remain
per block. The existing fixed two-input current SMZL relation is unchanged.

## Candidate acceptance

Retain the exact candidate revision, reviewed source inventory, artifact hashes,
features, commands and complete CI runs. Required evidence includes:

- Fresh timestamp bounds on CPU/ASIC import, announcements, both sync paths and
  stored promotion, with identical-byte retry and clock-free historical replay.
- Integer ASERT reference and Lean vectors, no-std checks, exact activation,
  branch anchors, cold resumption and real-clock native authoring/catch-up.
- Fixed-version and negotiated rolled-version work, both extranonce splits,
  malformed/out-of-mask rejection and independent import of actual rolled work.
- Treasury arithmetic, checked ranges, halving/exhaustion, omission and payout
  rejection, pending/issued accounting, maturity and a genuine current spend.
- Genuine funded current SMZL HTLC lock, claim and refund, deadlines,
  competing-nullifier rejection, encrypted recovery, reorg, restart and fresh sync.
- Every required full CI and preparation-platform job, including actual final
  binary proof verification and isolated H0 checks. Rehearsal executables and
  production executables retain distinct hashes and qualification scopes.

Software-mined work establishes no physical ASIC model/firmware performance.
Hardware claims require separately measured sustained accepted work on the exact
model/firmware/profile. A fresh mainnet remains a separate genesis/bootstrap and
identity-bound qualification, with adopted rules applied from its first block.

## Selected height and announcement

The common height H is **18,660**, divisible by 60. Friday morning November 13,
2026 in Calgary is an estimate; block height controls consensus and actual block
production controls the time. At 60-second blocks, two to three days is
2,880–4,320 blocks. Recheck actual tip and remaining lead before deployment.
The first treasury batch covers H18,660..H18,719, pays at H18,719 and becomes
spendable at H18,839. Miner rewards and fees remain per block.

Changing the compiled production height changes the candidate source. Freeze it,
rebuild all final artifacts, rerun the affected transition/source gates and
required CI, then verify the remaining block lead before announcing. Announce
both H and an estimated UTC date; block height controls consensus. Do not label
an unset-height preparation artifact as the final scheduled release.

Operators install the qualified scheduled artifact before H and verify its
source/artifact/manifest identity. Keep the approved shared seeds
`HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`
unless deliberately rotated. All miners on the network must share the same seed
list to avoid partitions and forks. Keep NTP or chrony enabled: future-skewed
PoW timestamps are rejected. Jobs retain their fixed advertised timestamps;
clock correction can temporarily pause work and retry an unexpired solution.

Preserve existing chain/wallet archives and stage the current release for
pre-activation recovery. After H, an old binary is consensus-incompatible with
the new rules and cannot serve as an ordinary compatible rollback. The exact
release publication, operator rollout and activation notice remain separately
recorded actions.
