import { useEffect, useRef, useState } from 'react';
import {
  hgn,
  parseHgn,
  exact,
  checkedAccount,
  sameRewardContext,
  type RewardAccount,
  type RewardStatus,
} from '../lib/rewardAccounts';
import { addressError, validateAddress } from '../lib/addresses';
import type { RewardViewState } from '../lib/useRewardAccounts';
type Props = {
  state: RewardViewState;
  url: string;
  storePath: string;
  token: string | null;
};
function Amount({ label, value }: { label: string; value: string }) {
  return (
    <div className="reward-metric">
      <p className="label">{label}</p>
      <strong className="mono">{hgn(value)}</strong>
    </div>
  );
}
export function RewardBuckets({ account }: { account: RewardAccount }) {
  return (
    <div className="overflow-x-auto">
      <table className="reward-table">
        <caption className="text-left text-sm text-surfaceMuted">
          Pending block rewards
        </caption>
        <thead>
          <tr>
            <th>Earned epoch</th>
            <th>First claim block</th>
            <th>Amount</th>
          </tr>
        </thead>
        <tbody>
          {account.pending.map((b) => (
            <tr key={b.earning_epoch}>
              <td>{b.earning_epoch}</td>
              <td>{b.release_height}</td>
              <td className="mono">{hgn(b.amount_atoms)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!account.pending.length ? (
        <p className="text-sm text-surfaceMuted">No pending rewards.</p>
      ) : null}
    </div>
  );
}
export function RewardSummary({
  status,
  account,
}: {
  status: RewardStatus;
  account: RewardAccount;
}) {
  return (
    <>
      <div className="reward-metrics">
        <Amount
          label="Available public balance"
          value={account.available_atoms}
        />
        <Amount label="Pending epoch rewards" value={account.pending_atoms} />
        <Amount
          label="Claimable next block"
          value={account.claimable_next_block_atoms}
        />
      </div>
      <p className="text-sm">
        Next claim sequence {account.next_sequence} · Snapshot block{' '}
        {status.context.height}
      </p>
      <RewardBuckets account={account} />
    </>
  );
}
export function RewardWorkspace({ state, url, storePath, token }: Props) {
  const s = state.status,
    [tab, setTab] = useState<
      'rewards' | 'treasury' | 'genesis' | 'approvals' | 'recovery'
    >('rewards');
  const [lookup, setLookup] = useState(''),
    [looked, setLooked] = useState<RewardAccount | null>(null),
    [amount, setAmount] = useState(''),
    [fee, setFee] = useState('0.00001'),
    [donationAmount, setDonationAmount] = useState(''),
    [donationFee, setDonationFee] = useState('0.00001'),
    [memo, setMemo] = useState(''),
    [publicMemo, setPublicMemo] = useState(false);
  const [error, setError] = useState<string | null>(null),
    [notice, setNotice] = useState<string | null>(null),
    [busy, setBusy] = useState(false),
    [output, setOutput] = useState<Record<string, unknown> | null>(null);
  const [page, setPage] = useState<{
      rows: Array<{ address: string; initial_amount_atoms: string }>;
      next_offset: number | null;
      total_rows: number;
    } | null>(null),
    [offset, setOffset] = useState(0);
  const [packageText, setPackageText] = useState(''),
    [review, setReview] = useState<Record<string, unknown> | null>(null),
    [approvalConfirmed, setApprovalConfirmed] = useState(false);
  const [destination, setDestination] = useState(''),
    [newPass, setNewPass] = useState(''),
    [confirmPass, setConfirmPass] = useState('');
  const generation = useRef(0);
  useEffect(() => {
    generation.current++;
    setOutput(null);
    setReview(null);
    setApprovalConfirmed(false);
    setNewPass('');
    setConfirmPass('');
    setLooked(null);
    setPage(null);
    setError(null);
    setNotice(null);
    setBusy(false);
    return () => {
      generation.current++;
    };
  }, [url, storePath, token, s?.context.block_hash]);
  useEffect(() => {
    setReview(null);
    setApprovalConfirmed(false);
  }, [packageText]);
  useEffect(() => {
    setOutput(null);
    setPublicMemo(false);
  }, [amount, fee, donationAmount, donationFee, memo, tab]);
  async function task(fn: () => Promise<void>) {
    const g = generation.current;
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      if (g === generation.current)
        setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (g === generation.current) setBusy(false);
    }
  }
  async function wallet(method: string, params: Record<string, unknown>) {
    if (!token) throw Error('Unlock the wallet first.');
    const g = generation.current;
    const result = await window.hegemon.wallet.reward(
      storePath,
      token,
      method,
      params,
    );
    if (g !== generation.current)
      throw Error('Wallet or canonical snapshot changed. Review again.');
    return result as Record<string, unknown>;
  }
  function selected() {
    if (!s?.active || !s.context.genesis_hash)
      throw Error('This node has no active reward accounts.');
    return {
      wsUrl: url,
      expectedChainId: s.context.chain_id,
      expectedGenesisHash: s.context.genesis_hash,
    };
  }
  async function prepareClaim() {
    await task(async () => {
      const a = parseHgn(amount),
        f = parseHgn(fee);
      if (!a || a === '0' || f === null)
        throw Error(
          'Enter positive HGN and an exact fee with up to eight decimals.',
        );
      const row = tab === 'treasury' ? s?.treasury : state.account;
      if (!row || exact(a) + exact(f) > exact(row.claimable_next_block_atoms))
        throw Error('Claim amount plus fee exceeds available balance.');
      const result = await wallet('prepareClaim', {
        ...selected(),
        amountAtoms: a,
        feeAtoms: f,
        treasury: tab === 'treasury',
      });
      setOutput(result);
      setNotice(
        'Claim package prepared and signed locally. It has not been submitted.',
      );
    });
  }
  async function reviewDonation() {
    await task(async () => {
      const a = parseHgn(donationAmount),
        f = parseHgn(donationFee);
      if (!a || a === '0' || f === null)
        throw Error('Enter a positive donation and an exact fee.');
      if (new TextEncoder().encode(memo).length > 256)
        throw Error('Public memo exceeds 256 UTF-8 bytes.');
      if (!publicMemo)
        throw Error('Acknowledge that the amount and memo are public.');
      setOutput(
        await wallet('reviewDonation', {
          ...selected(),
          amountAtoms: a,
          feeAtoms: f,
          memo,
        }),
      );
      setNotice(
        'Donation reviewed. No funds moved; this node does not yet support donation submission.',
      );
    });
  }
  async function copy(value: string) {
    await task(async () => {
      await window.hegemon.clipboard.writeText(value);
      setNotice('Copied.');
    });
  }
  async function inspectAccount() {
    await task(async () => {
      if (!s?.parameters) throw Error('Select an active account network.');
      const invalid = addressError(lookup, 'account', s.parameters.network);
      if (invalid) throw Error(invalid);
      const g = generation.current;
      const r = (await window.hegemon.node.rewardRead(
        url,
        'hegemon_rewardAccount',
        {
          address: validateAddress(lookup, 'account', s.parameters.network),
          at: s.context.block_hash,
        },
      )) as { context: RewardStatus['context']; account: RewardAccount };
      if (g !== generation.current || !sameRewardContext(r.context, s.context))
        throw Error('Snapshot changed. Refresh.');
      setLooked(checkedAccount(r.account, s.parameters.reward_epoch_blocks));
    });
  }
  async function loadGenesis(next = 0) {
    await task(async () => {
      const g = generation.current;
      const r = (await window.hegemon.node.rewardRead(
        url,
        'hegemon_rewardAccountsGenesis',
        { offset: next, limit: 25 },
      )) as NonNullable<typeof page> & {
        chain_id: string;
        genesis_hash: string;
      };
      if (
        g !== generation.current ||
        r.chain_id !== s?.context.chain_id ||
        (s.context.genesis_hash && r.genesis_hash !== s.context.genesis_hash)
      )
        throw Error('Genesis network changed.');
      for (const row of r.rows) exact(row.initial_amount_atoms);
      setPage(r);
      setOffset(next);
    });
  }
  function parsedPackage() {
    const p = JSON.parse(packageText) as Record<string, unknown>;
    if (
      !s?.active ||
      !s.parameters ||
      !s.context.genesis_hash ||
      !s.context.genesis_config_hash
    )
      throw Error('Read an active, verified network snapshot first.');
    return {
      kind: p.kind,
      intentHex: p.intentHex,
      policy: p.policy,
      carrierHex: p.carrierHex,
      approvals: p.approvals ?? [],
      expectedAuthorityHash: s.governance?.authority.policy_hash,
      expectedPolicyGeneration: s.governance?.policy_generation,
      network: s.parameters.network,
      expectedContext: {
        chainId: s.context.chain_id,
        genesisHash: s.context.genesis_hash,
        genesisConfigHash: s.context.genesis_config_hash,
      },
      approvedDigest: undefined,
    };
  }
  async function inspectIntent() {
    await task(async () => {
      const p = parsedPackage();
      const r = await wallet('reviewIntent', p);
      setReview(r);
      setApprovalConfirmed(false);
    });
  }
  async function signIntent() {
    await task(async () => {
      if (!approvalConfirmed || typeof review?.digest !== 'string')
        throw Error('Review and confirm this exact digest first.');
      setOutput(
        await wallet('signIntent', {
          ...parsedPackage(),
          approvedDigest: review.digest,
        }),
      );
      setNotice('Approval signed locally. No transaction was submitted.');
    });
  }
  const network = s?.parameters?.network.class;
  return (
    <div className="workspace-view max-w-7xl">
      <section className="card">
        <fieldset disabled={busy} className="space-y-5 min-w-0">
          <header className="flex flex-wrap justify-between gap-4">
            <div>
              <p className="label">Public accounts</p>
              <h1 className="text-title font-semibold">Rewards & treasury</h1>
            </div>
            <button
              className="secondary"
              onClick={() => {
                void state.refresh();
              }}
              disabled={busy || state.loading}
            >
              Refresh snapshot
            </button>
          </header>
          <div className="flex gap-3 flex-wrap">
            <span className="badge">
              {network === 'testnet'
                ? 'Testnet'
                : network === 'mainnet'
                  ? 'Mainnet'
                  : s || state.mode === 'legacy'
                    ? 'Legacy network'
                    : 'Network unavailable'}
            </span>
            {s ? (
              <span className="mono text-xs break-all">
                Block {s.context.height} · {s.context.chain_id}
              </span>
            ) : null}
          </div>
          {s?.active && s.epochs ? (
            <p className="reward-notice">
              Reward epoch {s.epochs.current_reward_epoch ?? 'genesis'} ·{' '}
              {s.epochs.blocks_per_epoch} blocks per epoch · next boundary block{' '}
              {s.epochs.next_epoch_boundary_height}. Claimable next block
              includes amounts released before that block’s transactions.
            </p>
          ) : null}
          {state.loading ? <p role="status">Reading account state…</p> : null}
          {state.error &&
          !(
            state.mode === 'legacy' &&
            /method not found|unknown method|-32601/i.test(state.error)
          ) ? (
            <p role="alert" className="text-guard">
              {state.error}
            </p>
          ) : null}
          {!s && state.mode === 'legacy' ? (
            <p className="reward-notice">
              This node uses legacy reward notes. Public reward accounts are not
              supported by this node.
            </p>
          ) : null}
          {s && !s.active ? (
            <p className="reward-notice">
              {s.configured
                ? 'Public reward-account balances are not available from this node yet.'
                : 'This network uses legacy reward notes. Its existing wallet and mining flows remain available.'}
            </p>
          ) : null}
          <nav className="reward-tabs" aria-label="Account tools">
            {(
              [
                ['rewards', 'My rewards'],
                ['treasury', 'Treasury'],
                ['genesis', 'Genesis & supply'],
                ['approvals', 'Offline approvals'],
                ['recovery', 'Backup & recovery'],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                className={tab === id ? 'primary' : 'secondary'}
                aria-pressed={tab === id}
                onClick={() => {
                  setTab(id);
                  setOutput(null);
                  setError(null);
                }}
              >
                {label}
              </button>
            ))}
          </nav>
          {error ? (
            <p role="alert" className="text-guard">
              {error}
            </p>
          ) : null}
          {notice ? (
            <p role="status" className="text-ionosphere">
              {notice}
            </p>
          ) : null}
          {tab === 'rewards' ? (
            <>
              <h2 className="text-lg font-semibold">
                Your public reward account
              </h2>
              {state.identity ? (
                <>
                  <div className="address-full break-all">
                    {state.identity.accountAddress}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      className="secondary"
                      onClick={() => copy(state.identity!.accountAddress)}
                    >
                      Copy reward account
                    </button>
                    <button
                      className="secondary"
                      onClick={() =>
                        copy(JSON.stringify(state.identity, null, 2))
                      }
                    >
                      Copy public signer identity
                    </button>
                  </div>
                  <p className="text-sm text-surfaceMuted">
                    Use this public address for mining. Public balances and
                    claims remain linkable. There are no public
                    account-to-account transfers. Your shielded receiving
                    address is separate. This account’s authorization is
                    recovered with your encrypted wallet backup.
                  </p>
                </>
              ) : (
                <p>
                  Unlock a full wallet on the selected account network to derive
                  its reward address.
                </p>
              )}
              {s?.active && state.account ? (
                <>
                  <RewardSummary status={s} account={state.account} />
                  <p className="text-sm">
                    Claim available rewards into one shielded note. The claim
                    fee is debited from this public account; the note has no
                    additional reward maturity.
                  </p>
                  {claimForm()}
                </>
              ) : null}
              <form
                className="space-y-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  void inspectAccount();
                }}
              >
                <label className="space-y-2">
                  <span className="label">Look up a public account</span>
                  <input
                    value={lookup}
                    maxLength={256}
                    onChange={(e) => setLookup(e.target.value)}
                    placeholder={network === 'testnet' ? 'heg_test1…' : 'heg1…'}
                    spellCheck={false}
                  />
                </label>
                <button className="secondary" disabled={!s?.active || busy}>
                  Inspect account
                </button>
              </form>
              {s?.active && looked ? (
                <RewardSummary status={s} account={looked} />
              ) : null}
            </>
          ) : null}
          {tab === 'treasury' ? (
            <>
              <h2 className="text-lg font-semibold">Protocol treasury</h2>
              {s?.parameters ? (
                <div className="address-full break-all">
                  {s.parameters.treasury_address}
                </div>
              ) : null}
              {s?.active && s.treasury && s.governance ? (
                <>
                  <RewardSummary status={s} account={s.treasury} />
                  <div>
                    <h3 className="text-lg">
                      {s.governance.authority.required} of{' '}
                      {s.governance.authority.members} signers
                    </h3>
                    <p>
                      Policy generation {s.governance.policy_generation}. Signer
                      changes require the current quorum and a matching hard
                      fork. The treasury address stays fixed.
                    </p>
                    <details>
                      <summary>Current signer-key hashes</summary>
                      <ol className="reward-signers mono">
                        {s.governance.authority.signer_key_hashes.map((k) => (
                          <li key={k}>{k}</li>
                        ))}
                      </ol>
                    </details>
                    {s.governance.pending_replacement ? (
                      <p className="reward-notice">
                        Certified signer replacement scheduled at block{' '}
                        {s.governance.pending_replacement.activation_height},
                        with {s.governance.pending_replacement.approval_count}{' '}
                        approvals.
                      </p>
                    ) : (
                      <p>No signer replacement is scheduled.</p>
                    )}
                  </div>
                  <p className="text-sm">
                    The treasury receives 20% of block subsidy. Fees and tips
                    credit the actual including miner. These block-derived
                    rewards become available in earning epoch + 2.
                  </p>
                  <h3 className="text-lg">Withdraw to this wallet</h3>
                  {claimForm()}
                  <h3 className="text-lg">Review a donation</h3>
                  <div className="grid gap-4 md:grid-cols-2">
                    <label className="space-y-2">
                      <span className="label">Donation amount (HGN)</span>
                      <input
                        inputMode="decimal"
                        value={donationAmount}
                        onChange={(e) => setDonationAmount(e.target.value)}
                      />
                    </label>
                    <label className="space-y-2">
                      <span className="label">Donation fee (HGN)</span>
                      <input
                        inputMode="decimal"
                        value={donationFee}
                        onChange={(e) => setDonationFee(e.target.value)}
                      />
                    </label>
                  </div>
                  <p>
                    Donations spend shielded HGN. The amount and optional memo
                    become public. Ordinary block-reward allocations have no
                    memo.
                  </p>
                  <label className="space-y-2">
                    <span className="label">Public memo (optional)</span>
                    <textarea
                      rows={3}
                      value={memo}
                      onChange={(e) => setMemo(e.target.value)}
                    />
                    <small>
                      {new TextEncoder().encode(memo).length}/256 UTF-8 bytes
                    </small>
                  </label>
                  <label className="flex gap-3 items-start">
                    <input
                      type="checkbox"
                      checked={publicMemo}
                      onChange={(e) => setPublicMemo(e.target.checked)}
                    />
                    I understand that the donation amount and memo will be
                    public.
                  </label>
                  <button
                    className="secondary"
                    disabled={!token || busy || !publicMemo}
                    onClick={() => {
                      void reviewDonation();
                    }}
                  >
                    Review donation
                  </button>
                  <p className="text-sm text-surfaceMuted">
                    Donation proof preparation and submission will be enabled
                    when the wallet and node support them. Reviewing a donation
                    moves no funds.
                  </p>
                </>
              ) : (
                <p>
                  Treasury balances and current authority require an active
                  account snapshot.
                </p>
              )}
            </>
          ) : null}
          {tab === 'genesis' ? (
            <>
              <h2 className="text-lg font-semibold">Genesis & supply</h2>
              {s?.parameters ? (
                <div className="reward-metrics">
                  <Amount
                    label="Initial genesis allocation"
                    value={s.parameters.genesis_allocation_atoms}
                  />
                  <Amount
                    label="Original mining budget"
                    value={s.parameters.mining_budget_atoms}
                  />
                  <Amount
                    label="Maximum supply"
                    value={s.parameters.max_supply_atoms}
                  />
                </div>
              ) : null}
              {s?.active && s.supply ? (
                <div className="reward-metrics">
                  <Amount
                    label="Shielded value"
                    value={s.supply.shielded_atoms}
                  />
                  <Amount
                    label="Available public accounts"
                    value={s.supply.available_account_atoms}
                  />
                  <Amount
                    label="Pending public accounts"
                    value={s.supply.pending_account_atoms}
                  />
                </div>
              ) : null}
              {s?.active && s.supply ? (
                <div className="reward-metrics">
                  <Amount
                    label="Total issued HGN"
                    value={s.supply.total_issued_atoms}
                  />
                  <Amount
                    label="Mining issuance to date"
                    value={s.supply.mining_issued_atoms}
                  />
                  <Amount
                    label="Remaining mining issuance"
                    value={s.supply.remaining_mining_atoms}
                  />
                </div>
              ) : null}
              <p>
                Genesis allocations are immediately available and reduce future
                mining issuance within the 21-million-HGN cap. Initial
                allocations are not current balances.
              </p>
              <button
                className="secondary"
                disabled={!s?.configured || busy}
                onClick={() => {
                  void loadGenesis();
                }}
              >
                Read genesis allocations
              </button>
              {page ? (
                <>
                  <div className="overflow-x-auto">
                    <table className="reward-table">
                      <thead>
                        <tr>
                          <th>Public account</th>
                          <th>Initial allocation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {page.rows.map((r) => (
                          <tr key={r.address}>
                            <td className="mono break-all">{r.address}</td>
                            <td>{hgn(r.initial_amount_atoms)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {!page.rows.length ? <p>No genesis allocations.</p> : null}
                  <div className="flex gap-3">
                    <button
                      className="secondary"
                      disabled={offset === 0 || busy}
                      onClick={() => {
                        void loadGenesis(Math.max(0, offset - 25));
                      }}
                    >
                      Previous
                    </button>
                    <span>{page.total_rows} allocations</span>
                    <button
                      className="secondary"
                      disabled={page.next_offset === null || busy}
                      onClick={() => {
                        void loadGenesis(page.next_offset!);
                      }}
                    >
                      Next
                    </button>
                  </div>
                </>
              ) : null}
            </>
          ) : null}
          {tab === 'approvals' ? (
            <>
              <h2 className="text-lg font-semibold">
                Review an offline approval package
              </h2>
              <p>
                Import a public claim or signer-replacement package. Private
                signing keys stay in the wallet daemon. A claim requires its
                matching payout proof. Signing creates an approval, not a
                withdrawal or hard fork.
              </p>
              <label className="space-y-2">
                <span className="label">Public approval package JSON</span>
                <textarea
                  rows={7}
                  maxLength={2097152}
                  value={packageText}
                  onChange={(e) => setPackageText(e.target.value)}
                  spellCheck={false}
                />
              </label>
              <button
                className="secondary"
                disabled={!s?.active || !token || busy || !packageText}
                onClick={() => {
                  void inspectIntent();
                }}
              >
                Verify and review package
              </button>
              {review ? (
                <>
                  <pre className="reward-json mono">
                    {JSON.stringify(
                      {
                        ...review,
                        carrierHex: review.carrierHex
                          ? '[payout proof verified]'
                          : undefined,
                        approvals: Array.isArray(review.approvals)
                          ? review.approvals.length
                          : 0,
                      },
                      null,
                      2,
                    )}
                  </pre>
                  <label className="flex gap-3">
                    <input
                      type="checkbox"
                      checked={approvalConfirmed}
                      onChange={(e) => setApprovalConfirmed(e.target.checked)}
                    />
                    I checked the network, recipient, amount/fee or signer
                    replacement, and this exact digest.
                  </label>
                  <button
                    className="primary"
                    disabled={busy || !token || !approvalConfirmed}
                    onClick={() => {
                      void signIntent();
                    }}
                  >
                    Sign this approval
                  </button>
                </>
              ) : null}
            </>
          ) : null}
          {tab === 'recovery' ? (
            <>
              <h2 className="text-lg font-semibold">
                Backup & network recovery
              </h2>
              <p>
                Your default public reward-account key is derived from the same
                encrypted wallet root. Keep the encrypted wallet file and
                passphrase backed up. Watch-only wallets cannot authorize
                claims.
              </p>
              <p>
                For a chain reset, recover keys into a separate wallet. This
                preserves the original file and issued-address registry, and
                starts a fresh scan without copying old balances or pending
                transactions.
              </p>
              <label className="space-y-2">
                <span className="label">New wallet filename</span>
                <input
                  value={destination}
                  onChange={(e) => setDestination(e.target.value)}
                  placeholder="reset-wallet.store"
                />
              </label>
              <label className="space-y-2">
                <span className="label">New passphrase</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={newPass}
                  onChange={(e) => setNewPass(e.target.value)}
                />
              </label>
              <label className="space-y-2">
                <span className="label">Confirm new passphrase</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirmPass}
                  onChange={(e) => setConfirmPass(e.target.value)}
                />
              </label>
              <button
                className="secondary"
                disabled={
                  !token ||
                  busy ||
                  !destination.trim() ||
                  newPass.length < 12 ||
                  newPass !== confirmPass
                }
                onClick={() => {
                  void task(async () => {
                    await wallet('recover', {
                      destination,
                      passphrase: newPass,
                    });
                    setNewPass('');
                    setConfirmPass('');
                    setNotice(
                      'A separate encrypted wallet was created. Open it from the Wallet page; the source wallet is unchanged.',
                    );
                  });
                }}
              >
                Recover keys to a separate wallet
              </button>
            </>
          ) : null}
          {output ? (
            <section className="space-y-3">
              <h2 className="text-lg font-semibold">Prepared public package</h2>
              <p className="reward-notice">
                Not submitted. Claim packages can become stale as their
                reference or account sequence changes. Quorum withdrawals still
                need the remaining approvals.
              </p>
              <button
                className="secondary"
                onClick={() => copy(JSON.stringify(output, null, 2))}
              >
                Copy complete public package
              </button>
              <pre className="reward-json mono">
                {JSON.stringify(
                  {
                    ...output,
                    approvals: Array.isArray(output.approvals)
                      ? `${output.approvals.length} verified approvals (included in copy)`
                      : undefined,
                    carrierHex: output.carrierHex
                      ? '[encrypted payout proof: included in copy]'
                      : undefined,
                  },
                  null,
                  2,
                )}
              </pre>
            </section>
          ) : null}
          <footer className="text-sm text-surfaceMuted">
            Rewards earned in epoch N become available in N+2. Epoch boundaries
            are not finality: reorganizations may change rewards and claims. At
            the target interval the wait is approximately one to two days;
            elapsed time varies.
          </footer>
        </fieldset>
      </section>
    </div>
  );
  function claimForm() {
    return (
      <div className="space-y-3">
        <div className="grid gap-4 md:grid-cols-2">
          <label className="space-y-2">
            <span className="label">Claim amount (HGN)</span>
            <input
              inputMode="decimal"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
            />
          </label>
          <label className="space-y-2">
            <span className="label">Fee / miner tip (HGN)</span>
            <input
              inputMode="decimal"
              value={fee}
              onChange={(e) => setFee(e.target.value)}
            />
          </label>
        </div>
        <button
          className="primary"
          disabled={!token || busy || !state.identity || !s?.active}
          onClick={() => {
            void prepareClaim();
          }}
        >
          {busy
            ? 'Preparing…'
            : tab === 'treasury'
              ? 'Prepare withdrawal approval'
              : 'Prepare claim to shielded wallet'}
        </button>
        <p className="text-sm text-surfaceMuted">
          Prepares a real payout proof and a local signature for export. This
          node does not yet provide account-transaction submission.
        </p>
      </div>
    );
  }
}
