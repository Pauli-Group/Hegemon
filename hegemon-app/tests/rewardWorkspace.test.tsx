import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  RewardWorkspace,
  RewardSummary,
} from '../src/components/RewardWorkspace';
import type { RewardViewState } from '../src/lib/useRewardAccounts';
import { accountFixture, statusFixture } from './rewardFixtures';
describe('public account rendering', () => {
  it('separates available, pending and first-block amounts and preserves exact heights', () => {
    const html = renderToStaticMarkup(
      <RewardSummary status={statusFixture()} account={accountFixture()} />,
    );
    expect(html).toContain('Available public balance');
    expect(html).toContain('Pending epoch rewards');
    expect(html).toContain('Claimable next block');
    expect(html).toContain('2881');
    expect(html).toContain('9007199254740993');
  });
  it('shows an inactive successor without pretending to have a zero balance or submission', () => {
    const s = statusFixture();
    s.active = false;
    s.supply = null;
    s.treasury = null;
    s.governance = null;
    const state: RewardViewState = {
      mode: 'accounts',
      status: s,
      identity: null,
      account: null,
      error: null,
      loading: false,
      refresh: async () => {},
    };
    const html = renderToStaticMarkup(
      <RewardWorkspace
        state={state}
        url="http://localhost:9944"
        storePath="wallet"
        token={null}
      />,
    );
    expect(html).toContain('Testnet');
    expect(html).toContain('not available from this node yet');
    expect(html).not.toContain('Available public balance');
    expect(html).toContain('Epoch boundaries are not finality');
    expect(html).not.toContain('transaction submitted');
  });
  it('distinguishes an older unsupported node from an unreachable network', () => {
    const state: RewardViewState = {
      mode: 'legacy',
      status: null,
      identity: null,
      account: null,
      error: 'Method not found',
      loading: false,
      refresh: async () => {},
    };
    const html = renderToStaticMarkup(
      <RewardWorkspace
        state={state}
        url="http://localhost:9944"
        storePath="wallet"
        token={null}
      />,
    );
    expect(html).toContain('Legacy network');
    expect(html).toContain('not supported by this node');
    expect(html).not.toContain('Network unavailable');
  });
  it('escapes node error strings rather than interpreting markup', () => {
    const state: RewardViewState = {
      mode: 'unknown',
      status: null,
      identity: null,
      account: null,
      error: '<img src=x onerror=evil()>',
      loading: false,
      refresh: async () => {},
    };
    const html = renderToStaticMarkup(
      <RewardWorkspace state={state} url="" storePath="wallet" token={null} />,
    );
    expect(html).toContain('&lt;img');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('Network unavailable');
  });
});
