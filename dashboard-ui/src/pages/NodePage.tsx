import { useMemo, useState } from 'react';
import { PageShell } from '../components/PageShell';
import { ConnectionBadge } from '../components/ConnectionBadge';
import { DataStatusBanner } from '../components/DataStatusBanner';
import { useNodeMetrics } from '../hooks/useNodeData';
import styles from './NodePage.module.css';

type NodeMode = 'genesis' | 'join';

type RoutingOption = {
  key: keyof RoutingState;
  label: string;
  description: string;
  weight: number;
};

type RoutingState = {
  tls: boolean;
  doh: boolean;
  vpn: boolean;
  tor: boolean;
  mtls: boolean;
  localOnly: boolean;
};

const routingOptions: RoutingOption[] = [
  {
    key: 'tls',
    label: 'TLS',
    description: 'Encrypt RPC and gossip transport.',
    weight: 16,
  },
  {
    key: 'mtls',
    label: 'Mutual auth',
    description: 'Require client certificates or signed tokens.',
    weight: 18,
  },
  {
    key: 'vpn',
    label: 'Dedicated VPN',
    description: 'Tunnel node-to-node traffic inside a private overlay.',
    weight: 20,
  },
  {
    key: 'tor',
    label: 'Tor/mixnet',
    description: 'Route through onion services to hide IP/ASN.',
    weight: 22,
  },
  {
    key: 'doh',
    label: 'DNS-over-HTTPS',
    description: 'Mask resolver metadata for RPC lookups.',
    weight: 10,
  },
  {
    key: 'localOnly',
    label: 'Local-only RPC',
    description: 'Expose RPC on loopback; peer through relays.',
    weight: 14,
  },
];

const maxRoutingWeight = routingOptions.reduce((total, option) => total + option.weight, 0);

export function NodePage() {
  const metricsQuery = useNodeMetrics();
  const [mode, setMode] = useState<NodeMode>('genesis');
  const [host, setHost] = useState('10.0.0.18');
  const [port, setPort] = useState('8545');
  const [peerUrl, setPeerUrl] = useState('https://node.operator.shc:8545');
  const [routing, setRouting] = useState<RoutingState>({
    tls: true,
    doh: true,
    vpn: false,
    tor: false,
    mtls: true,
    localOnly: false,
  });

  const protocol = routing.tls ? 'https' : 'http';
  const shareableUrl = `${protocol}://${host}:${port}`;
  const activeRouting = routingOptions.filter((option) => routing[option.key]);

  const privacyScore = useMemo(() => {
    const activeWeight = routingOptions.reduce((total, option) => {
      return routing[option.key] ? total + option.weight : total;
    }, 0);
    const normalized = Math.min(100, Math.round((activeWeight / maxRoutingWeight) * 100) + (mode === 'genesis' ? 6 : 0));
    if (normalized >= 78) {
      return { label: 'Strong', value: normalized, guidance: 'Peer over private transports; keep RPC air-gapped except for relays.' };
    }
    if (normalized >= 52) {
      return { label: 'Moderate', value: normalized, guidance: 'Add Tor or VPN and enforce client auth to harden against metadata leaks.' };
    }
    return { label: 'Weak', value: normalized, guidance: 'Enable TLS + mutual auth at minimum, and prefer private routing for peers.' };
  }, [mode, routing]);

  const hygieneChecklist = routingOptions.map((option) => ({
    ...option,
    enabled: routing[option.key],
  }));

  const connectionSource = metricsQuery.data?.source ?? 'mock';

  return (
    <PageShell
      title="Node orchestration"
      intro="Launch a fresh genesis node, advertise a node_url with routing controls, or join an existing peer while tracking the privacy posture of your transport choices."
    >
      <div className={styles.statusRow}>
        <div className={styles.badgeRow}>
          <p className={styles.kicker}>Node connection</p>
          <ConnectionBadge
            source={connectionSource}
            error={metricsQuery.data?.error}
            label="Node metrics feed"
          />
        </div>
        <p className={styles.helperText}>
          Toggle routing layers to see how network hygiene shifts before sharing your node_url with collaborators.
        </p>
      </div>

      <DataStatusBanner
        label="Node metrics feed"
        result={metricsQuery.data}
        isPlaceholder={metricsQuery.isPlaceholderData}
      />

      <section className={`grid-12 ${styles.grid}`}>
        <article className={styles.card}>
          <header className={styles.cardHeader}>
            <div>
              <p className={styles.kicker}>Role</p>
              <h3>Choose how this node participates</h3>
            </div>
            <div className={styles.modeSwitcher}>
              <label className={mode === 'genesis' ? styles.modeSelected : ''}>
                <input
                  type="radio"
                  name="node-mode"
                  value="genesis"
                  checked={mode === 'genesis'}
                  onChange={() => setMode('genesis')}
                />
                Start genesis block
              </label>
              <label className={mode === 'join' ? styles.modeSelected : ''}>
                <input
                  type="radio"
                  name="node-mode"
                  value="join"
                  checked={mode === 'join'}
                  onChange={() => setMode('join')}
                />
                Join existing network
              </label>
            </div>
          </header>
          <div className={styles.formGrid}>
            <div>
              <label className={styles.label} htmlFor="host">
                Host / IP
              </label>
              <input
                id="host"
                className={styles.input}
                value={host}
                onChange={(event) => setHost(event.target.value)}
              />
            </div>
            <div>
              <label className={styles.label} htmlFor="port">
                Port
              </label>
              <input
                id="port"
                className={styles.input}
                value={port}
                onChange={(event) => setPort(event.target.value)}
              />
            </div>
            {mode === 'join' && (
              <div className={styles.peerField}>
                <label className={styles.label} htmlFor="peerUrl">
                  Peer node_url to join
                </label>
                <input
                  id="peerUrl"
                  className={styles.input}
                  value={peerUrl}
                  onChange={(event) => setPeerUrl(event.target.value)}
                  placeholder="https://peer-node:8545"
                />
                <p className={styles.helperText}>Paste the bootstrap node_url to sync headers and pull routing hints.</p>
              </div>
            )}
          </div>
          <div className={styles.shareableBox}>
            <div>
              <p className={styles.label}>Shareable node_url</p>
              <p className={styles.nodeUrl} aria-live="polite">
                {shareableUrl}
              </p>
              <p className={styles.helperText}>
                {mode === 'genesis'
                  ? 'Distribute this endpoint so peers can join your genesis block with the same routing posture.'
                  : 'Advertise your node_url back to the peer so they can add you to their allow-list.'}
              </p>
            </div>
            <div className={styles.activeRoutes}>
              <p className={styles.kicker}>Active routing layers</p>
              <div className={styles.routeChips}>
                {activeRouting.length === 0 && <span className={styles.emptyChip}>No hygiene selected</span>}
                {activeRouting.map((option) => (
                  <span key={option.key} className={styles.routeChip}>
                    {option.label}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </article>

        <article className={styles.card}>
          <header className={styles.cardHeader}>
            <div>
              <p className={styles.kicker}>Routing posture</p>
              <h3>Choose which hygiene layers to enforce</h3>
            </div>
            <p className={styles.helperText}>Combine overlays (VPN, Tor) with auth to prevent DNS/IP leakage.</p>
          </header>
          <div className={styles.optionList}>
            {routingOptions.map((option) => (
              <label key={option.key} className={styles.optionRow}>
                <input
                  type="checkbox"
                  checked={routing[option.key]}
                  onChange={(event) =>
                    setRouting((current) => ({
                      ...current,
                      [option.key]: event.target.checked,
                    }))
                  }
                />
                <div>
                  <div className={styles.optionTitle}>{option.label}</div>
                  <p className={styles.optionDescription}>{option.description}</p>
                </div>
              </label>
            ))}
          </div>
        </article>

        <article className={styles.card}>
          <header className={styles.cardHeader}>
            <div>
              <p className={styles.kicker}>Privacy posture</p>
              <h3>Assessment</h3>
            </div>
            <span className={styles.scoreBadge}>{privacyScore.label}</span>
          </header>
          <div className={styles.scoreRow}>
            <div className={styles.scoreBar}>
              <div className={styles.scoreFill} style={{ width: `${privacyScore.value}%` }} aria-hidden />
            </div>
            <div className={styles.scoreValue}>{privacyScore.value}/100</div>
          </div>
          <p className={styles.guidance}>{privacyScore.guidance}</p>
          <ul className={styles.checklist}>
            {hygieneChecklist.map((item) => (
              <li key={item.key} className={item.enabled ? styles.checkOn : styles.checkOff}>
                <span className={styles.bullet}>{item.enabled ? '●' : '○'}</span>
                <div>
                  <div className={styles.optionTitle}>{item.label}</div>
                  <p className={styles.helperText}>{item.description}</p>
                </div>
              </li>
            ))}
          </ul>
        </article>

        <article className={styles.card}>
          <header className={styles.cardHeader}>
            <div>
              <p className={styles.kicker}>Launch kit</p>
              <h3>Operational checklist</h3>
            </div>
          </header>
          <div className={styles.launchGrid}>
            <div>
              <p className={styles.label}>Genesis launch</p>
              <p className={styles.helperText}>
                Initialize ledger state, seal the genesis block, then share your node_url plus auth token with collaborators.
              </p>
            </div>
            <div>
              <p className={styles.label}>Peering</p>
              <p className={styles.helperText}>
                When joining, pin the peer node_url above and keep TLS + mTLS enabled so peers can authenticate you.
              </p>
            </div>
            <div>
              <p className={styles.label}>Routing hygiene</p>
              <p className={styles.helperText}>
                Prefer VPN or Tor for cross-org peering; keep RPC local-only unless behind an ingress that enforces auth.
              </p>
            </div>
            <div>
              <p className={styles.label}>Health monitoring</p>
              <p className={styles.helperText}>
                The Node metrics badge above should show live data; if it stays on mock, double-check your endpoint wiring.
              </p>
            </div>
          </div>
        </article>
      </section>
    </PageShell>
  );
}
