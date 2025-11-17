import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { PageShell } from '../components/PageShell';
import { ConnectionBadge } from '../components/ConnectionBadge';
import { DataStatusBanner } from '../components/DataStatusBanner';
import { useToasts } from '../components/ToastProvider';
import { HttpError, type NodeLifecyclePayload, useNodeLifecycle, useNodeMetrics } from '../hooks/useNodeData';
import { useNodeConnection } from '../providers/NodeConnectionProvider';
import styles from './NodePage.module.css';

type NodeMode = 'genesis' | 'join';

export function NodePage() {
  const metricsQuery = useNodeMetrics();
  const lifecycle = useNodeLifecycle();
  const { pushToast } = useToasts();
  const { markActiveEndpoint, endpoint: activeEndpoint } = useNodeConnection();
  const [mode, setMode] = useState<NodeMode>('genesis');
  const [host, setHost] = useState('10.0.0.18');
  const [port, setPort] = useState('8545');
  const [peerUrl, setPeerUrl] = useState('https://node.operator.shc:8545');
  const [serverError, setServerError] = useState<string | null>(null);

  const defaultRouting: NodeLifecyclePayload['routing'] = {
    tls: true,
    doh: true,
    vpn: false,
    tor: false,
    mtls: true,
    local_only: false,
  };

  const protocol = defaultRouting.tls ? 'https' : 'http';
  const shareableUrl = `${protocol}://${host}:${port}`;
  const isActiveEndpoint =
    activeEndpoint.host === host && activeEndpoint.port === Number(port) && activeEndpoint.protocol === protocol;
  const connectionSource = metricsQuery.data?.source ?? 'mock';

  const validationMessage = useMemo(() => {
    if (!host.trim()) {
      return 'Host or IP is required to advertise your node_url.';
    }
    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort <= 0 || parsedPort > 65535) {
      return 'Port must be between 1 and 65535.';
    }
    if (mode === 'join' && !peerUrl.trim()) {
      return 'Joining a network requires a peer node_url.';
    }
    return null;
  }, [host, mode, peerUrl, port]);

  useEffect(() => {
    setServerError(null);
  }, [host, mode, peerUrl, port]);

  const formatError = (error: unknown) => {
    if (error instanceof HttpError) {
      if (error.detail && typeof error.detail === 'object' && 'error' in (error.detail as Record<string, unknown>)) {
        const detail = (error.detail as Record<string, unknown>).error;
        if (typeof detail === 'string') {
          return detail;
        }
      }
      return error.message;
    }
    if (error instanceof Error) {
      return error.message;
    }
    return 'Unexpected error while contacting the dashboard service.';
  };

  const handleLifecycle = () => {
    if (validationMessage) {
      setServerError(validationMessage);
      return;
    }
    setServerError(null);
    const payload: NodeLifecyclePayload = {
      mode,
      host,
      port: Number(port),
      peer_url: mode === 'join' ? peerUrl : undefined,
      routing: defaultRouting,
    };

    lifecycle.mutate(payload, {
        onMutate: () => {
          pushToast({
            kind: 'success',
            title: mode === 'genesis' ? 'Dispatching genesis start' : 'Dispatching join request',
            description: 'Sending lifecycle request to the node process...',
          });
        },
        onSuccess: (response) => {
          metricsQuery.refetch();
          pushToast({
            kind: 'success',
            title: mode === 'genesis' ? 'Genesis node started' : 'Join request applied',
            description: `Configuration saved for ${response.node_url}`,
          });
        },
      onError: (error) => {
        const message = formatError(error);
        setServerError(message);
        pushToast({
          kind: 'error',
          title: 'Node orchestration failed',
          description: message,
        });
      },
    });
  };

  const errorMessage = serverError ?? validationMessage;
  const isSubmitting = lifecycle.isPending;

  const handleCopyNodeUrl = async () => {
    try {
      await navigator.clipboard.writeText(shareableUrl);
      pushToast({
        kind: 'success',
        title: 'Node URL copied',
        description: 'Share this endpoint with collaborators or pin it as the active dashboard node.',
      });
    } catch (error) {
      pushToast({
        kind: 'error',
        title: 'Unable to copy node_url',
        description: error instanceof Error ? error.message : 'Clipboard unavailable in this browser.',
      });
    }
  };

  const handleActivateEndpoint = () => {
    if (validationMessage) {
      setServerError(validationMessage);
      return;
    }
    const parsedPort = Number(port);
    markActiveEndpoint({ protocol, host, port: parsedPort });
    pushToast({
      kind: 'success',
      title: 'Endpoint marked active',
      description: `${shareableUrl} is now the live dashboard target.`,
    });
  };

  return (
    <PageShell
      title="Node orchestration"
      intro="Launch a fresh genesis node, advertise a node_url, or join an existing peer."
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
        <p className={styles.helperText}>Define your node_url, copy it, and activate it for this dashboard session.</p>
      </div>

      <DataStatusBanner
        label="Node metrics feed"
        result={metricsQuery.data}
        isPlaceholder={metricsQuery.isPlaceholderData}
        cta={<Link to="/node">Configure a node</Link>}
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
              <div className={styles.shareableActions}>
                <button type="button" className={styles.secondaryButton} onClick={handleCopyNodeUrl}>
                  Copy node_url
                </button>
                <button
                  type="button"
                  className={styles.secondaryButton}
                  onClick={handleActivateEndpoint}
                  disabled={Boolean(validationMessage) || isActiveEndpoint}
                >
                  {isActiveEndpoint ? 'Active for this session' : 'Use for dashboard session'}
                </button>
              </div>
              <p className={styles.helperText}>
                {isActiveEndpoint
                  ? 'Dashboard requests are targeting this endpoint right now.'
                  : 'Mark this endpoint as active to have the dashboard query it live.'}
              </p>
            </div>
          </div>

          <div className={styles.controlRow}>
            <button
              type="button"
              className={styles.actionButton}
              onClick={handleLifecycle}
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Applying node settings…' : mode === 'genesis' ? 'Start genesis node' : 'Join network'}
            </button>
            <div className={styles.controlMeta}>
              <p className={styles.helperText}>
                {isSubmitting
                  ? 'Dispatching configuration to the node process.'
                  : 'Push these lifecycle choices into the active node runtime.'}
              </p>
              {errorMessage && (
                <p className={styles.errorText} role="alert">
                  {errorMessage}
                </p>
              )}
            </div>
          </div>
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
