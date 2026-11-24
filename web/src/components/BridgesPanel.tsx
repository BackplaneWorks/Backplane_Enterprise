import React, { useEffect, useState } from 'react';
import { api } from '../api/endpoints';
import { useSession } from '../context/SessionContext';
import { sanitizeExternalUrl } from '../lib/safeUrl';
import { Empty, Panel, Status, Tag } from './ui';
import type {
  BridgeConfig,
  BridgeDirection,
  BridgeEventKind,
  BridgeKind,
  ExternalPeerScope,
} from '../types/domain';

const ALL_EVENTS: BridgeEventKind[] = [
  'room.post',
  'bot.reply',
  'ask.opened',
  'order.status_changed',
  'release.published',
];

const KIND_LABELS: Record<BridgeKind, string> = {
  webhook: 'Signed Webhook (Dots / Grok / n8n)',
  slack: 'Slack (v0 HMAC)',
  teams: 'Microsoft Teams (RS256 JWT)',
  discord: 'Discord (Ed25519)',
  a2a: 'A2A / MCP Peer (HMAC)',
};

interface EphemeralSecretReveal {
  bridgeName: string;
  inboundPath: string;
  a2aPath: string;
  inboundSecretOnce?: string;
  outboundSecretOnce?: string;
}

export const BridgesPanel: React.FC = () => {
  const { sandboxMode, principal, bridges, setBridges, notify, recordAudit } = useSession();

  const [name, setName] = useState('');
  const [kind, setKind] = useState<BridgeKind>('webhook');
  const [direction, setDirection] = useState<BridgeDirection>('bidirectional');
  const [targetUrl, setTargetUrl] = useState('');
  const [rateLimitRpm, setRateLimitRpm] = useState(60);
  const [selectedEvents, setSelectedEvents] = useState<BridgeEventKind[]>([
    'room.post',
    'order.status_changed',
  ]);
  const [peerEnabled, setPeerEnabled] = useState(true);
  const [peerRead, setPeerRead] = useState(true);
  const [peerComment, setPeerComment] = useState(true);
  const [discordPubkeyHex, setDiscordPubkeyHex] = useState('');
  const [teamsAppId, setTeamsAppId] = useState('');
  const [slackChannel, setSlackChannel] = useState('');
  const [ephemeralSecret, setEphemeralSecret] = useState<EphemeralSecretReveal | null>(null);

  useEffect(() => {
    return () => {
      setEphemeralSecret(null);
    };
  }, []);

  const toggleEvent = (ev: BridgeEventKind) => {
    setSelectedEvents((prev) =>
      prev.includes(ev) ? prev.filter((item) => item !== ev) : [...prev, ev],
    );
  };

  const handleCreateBridge = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = name.trim();
    if (!cleanName) {
      notify('error', 'Bridge name is required.');
      return;
    }

    let checkedUrl: string | undefined;
    if (targetUrl.trim()) {
      const safe = sanitizeExternalUrl(targetUrl.trim());
      if (!safe) {
        notify('error', 'Target URL must be a public https:// endpoint.');
        return;
      }
      checkedUrl = safe;
    } else if (direction === 'outbound') {
      notify('error', 'Outbound bridges require a public https:// target URL.');
      return;
    }

    const peerScopes: ExternalPeerScope[] = [];
    if (peerEnabled) {
      if (peerRead) peerScopes.push('boards:read');
      if (peerComment) peerScopes.push('boards:comment');
    }

    try {
      if (sandboxMode) {
        const tenantHex = (principal?.tenantId ?? '00000000-0000-0000-0000-000000000000').replace(
          /-/g,
          '',
        );
        const bridgeId = `brg-${Date.now()}`;
        const bridgeHex = `${Date.now().toString(16).padStart(16, '0')}0000000000000000`;
        const publicId = `bpb_${tenantHex}_${bridgeHex}`;
        const mockIn =
          kind === 'discord' || kind === 'teams' ? undefined : 'bps_sandbox_shown_once_9f2a';
        const mockOut = direction !== 'inbound' ? 'bpo_sandbox_shown_once_4c18' : undefined;
        const created: BridgeConfig = {
          id: bridgeId,
          publicId,
          name: cleanName,
          kind,
          enabled: true,
          direction,
          targetUrl: checkedUrl,
          subscribedEvents: selectedEvents,
          secretHint:
            kind === 'discord'
              ? 'ed25519-pubkey'
              : kind === 'teams'
                ? 'ms-teams-jwks'
                : '...9f2a',
          rateLimitRpm,
          peerEnabled,
          peerScopes,
          inboundPath: `/v1/bridges/${publicId}/inbound`,
          a2aPath: `/v1/bridges/${publicId}/a2a`,
          createdAt: 'just now',
          updatedAt: 'just now',
        };
        setBridges((prev) => [created, ...prev]);
        setEphemeralSecret({
          bridgeName: created.name,
          inboundPath: created.inboundPath,
          a2aPath: created.a2aPath,
          inboundSecretOnce: mockIn,
          outboundSecretOnce: mockOut,
        });
      } else {
        const res = await api.createBridge({
          name: cleanName,
          kind,
          direction,
          targetUrl: checkedUrl,
          subscribedEvents: selectedEvents,
          rateLimitRpm,
          peerEnabled,
          peerScopes,
          adapterConfig: {
            slackChannel: slackChannel.trim() || undefined,
            discordPublicKeyHex: discordPubkeyHex.trim() || undefined,
            teamsAppId: teamsAppId.trim() || undefined,
          },
        });
        setBridges((prev) => [res.bridge, ...prev]);
        setEphemeralSecret({
          bridgeName: res.bridge.name,
          inboundPath: res.bridge.inboundPath,
          a2aPath: res.bridge.a2aPath,
          inboundSecretOnce: res.inboundSecretOnce,
          outboundSecretOnce: res.outboundSecretOnce,
        });
      }
      setName('');
      setTargetUrl('');
      recordAudit('bridge.created', cleanName);
      notify('success', `Bridge "${cleanName}" created with envelope-encrypted secrets.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to create bridge');
    }
  };

  const handleToggleEnabled = async (bridge: BridgeConfig) => {
    const nextEnabled = !bridge.enabled;
    try {
      if (!sandboxMode) {
        const updated = await api.updateBridge(bridge.id, { enabled: nextEnabled });
        setBridges((prev) => prev.map((b) => (b.id === bridge.id ? updated : b)));
      } else {
        setBridges((prev) =>
          prev.map((b) => (b.id === bridge.id ? { ...b, enabled: nextEnabled } : b)),
        );
      }
      recordAudit('bridge.updated', `${bridge.name}:enabled=${String(nextEnabled)}`);
      notify('success', `Bridge "${bridge.name}" ${nextEnabled ? 'enabled' : 'paused'}.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to update bridge');
    }
  };

  const handleRotateSecret = async (bridge: BridgeConfig) => {
    try {
      if (sandboxMode) {
        const newIn =
          bridge.kind === 'discord' || bridge.kind === 'teams'
            ? undefined
            : 'bps_rotated_shown_once_7e31';
        const newOut =
          bridge.direction !== 'inbound' ? 'bpo_rotated_shown_once_2b94' : undefined;
        setBridges((prev) =>
          prev.map((b) => (b.id === bridge.id ? { ...b, secretHint: '...7e31' } : b)),
        );
        setEphemeralSecret({
          bridgeName: bridge.name,
          inboundPath: bridge.inboundPath,
          a2aPath: bridge.a2aPath,
          inboundSecretOnce: newIn,
          outboundSecretOnce: newOut,
        });
      } else {
        const res = await api.rotateBridgeSecret(bridge.id);
        setBridges((prev) =>
          prev.map((b) => (b.id === bridge.id ? { ...b, secretHint: res.secretHint } : b)),
        );
        setEphemeralSecret({
          bridgeName: bridge.name,
          inboundPath: bridge.inboundPath,
          a2aPath: bridge.a2aPath,
          inboundSecretOnce: res.inboundSecretOnce,
          outboundSecretOnce: res.outboundSecretOnce,
        });
      }
      recordAudit('bridge.secret_rotated', bridge.name);
      notify('success', `Rotated signing secrets for "${bridge.name}".`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Secret rotation failed');
    }
  };

  const handleTestBridge = async (bridge: BridgeConfig) => {
    try {
      if (!sandboxMode) {
        const res = await api.testBridge(bridge.id);
        notify('success', `Test delivery ${res.deliveryId}: ${res.status}`);
      } else {
        notify('info', `Sandbox: dispatched signed test event to ${bridge.name}.`);
      }
      recordAudit('bridge.tested', bridge.name);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Test dispatch failed');
    }
  };

  const handleDeleteBridge = async (bridge: BridgeConfig) => {
    try {
      if (!sandboxMode) {
        await api.deleteBridge(bridge.id);
      }
      setBridges((prev) => prev.filter((b) => b.id !== bridge.id));
      recordAudit('bridge.deleted', bridge.name);
      notify('success', `Deleted bridge "${bridge.name}".`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Delete failed');
    }
  };

  return (
    <>
      {ephemeralSecret && (
        <div className="note secret stack sm-gap" role="region" aria-label="One-time bridge secret">
          <div className="between">
            <strong className="c-warn">
              One-Time Signing Credentials — {ephemeralSecret.bridgeName}
            </strong>
            <button type="button" className="btn btn-sm" onClick={() => setEphemeralSecret(null)}>
              Dismiss Secret
            </button>
          </div>
          <div className="prose dim">
            Shown once in memory only (never stored in browser storage). Copy now; it cannot be
            retrieved again.
          </div>
          <pre className="code">
            {[
              `Inbound URL:  ${ephemeralSecret.inboundPath}`,
              `A2A Peer URL: ${ephemeralSecret.a2aPath}`,
              ephemeralSecret.inboundSecretOnce
                ? `Inbound Secret:  ${ephemeralSecret.inboundSecretOnce}`
                : null,
              ephemeralSecret.outboundSecretOnce
                ? `Outbound Secret: ${ephemeralSecret.outboundSecretOnce}`
                : null,
            ]
              .filter(Boolean)
              .join('\n')}
          </pre>
        </div>
      )}

      <Panel title="Bridges" meta={bridges.length ? `${bridges.length} configured` : undefined}>
        {bridges.length === 0 ? (
          <Empty title="No bridges yet" icon="bridge" variant="compact">
            Connect a team channel or an external agent with the form below. Every bridge gets its
            own signing secret and a sandboxed peer that can only read boards and leave comments.
          </Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Adapter</th>
                  <th>Inbound endpoint</th>
                  <th>Peer scopes</th>
                  <th>Secret</th>
                  <th>Status</th>
                  <th className="r">Actions</th>
                </tr>
              </thead>
              <tbody>
                {bridges.map((b) => (
                  <tr key={b.id} className={b.enabled ? '' : 'off'}>
                    <td>
                      <strong className="cell-main">{b.name}</strong>
                      <div className="cell-sub">{b.subscribedEvents.join(', ') || 'no events'}</div>
                    </td>
                    <td>
                      <div>{b.kind}</div>
                      <div className="cell-sub">{b.direction}</div>
                    </td>
                    <td className="dim break">{b.inboundPath}</td>
                    <td>
                      {b.peerEnabled ? (
                        <div className="row tight">
                          {b.peerScopes.length === 0 ? (
                            <Tag>no scopes</Tag>
                          ) : (
                            b.peerScopes.map((scope) => <Tag key={scope}>{scope}</Tag>)
                          )}
                        </div>
                      ) : (
                        <span className="faint">peer off</span>
                      )}
                    </td>
                    <td className="dim nowrap">{b.secretHint}</td>
                    <td>
                      <Status tone={b.enabled ? 'ok' : 'warn'}>
                        {b.enabled ? 'enabled' : 'paused'}
                      </Status>
                    </td>
                    <td className="r shrink">
                      <div className="row tight nowrap">
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void handleToggleEnabled(b)}
                        >
                          {b.enabled ? 'Pause' : 'Enable'}
                        </button>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void handleRotateSecret(b)}
                        >
                          Rotate Secret
                        </button>
                        {b.targetUrl && (
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={() => void handleTestBridge(b)}
                          >
                            Send Test
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn btn-danger btn-sm"
                          onClick={() => void handleDeleteBridge(b)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="New bridge" meta="HMAC · Ed25519 · RS256">
        <div className="panel-note">
          Natively signed webhooks in both directions, plus an optional MCP/A2A peer limited to{' '}
          <code>boards:read</code> and <code>boards:comment</code>. Peers get no shell, no private
          library and no secrets.
        </div>
        <form className="panel-body stack" onSubmit={(e) => void handleCreateBridge(e)}>
          <div className="form-grid three">
            <label className="field">
              <span className="field-cap">Bridge Name</span>
              <input
                className="input"
                placeholder="Dots + Grok Hardware Bot"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </label>

            <label className="field">
              <span className="field-cap">Adapter</span>
              <select
                aria-label="Bridge Adapter"
                className="select"
                value={kind}
                onChange={(e) => setKind(e.target.value as BridgeKind)}
              >
                {Object.entries(KIND_LABELS).map(([k, label]) => (
                  <option key={k} value={k}>
                    {label}
                  </option>
                ))}
              </select>
            </label>

            <label className="field">
              <span className="field-cap">Direction</span>
              <select
                aria-label="Bridge Direction"
                className="select"
                value={direction}
                onChange={(e) => setDirection(e.target.value as BridgeDirection)}
              >
                <option value="bidirectional">Bidirectional</option>
                <option value="inbound">Inbound Only</option>
                <option value="outbound">Outbound Only</option>
              </select>
            </label>

            <label className="field span-2">
              <span className="field-cap">Outbound Webhook URL (public https://)</span>
              <input
                className="input mono"
                placeholder="https://bots.example.com/dots/inbound"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
              />
            </label>

            <label className="field">
              <span className="field-cap">Rate Limit (requests / min)</span>
              <input
                className="input mono"
                type="number"
                min={1}
                max={600}
                value={rateLimitRpm}
                onChange={(e) => setRateLimitRpm(Number(e.target.value) || 60)}
              />
            </label>
          </div>

          {kind === 'discord' && (
            <label className="field">
              <span className="field-cap">Discord Ed25519 Application Public Key (64 hex chars)</span>
              <input
                className="input mono"
                placeholder="64-hex Ed25519 public key"
                value={discordPubkeyHex}
                onChange={(e) => setDiscordPubkeyHex(e.target.value)}
              />
            </label>
          )}

          {kind === 'teams' && (
            <label className="field">
              <span className="field-cap">Microsoft Teams Bot App ID (JWT Audience)</span>
              <input
                className="input mono"
                placeholder="00000000-0000-0000-0000-000000000000"
                value={teamsAppId}
                onChange={(e) => setTeamsAppId(e.target.value)}
              />
            </label>
          )}

          {kind === 'slack' && (
            <label className="field">
              <span className="field-cap">Slack Target Channel (optional)</span>
              <input
                className="input mono"
                placeholder="#hw-releases"
                value={slackChannel}
                onChange={(e) => setSlackChannel(e.target.value)}
              />
            </label>
          )}

          <div className="field">
            <span className="field-cap">Subscribed Events</span>
            <div className="row tight">
              {ALL_EVENTS.map((ev) => (
                <label key={ev} className="check">
                  <input
                    type="checkbox"
                    checked={selectedEvents.includes(ev)}
                    onChange={() => toggleEvent(ev)}
                  />
                  <span>{ev}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="field">
            <span className="field-cap">Agent Peer</span>
            <div className="row tight">
              <label className="check">
                <input
                  type="checkbox"
                  checked={peerEnabled}
                  onChange={(e) => setPeerEnabled(e.target.checked)}
                />
                <span>Enable Sandboxed A2A Peer</span>
              </label>
              {peerEnabled && (
                <>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={peerRead}
                      onChange={(e) => setPeerRead(e.target.checked)}
                    />
                    <span>boards:read</span>
                  </label>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={peerComment}
                      onChange={(e) => setPeerComment(e.target.checked)}
                    />
                    <span>boards:comment</span>
                  </label>
                </>
              )}
            </div>
            {peerEnabled && (
              <span className="field-hint">
                Proposals filed by this bridge are attributed to the bridge creator; under four-eyes
                approval policy, a different admin must approve them (unless self-approval is
                enabled).
              </span>
            )}
          </div>

          <div>
            <button type="submit" className="btn btn-primary">
              Create Bridge
            </button>
          </div>
        </form>
      </Panel>
    </>
  );
};
