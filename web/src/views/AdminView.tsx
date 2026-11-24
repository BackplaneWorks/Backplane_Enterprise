import React, { useState } from 'react';
import { api } from '../api/endpoints';
import { BridgesPanel } from '../components/BridgesPanel';
import { Empty, PageHead, Panel, Stat, Status, Tag } from '../components/ui';
import { useSession } from '../context/SessionContext';
import { fmtTime, humanize, personName, shortHash, usd } from '../lib/format';
import { roleLabel } from '../lib/rbac';
import { sanitizeExternalUrl } from '../lib/safeUrl';
import type { AdminSection, Role } from '../types/domain';

const SECTIONS: Array<[AdminSection, string]> = [
  ['llm', 'LLM Policy & ZDR'],
  ['sso', 'SSO & RBAC'],
  ['vms', 'Boat VMs'],
  ['gates', 'Approval Gates'],
  ['bridges', 'External Bridges'],
  ['billing', 'Mail & Stripe Billing'],
  ['audit', 'KMS & Audit Log'],
];

const IDP_LABEL: Record<string, string> = {
  google: 'Google Workspace',
  microsoft: 'Microsoft Entra ID',
  oidc: 'OpenID Connect',
  saml: 'SAML 2.0',
};

type ChainState = 'unchecked' | 'valid' | 'broken';

export const AdminView: React.FC = () => {
  const {
    principal,
    adminSection: subTab,
    navigate,
    sandboxMode,
    users,
    setUsers,
    idps,
    boatVms,
    setBoatVms,
    llmPolicy,
    setLlmPolicy,
    approvalGates,
    setApprovalGates,
    pendingApprovals,
    setPendingApprovals,
    mailConnectors,
    billing,
    auditLogs,
    keyInfo,
    setKeyInfo,
    notify,
    recordAudit,
  } = useSession();

  const [newModel, setNewModel] = useState('');
  const [chain, setChain] = useState<{ state: ChainState; count?: number }>({ state: 'unchecked' });

  const handleRoleChange = async (userId: string, role: Role) => {
    try {
      if (!sandboxMode) {
        await api.updateUserRole(userId, role);
      }
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, role } : u)));
      recordAudit('admin.rbac.role_updated', `${userId} -> ${role}`);
      notify('success', `Updated user role to ${roleLabel(role)}.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Role update failed');
    }
  };

  const handleToggleVm = async (vmId: string, action: 'wake' | 'stop') => {
    try {
      if (!sandboxMode) {
        if (action === 'wake') await api.wakeBoatVm(vmId);
        else await api.stopBoatVm(vmId);
      }
      setBoatVms((prev) =>
        prev.map((vm) =>
          vm.id === vmId
            ? {
                ...vm,
                tunnelState: action === 'wake' ? 'connected_mtls' : 'stopped',
                idleMinutes: action === 'wake' ? 0 : vm.idleMinutes,
              }
            : vm,
        ),
      );
      recordAudit(`vm.${action}`, vmId);
      notify('success', `Boat VM ${vmId} ${action === 'wake' ? 'connected via outbound mTLS' : 'stopped'}.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'VM action failed');
    }
  };

  const handleToggleZdr = async () => {
    const next = { ...llmPolicy, zdrRequired: !llmPolicy.zdrRequired };
    try {
      if (!sandboxMode) {
        await api.updateLlmPolicy(next);
      }
      setLlmPolicy(next);
      recordAudit('admin.llm_policy.zdr_toggled', `zdrRequired=${String(next.zdrRequired)}`);
      notify(
        'success',
        next.zdrRequired
          ? 'ZDR-only LLM routing enforced for this organization.'
          : 'ZDR-only constraint relaxed (standard provider allowlist active).',
      );
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to update LLM policy');
    }
  };

  const handleAddAllowedModel = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newModel.trim();
    if (!trimmed) return;
    const baseProviders =
      llmPolicy.providers.length > 0
        ? llmPolicy.providers
        : [{ provider: 'Anthropic', models: [], zdr: true }];
    const nextProviders = baseProviders.map((p, idx) =>
      idx === 0 ? { ...p, models: Array.from(new Set([...p.models, trimmed])) } : p,
    );
    const next = {
      ...llmPolicy,
      providers: nextProviders,
    };
    try {
      if (!sandboxMode) {
        await api.updateLlmPolicy(next);
      }
      setLlmPolicy(next);
      setNewModel('');
      recordAudit('admin.llm_policy.model_added', trimmed);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to update models');
    }
  };

  const handleVerifyAuditChain = async () => {
    try {
      if (sandboxMode) {
        setChain({ state: 'valid', count: auditLogs.length });
        notify('success', 'Hash-chain integrity verified.');
        return;
      }
      const res = await api.verifyAuditChain();
      const valid = res.ok ?? res.valid ?? false;
      setChain({ state: valid ? 'valid' : 'broken', count: res.entries ?? res.count ?? auditLogs.length });
      notify(
        valid ? 'success' : 'error',
        valid
          ? 'Audit hash chain verified.'
          : `Audit chain verification failed${res.error ? `: ${res.error}` : '.'}`,
      );
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Audit verification failed');
    }
  };

  const handleToggleGate = async (gateId: string) => {
    const target = approvalGates.find((g) => g.id === gateId);
    if (!target) return;
    const nextEnabled = !target.enabled;
    try {
      if (!sandboxMode) {
        await api.toggleApprovalGate(gateId, nextEnabled);
      }
      setApprovalGates((prev) =>
        prev.map((g) => (g.id === gateId ? { ...g, enabled: nextEnabled } : g)),
      );
      recordAudit('admin.approval_gate.toggled', `${gateId}=${String(nextEnabled)}`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to toggle gate');
    }
  };

  const handleDecideApproval = async (approvalId: string, decision: 'approved' | 'rejected') => {
    try {
      if (!sandboxMode) {
        await api.decideApproval(approvalId, decision);
      }
      setPendingApprovals((prev) =>
        prev.map((a) => (a.id === approvalId ? { ...a, status: decision } : a)),
      );
      recordAudit(`admin.approval.${decision}`, approvalId);
      notify('success', `Approval request ${approvalId} marked ${decision}.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to decide approval');
    }
  };

  const handleRotateDek = async () => {
    try {
      const updated = sandboxMode
        ? {
            ...keyInfo,
            activeVersion: keyInfo.activeVersion + 1,
            lastRotatedAt: 'just now',
            wrappedDekFingerprint: `sha256:rotated-v${keyInfo.activeVersion + 1}`,
          }
        : await api.rotateTenantDek();
      setKeyInfo(updated);
      recordAudit('kms.dek.rotated', `v${updated.activeVersion}`);
      notify('success', `Tenant DEK rotated to version ${updated.activeVersion}.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Key rotation failed');
    }
  };

  const handleOpenBillingPortal = async () => {
    if (sandboxMode) {
      notify('info', 'Sandbox: Stripe Customer Billing Portal ready.');
      return;
    }
    try {
      const res = await api.openBillingPortal();
      const safe = sanitizeExternalUrl(res.checkoutUrl);
      if (!safe) throw new Error('Blocked unsafe Stripe Billing Portal URL');
      window.location.assign(safe);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to open billing portal');
    }
  };

  const pendingCount = pendingApprovals.filter((a) => a.status === 'pending').length;
  const vmsUp = boatVms.filter((vm) => vm.tunnelState === 'connected_mtls').length;
  const seatsOver = billing.seatsIncluded > 0 && billing.seatsActive > billing.seatsIncluded;

  return (
    <>
      <PageHead
        num="04"
        eyebrow="Admin"
        title="Enterprise Admin Console"
        sub="Identity and roles, the Boat VM fleet, LLM routing policy, human approval gates, bridges, billing, tenant keys and the hash-chained audit log."
      />

      <div className="tabs" role="tablist">
        {SECTIONS.map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={subTab === id}
            className={`tab${subTab === id ? ' on' : ''}`}
            onClick={() => navigate('admin', id)}
          >
            {label}
          </button>
        ))}
      </div>

      {subTab === 'sso' && (
        <>
          <Panel title="Identity providers" meta={idps.length || undefined}>
            {idps.length === 0 ? (
              <Empty title="No identity provider configured" icon="people" variant="compact">
                Members sign in through your IdP: Google Workspace, Microsoft Entra ID, any OIDC
                issuer or SAML 2.0. Providers are registered with the control plane by the operator;
                once one exists it is listed here with its verified domain and enforcement mode.
              </Empty>
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Provider</th>
                      <th>Verified domain</th>
                      <th>Enforcement</th>
                      <th className="r">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {idps.map((idp) => (
                      <tr key={idp.id} className={idp.enabled ? '' : 'off'}>
                        <td>
                          <div className="cell-main">
                            {idp.displayName ?? IDP_LABEL[idp.provider] ?? idp.provider}
                          </div>
                          <div className="cell-sub">{idp.provider}</div>
                        </td>
                        <td>{idp.domain}</td>
                        <td className="dim">
                          {idp.enforcedSso ? 'SSO required' : 'SSO optional'}
                        </td>
                        <td className="r">
                          <Status tone={idp.enabled ? 'ok' : 'idle'}>
                            {idp.enabled ? 'enabled' : 'disabled'}
                          </Status>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title="Members & roles" meta={users.length || undefined}>
            {users.length === 0 ? (
              <Empty title="No members" icon="people" variant="compact">
                Members are provisioned on first SSO sign-in.
              </Empty>
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Member</th>
                      <th>Email</th>
                      <th>Status</th>
                      <th>Last sign-in</th>
                      <th className="r">Role</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u.id}>
                        <td className="cell-main">
                          {personName(u.displayName, u.email)}
                          {u.id === principal?.userId && <span className="faint"> (you)</span>}
                        </td>
                        <td className="dim">{u.email}</td>
                        <td>
                          <Status
                            tone={
                              u.status === 'active' ? 'ok' : u.status === 'invited' ? 'accent' : 'bad'
                            }
                          >
                            {u.status}
                          </Status>
                        </td>
                        <td className="faint nowrap">{fmtTime(u.lastLoginAt, 'never')}</td>
                        <td className="r shrink">
                          <select
                            aria-label={`Role for ${u.email}`}
                            className="select auto"
                            value={u.role}
                            onChange={(e) => void handleRoleChange(u.id, e.target.value as Role)}
                          >
                            <option value="org_admin">Org Admin</option>
                            <option value="engineer">Engineer</option>
                            <option value="librarian">Librarian</option>
                            <option value="purchasing">Purchasing</option>
                            <option value="external_reviewer">External Reviewer</option>
                          </select>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}

      {subTab === 'vms' && (
        <>
          <div className="stats">
            <Stat label="Enrolled" value={boatVms.length} sub="managed KiCad seats" />
            <Stat
              label="On mTLS"
              value={vmsUp}
              tone={vmsUp > 0 ? 'ok' : 'plain'}
              sub="outbound tunnels up"
            />
            <Stat
              label="Metered this month"
              value={
                <>
                  {boatVms.reduce((acc, vm) => acc + vm.meteredHoursMonth, 0).toFixed(1)}
                  <small> h</small>
                </>
              }
              sub="across the fleet"
            />
            <Stat label="Client cert TTL" value="≤ 24 h" sub="auto-renewed by the VM" />
          </div>

          <Panel title="Managed VM fleet" meta="outbound mTLS relay · no inbound ports">
            {boatVms.length === 0 ? (
              <Empty title="No Boat VMs enrolled" icon="vm" variant="canvas">
                A Boat VM is a managed KiCad seat that dials out to the relay over mTLS, so nothing
                listens on your network. Once the operator enrolls one for a member it appears here
                with its tunnel state, certificate expiry and metered hours.
              </Empty>
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>VM</th>
                      <th>Assigned to</th>
                      <th>KiCad</th>
                      <th>Tunnel</th>
                      <th>Cert expires</th>
                      <th className="r">Idle</th>
                      <th className="r">Metered</th>
                      <th className="r">Control</th>
                    </tr>
                  </thead>
                  <tbody>
                    {boatVms.map((vm) => (
                      <tr key={vm.id}>
                        <td>
                          <div className="cell-main">{vm.name}</div>
                          <div className="cell-sub">{vm.region}</div>
                        </td>
                        <td className="dim">{vm.assignedUserEmail}</td>
                        <td>{vm.kicadVersion}</td>
                        <td>
                          <Status
                            tone={
                              vm.tunnelState === 'connected_mtls'
                                ? 'ok'
                                : vm.tunnelState === 'waking'
                                  ? 'accent'
                                  : 'idle'
                            }
                            pulse={vm.tunnelState === 'waking'}
                          >
                            {vm.tunnelState}
                          </Status>
                        </td>
                        <td className="faint nowrap">{fmtTime(vm.certExpiresAt)}</td>
                        <td className="num r">{vm.idleMinutes} min</td>
                        <td className="num r">{vm.meteredHoursMonth.toFixed(1)} h</td>
                        <td className="r shrink">
                          {vm.tunnelState === 'stopped' ? (
                            <button
                              type="button"
                              className="btn btn-success btn-sm"
                              onClick={() => void handleToggleVm(vm.id, 'wake')}
                            >
                              Wake VM
                            </button>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-danger btn-sm"
                              onClick={() => void handleToggleVm(vm.id, 'stop')}
                            >
                              Stop VM
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}

      {subTab === 'llm' && (
        <>
          <Panel
            title="Routing policy"
            actions={
              <button
                type="button"
                role="switch"
                aria-checked={llmPolicy.zdrRequired}
                className="switch"
                onClick={() => void handleToggleZdr()}
              >
                {llmPolicy.zdrRequired ? 'ZDR-Only Enforced: ON' : 'ZDR-Only Enforced: OFF'}
              </button>
            }
          >
            <div className="panel-note">
              With ZDR-only on, agents may route only to providers under a zero-data-retention
              contract. Turn it on if your organization&apos;s own provider agreement requires it.
            </div>
            <dl className="kv flush wide">
              <dt>Zero data retention</dt>
              <dd className={llmPolicy.zdrRequired ? 'c-ok' : undefined}>
                {llmPolicy.zdrRequired ? 'required for every request' : 'not required'}
              </dd>
              <dt>External MCP servers</dt>
              <dd>{llmPolicy.allowExternalMcp ? 'allowed' : 'approval gated'}</dd>
              <dt>Monthly budget</dt>
              <dd>
                {llmPolicy.monthlyBudgetCents !== null
                  ? usd(llmPolicy.monthlyBudgetCents / 100)
                  : 'no cap'}
              </dd>
            </dl>
          </Panel>

          <Panel title="Provider allowlist" meta={llmPolicy.providers.length || undefined}>
            {llmPolicy.providers.length === 0 ? (
              <Empty title="No providers allowed" variant="compact">
                Add a model ID below to start an allowlist. Until then agents cannot call any LLM.
              </Empty>
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Provider</th>
                      <th>Allowed models</th>
                      <th className="r">Retention</th>
                    </tr>
                  </thead>
                  <tbody>
                    {llmPolicy.providers.map((prov) => {
                      const blocked = llmPolicy.zdrRequired && !prov.zdr;
                      return (
                        <tr key={prov.provider} className={blocked ? 'off' : ''}>
                          <td className="cell-main shrink">{prov.provider}</td>
                          <td>
                            <div className="row tight">
                              {prov.models.map((mod) => (
                                <Tag key={mod}>{mod === '*' ? 'any model' : mod}</Tag>
                              ))}
                            </div>
                          </td>
                          <td className="r shrink">
                            {blocked ? (
                              <Status tone="bad">blocked by ZDR-only</Status>
                            ) : (
                              <Status tone={prov.zdr ? 'ok' : 'idle'}>
                                {prov.zdr ? 'ZDR' : 'standard'}
                              </Status>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <form className="panel-foot" onSubmit={(e) => void handleAddAllowedModel(e)}>
              <input
                className="input mono"
                aria-label="Model ID"
                placeholder="Add allowed model ID (e.g. claude-haiku-4)"
                value={newModel}
                onChange={(e) => setNewModel(e.target.value)}
              />
              <button type="submit" className="btn btn-primary btn-sm" disabled={!newModel.trim()}>
                Allow Model
              </button>
            </form>
          </Panel>
        </>
      )}

      {subTab === 'gates' && (
        <div className="cols-2">
          <Panel title="Human approval gates" meta={approvalGates.length || undefined}>
            {approvalGates.length === 0 ? (
              <Empty title="No gates defined" icon="gate" variant="compact">
                Gates force a human sign-off before an agent or member can take a risky action.
              </Empty>
            ) : (
              approvalGates.map((gate) => (
                <div key={gate.id} className="item">
                  <div className="item-head">
                    <strong className="cell-main">{gate.kind}</strong>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={gate.enabled}
                      aria-label={`Gate ${gate.kind}`}
                      className="switch sm"
                      onClick={() => void handleToggleGate(gate.id)}
                    >
                      {gate.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>
                  <div className="dim prose">{gate.description}</div>
                  {(gate.approvers?.length || gate.thresholdCents) && (
                    <div className="item-meta">
                      {gate.approvers?.length ? `approvers: ${gate.approvers.join(', ')}` : ''}
                      {gate.approvers?.length && gate.thresholdCents ? ' · ' : ''}
                      {gate.thresholdCents ? `over ${usd(gate.thresholdCents / 100)}` : ''}
                    </div>
                  )}
                </div>
              ))
            )}
          </Panel>

          <Panel title="Approval queue" meta={`${pendingCount} pending`}>
            {pendingApprovals.length === 0 ? (
              <Empty title="Queue is clear" icon="gate" variant="compact">
                Requests that trip a gate wait here for a second person. Nobody can approve their
                own request.
              </Empty>
            ) : (
              pendingApprovals.map((item) => {
                const summaryText =
                  typeof item.summary === 'string' ? item.summary : JSON.stringify(item.summary);
                return (
                  <div key={item.id} className="item">
                    <div className="item-head">
                      <strong className="cell-main">{item.gateKind}</strong>
                      <Tag
                        tone={
                          item.status === 'approved'
                            ? 'ok'
                            : item.status === 'rejected'
                              ? 'bad'
                              : 'warn'
                        }
                      >
                        {item.status}
                      </Tag>
                    </div>
                    <div className="prose">{summaryText}</div>
                    <div className="item-meta">
                      {item.requestedByEmail}
                      {item.subject ? ` · ${item.subject}` : ''} · {fmtTime(item.createdAt)}
                    </div>
                    {item.status === 'pending' && (
                      <div className="row tight">
                        <button
                          type="button"
                          className="btn btn-success btn-sm"
                          disabled={item.canDecide === false}
                          onClick={() => void handleDecideApproval(item.id, 'approved')}
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          className="btn btn-danger btn-sm"
                          disabled={item.canDecide === false}
                          onClick={() => void handleDecideApproval(item.id, 'rejected')}
                        >
                          Reject
                        </button>
                        {item.canDecide === false && (
                          <span className="faint">Four-eyes: requires a second approver</span>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </Panel>
        </div>
      )}

      {subTab === 'bridges' && <BridgesPanel />}

      {subTab === 'billing' && (
        <>
          <div className="stats">
            <Stat
              label="Plan"
              value={<span className="stat-text">{billing.planName}</span>}
              sub={billing.subscriptionStatus ? humanize(billing.subscriptionStatus) : undefined}
            />
            <Stat
              label="Seats"
              value={
                <>
                  {billing.seatsActive}
                  <small> / {billing.seatsIncluded} included</small>
                </>
              }
              tone={seatsOver ? 'warn' : 'plain'}
              sub={seatsOver ? 'over the included count' : 'active members'}
            />
            <Stat
              label="VM hours"
              value={
                <>
                  {billing.vmHoursThisCycle}
                  <small> h</small>
                </>
              }
              sub="this cycle"
            />
            <Stat
              label="Est. invoice"
              value={usd(billing.estimatedInvoiceUsd)}
              sub={
                billing.currentPeriodEnd
                  ? `period ends ${fmtTime(billing.currentPeriodEnd)}`
                  : 'this cycle'
              }
            />
          </div>

          <Panel
            title="Subscription"
            meta="Stripe"
            actions={
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => void handleOpenBillingPortal()}
              >
                Open Stripe Billing Portal
              </button>
            }
          >
            <dl className="kv flush wide">
              <dt>Stripe customer</dt>
              <dd className={billing.stripeCustomerLinked ? 'c-ok' : 'faint'}>
                {billing.stripeCustomerLinked ? 'linked' : 'not linked'}
              </dd>
              <dt>Subscription</dt>
              <dd>{billing.subscriptionStatus ? humanize(billing.subscriptionStatus) : '—'}</dd>
              <dt>Order mailboxes</dt>
              <dd>
                {mailConnectors.length === 0
                  ? 'none connected'
                  : mailConnectors.map((m) => m.mailboxEmail).join(', ')}
              </dd>
            </dl>
          </Panel>
        </>
      )}

      {subTab === 'audit' && (
        <>
          <Panel
            title="Tenant encryption key"
            meta="envelope encryption"
            actions={
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => void handleRotateDek()}
              >
                Rotate Tenant DEK
              </button>
            }
          >
            <dl className="kv flush wide">
              <dt>Active DEK</dt>
              <dd>{keyInfo.activeVersion > 0 ? `v${keyInfo.activeVersion}` : '—'}</dd>
              <dt>Key provider</dt>
              <dd>
                {keyInfo.provider}
                {keyInfo.kekId ? ` · ${keyInfo.kekId}` : ''}
              </dd>
              <dt>Wrapped DEK fingerprint</dt>
              <dd>{keyInfo.wrappedDekFingerprint || '—'}</dd>
              <dt>Last rotated</dt>
              <dd>{fmtTime(keyInfo.lastRotatedAt)}</dd>
            </dl>
          </Panel>

          <Panel
            title="Audit log"
            meta={`${auditLogs.length} entries · hash-chained`}
            actions={
              <>
                <Status
                  tone={chain.state === 'valid' ? 'ok' : chain.state === 'broken' ? 'bad' : 'idle'}
                >
                  {chain.state === 'valid'
                    ? `chain verified · ${chain.count ?? auditLogs.length} entries`
                    : chain.state === 'broken'
                      ? 'chain mismatch'
                      : 'not verified this session'}
                </Status>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void handleVerifyAuditChain()}
                >
                  Verify Chain
                </button>
              </>
            }
          >
            {auditLogs.length === 0 ? (
              <Empty title="No audit entries" variant="compact">
                Each entry commits to the one before it, so any edit or deletion breaks the chain.
              </Empty>
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th className="shrink">Seq</th>
                      <th>Timestamp</th>
                      <th>Actor</th>
                      <th>Action</th>
                      <th>Target</th>
                      <th>Prev → Entry hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((entry) => (
                      <tr key={entry.seq}>
                        <td className="num faint shrink">#{entry.seq}</td>
                        <td className="dim nowrap">{fmtTime(entry.timestamp)}</td>
                        <td className="dim">{entry.actorEmail ?? entry.actor ?? 'system'}</td>
                        <td className="cell-main">{entry.action}</td>
                        <td className="break">{entry.target}</td>
                        <td className="nowrap">
                          <span className="faint" title={entry.prevHash}>
                            {shortHash(entry.prevHash)} →{' '}
                          </span>
                          <span title={entry.entryHash}>{shortHash(entry.entryHash)}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </>
  );
};
