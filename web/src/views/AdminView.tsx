import React, { useState } from 'react';
import { api } from '../api/endpoints';
import { BridgesPanel } from '../components/BridgesPanel';
import { useSession } from '../context/SessionContext';
import { roleLabel } from '../lib/rbac';
import { sanitizeExternalUrl } from '../lib/safeUrl';
import type { Role } from '../types/domain';

type AdminSubTab = 'sso' | 'vms' | 'llm' | 'gates' | 'bridges' | 'billing' | 'audit';

export const AdminView: React.FC = () => {
  const {
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

  const [subTab, setSubTab] = useState<AdminSubTab>('llm');
  const [newModel, setNewModel] = useState('');
  const [chainStatus, setChainStatus] = useState<string>('Chain Verified');

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
        setChainStatus(`Chain Verified (${auditLogs.length} entries)`);
        notify('success', 'Hash-chain integrity verified.');
        return;
      }
      const res = await api.verifyAuditChain();
      setChainStatus(res.valid ? `Chain Verified (${res.count ?? auditLogs.length})` : 'Chain Mismatch');
      notify(res.valid ? 'success' : 'error', res.valid ? 'Audit hash chain verified.' : 'Audit chain verification failed.');
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

  return (
    <div className="stack-md">
      <div className="page-header">
        <div>
          <h1 className="page-title">Enterprise Admin Console</h1>
          <p className="page-subtitle">
            SSO &amp; RBAC, Zero-Tailscale Boat VM fleet, LLM allowlists &amp; optional ZDR policy,
            approval gates, Stripe billing, KMS keys, and hash-chained audit logs.
          </p>
        </div>
      </div>

      <div className="tab-strip">
        {(
          [
            ['sso', 'SSO & RBAC'],
            ['vms', 'Boat VMs'],
            ['llm', 'LLM Policy & ZDR'],
            ['gates', 'Approval Gates'],
            ['bridges', 'External Bridges'],
            ['billing', 'Mail & Stripe Billing'],
            ['audit', 'KMS & Audit Log'],
          ] as Array<[AdminSubTab, string]>
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={`tab-pill ${subTab === id ? 'active' : ''}`}
            onClick={() => setSubTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {subTab === 'sso' && (
        <div className="stack-md">
          <div className="card stack-sm">
            <h3 className="card-title">Identity Providers (Google Workspace / Entra / OIDC / SAML)</h3>
            <div className="grid-3">
              {idps.map((idp) => (
                <div key={idp.id} className="stat-card stack-sm">
                  <div className="row-between">
                    <strong className="mono">{idp.provider}</strong>
                    <span className={`badge ${idp.enabled ? 'badge-green' : 'badge'}`}>
                      {idp.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  <div className="text-sm muted">Verified domain: {idp.domain}</div>
                  <div className="text-sm">
                    {idp.enforcedSso ? 'Strict SSO Enforced' : 'Optional SSO'}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <h3 className="card-title">Organization Members &amp; RBAC</h3>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Last Login</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>{u.displayName}</td>
                      <td className="mono">{u.email}</td>
                      <td>
                        <select
                          aria-label={`Role for ${u.email}`}
                          className="select"
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
                      <td className="text-sm muted">{u.lastLoginAt}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {subTab === 'vms' && (
        <div className="card stack-md">
          <div className="card-header">
            <h3 className="card-title">Managed Boat VMs (Outbound mTLS Relay — Zero Tailscale)</h3>
            <span className="badge badge-green">Cert TTL &lt;= 24h</span>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>VM Name</th>
                  <th>Assigned User</th>
                  <th>KiCad</th>
                  <th>Tunnel State</th>
                  <th>Metered Hours</th>
                  <th>Control</th>
                </tr>
              </thead>
              <tbody>
                {boatVms.map((vm) => (
                  <tr key={vm.id}>
                    <td className="mono">{vm.name}</td>
                    <td>{vm.assignedUserEmail}</td>
                    <td className="mono">{vm.kicadVersion}</td>
                    <td>
                      <span
                        className={`badge ${
                          vm.tunnelState === 'connected_mtls' ? 'badge-green' : 'badge-amber'
                        }`}
                      >
                        {vm.tunnelState}
                      </span>
                    </td>
                    <td className="mono">{vm.meteredHoursMonth.toFixed(1)} h</td>
                    <td>
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
        </div>
      )}

      {subTab === 'llm' && (
        <div className="card stack-md">
          <div className="row-between">
            <div>
              <h3 className="card-title">LLM Provider Governance &amp; Optional ZDR Policy</h3>
              <p className="text-sm muted">
                Toggle Zero-Data-Retention (ZDR) enforcement based on your organization&apos;s own
                LLM provider contract.
              </p>
            </div>
            <button
              type="button"
              className={`btn ${llmPolicy.zdrRequired ? 'btn-success' : ''}`}
              onClick={() => void handleToggleZdr()}
            >
              {llmPolicy.zdrRequired ? 'ZDR-Only Enforced: ON' : 'ZDR-Only Enforced: OFF'}
            </button>
          </div>

          <div className="row text-sm muted">
            <span className="badge">
              External MCP: {llmPolicy.allowExternalMcp ? 'Allowed' : 'Approval Gated'}
            </span>
            {llmPolicy.monthlyBudgetCents !== null && (
              <span className="badge mono">
                Monthly Cap: ${(llmPolicy.monthlyBudgetCents / 100).toFixed(2)}
              </span>
            )}
          </div>

          <div className="grid-3">
            {llmPolicy.providers.map((prov) => (
              <div key={prov.provider} className="stat-card stack-sm">
                <div className="row-between">
                  <strong>{prov.provider}</strong>
                  <span className={`badge ${prov.zdr ? 'badge-green' : 'badge-amber'}`}>
                    {prov.zdr ? 'ZDR' : 'Standard'}
                  </span>
                </div>
                <div className="row">
                  {prov.models.map((mod) => (
                    <span key={mod} className="badge badge-cyan mono">
                      {mod}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <form className="row" onSubmit={(e) => void handleAddAllowedModel(e)}>
            <input
              className="input mono"
              placeholder="Add allowed model ID (e.g. claude-haiku-4)"
              value={newModel}
              onChange={(e) => setNewModel(e.target.value)}
            />
            <button type="submit" className="btn btn-primary">
              Allow Model
            </button>
          </form>
        </div>
      )}

      {subTab === 'gates' && (
        <div className="split-pane-equal">
          <div className="card stack-sm">
            <h3 className="card-title">Mandatory Human Approval Gates</h3>
            {approvalGates.map((gate) => (
              <div key={gate.id} className="comment-card row-between">
                <div>
                  <strong className="mono">{gate.kind}</strong>
                  <div className="text-sm muted">{gate.description}</div>
                </div>
                <button
                  type="button"
                  className={`btn btn-sm ${gate.enabled ? 'btn-success' : ''}`}
                  onClick={() => void handleToggleGate(gate.id)}
                >
                  {gate.enabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            ))}
          </div>

          <div className="card stack-sm">
            <h3 className="card-title">Pending Approval Queue</h3>
            {pendingApprovals.map((item) => {
              const summaryText =
                typeof item.summary === 'string'
                  ? item.summary
                  : JSON.stringify(item.summary);
              return (
                <div key={item.id} className="comment-card stack-sm">
                  <div className="row-between">
                    <strong className="mono">{item.gateKind}</strong>
                    <span
                      className={`badge ${
                        item.status === 'approved'
                          ? 'badge-green'
                          : item.status === 'rejected'
                            ? 'badge-red'
                            : 'badge-amber'
                      }`}
                    >
                      {item.status}
                    </span>
                  </div>
                  <div>{summaryText}</div>
                  <div className="text-sm muted">
                    Requested by {item.requestedByEmail}
                    {item.subject ? ` · ${item.subject}` : ''}
                  </div>
                  {item.status === 'pending' && (
                    <div className="row">
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
                        <span className="text-sm muted">Four-eyes: requires a second approver</span>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {subTab === 'bridges' && <BridgesPanel />}

      {subTab === 'billing' && (
        <div className="stack-md">
          <div className="grid-4">
            <div className="stat-card">
              <div className="stat-label">Plan</div>
              <div className="stat-value">{billing.planName}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Seats Active</div>
              <div className="stat-value">
                {billing.seatsActive}/{billing.seatsIncluded}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Boat VM Hours</div>
              <div className="stat-value">{billing.vmHoursThisCycle} h</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Est. Cycle Invoice</div>
              <div className="stat-value">${billing.estimatedInvoiceUsd.toFixed(2)}</div>
            </div>
          </div>

          <div className="card row-between">
            <div>
              <h3 className="card-title">Stripe Subscription &amp; Usage Metering</h3>
              <div className="text-sm muted">
                Connected Mailboxes: {mailConnectors.map((m) => m.mailboxEmail).join(', ')}
              </div>
            </div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void handleOpenBillingPortal()}
            >
              Open Stripe Billing Portal
            </button>
          </div>
        </div>
      )}

      {subTab === 'audit' && (
        <div className="stack-md">
          <div className="card row-between">
            <div>
              <h3 className="card-title">Per-Tenant KMS Envelope Encryption</h3>
              <div className="text-sm mono muted">
                Active DEK v{keyInfo.activeVersion} · Provider: {keyInfo.provider}
                {keyInfo.kekId ? ` (${keyInfo.kekId})` : ''} · Fingerprint:{' '}
                {keyInfo.wrappedDekFingerprint}
              </div>
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void handleRotateDek()}>
              Rotate Tenant DEK
            </button>
          </div>

          <div className="card stack-sm">
            <div className="card-header">
              <h3 className="card-title">Tamper-Evident Hash-Chained Audit Log</h3>
              <div className="row">
                <span className="badge badge-green">{chainStatus}</span>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void handleVerifyAuditChain()}
                >
                  Verify Chain
                </button>
              </div>
            </div>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Timestamp</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Entry Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((entry) => (
                    <tr key={entry.seq}>
                      <td className="mono">#{entry.seq}</td>
                      <td className="text-sm muted">{entry.timestamp}</td>
                      <td className="mono text-sm">{entry.actorEmail}</td>
                      <td className="mono">{entry.action}</td>
                      <td className="mono">{entry.target}</td>
                      <td className="mono text-sm">{entry.entryHash}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
