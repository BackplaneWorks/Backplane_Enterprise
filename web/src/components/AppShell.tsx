import React, { useEffect } from 'react';
import { useSession } from '../context/SessionContext';
import { initials, personName } from '../lib/format';
import { canAccessTab, roleLabel } from '../lib/rbac';
import type { AdminSection, NavTab } from '../types/domain';
import { Icon, Mark, Status, type IconName } from './ui';

const TABS: Array<{ id: NavTab; label: string; crumb: string; icon: IconName }> = [
  { id: 'overview', label: 'Overview', crumb: 'overview', icon: 'overview' },
  { id: 'codev', label: 'Boards & Review', crumb: 'boards', icon: 'board' },
  { id: 'librarian', label: 'Library', crumb: 'library', icon: 'library' },
  { id: 'purchasing', label: 'Orders', crumb: 'orders', icon: 'orders' },
  { id: 'admin', label: 'Admin', crumb: 'admin', icon: 'admin' },
];

const ADMIN_CRUMBS: Record<AdminSection, string> = {
  llm: 'llm-policy',
  sso: 'members',
  vms: 'vm-fleet',
  gates: 'approvals',
  bridges: 'bridges',
  billing: 'billing',
  audit: 'audit',
};

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const {
    principal,
    sandboxMode,
    activeTab,
    adminSection,
    setActiveTab,
    toast,
    clearToast,
    signOut,
    enterSandboxAsRole,
    boatVms,
    boards,
    parts,
    orders,
    pendingApprovals,
  } = useSession();

  // Confirmations clear themselves; errors stay until dismissed.
  useEffect(() => {
    if (!toast || toast.kind === 'error') return;
    const timer = window.setTimeout(clearToast, 7000);
    return () => window.clearTimeout(timer);
  }, [toast, clearToast]);

  if (!principal) return null;

  const connectedVmCount = boatVms.filter((vm) => vm.tunnelState === 'connected_mtls').length;
  const pendingCount = pendingApprovals.filter((a) => a.status === 'pending').length;
  const name = personName(principal.displayName, principal.email);
  const current = TABS.find((t) => t.id === activeTab) ?? TABS[0];

  const counts: Partial<Record<NavTab, number>> = {
    codev: boards.length,
    librarian: parts.length,
    purchasing: orders.length,
    admin: pendingCount,
  };

  return (
    <div className="app">
      <aside className="side" aria-label="Workspace navigation">
        <div className="brand">
          <Mark size={22} />
          <span className="brand-name">backplane</span>
          <span className="brand-tier">Enterprise</span>
        </div>

        <div className="org">
          <div className="org-name trunc">{principal.tenantName}</div>
          <div className="org-id trunc">
            {principal.tenantSlug} · {principal.tenantId.slice(0, 8)}
          </div>
        </div>

        <nav className="nav">
          <div className="nav-cap">Workspace</div>
          {TABS.filter((t) => canAccessTab(principal, t.id)).map((tab) => {
            const count = counts[tab.id];
            return (
              <button
                key={tab.id}
                type="button"
                className={`nav-item${activeTab === tab.id ? ' on' : ''}`}
                aria-current={activeTab === tab.id ? 'page' : undefined}
                onClick={() => setActiveTab(tab.id)}
              >
                <Icon name={tab.icon} />
                <span className="nav-label trunc">{tab.label}</span>
                {count !== undefined && count > 0 && (
                  <span className={`nav-count${tab.id === 'admin' ? ' hot' : ''}`}>{count}</span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="side-foot">
          {sandboxMode && (
            <label className="field">
              <span className="field-cap">Preview role</span>
              <select
                aria-label="Preview Role Switch"
                className="select"
                value={principal.role}
                onChange={(e) => enterSandboxAsRole(e.target.value as typeof principal.role)}
              >
                <option value="org_admin">Org Admin</option>
                <option value="engineer">Engineer</option>
                <option value="librarian">Librarian</option>
                <option value="purchasing">Purchasing</option>
                <option value="external_reviewer">External Reviewer</option>
              </select>
            </label>
          )}
          <div className="who">
            <span className="avatar" aria-hidden="true">
              {initials(name)}
            </span>
            <div className="who-text grow">
              <div className="who-name trunc">{name}</div>
              <div className="who-role trunc">{roleLabel(principal.role)}</div>
            </div>
          </div>
          <button type="button" className="btn btn-sm" onClick={() => void signOut()}>
            Sign Out
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="top">
          <div className="crumbs">
            <span>{principal.tenantSlug}</span>
            <span>/</span>
            <b>{current.crumb}</b>
            {activeTab === 'admin' && (
              <>
                <span>/</span>
                <b>{ADMIN_CRUMBS[adminSection]}</b>
              </>
            )}
          </div>

          <div className="top-meta">
            <span className="hide-narrow">
              {boatVms.length === 0 ? (
                <Status tone="idle">relay · no VMs enrolled</Status>
              ) : (
                <Status tone={connectedVmCount > 0 ? 'ok' : 'idle'}>
                  relay · {connectedVmCount}/{boatVms.length} VMs on mTLS
                </Status>
              )}
            </span>
            {sandboxMode ? (
              <Status tone="warn">sandbox preview</Status>
            ) : (
              <Status tone="ok">live session</Status>
            )}
            <span className="faint hide-narrow">{principal.email}</span>
          </div>
        </header>

        {sandboxMode && (
          <div className="banner" role="alert">
            <strong>
              DEMO DATA — Sandbox preview active. Orders, KMS keys, and audit logs are synthetic and
              not connected to a live Backplane tenant.
            </strong>
          </div>
        )}

        <main className="work">
          <div className="page">{children}</div>
        </main>
      </div>

      {toast && (
        <div className="toasts">
          <div className={`toast ${toast.kind}`} role="status">
            <span>{toast.text}</span>
            <button type="button" className="btn btn-ghost btn-sm" onClick={clearToast}>
              Dismiss
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
