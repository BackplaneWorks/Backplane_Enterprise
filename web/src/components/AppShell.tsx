import React from 'react';
import { useSession } from '../context/SessionContext';
import { canAccessTab, roleLabel } from '../lib/rbac';
import type { NavTab } from '../types/domain';

const TABS: Array<{ id: NavTab; label: string }> = [
  { id: 'codev', label: 'Co-Dev & Review' },
  { id: 'librarian', label: 'Web Librarian' },
  { id: 'purchasing', label: 'Purchasing & Orders' },
  { id: 'admin', label: 'Admin Console' },
];

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const {
    principal,
    sandboxMode,
    activeTab,
    setActiveTab,
    toast,
    clearToast,
    signOut,
    enterSandboxAsRole,
    boatVms,
  } = useSession();

  if (!principal) return null;

  const connectedVmCount = boatVms.filter((vm) => vm.tunnelState === 'connected_mtls').length;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-brand">
          <div className="topbar-logo" aria-hidden="true">
            BP
          </div>
          <span>Backplane Enterprise</span>
          <span className="badge badge-cyan mono">{principal.tenantSlug}</span>
        </div>

        <div className="topbar-meta">
          <span className="badge badge-green">
            Zero-Tailscale mTLS ({connectedVmCount}/{boatVms.length} Boat VMs)
          </span>
          {sandboxMode ? (
            <span className="badge badge-amber">Sandbox Preview</span>
          ) : (
            <span className="badge badge-blue">Live TLS 1.3 Session</span>
          )}
          <span className="badge badge-purple">{roleLabel(principal.role)}</span>
          <span className="text-sm muted">{principal.email}</span>
          <button type="button" className="btn btn-sm" onClick={() => void signOut()}>
            Sign Out
          </button>
        </div>
      </header>

      <aside className="sidebar" aria-label="Workspace navigation">
        <nav className="sidebar-nav">
          {TABS.filter((t) => canAccessTab(principal, t.id)).map((tab) => (
            <button
              key={tab.id}
              type="button"
              className={`nav-item ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div>Org: {principal.tenantName}</div>
          <div className="mono">Tenant: {principal.tenantId.slice(0, 8)}...</div>
          {sandboxMode && (
            <label className="field-label">
              <span>Preview Role Switch</span>
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
        </div>
      </aside>

      <main className="main-content">
        {sandboxMode && (
          <div className="toast-banner error" role="alert">
            <strong>
              DEMO DATA — Sandbox preview active. Orders, KMS keys, and audit logs are synthetic and
              not connected to a live Backplane tenant.
            </strong>
          </div>
        )}
        {toast && (
          <div className={`toast-banner ${toast.kind}`} role="status">
            <span>{toast.text}</span>
            <button type="button" className="btn btn-sm" onClick={clearToast}>
              Dismiss
            </button>
          </div>
        )}
        {children}
      </main>
    </div>
  );
};
