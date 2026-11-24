import React, { useEffect, useState } from 'react';
import { api } from '../api/endpoints';
import { useSession } from '../context/SessionContext';
import { isSandboxEnabled } from '../lib/env';
import { sanitizeServerRedirectUrl } from '../lib/safeUrl';
import type { AuthProviderOption, IdpProviderKind, Role } from '../types/domain';

const OAUTH_ERROR_LABELS: Record<string, string> = {
  not_allowed: 'Your account or domain is not authorized for this organization.',
  failed: 'SSO authentication failed. Please try again or contact your org admin.',
  idp_unavailable: 'The configured Identity Provider is temporarily unreachable.',
  rate_limited: 'Too many sign-in attempts. Please wait a moment and try again.',
};

export const LoginView: React.FC = () => {
  const { enterSandboxAsRole, notify } = useSession();
  const [orgSlug, setOrgSlug] = useState('aeroworks');
  const [busyProvider, setBusyProvider] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [discoveredProviders, setDiscoveredProviders] = useState<AuthProviderOption[] | null>(null);
  const sandboxEnabled = isSandboxEnabled();

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const errCode = params.get('error');
    if (errCode) {
      setErrorMsg(OAUTH_ERROR_LABELS[errCode] ?? `Sign-in failed (${errCode}).`);
    }
  }, []);

  const handleDiscoverProviders = async () => {
    setErrorMsg(null);
    try {
      const list = await api.listAuthProviders(orgSlug.trim() || 'aeroworks');
      setDiscoveredProviders(list);
    } catch {
      setDiscoveredProviders(null);
    }
  };

  const handleOAuth = async (provider: IdpProviderKind, idpId?: string) => {
    setBusyProvider(idpId ?? provider);
    setErrorMsg(null);
    try {
      const res = await api.startOAuth({
        orgSlug: orgSlug.trim() || 'aeroworks',
        provider,
        idpId,
      });
      const safeUrl = sanitizeServerRedirectUrl(res.authorizeUrl);
      if (!safeUrl) {
        throw new Error('Blocked unsafe OAuth redirect URL');
      }
      window.location.assign(safeUrl);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Control plane API unreachable.';
      setErrorMsg(msg);
      notify('error', msg);
    } finally {
      setBusyProvider(null);
    }
  };

  const sandboxRoles: Array<{ role: Role; label: string; desc: string }> = [
    { role: 'engineer', label: 'Engineer', desc: 'Co-Dev, pin comments, diffs, ECOs, Boat VM' },
    { role: 'librarian', label: 'Librarian', desc: 'Parts, lifecycle, IPC-7351, .kicad_httplib' },
    { role: 'purchasing', label: 'Purchasing', desc: 'BOM, alternates, RFQ, encrypted orders' },
    { role: 'org_admin', label: 'Org Admin', desc: 'SSO/RBAC, Boat VMs, ZDR, gates, KMS, Stripe' },
    { role: 'external_reviewer', label: 'CM / Reviewer', desc: 'Read-only board review & pin comments' },
  ];

  return (
    <div className="login-page">
      <div className="login-card stack-md">
        <div className="row-between">
          <div className="topbar-brand">
            <div className="topbar-logo" aria-hidden="true">
              BP
            </div>
            <div>
              <div>Backplane Enterprise</div>
              <div className="text-sm muted">Hardware &amp; Firmware Control Plane</div>
            </div>
          </div>
          <span className="badge badge-green">Zero-Tailscale</span>
        </div>

        <div className="row">
          <label className="field-label">
            <span>Organization Slug</span>
            <input
              className="input mono"
              value={orgSlug}
              onChange={(e) => setOrgSlug(e.target.value)}
              placeholder="aeroworks"
            />
          </label>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void handleDiscoverProviders()}
          >
            Check Org IdPs
          </button>
        </div>

        {errorMsg && (
          <div className="toast-banner error" role="alert">
            <span>{errorMsg}</span>
          </div>
        )}

        {discoveredProviders && discoveredProviders.length > 0 ? (
          <div className="stack-sm">
            {discoveredProviders.map((item) => (
              <button
                key={item.id}
                type="button"
                className="btn btn-primary"
                disabled={busyProvider !== null}
                onClick={() => void handleOAuth(item.provider, item.id)}
              >
                {busyProvider === item.id ? 'Redirecting...' : `Continue with ${item.displayName}`}
              </button>
            ))}
          </div>
        ) : (
          <div className="stack-sm">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busyProvider !== null}
              onClick={() => void handleOAuth('google')}
            >
              {busyProvider === 'google' ? 'Redirecting...' : 'Continue with Google Workspace'}
            </button>
            <button
              type="button"
              className="btn"
              disabled={busyProvider !== null}
              onClick={() => void handleOAuth('microsoft')}
            >
              {busyProvider === 'microsoft'
                ? 'Redirecting...'
                : 'Continue with Microsoft 365 / Entra ID'}
            </button>
            <div className="grid-2">
              <button
                type="button"
                className="btn"
                disabled={busyProvider !== null}
                onClick={() => void handleOAuth('oidc')}
              >
                Enterprise OIDC
              </button>
              <button
                type="button"
                className="btn"
                disabled={busyProvider !== null}
                onClick={() => void handleOAuth('saml')}
              >
                SAML 2.0 SSO
              </button>
            </div>
          </div>
        )}

        {sandboxEnabled && (
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Interactive Sandbox Role Preview</h3>
              <span className="badge badge-amber">Demo Data</span>
            </div>
            <p className="text-sm muted">
              Preview role-scoped workflows locally with synthetic demo data when running without
              a live PostgreSQL/Axum backend.
            </p>
            <div className="stack-sm">
              {sandboxRoles.map((item) => (
                <button
                  key={item.role}
                  type="button"
                  className="btn row-between"
                  onClick={() => enterSandboxAsRole(item.role)}
                >
                  <span>Enter as {item.label}</span>
                  <span className="text-sm muted">{item.desc}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="row-between text-sm muted">
          <span>HttpOnly Cookie + CSRF Guard</span>
          <span>Postgres RLS + Per-Tenant KMS</span>
        </div>
      </div>
    </div>
  );
};
