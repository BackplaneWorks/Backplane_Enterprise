import React, { useEffect, useState } from 'react';
import { api } from '../api/endpoints';
import { Mark, Tag } from '../components/ui';
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
  const [orgSlug, setOrgSlug] = useState(isSandboxEnabled() ? 'aeroworks' : '');
  const [busyProvider, setBusyProvider] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [discoveredProviders, setDiscoveredProviders] = useState<AuthProviderOption[] | null>(null);
  const [lookedUpSlug, setLookedUpSlug] = useState<string | null>(null);
  const sandboxEnabled = isSandboxEnabled();

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const errCode = params.get('error');
    if (errCode) {
      setErrorMsg(OAUTH_ERROR_LABELS[errCode] ?? `Sign-in failed (${errCode}).`);
    }
  }, []);

  // The sandbox build keeps its demo org as a fallback; a live sign-in needs a real slug.
  const resolveSlug = (): string | null => {
    const slug = orgSlug.trim() || (sandboxEnabled ? 'aeroworks' : '');
    if (!slug) {
      setErrorMsg('Enter your organization slug to continue.');
      return null;
    }
    return slug;
  };

  const handleDiscoverProviders = async () => {
    setErrorMsg(null);
    const slug = resolveSlug();
    if (!slug) return;
    try {
      const list = await api.listAuthProviders(slug);
      setDiscoveredProviders(list);
      setLookedUpSlug(slug);
    } catch {
      setDiscoveredProviders(null);
      setLookedUpSlug(null);
    }
  };

  const handleOAuth = async (provider: IdpProviderKind, idpId?: string) => {
    setErrorMsg(null);
    const slug = resolveSlug();
    if (!slug) return;
    setBusyProvider(idpId ?? provider);
    try {
      const res = await api.startOAuth({
        orgSlug: slug,
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

  const hasDiscovered = discoveredProviders !== null && discoveredProviders.length > 0;

  return (
    <div className="login">
      <section className="login-brand">
        <div className="login-logo">
          <Mark size={44} />
          <span className="brand-name">backplane</span>
          <span className="brand-tier">Enterprise</span>
        </div>

        <div className="login-hero">
          <h1 className="login-headline">
            One control plane for boards, parts and <em>orders</em>.
          </h1>
          <p className="login-lede">
            Review layouts in the browser, serve a private KiCad library to every seat, and take a
            board from ECO to purchase order with approvals and a hash-chained audit trail.
          </p>
        </div>

        <dl className="login-spec">
          <dt>Session</dt>
          <dd>HttpOnly cookie, CSRF header on every write</dd>
          <dt>Tenancy</dt>
          <dd>Postgres row-level security per organization</dd>
          <dt>Keys</dt>
          <dd>Per-tenant KMS envelope, AES-256-GCM</dd>
          <dt>Relay</dt>
          <dd>Outbound mTLS to Boat VMs, certs ≤ 24 h</dd>
          <dt>Library</dt>
          <dd>kicad_httplib v1, scoped bearer tokens</dd>
        </dl>
      </section>

      <section className="login-form">
        <div className="login-box">
          <div>
            <h2 className="login-title">Sign in</h2>
            <p className="dim prose">Use your organization&apos;s identity provider.</p>
          </div>

          <form
            className="field"
            onSubmit={(e) => {
              e.preventDefault();
              void handleDiscoverProviders();
            }}
          >
            <span className="field-cap">Organization</span>
            <div className="inset">
              <span className="inset-pre">org/</span>
              <input
                aria-label="Organization Slug"
                className="input mono"
                value={orgSlug}
                onChange={(e) => setOrgSlug(e.target.value)}
                placeholder="your-org"
                autoCapitalize="none"
                spellCheck={false}
              />
              <button type="submit" className="btn">
                Check Org IdPs
              </button>
            </div>
            {lookedUpSlug && !hasDiscovered && (
              <span className="field-hint">
                No identity providers are published for <span className="mono">{lookedUpSlug}</span>
                . The standard options below still work once an admin configures one.
              </span>
            )}
          </form>

          {errorMsg && (
            <div className="note error" role="alert">
              <span>{errorMsg}</span>
            </div>
          )}

          {hasDiscovered ? (
            <div className="stack sm-gap">
              {discoveredProviders.map((item, idx) => (
                <button
                  key={item.id}
                  type="button"
                  className={`btn btn-block${idx === 0 ? ' btn-bone' : ''}`}
                  disabled={busyProvider !== null}
                  onClick={() => void handleOAuth(item.provider, item.id)}
                >
                  <span>
                    {busyProvider === item.id
                      ? 'Redirecting...'
                      : `Continue with ${item.displayName}`}
                  </span>
                  <span className="arrow">→</span>
                </button>
              ))}
            </div>
          ) : (
            <div className="stack sm-gap">
              <button
                type="button"
                className="btn btn-block btn-bone"
                disabled={busyProvider !== null}
                onClick={() => void handleOAuth('google')}
              >
                <span>
                  {busyProvider === 'google' ? 'Redirecting...' : 'Continue with Google Workspace'}
                </span>
                <span className="arrow">→</span>
              </button>
              <button
                type="button"
                className="btn btn-block"
                disabled={busyProvider !== null}
                onClick={() => void handleOAuth('microsoft')}
              >
                <span>
                  {busyProvider === 'microsoft'
                    ? 'Redirecting...'
                    : 'Continue with Microsoft 365 / Entra ID'}
                </span>
                <span className="arrow">→</span>
              </button>
              <div className="form-grid two">
                <button
                  type="button"
                  className="btn btn-block"
                  disabled={busyProvider !== null}
                  onClick={() => void handleOAuth('oidc')}
                >
                  <span>Enterprise OIDC</span>
                  <span className="arrow">→</span>
                </button>
                <button
                  type="button"
                  className="btn btn-block"
                  disabled={busyProvider !== null}
                  onClick={() => void handleOAuth('saml')}
                >
                  <span>SAML 2.0 SSO</span>
                  <span className="arrow">→</span>
                </button>
              </div>
            </div>
          )}

          {sandboxEnabled && (
            <section className="panel">
              <header className="panel-head">
                <h3 className="panel-title">Sandbox role preview</h3>
                <Tag tone="warn">demo data</Tag>
              </header>
              <div className="panel-note">
                Explore each role with synthetic data. Nothing is sent to a backend.
              </div>
              <div>
                {sandboxRoles.map((item) => (
                  <button
                    key={item.role}
                    type="button"
                    className="item-link"
                    onClick={() => enterSandboxAsRole(item.role)}
                  >
                    <span className="grow">
                      <span className="cell-main">Enter as {item.label}</span>
                      <span className="cell-sub trunc"> · {item.desc}</span>
                    </span>
                    <span className="arrow">→</span>
                  </button>
                ))}
              </div>
            </section>
          )}

          <div className="login-foot">
            <span>TLS 1.3</span>
            <span>SSO only · no passwords stored</span>
          </div>
        </div>
      </section>
    </div>
  );
};
