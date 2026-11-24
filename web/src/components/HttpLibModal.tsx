import React, { useCallback, useEffect, useState } from 'react';
import { api, type HttpLibTokenSummary } from '../api/endpoints';
import { useSession } from '../context/SessionContext';
import { fmtTime } from '../lib/format';
import { buildKicadHttpLibConfig } from '../lib/safeUrl';
import { Status } from './ui';

interface HttpLibModalProps {
  open: boolean;
  onClose: () => void;
}

export const HttpLibModal: React.FC<HttpLibModalProps> = ({ open, onClose }) => {
  const { principal, sandboxMode, notify, recordAudit } = useSession();
  const [label, setLabel] = useState('kicad-workstation');
  // Ephemeral one-time token held in memory only; never persisted to web storage.
  const [ephemeralToken, setEphemeralToken] = useState<string>('');
  const [tokens, setTokens] = useState<HttpLibTokenSummary[]>([]);
  const [busy, setBusy] = useState(false);

  const loadTokens = useCallback(async () => {
    if (!principal || sandboxMode || !open) return;
    try {
      const list = await api.listHttpLibTokens(principal.tenantSlug);
      setTokens(list);
    } catch {
      // non-fatal if user lacks token list scope
    }
  }, [open, principal, sandboxMode]);

  useEffect(() => {
    void loadTokens();
  }, [loadTokens]);

  if (!open || !principal) return null;

  const baseUrl =
    typeof window !== 'undefined' ? window.location.origin : 'https://enterprise.backplane.dev';

  const configJson = buildKicadHttpLibConfig({
    orgName: principal.tenantName,
    tenantSlug: principal.tenantSlug,
    baseUrl,
    token: ephemeralToken || '<MINT_SCOPED_TOKEN_FIRST>',
  });

  const handleMintToken = async () => {
    setBusy(true);
    try {
      if (sandboxMode) {
        const hexTenant = principal.tenantId.replace(/-/g, '');
        setEphemeralToken(`bpe_usr_${hexTenant}_sandbox_ephemeral_token`);
      } else {
        const res = await api.mintHttpLibToken(principal.tenantSlug, label.trim() || 'kicad');
        setEphemeralToken(res.token);
        await loadTokens();
      }
      recordAudit('httplib.token.minted', label.trim() || 'kicad');
      notify('success', 'Scoped KiCad HTTP Library token minted (kept in memory only).');
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to mint token');
    } finally {
      setBusy(false);
    }
  };

  const handleRevokeToken = async (tokenId: string) => {
    if (sandboxMode) return;
    try {
      await api.revokeHttpLibToken(principal.tenantSlug, tokenId);
      setTokens((prev) => prev.filter((t) => t.id !== tokenId));
      recordAudit('httplib.token.revoked', tokenId);
      notify('success', 'Device token revoked.');
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to revoke token');
    }
  };

  const handleDownload = () => {
    const blob = new Blob([configJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${principal.tenantSlug}.kicad_httplib`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleClose = () => {
    setEphemeralToken('');
    onClose();
  };

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label="KiCad HTTP Library Setup"
      onKeyDown={(e) => {
        if (e.key === 'Escape') handleClose();
      }}
    >
      <div className="modal">
        <header className="panel-head">
          <div className="row tight nowrap trunc">
            <h3 className="panel-title">Connect KiCad</h3>
            <span className="panel-meta">{principal.tenantSlug}.kicad_httplib</span>
          </div>
          <button type="button" className="btn btn-ghost btn-sm" onClick={handleClose}>
            Close
          </button>
        </header>

        <div className="modal-body">
          <p className="prose dim">
            A tenant-isolated <code>kicad_httplib</code> v1 configuration. Tokens are SHA-256 hashed
            on the server, never stored in browser storage, and cleared from memory when you close
            this dialog.
          </p>

          <div className="step">
            <span className="step-box">1</span>
            <div className="grow stack sm-gap">
              <div className="cell-main">Mint a token for this workstation</div>
              <div className="row nowrap">
                <input
                  className="input mono"
                  aria-label="Token Label"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="e.g. macbook-kicad-10"
                />
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busy}
                  onClick={() => void handleMintToken()}
                >
                  {busy ? 'Minting...' : 'Mint Scoped Bearer Token'}
                </button>
              </div>
            </div>
          </div>

          <div className="step">
            <span className={`step-box${ephemeralToken ? ' done' : ''}`}>2</span>
            <div className="grow stack sm-gap">
              <div className="between">
                <div className="cell-main">Download the library file</div>
                {ephemeralToken ? (
                  <Status tone="ok">token embedded · shown once</Status>
                ) : (
                  <Status tone="idle">waiting for a token</Status>
                )}
              </div>
              <pre className="code">{configJson}</pre>
              <div className="between">
                <span className="faint break">
                  /v1/httplib/{principal.tenantSlug}/categories.json
                </span>
                <button
                  type="button"
                  className="btn btn-success"
                  disabled={!ephemeralToken}
                  onClick={handleDownload}
                >
                  Download {principal.tenantSlug}.kicad_httplib
                </button>
              </div>
            </div>
          </div>

          <div className="step">
            <span className="step-box">3</span>
            <div className="grow">
              <div className="cell-main">Add it in KiCad</div>
              <div className="prose dim">
                Preferences → Manage Symbol Libraries → add the file as an HTTP library. Released
                parts appear in the symbol chooser.
              </div>
            </div>
          </div>

          {tokens.length > 0 && (
            <section className="panel">
              <header className="panel-head">
                <h4 className="panel-title">Active device tokens</h4>
                <span className="panel-meta">{tokens.length}</span>
              </header>
              {tokens.map((tok) => (
                <div key={tok.id} className="item">
                  <div className="item-head">
                    <span className="trunc">
                      <span className="cell-main">{tok.label}</span>{' '}
                      <span className="faint">
                        {tok.tokenPrefix}… · created {fmtTime(tok.createdAt)}
                      </span>
                    </span>
                    <button
                      type="button"
                      className="btn btn-danger btn-sm"
                      onClick={() => void handleRevokeToken(tok.id)}
                    >
                      Revoke
                    </button>
                  </div>
                </div>
              ))}
            </section>
          )}
        </div>
      </div>
    </div>
  );
};
