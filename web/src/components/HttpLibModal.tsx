import React, { useCallback, useEffect, useState } from 'react';
import { api, type HttpLibTokenSummary } from '../api/endpoints';
import { useSession } from '../context/SessionContext';
import { buildKicadHttpLibConfig } from '../lib/safeUrl';

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
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="KiCad HTTP Library Setup">
      <div className="modal-panel stack-md">
        <div className="row-between">
          <h3 className="card-title">Generate {principal.tenantSlug}.kicad_httplib</h3>
          <button type="button" className="btn btn-sm" onClick={handleClose}>
            Close
          </button>
        </div>

        <p className="text-sm muted">
          Tenant-isolated <code>kicad_httplib</code> v1 configuration. Tokens are SHA-256 hashed
          on the server, never stored in browser storage, and cleared from memory when you close
          this dialog.
        </p>

        <div className="row">
          <label className="field-label">
            <span>Token Label</span>
            <input
              className="input"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. macbook-kicad-10"
            />
          </label>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy}
            onClick={() => void handleMintToken()}
          >
            {busy ? 'Minting...' : 'Mint Scoped Bearer Token'}
          </button>
        </div>

        <pre className="code-block">{configJson}</pre>

        {tokens.length > 0 && (
          <div className="stack-sm">
            <div className="text-sm muted">Active Scoped Device Tokens</div>
            {tokens.map((tok) => (
              <div key={tok.id} className="comment-card row-between text-sm">
                <span className="mono">
                  {tok.label} ({tok.tokenPrefix}...)
                </span>
                <button
                  type="button"
                  className="btn btn-danger btn-sm"
                  onClick={() => void handleRevokeToken(tok.id)}
                >
                  Revoke
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="row-between">
          <span className="text-sm muted">
            Endpoint: <code>/v1/httplib/{principal.tenantSlug}/categories.json</code>
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
  );
};
