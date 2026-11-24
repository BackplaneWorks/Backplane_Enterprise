import React, { useState } from 'react';
import { api } from '../api/endpoints';
import { FootprintPreview } from '../components/FootprintPreview';
import { HttpLibModal } from '../components/HttpLibModal';
import { useSession } from '../context/SessionContext';
import { hasPermission } from '../lib/rbac';
import { buildKiCadDeepLink, sanitizeExternalUrl } from '../lib/safeUrl';
import type { IpcPackageFamily, LibraryPart, PartLifecycle } from '../types/domain';

const LIFECYCLE_BADGE: Record<PartLifecycle, string> = {
  Draft: 'badge-amber',
  'In Review': 'badge-blue',
  Released: 'badge-green',
  Obsolete: 'badge-red',
};

export const LibrarianView: React.FC = () => {
  const { principal, sandboxMode, parts, setParts, notify, recordAudit } = useSession();
  const [search, setSearch] = useState('');
  const [lifecycleFilter, setLifecycleFilter] = useState<'ALL' | PartLifecycle>('ALL');
  const [selectedPartId, setSelectedPartId] = useState(parts[0]?.id ?? '');
  const [httpLibOpen, setHttpLibOpen] = useState(false);

  // Create/Clone form state
  const [showNewForm, setShowNewForm] = useState(false);
  const [newMpn, setNewMpn] = useState('');
  const [newMfr, setNewMfr] = useState('');
  const [newCategory, setNewCategory] = useState('Microcontrollers');
  const [newValue, setNewValue] = useState('');
  const [newFamily, setNewFamily] = useState<IpcPackageFamily>('QFN');
  const [newPins, setNewPins] = useState(16);
  const [newPitch, setNewPitch] = useState(0.5);
  const [newDatasheet, setNewDatasheet] = useState('https://www.ti.com/lit/ds/symlink/tps54302.pdf');

  if (!principal) return null;

  const canWrite = hasPermission(principal, 'PartsWrite');
  const canRelease = hasPermission(principal, 'PartsRelease');

  const filteredParts = parts.filter((part) => {
    if (lifecycleFilter !== 'ALL' && part.lifecycle !== lifecycleFilter) return false;
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      part.mpn.toLowerCase().includes(q) ||
      part.partNumber.toLowerCase().includes(q) ||
      part.manufacturer.toLowerCase().includes(q) ||
      part.category.toLowerCase().includes(q)
    );
  });

  const selectedPart =
    parts.find((p) => p.id === selectedPartId) ?? filteredParts[0] ?? parts[0];

  const handleTransition = async (part: LibraryPart, nextLifecycle: PartLifecycle) => {
    try {
      if (!sandboxMode) {
        await api.updatePartLifecycle(part.id, nextLifecycle);
      }
      setParts((prev) =>
        prev.map((p) =>
          p.id === part.id ? { ...p, lifecycle: nextLifecycle, updatedAt: 'just now' } : p,
        ),
      );
      recordAudit('librarian.part.lifecycle', `${part.mpn} -> ${nextLifecycle}`);
      notify('success', `${part.mpn} moved to ${nextLifecycle}.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Lifecycle update failed');
    }
  };

  const handleCreatePart = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMpn.trim() || !newMfr.trim()) return;
    const safeDs = sanitizeExternalUrl(newDatasheet);
    if (newDatasheet.trim() && !safeDs) {
      notify('error', 'Datasheet URL must be a valid public https:// URL.');
      return;
    }

    const payload: Omit<LibraryPart, 'id' | 'whereUsed' | 'updatedAt'> = {
      partNumber: `BP-NEW-${Math.floor(1000 + Math.random() * 8999)}`,
      mpn: newMpn.trim(),
      manufacturer: newMfr.trim(),
      category: newCategory,
      value: newValue.trim() || newMpn.trim(),
      packageName: `${newFamily}-${newPins}`,
      lifecycle: 'Draft',
      preferredByFab: true,
      fabStockQty: 1250,
      unitPriceUsd: 1.45,
      datasheetUrl: safeDs ?? '',
      description: `Created in Web Librarian (${newFamily}-${newPins} IPC-7351)`,
      attributes: {
        Package: `${newFamily}-${newPins}`,
        Pitch: `${newPitch} mm`,
      },
      ipcSpec: {
        family: newFamily,
        pinCount: newPins,
        pitchMm: newPitch,
        bodyWidthMm: newFamily === 'CHIP' ? 1.6 : 4.0,
        bodyLengthMm: newFamily === 'CHIP' ? 3.2 : 4.0,
        padWidthMm: newFamily === 'CHIP' ? 0.9 : 0.3,
        padLengthMm: newFamily === 'CHIP' ? 1.2 : 0.85,
        thermalPadMm: newFamily === 'QFN' ? 2.1 : undefined,
      },
    };

    try {
      const created: LibraryPart = sandboxMode
        ? {
            ...payload,
            id: `prt-${Date.now()}`,
            whereUsed: [],
            updatedAt: 'just now',
          }
        : await api.createPart(payload);

      setParts((prev) => [created, ...prev]);
      setSelectedPartId(created.id);
      setShowNewForm(false);
      setNewMpn('');
      setNewMfr('');
      setNewValue('');
      recordAudit('librarian.part.created', created.mpn);
      notify('success', `Created ${created.mpn} (${created.partNumber}) in Draft state.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to create part');
    }
  };

  const safeDatasheet = selectedPart ? sanitizeExternalUrl(selectedPart.datasheetUrl) : null;

  return (
    <div className="stack-md">
      <div className="page-header">
        <div>
          <h1 className="page-title">Web Librarian &amp; Private KiCad HTTP Library</h1>
          <p className="page-subtitle">
            Manage parametric parts, lifecycle approvals, Where-Used impact, IPC-7351 footprints,
            and tenant-isolated <code>.kicad_httplib</code> exports.
          </p>
        </div>

        <div className="row">
          <button type="button" className="btn" onClick={() => setHttpLibOpen(true)}>
            Generate .kicad_httplib
          </button>
          {canWrite && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setShowNewForm((s) => !s)}
            >
              {showNewForm ? 'Cancel New Part' : '+ New Library Part'}
            </button>
          )}
        </div>
      </div>

      {showNewForm && canWrite && (
        <form className="card stack-md" onSubmit={(e) => void handleCreatePart(e)}>
          <h3 className="card-title">Create Parametric Part &amp; IPC-7351 Footprint</h3>
          <div className="grid-4">
            <label className="field-label">
              <span>MPN *</span>
              <input
                className="input mono"
                required
                value={newMpn}
                onChange={(e) => setNewMpn(e.target.value)}
                placeholder="RP2350A"
              />
            </label>
            <label className="field-label">
              <span>Manufacturer *</span>
              <input
                className="input"
                required
                value={newMfr}
                onChange={(e) => setNewMfr(e.target.value)}
                placeholder="Raspberry Pi"
              />
            </label>
            <label className="field-label">
              <span>Category</span>
              <input
                className="input"
                value={newCategory}
                onChange={(e) => setNewCategory(e.target.value)}
              />
            </label>
            <label className="field-label">
              <span>Value / Spec</span>
              <input
                className="input"
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                placeholder="Dual Cortex-M33 MCU"
              />
            </label>
          </div>
          <div className="grid-4">
            <label className="field-label">
              <span>IPC-7351 Family</span>
              <select
                className="select"
                value={newFamily}
                onChange={(e) => setNewFamily(e.target.value as IpcPackageFamily)}
              >
                <option value="QFN">QFN</option>
                <option value="SOIC">SOIC</option>
                <option value="LQFP">LQFP</option>
                <option value="CHIP">CHIP</option>
                <option value="BGA">BGA</option>
              </select>
            </label>
            <label className="field-label">
              <span>Pin Count</span>
              <input
                className="input mono"
                type="number"
                min={2}
                max={256}
                value={newPins}
                onChange={(e) => setNewPins(Number(e.target.value) || 2)}
              />
            </label>
            <label className="field-label">
              <span>Pitch (mm)</span>
              <input
                className="input mono"
                type="number"
                step="0.05"
                min={0.25}
                value={newPitch}
                onChange={(e) => setNewPitch(Number(e.target.value) || 0.5)}
              />
            </label>
            <label className="field-label">
              <span>Datasheet URL (https only)</span>
              <input
                className="input"
                value={newDatasheet}
                onChange={(e) => setNewDatasheet(e.target.value)}
              />
            </label>
          </div>
          <div className="row">
            <button type="submit" className="btn btn-primary">
              Save Part to Tenant Library
            </button>
          </div>
        </form>
      )}

      <div className="split-pane">
        <div className="card stack-md">
          <div className="row-between">
            <input
              aria-label="Search parts"
              className="input"
              placeholder="Search MPN, internal part #, manufacturer..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <select
              aria-label="Filter lifecycle"
              className="select"
              value={lifecycleFilter}
              onChange={(e) => setLifecycleFilter(e.target.value as 'ALL' | PartLifecycle)}
            >
              <option value="ALL">All Lifecycles</option>
              <option value="Draft">Draft</option>
              <option value="In Review">In Review</option>
              <option value="Released">Released</option>
              <option value="Obsolete">Obsolete</option>
            </select>
          </div>

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Part #</th>
                  <th>MPN</th>
                  <th>Package</th>
                  <th>Lifecycle</th>
                  <th>Fab Stock</th>
                </tr>
              </thead>
              <tbody>
                {filteredParts.map((part) => (
                  <tr
                    key={part.id}
                    className={part.id === selectedPart?.id ? 'selected-row' : ''}
                    onClick={() => setSelectedPartId(part.id)}
                  >
                    <td className="mono">{part.partNumber}</td>
                    <td>
                      <strong>{part.mpn}</strong>
                      <div className="text-sm muted">{part.manufacturer}</div>
                    </td>
                    <td className="mono">{part.packageName}</td>
                    <td>
                      <span className={`badge ${LIFECYCLE_BADGE[part.lifecycle]}`}>
                        {part.lifecycle}
                      </span>
                    </td>
                    <td className="mono">
                      {part.fabStockQty.toLocaleString()}{' '}
                      {part.preferredByFab && <span className="badge badge-cyan">Preferred</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {selectedPart && (
          <div className="stack-md">
            <div className="card stack-md">
              <div className="row-between">
                <div>
                  <div className="text-sm mono muted">{selectedPart.partNumber}</div>
                  <h3 className="card-title">{selectedPart.mpn}</h3>
                  <div className="text-sm muted">{selectedPart.description}</div>
                </div>
                <span className={`badge ${LIFECYCLE_BADGE[selectedPart.lifecycle]}`}>
                  {selectedPart.lifecycle}
                </span>
              </div>

              <div className="row">
                <a
                  className="btn btn-primary btn-sm"
                  href={buildKiCadDeepLink({
                    tenantSlug: principal.tenantSlug,
                    target: 'local',
                    partId: selectedPart.id,
                  })}
                >
                  Open in KiCad (Local)
                </a>
                <a
                  className="btn btn-sm"
                  href={buildKiCadDeepLink({
                    tenantSlug: principal.tenantSlug,
                    target: 'boat_vm',
                    partId: selectedPart.id,
                    vmId: principal.assignedVmId,
                  })}
                >
                  Open in Boat VM KiCad
                </a>
                {safeDatasheet && (
                  <a
                    className="btn btn-sm"
                    href={safeDatasheet}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Datasheet PDF
                  </a>
                )}
              </div>

              <div className="row">
                {canWrite && selectedPart.lifecycle === 'Draft' && (
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => void handleTransition(selectedPart, 'In Review')}
                  >
                    Submit for Review
                  </button>
                )}
                {canRelease &&
                  (selectedPart.lifecycle === 'In Review' || selectedPart.lifecycle === 'Draft') && (
                    <button
                      type="button"
                      className="btn btn-success btn-sm"
                      onClick={() => void handleTransition(selectedPart, 'Released')}
                    >
                      Approve &amp; Release
                    </button>
                  )}
                {canRelease && selectedPart.lifecycle !== 'Obsolete' && (
                  <button
                    type="button"
                    className="btn btn-danger btn-sm"
                    onClick={() => void handleTransition(selectedPart, 'Obsolete')}
                  >
                    Mark Obsolete
                  </button>
                )}
              </div>

              <div className="grid-2">
                <div className="stat-card">
                  <div className="stat-label">Parametric Attributes</div>
                  <div className="stack-sm text-sm">
                    {Object.entries(selectedPart.attributes).map(([k, v]) => (
                      <div key={k} className="row-between">
                        <span className="muted">{k}</span>
                        <span className="mono">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-label">Where-Used Impact</div>
                  {selectedPart.whereUsed.length === 0 ? (
                    <div className="text-sm muted">Not yet placed on any board revision.</div>
                  ) : (
                    <div className="stack-sm text-sm">
                      {selectedPart.whereUsed.map((wu) => (
                        <div key={`${wu.boardId}-${wu.revisionTag}`}>
                          <strong>{wu.boardName}</strong>{' '}
                          <span className="mono muted">
                            ({wu.revisionTag}) · {wu.refdesList.join(', ')}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            <FootprintPreview spec={selectedPart.ipcSpec} mpn={selectedPart.mpn} />
          </div>
        )}
      </div>

      <HttpLibModal open={httpLibOpen} onClose={() => setHttpLibOpen(false)} />
    </div>
  );
};
