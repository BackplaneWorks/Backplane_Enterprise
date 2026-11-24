import React, { useState } from 'react';
import { api } from '../api/endpoints';
import { FootprintPreview } from '../components/FootprintPreview';
import { HttpLibModal } from '../components/HttpLibModal';
import { Empty, PageHead, Panel, Stat, Status, Tag, type Tone } from '../components/ui';
import { useSession } from '../context/SessionContext';
import { fmtTime, usd } from '../lib/format';
import { hasPermission } from '../lib/rbac';
import { buildKiCadDeepLink, sanitizeExternalUrl } from '../lib/safeUrl';
import type { Ipc7351Spec, IpcPackageFamily, LibraryPart, PartLifecycle } from '../types/domain';

const LIFECYCLE_TONE: Record<PartLifecycle, Tone> = {
  Draft: 'warn',
  'In Review': 'accent',
  Released: 'ok',
  Obsolete: 'bad',
};

const LIFECYCLES: PartLifecycle[] = ['Draft', 'In Review', 'Released', 'Obsolete'];

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

  // One spec feeds both the live preview and the saved part.
  const draftSpec: Ipc7351Spec = {
    family: newFamily,
    pinCount: newPins,
    pitchMm: newPitch,
    bodyWidthMm: newFamily === 'CHIP' ? 1.6 : 4.0,
    bodyLengthMm: newFamily === 'CHIP' ? 3.2 : 4.0,
    padWidthMm: newFamily === 'CHIP' ? 0.9 : 0.3,
    padLengthMm: newFamily === 'CHIP' ? 1.2 : 0.85,
    thermalPadMm: newFamily === 'QFN' ? 2.1 : undefined,
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
      ipcSpec: draftSpec,
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
  const countBy = (lc: PartLifecycle) => parts.filter((p) => p.lifecycle === lc).length;
  const filtering = search.trim() !== '' || lifecycleFilter !== 'ALL';

  const newPartButton = canWrite && (
    <button type="button" className="btn btn-primary" onClick={() => setShowNewForm((v) => !v)}>
      {showNewForm ? 'Cancel New Part' : '+ New Library Part'}
    </button>
  );

  return (
    <>
      <PageHead
        num="02"
        eyebrow="Library"
        title="Web Librarian & Private KiCad HTTP Library"
        sub={
          <>
            Parametric parts, lifecycle approvals, where-used impact and IPC-7351 footprints, served
            to KiCad over a tenant-isolated <code>.kicad_httplib</code>.
          </>
        }
      >
        <button type="button" className="btn" onClick={() => setHttpLibOpen(true)}>
          Generate .kicad_httplib
        </button>
        {newPartButton}
      </PageHead>

      <div className="stats">
        <Stat label="Parts" value={parts.length} sub="in this tenant" />
        <Stat label="Released" value={countBy('Released')} tone={countBy('Released') ? 'ok' : 'plain'} sub="orderable" />
        <Stat label="In review" value={countBy('In Review')} sub="awaiting librarian" />
        <Stat label="Draft" value={countBy('Draft')} sub="not yet submitted" />
        <Stat
          label="Obsolete"
          value={countBy('Obsolete')}
          tone={countBy('Obsolete') ? 'bad' : 'plain'}
          sub="blocked from new designs"
        />
      </div>

      {showNewForm && canWrite && (
        <Panel title="New part" meta="IPC-7351 generator">
          <div className="split">
            <form className="panel-body stack" onSubmit={(e) => void handleCreatePart(e)}>
              <div className="form-grid two">
                <label className="field">
                  <span className="field-cap">MPN *</span>
                  <input
                    className="input mono"
                    required
                    value={newMpn}
                    onChange={(e) => setNewMpn(e.target.value)}
                    placeholder="RP2350A"
                  />
                </label>
                <label className="field">
                  <span className="field-cap">Manufacturer *</span>
                  <input
                    className="input"
                    required
                    value={newMfr}
                    onChange={(e) => setNewMfr(e.target.value)}
                    placeholder="Raspberry Pi"
                  />
                </label>
                <label className="field">
                  <span className="field-cap">Category</span>
                  <input
                    className="input"
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                  />
                </label>
                <label className="field">
                  <span className="field-cap">Value / Spec</span>
                  <input
                    className="input"
                    value={newValue}
                    onChange={(e) => setNewValue(e.target.value)}
                    placeholder="Dual Cortex-M33 MCU"
                  />
                </label>
              </div>
              <div className="form-grid three">
                <label className="field">
                  <span className="field-cap">IPC-7351 Family</span>
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
                <label className="field">
                  <span className="field-cap">Pin Count</span>
                  <input
                    className="input mono"
                    type="number"
                    min={2}
                    max={256}
                    value={newPins}
                    onChange={(e) => setNewPins(Number(e.target.value) || 2)}
                  />
                </label>
                <label className="field">
                  <span className="field-cap">Pitch (mm)</span>
                  <input
                    className="input mono"
                    type="number"
                    step="0.05"
                    min={0.25}
                    value={newPitch}
                    onChange={(e) => setNewPitch(Number(e.target.value) || 0.5)}
                  />
                </label>
              </div>
              <label className="field">
                <span className="field-cap">Datasheet URL (https only)</span>
                <input
                  className="input"
                  value={newDatasheet}
                  onChange={(e) => setNewDatasheet(e.target.value)}
                />
              </label>
              <div className="row">
                <button type="submit" className="btn btn-primary">
                  Save Part to Tenant Library
                </button>
                <span className="faint">Saved as Draft · footprint regenerates as you type</span>
              </div>
            </form>
            <div className="panel-body">
              <FootprintPreview spec={draftSpec} mpn={newMpn.trim() || 'new part'} compact />
            </div>
          </div>
        </Panel>
      )}

      {parts.length === 0 ? (
        <section className="panel">
          <Empty
            title="The library is empty"
            icon="library"
            variant="canvas"
            actions={
              <>
                {newPartButton}
                <button type="button" className="btn" onClick={() => setHttpLibOpen(true)}>
                  Connect KiCad first
                </button>
              </>
            }
          >
            Add a part to generate its IPC-7351 footprint and schematic symbol. Released parts are
            served straight into KiCad&apos;s symbol chooser for every seat in{' '}
            {principal.tenantName}.
          </Empty>
        </section>
      ) : (
        <div className="split wide-right">
          <Panel
            title="Parts"
            meta={
              filtering ? `${filteredParts.length} of ${parts.length}` : `${parts.length} total`
            }
          >
            <div className="panel-body row nowrap">
              <input
                aria-label="Search parts"
                className="input"
                placeholder="Search MPN, internal part #, manufacturer..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <select
                aria-label="Filter lifecycle"
                className="select auto"
                value={lifecycleFilter}
                onChange={(e) => setLifecycleFilter(e.target.value as 'ALL' | PartLifecycle)}
              >
                <option value="ALL">All Lifecycles</option>
                {LIFECYCLES.map((lc) => (
                  <option key={lc} value={lc}>
                    {lc}
                  </option>
                ))}
              </select>
            </div>

            {filteredParts.length === 0 ? (
              <Empty
                title="No parts match"
                variant="compact"
                actions={
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => {
                      setSearch('');
                      setLifecycleFilter('ALL');
                    }}
                  >
                    Clear filters
                  </button>
                }
              >
                Nothing matches the current search and lifecycle filter.
              </Empty>
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Part #</th>
                      <th>MPN</th>
                      <th>Package</th>
                      <th>Lifecycle</th>
                      <th className="r">Fab Stock</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredParts.map((part) => (
                      <tr
                        key={part.id}
                        className={`click${part.id === selectedPart?.id ? ' sel' : ''}`}
                        onClick={() => setSelectedPartId(part.id)}
                      >
                        <td className="dim nowrap">{part.partNumber}</td>
                        <td>
                          <strong className="cell-main">{part.mpn}</strong>
                          <div className="cell-sub">{part.manufacturer}</div>
                        </td>
                        <td className="nowrap">{part.packageName}</td>
                        <td>
                          <Status tone={LIFECYCLE_TONE[part.lifecycle]}>{part.lifecycle}</Status>
                        </td>
                        <td className="num r nowrap">
                          {part.fabStockQty.toLocaleString()}
                          {part.preferredByFab && <div className="cell-sub">preferred</div>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          {selectedPart && (
            <div className="stack lg-gap">
              <Panel
                title={selectedPart.partNumber}
                meta={`updated ${fmtTime(selectedPart.updatedAt)}`}
                actions={
                  <Tag tone={LIFECYCLE_TONE[selectedPart.lifecycle]}>{selectedPart.lifecycle}</Tag>
                }
              >
                <div className="panel-body stack">
                  <div>
                    <h3 className="part-mpn">{selectedPart.mpn}</h3>
                    <div className="dim prose">
                      {selectedPart.manufacturer} · {selectedPart.description}
                    </div>
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
                        Datasheet PDF ↗
                      </a>
                    )}
                  </div>
                </div>

                {(canWrite || canRelease) && selectedPart.lifecycle !== 'Obsolete' && (
                  <div className="panel-foot">
                    <span>Lifecycle</span>
                    <div className="row tight">
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
                        (selectedPart.lifecycle === 'In Review' ||
                          selectedPart.lifecycle === 'Draft') && (
                          <button
                            type="button"
                            className="btn btn-success btn-sm"
                            onClick={() => void handleTransition(selectedPart, 'Released')}
                          >
                            Approve &amp; Release
                          </button>
                        )}
                      {canRelease && (
                        <button
                          type="button"
                          className="btn btn-danger btn-sm"
                          onClick={() => void handleTransition(selectedPart, 'Obsolete')}
                        >
                          Mark Obsolete
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </Panel>

              <div className="cols-2">
                <Panel title="Attributes">
                  <dl className="kv flush">
                    <dt>Category</dt>
                    <dd>{selectedPart.category}</dd>
                    <dt>Unit price</dt>
                    <dd>{usd(selectedPart.unitPriceUsd)}</dd>
                    <dt>Fab stock</dt>
                    <dd>{selectedPart.fabStockQty.toLocaleString()}</dd>
                    {Object.entries(selectedPart.attributes).map(([k, v]) => (
                      <React.Fragment key={k}>
                        <dt>{k}</dt>
                        <dd>{v}</dd>
                      </React.Fragment>
                    ))}
                  </dl>
                </Panel>

                <Panel title="Where used" meta={selectedPart.whereUsed.length || undefined}>
                  {selectedPart.whereUsed.length === 0 ? (
                    <Empty title="Not placed yet" variant="compact">
                      Not yet placed on any board revision.
                    </Empty>
                  ) : (
                    <div>
                      {selectedPart.whereUsed.map((wu) => (
                        <div key={`${wu.boardId}-${wu.revisionTag}`} className="item">
                          <div className="item-head">
                            <strong className="cell-main trunc">{wu.boardName}</strong>
                            <span className="item-meta">{wu.revisionTag}</span>
                          </div>
                          <div className="item-meta">{wu.refdesList.join(', ')}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>

              <FootprintPreview spec={selectedPart.ipcSpec} mpn={selectedPart.mpn} />
            </div>
          )}
        </div>
      )}

      <HttpLibModal open={httpLibOpen} onClose={() => setHttpLibOpen(false)} />
    </>
  );
};
