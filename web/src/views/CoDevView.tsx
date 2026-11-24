import React, { useState } from 'react';
import { api } from '../api/endpoints';
import { BoardViewport, type ViewportMode } from '../components/BoardViewport';
import { useSession } from '../context/SessionContext';
import { hasPermission } from '../lib/rbac';
import { buildKiCadDeepLink } from '../lib/safeUrl';

export const CoDevView: React.FC = () => {
  const { principal, sandboxMode, boards, setBoards, notify, recordAudit } = useSession();
  const [selectedBoardId, setSelectedBoardId] = useState(boards[0]?.id ?? '');
  const [mode, setMode] = useState<ViewportMode>('pcb');
  const [activeLayer, setActiveLayer] = useState<'F.Cu' | 'B.Cu' | 'F.SilkS' | 'Edge.Cuts'>('F.Cu');
  const [selectedCommentId, setSelectedCommentId] = useState<string | null>(null);
  const [pendingPin, setPendingPin] = useState<{
    layer: string;
    xMm: number;
    yMm: number;
    refdes?: string;
  } | null>(null);
  const [commentBody, setCommentBody] = useState('');
  const [ecoTitle, setEcoTitle] = useState('');
  const [ecoRationale, setEcoRationale] = useState('');
  const [kicadTarget, setKicadTarget] = useState<'local' | 'boat_vm'>('boat_vm');

  const board = boards.find((b) => b.id === selectedBoardId) ?? boards[0];
  const [selectedRevisionId, setSelectedRevisionId] = useState(board?.revisions[0]?.id ?? '');

  if (!board || !principal) {
    return <div className="card">No boards registered for this tenant.</div>;
  }

  const canComment = hasPermission(principal, 'BoardsComment');
  const canWriteBoard = hasPermission(principal, 'BoardsWrite');
  const currentRevision =
    board.revisions.find((r) => r.id === selectedRevisionId) ?? board.revisions[0];

  const handleSubmitPinComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pendingPin || !commentBody.trim()) return;

    const payload = {
      revisionId: currentRevision?.id ?? 'rev-latest',
      layer: pendingPin.layer,
      xMm: pendingPin.xMm,
      yMm: pendingPin.yMm,
      refdes: pendingPin.refdes,
      body: commentBody.trim(),
    };

    try {
      const created = sandboxMode
        ? {
            id: `cmt-${Date.now()}`,
            boardId: board.id,
            authorEmail: principal.email,
            resolved: false,
            createdAt: 'just now',
            ...payload,
          }
        : await api.addPinComment(board.id, payload);

      setBoards((prev) =>
        prev.map((b) =>
          b.id === board.id ? { ...b, comments: [created, ...b.comments] } : b,
        ),
      );
      setSelectedCommentId(created.id);
      setPendingPin(null);
      setCommentBody('');
      recordAudit('board.comment.created', `${board.slug} (${payload.layer} ${payload.xMm},${payload.yMm})`);
      notify('success', 'Spatial review comment pinned.');
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to create comment');
    }
  };

  const handleResolveComment = async (commentId: string) => {
    const target = board.comments.find((c) => c.id === commentId);
    if (!target) return;
    try {
      if (!sandboxMode) {
        if (target.resolved) {
          await api.reopenPinComment(board.id, commentId);
        } else {
          await api.resolvePinComment(board.id, commentId);
        }
      }
      setBoards((prev) =>
        prev.map((b) =>
          b.id === board.id
            ? {
                ...b,
                comments: b.comments.map((c) =>
                  c.id === commentId ? { ...c, resolved: !c.resolved } : c,
                ),
              }
            : b,
        ),
      );
      recordAudit('board.comment.toggled', commentId);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to update comment');
    }
  };

  const handleCreateEco = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ecoTitle.trim() || !ecoRationale.trim()) return;
    try {
      const created = sandboxMode
        ? {
            id: `eco-${Date.now()}`,
            code: `ECO-2026-${Math.floor(110 + Math.random() * 880)}`,
            title: ecoTitle.trim(),
            rationale: ecoRationale.trim(),
            status: 'in_review' as const,
            createdBy: principal.email,
            createdAt: 'just now',
          }
        : await api.createEco(board.id, {
            title: ecoTitle.trim(),
            rationale: ecoRationale.trim(),
          });

      setBoards((prev) =>
        prev.map((b) => (b.id === board.id ? { ...b, ecos: [created, ...b.ecos] } : b)),
      );
      setEcoTitle('');
      setEcoRationale('');
      recordAudit('board.eco.created', created.code);
      notify('success', `${created.code} opened for engineering review.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to create ECO');
    }
  };

  const deepLink = buildKiCadDeepLink({
    tenantSlug: principal.tenantSlug,
    target: kicadTarget,
    boardId: board.id,
    vmId: kicadTarget === 'boat_vm' ? principal.assignedVmId : undefined,
  });

  return (
    <div className="stack-md">
      <div className="page-header">
        <div>
          <h1 className="page-title">Co-Development &amp; Design Review</h1>
          <p className="page-subtitle">
            Inspect PCB, schematic, and 3D views in the browser, drop spatial pin comments, review
            git diffs, and manage ECOs without local KiCad.
          </p>
        </div>

        <div className="row">
          <select
            aria-label="Select Board"
            className="select"
            value={board.id}
            onChange={(e) => {
              const next = boards.find((b) => b.id === e.target.value);
              setSelectedBoardId(e.target.value);
              setSelectedRevisionId(next?.revisions[0]?.id ?? '');
              setPendingPin(null);
            }}
          >
            {boards.map((b) => (
              <option key={b.id} value={b.id}>
                {b.name} ({b.layerCount}L)
              </option>
            ))}
          </select>

          <select
            aria-label="KiCad Launch Target"
            className="select"
            value={kicadTarget}
            onChange={(e) => setKicadTarget(e.target.value as 'local' | 'boat_vm')}
          >
            <option value="boat_vm">Boat VM (Zero-Tailscale)</option>
            <option value="local">Local KiCad</option>
          </select>

          <a className="btn btn-primary" href={deepLink}>
            Open in KiCad
          </a>
        </div>
      </div>

      <div className="split-pane">
        <div className="card stack-md">
          <div className="row-between">
            <div className="row">
              <button
                type="button"
                className={`tab-pill ${mode === 'pcb' ? 'active' : ''}`}
                onClick={() => setMode('pcb')}
              >
                PCB Layout
              </button>
              <button
                type="button"
                className={`tab-pill ${mode === 'schematic' ? 'active' : ''}`}
                onClick={() => setMode('schematic')}
              >
                Schematic
              </button>
              <button
                type="button"
                className={`tab-pill ${mode === '3d' ? 'active' : ''}`}
                onClick={() => setMode('3d')}
              >
                3D Iso
              </button>
            </div>

            {mode === 'pcb' && (
              <select
                aria-label="PCB Layer"
                className="select"
                value={activeLayer}
                onChange={(e) =>
                  setActiveLayer(e.target.value as 'F.Cu' | 'B.Cu' | 'F.SilkS' | 'Edge.Cuts')
                }
              >
                <option value="F.Cu">F.Cu</option>
                <option value="B.Cu">B.Cu</option>
                <option value="F.SilkS">F.SilkS</option>
                <option value="Edge.Cuts">Edge.Cuts</option>
              </select>
            )}
          </div>

          <BoardViewport
            board={board}
            mode={mode}
            activeLayer={activeLayer}
            selectedCommentId={selectedCommentId}
            onSelectComment={setSelectedCommentId}
            onPlacePin={(coords) => {
              if (canComment) setPendingPin(coords);
            }}
          />

          <div className="row-between text-sm muted">
            <span>
              Dimensions: <strong className="mono">{board.widthMm} x {board.heightMm} mm</strong> (
              {board.layerCount} layers)
            </span>
            <span>
              Revision:{' '}
              <strong className="mono">
                {currentRevision?.tag} ({currentRevision?.commitSha})
              </strong>
            </span>
          </div>
        </div>

        <div className="stack-md">
          <div className="card stack-sm">
            <div className="card-header">
              <h3 className="card-title">Spatial Pin-Drop Comments ({board.comments.length})</h3>
              <span className="badge badge-cyan">Click canvas to pin</span>
            </div>

            {pendingPin && canComment && (
              <form className="comment-card stack-sm" onSubmit={(e) => void handleSubmitPinComment(e)}>
                <div className="text-sm mono">
                  New pin: {pendingPin.layer} @ ({pendingPin.xMm}, {pendingPin.yMm}) mm
                  {pendingPin.refdes ? ` · ${pendingPin.refdes}` : ''}
                </div>
                <textarea
                  className="textarea"
                  rows={2}
                  placeholder="Write review feedback for this coordinate or refdes..."
                  value={commentBody}
                  onChange={(e) => setCommentBody(e.target.value)}
                />
                <div className="row">
                  <button type="submit" className="btn btn-primary btn-sm">
                    Post Pin Comment
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => setPendingPin(null)}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}

            {board.comments.map((cmt, idx) => (
              <div
                key={cmt.id}
                className={`comment-card stack-sm ${cmt.resolved ? 'resolved' : ''}`}
              >
                <div className="row-between text-sm">
                  <span className="mono">
                    #{idx + 1} · {cmt.layer} ({cmt.xMm}, {cmt.yMm})
                    {cmt.refdes ? ` · ${cmt.refdes}` : ''}
                  </span>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => void handleResolveComment(cmt.id)}
                  >
                    {cmt.resolved ? 'Reopen' : 'Resolve'}
                  </button>
                </div>
                <div>{cmt.body}</div>
                <div className="text-sm muted">
                  {cmt.authorEmail} · {cmt.createdAt}
                </div>
              </div>
            ))}
          </div>

          <div className="card stack-sm">
            <div className="card-header">
              <h3 className="card-title">Git Revisions &amp; Diffs</h3>
              <select
                aria-label="Git Revision"
                className="select"
                value={currentRevision?.id ?? ''}
                onChange={(e) => setSelectedRevisionId(e.target.value)}
              >
                {board.revisions.map((rev) => (
                  <option key={rev.id} value={rev.id}>
                    {rev.tag} ({rev.commitSha})
                  </option>
                ))}
              </select>
            </div>
            {board.diffs.map((diff, idx) => (
              <div key={idx} className={`comment-card diff-${diff.kind}`}>
                <div className="row-between text-sm">
                  <strong>
                    [{diff.scope}] {diff.target}
                  </strong>
                  <span className="badge">{diff.kind}</span>
                </div>
                <div className="text-sm">{diff.detail}</div>
              </div>
            ))}
          </div>

          <div className="card stack-sm">
            <div className="card-header">
              <h3 className="card-title">Engineering Change Orders (ECOs)</h3>
            </div>
            {board.ecos.map((eco) => (
              <div key={eco.id} className="comment-card stack-sm">
                <div className="row-between">
                  <strong className="mono">{eco.code}</strong>
                  <span className="badge badge-blue">{eco.status}</span>
                </div>
                <div>{eco.title}</div>
                <div className="text-sm muted">{eco.rationale}</div>
              </div>
            ))}

            {canWriteBoard && (
              <form className="stack-sm" onSubmit={(e) => void handleCreateEco(e)}>
                <input
                  className="input"
                  placeholder="New ECO title..."
                  value={ecoTitle}
                  onChange={(e) => setEcoTitle(e.target.value)}
                />
                <input
                  className="input"
                  placeholder="Engineering rationale..."
                  value={ecoRationale}
                  onChange={(e) => setEcoRationale(e.target.value)}
                />
                <button type="submit" className="btn btn-primary btn-sm">
                  Open ECO
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
