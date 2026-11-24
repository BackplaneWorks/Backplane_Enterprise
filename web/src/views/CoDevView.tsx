import React, { useState } from 'react';
import { api } from '../api/endpoints';
import { BoardViewport, type ViewportMode } from '../components/BoardViewport';
import { useSession } from '../context/SessionContext';
import { Empty, PageHead, Panel, Status, Tag, type Tone } from '../components/ui';
import { fmtTime, humanize } from '../lib/format';
import { canAccessTab, hasPermission } from '../lib/rbac';
import { buildKiCadDeepLink } from '../lib/safeUrl';
import type { EcoStatus } from '../types/domain';

const ECO_TONE: Record<EcoStatus, Tone> = {
  draft: 'plain',
  in_review: 'accent',
  approved: 'ok',
  implemented: 'ok',
};

const MODES: Array<[ViewportMode, string]> = [
  ['pcb', 'PCB Layout'],
  ['schematic', 'Schematic'],
  ['3d', '3D Iso'],
];

const LAYERS = ['F.Cu', 'B.Cu', 'F.SilkS', 'Edge.Cuts'] as const;

export const CoDevView: React.FC = () => {
  const { principal, sandboxMode, boards, setBoards, notify, recordAudit, navigate } =
    useSession();
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

  if (!principal) return null;

  if (!board) {
    return (
      <>
        <PageHead
          num="01"
          eyebrow="Boards"
          title="Co-Development & Design Review"
          sub="Inspect layout, schematic and 3D views in the browser, pin review comments to coordinates, read revision diffs and run ECOs without a local KiCad."
        />
        <section className="panel">
          <Empty
            title="No boards in this organization yet"
            icon="board"
            variant="canvas"
            actions={
              <>
                {canAccessTab(principal, 'librarian') && (
                  <button type="button" className="btn btn-primary" onClick={() => navigate('librarian')}>
                    Set up the part library
                  </button>
                )}
                {canAccessTab(principal, 'admin') && (
                  <button type="button" className="btn" onClick={() => navigate('admin', 'vms')}>
                    Enroll a Boat VM
                  </button>
                )}
              </>
            }
          >
            A board shows up here when its first revision is pushed from Backplane or from KiCad on
            a Boat VM. Reviewers can then drop pin comments on the layout and open ECOs against it.
          </Empty>
        </section>
      </>
    );
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

  const openCount = board.comments.filter((c) => !c.resolved).length;

  return (
    <>
      <PageHead
        num="01"
        eyebrow="Boards"
        title="Co-Development & Design Review"
        sub="Inspect layout, schematic and 3D views in the browser, pin review comments to coordinates, read revision diffs and run ECOs without a local KiCad."
      >
        <select
          aria-label="Select Board"
          className="select auto"
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
          className="select auto"
          value={kicadTarget}
          onChange={(e) => setKicadTarget(e.target.value as 'local' | 'boat_vm')}
        >
          <option value="boat_vm">Boat VM (Zero-Tailscale)</option>
          <option value="local">Local KiCad</option>
        </select>

        <a className="btn btn-primary" href={deepLink}>
          Open in KiCad
        </a>
      </PageHead>

      <div className="split">
        <div className="stack lg-gap">
          <Panel
            title={board.slug}
            meta={currentRevision ? `${currentRevision.tag} · ${currentRevision.commitSha}` : undefined}
            actions={
              <>
                {mode === 'pcb' && (
                  <select
                    aria-label="PCB Layer"
                    className="select auto"
                    value={activeLayer}
                    onChange={(e) => setActiveLayer(e.target.value as (typeof LAYERS)[number])}
                  >
                    {LAYERS.map((layer) => (
                      <option key={layer} value={layer}>
                        {layer}
                      </option>
                    ))}
                  </select>
                )}
                <div className="seg">
                  {MODES.map(([id, label]) => (
                    <button
                      key={id}
                      type="button"
                      className={mode === id ? 'on' : ''}
                      onClick={() => setMode(id)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </>
            }
          >
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
            <div className="panel-foot">
              <span>
                {board.widthMm} × {board.heightMm} mm · {board.layerCount} layers ·{' '}
                {board.components.length} components
              </span>
              <span>{canComment ? 'click the canvas to pin a comment' : 'read-only'}</span>
            </div>
          </Panel>

          <Panel
            title="Revisions & diff"
            actions={
              <select
                aria-label="Git Revision"
                className="select auto"
                value={currentRevision?.id ?? ''}
                onChange={(e) => setSelectedRevisionId(e.target.value)}
              >
                {board.revisions.map((rev) => (
                  <option key={rev.id} value={rev.id}>
                    {rev.tag} ({rev.commitSha})
                  </option>
                ))}
              </select>
            }
          >
            {currentRevision && (
              <div className="panel-note">
                {currentRevision.summary}
                <span className="faint">
                  {' '}
                  — {currentRevision.author}, {fmtTime(currentRevision.createdAt)}
                </span>
              </div>
            )}
            {board.diffs.length === 0 ? (
              <Empty title="No changes against the previous revision" variant="compact" />
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th className="shrink">Change</th>
                      <th className="shrink">Scope</th>
                      <th>Target</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {board.diffs.map((diff, idx) => (
                      <tr key={idx}>
                        <td className="shrink">
                          <Status
                            tone={
                              diff.kind === 'added' ? 'ok' : diff.kind === 'removed' ? 'bad' : 'warn'
                            }
                          >
                            {diff.kind}
                          </Status>
                        </td>
                        <td className="shrink dim">{diff.scope}</td>
                        <td className="cell-main">{diff.target}</td>
                        <td className="dim prose">{diff.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>

        <div className="stack lg-gap">
          <Panel
            title="Pin comments"
            meta={`${openCount} open · ${board.comments.length} total`}
          >
            {pendingPin && canComment && (
              <form className="item form" onSubmit={(e) => void handleSubmitPinComment(e)}>
                <div className="item-id c-accent">
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
                <div className="row tight">
                  <button type="submit" className="btn btn-primary btn-sm">
                    Post Pin Comment
                  </button>
                  <button type="button" className="btn btn-sm" onClick={() => setPendingPin(null)}>
                    Cancel
                  </button>
                </div>
              </form>
            )}

            {board.comments.length === 0 && !pendingPin ? (
              <Empty title="No review comments" variant="compact">
                {canComment
                  ? 'Click anywhere on the board to pin the first comment to a coordinate or refdes.'
                  : 'Nothing has been flagged on this board.'}
              </Empty>
            ) : (
              board.comments.map((cmt, idx) => (
                <div
                  key={cmt.id}
                  className={`item${cmt.id === selectedCommentId ? ' sel' : ''}${
                    cmt.resolved ? ' done' : ''
                  }`}
                >
                  <div className="item-head">
                    <button
                      type="button"
                      className="pin-ref"
                      onClick={() => setSelectedCommentId(cmt.id)}
                    >
                      <span className={`pin-num${cmt.resolved ? ' ok' : ''}`}>{idx + 1}</span>
                      <span className="item-id">
                        {cmt.layer} ({cmt.xMm}, {cmt.yMm}){cmt.refdes ? ` · ${cmt.refdes}` : ''}
                      </span>
                    </button>
                    {canComment && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => void handleResolveComment(cmt.id)}
                      >
                        {cmt.resolved ? 'Reopen' : 'Resolve'}
                      </button>
                    )}
                  </div>
                  <div className="prose">{cmt.body}</div>
                  <div className="item-meta">
                    {cmt.authorEmail} · {fmtTime(cmt.createdAt)}
                  </div>
                </div>
              ))
            )}
          </Panel>

          <Panel title="Engineering change orders" meta={board.ecos.length || undefined}>
            {board.ecos.length === 0 && (
              <Empty title="No ECOs on this board" variant="compact">
                {canWriteBoard
                  ? 'Open one below to put a change through engineering review.'
                  : 'Changes under review are listed here.'}
              </Empty>
            )}
            {board.ecos.map((eco) => (
              <div key={eco.id} className="item">
                <div className="item-head">
                  <strong className="item-id">{eco.code}</strong>
                  <Tag tone={ECO_TONE[eco.status]}>{humanize(eco.status)}</Tag>
                </div>
                <div className="cell-main">{eco.title}</div>
                <div className="dim prose">{eco.rationale}</div>
              </div>
            ))}

            {canWriteBoard && (
              <form className="item form" onSubmit={(e) => void handleCreateEco(e)}>
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
                <div>
                  <button type="submit" className="btn btn-primary btn-sm">
                    Open ECO
                  </button>
                </div>
              </form>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
};
