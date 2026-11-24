import React from 'react';
import { Empty, PageHead, Panel, Stat, Status, type Tone } from '../components/ui';
import { useSession } from '../context/SessionContext';
import { fmtTime, humanize, personName, usd } from '../lib/format';
import { canAccessTab, hasPermission, roleLabel } from '../lib/rbac';
import type { AdminSection, NavTab } from '../types/domain';

interface AttentionItem {
  key: string;
  tone: Tone;
  label: string;
  detail: string;
  tab: NavTab;
  section?: AdminSection;
}

interface SetupStep {
  key: string;
  done: boolean;
  label: string;
  detail: string;
  tab: NavTab;
  section?: AdminSection;
}

export const OverviewView: React.FC = () => {
  const {
    principal,
    navigate,
    boards,
    parts,
    orders,
    boatVms,
    pendingApprovals,
    auditLogs,
    idps,
    mailConnectors,
    bridges,
    users,
    keyInfo,
    llmPolicy,
  } = useSession();

  if (!principal) return null;

  const isAdmin = canAccessTab(principal, 'admin');
  const seesParts = canAccessTab(principal, 'librarian');
  const seesOrders = canAccessTab(principal, 'purchasing');
  const seesAudit = hasPermission(principal, 'AuditRead');

  const released = parts.filter((p) => p.lifecycle === 'Released').length;
  const inReview = parts.filter((p) => p.lifecycle === 'In Review');
  const openOrders = orders.filter((o) => o.state !== 'delivered' && o.state !== 'cancelled');
  const awaitingPo = orders.filter((o) => o.state === 'pending_approval');
  const pending = pendingApprovals.filter((a) => a.status === 'pending');
  const vmsUp = boatVms.filter((vm) => vm.tunnelState === 'connected_mtls').length;
  const openComments = boards.reduce(
    (acc, b) => acc + b.comments.filter((c) => !c.resolved).length,
    0,
  );
  const openEcos = boards.reduce(
    (acc, b) => acc + b.ecos.filter((e) => e.status === 'in_review' || e.status === 'draft').length,
    0,
  );

  const attention: AttentionItem[] = [];
  if (isAdmin && pending.length > 0) {
    attention.push({
      key: 'approvals',
      tone: 'warn',
      label: `${pending.length} approval request${pending.length === 1 ? '' : 's'} waiting`,
      detail: pending.map((a) => a.subject ?? humanize(a.gateKind)).join(', '),
      tab: 'admin',
      section: 'gates',
    });
  }
  if (seesOrders && awaitingPo.length > 0) {
    attention.push({
      key: 'orders',
      tone: 'warn',
      label: `${awaitingPo.length} order${awaitingPo.length === 1 ? '' : 's'} pending approval`,
      detail: awaitingPo.map((o) => o.orderNumber).join(', '),
      tab: 'purchasing',
    });
  }
  if (seesParts && inReview.length > 0) {
    attention.push({
      key: 'parts',
      tone: 'accent',
      label: `${inReview.length} part${inReview.length === 1 ? '' : 's'} in review`,
      detail: inReview.map((p) => p.mpn).join(', '),
      tab: 'librarian',
    });
  }
  if (openComments > 0) {
    attention.push({
      key: 'comments',
      tone: 'accent',
      label: `${openComments} open review comment${openComments === 1 ? '' : 's'}`,
      detail: `${openEcos} ECO${openEcos === 1 ? '' : 's'} in progress`,
      tab: 'codev',
    });
  }

  const setup: SetupStep[] = isAdmin
    ? [
        {
          key: 'idp',
          done: idps.length > 0,
          label: 'Connect an identity provider',
          detail: 'Google Workspace, Entra ID, OIDC or SAML',
          tab: 'admin',
          section: 'sso',
        },
        {
          key: 'parts',
          done: parts.length > 0,
          label: 'Add the first library part',
          detail: 'Parametric part with an IPC-7351 footprint',
          tab: 'librarian',
        },
        {
          key: 'vm',
          done: boatVms.length > 0,
          label: 'Enroll a Boat VM',
          detail: 'Managed KiCad seat over outbound mTLS',
          tab: 'admin',
          section: 'vms',
        },
        {
          key: 'mail',
          done: mailConnectors.length > 0,
          label: 'Connect an orders mailbox',
          detail: 'Gmail or Microsoft 365 order tracking',
          tab: 'purchasing',
        },
        {
          key: 'bridge',
          done: bridges.length > 0,
          label: 'Bridge a team channel',
          detail: 'Slack, Teams, Discord or a signed webhook',
          tab: 'admin',
          section: 'bridges',
        },
      ]
    : [];
  const setupDone = setup.filter((s) => s.done).length;
  const showSetup = setup.length > 0 && setupDone < setup.length;

  return (
    <>
      <PageHead
        num="00"
        eyebrow="Overview"
        title={principal.tenantName}
        sub={
          <>
            Signed in as {personName(principal.displayName, principal.email)} ·{' '}
            {roleLabel(principal.role)}
          </>
        }
      />

      <div className="stats">
        <Stat
          label="Boards"
          value={boards.length}
          sub={`${openComments} open comments · ${openEcos} ECOs`}
          onClick={() => navigate('codev')}
        />
        {seesParts && (
          <Stat
            label="Library parts"
            value={
              <>
                {parts.length}
                <small> / {released} released</small>
              </>
            }
            sub={`${inReview.length} in review`}
            onClick={() => navigate('librarian')}
          />
        )}
        {seesOrders && (
          <Stat
            label="Open orders"
            value={openOrders.length}
            sub={
              openOrders.length > 0
                ? usd(openOrders.reduce((acc, o) => acc + o.totalCents, 0) / 100)
                : `${orders.length} total`
            }
            onClick={() => navigate('purchasing')}
          />
        )}
        {isAdmin && (
          <Stat
            label="Pending approvals"
            value={pending.length}
            tone={pending.length > 0 ? 'warn' : 'plain'}
            sub="four-eyes queue"
            onClick={() => navigate('admin', 'gates')}
          />
        )}
        {isAdmin && (
          <Stat
            label="VM relay"
            value={
              <>
                {vmsUp}
                <small> / {boatVms.length} on mTLS</small>
              </>
            }
            sub={boatVms.length === 0 ? 'none enrolled' : 'outbound tunnels'}
            onClick={() => navigate('admin', 'vms')}
          />
        )}
      </div>

      <div className="cols-2">
        <div className="stack lg-gap">
          <Panel title="Needs attention" meta={attention.length > 0 ? attention.length : undefined}>
            {attention.length === 0 ? (
              <Empty title="Nothing is waiting on you" variant="compact">
                Approvals, orders awaiting sign-off and open review comments show up here.
              </Empty>
            ) : (
              <div>
                {attention.map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    className="item-link"
                    onClick={() => navigate(item.tab, item.section)}
                  >
                    <span className="grow">
                      <Status tone={item.tone}>{item.label}</Status>
                      <div className="cell-sub trunc">{item.detail}</div>
                    </span>
                    <span className="arrow">→</span>
                  </button>
                ))}
              </div>
            )}
          </Panel>

          {showSetup && (
            <Panel title="Set up this organization" meta={`${setupDone}/${setup.length}`}>
              <div>
                {setup.map((step) => (
                  <button
                    key={step.key}
                    type="button"
                    className="item-link"
                    onClick={() => navigate(step.tab, step.section)}
                  >
                    <span className={`step-box${step.done ? ' done' : ''}`} aria-hidden="true">
                      {step.done ? '✓' : ''}
                    </span>
                    <span className="grow">
                      <div className={step.done ? 'dim' : 'cell-main'}>{step.label}</div>
                      <div className="cell-sub trunc">{step.detail}</div>
                    </span>
                    <span className="arrow">{step.done ? 'done' : '→'}</span>
                  </button>
                ))}
              </div>
            </Panel>
          )}

          {isAdmin && (
            <Panel title="Governance">
              <dl className="kv flush">
                <dt>Members</dt>
                <dd>{users.length}</dd>
                <dt>Identity providers</dt>
                <dd>{idps.length === 0 ? 'none configured' : idps.length}</dd>
                <dt>LLM routing</dt>
                <dd className={llmPolicy.zdrRequired ? 'c-ok' : undefined}>
                  {llmPolicy.zdrRequired ? 'ZDR only' : 'provider allowlist'} ·{' '}
                  {llmPolicy.providers.length} providers
                </dd>
                <dt>Tenant DEK</dt>
                <dd>
                  {keyInfo.activeVersion > 0
                    ? `v${keyInfo.activeVersion} · ${keyInfo.provider}`
                    : '—'}
                </dd>
              </dl>
            </Panel>
          )}
        </div>

        {seesAudit ? (
          <Panel
            title="Recent activity"
            meta="audit log"
            actions={
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => navigate('admin', 'audit')}
              >
                Open log →
              </button>
            }
          >
            {auditLogs.length === 0 ? (
              <Empty title="No activity recorded yet" variant="compact">
                Every change to parts, boards, orders and policy lands in the hash-chained log.
              </Empty>
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th className="shrink">Seq</th>
                      <th>Action</th>
                      <th>Actor</th>
                      <th className="r">When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.slice(0, 10).map((entry) => (
                      <tr key={entry.seq}>
                        <td className="num faint shrink">#{entry.seq}</td>
                        <td>
                          <div>{entry.action}</div>
                          <div className="cell-sub break">{entry.target}</div>
                        </td>
                        <td className="dim">{entry.actorEmail ?? entry.actor ?? 'system'}</td>
                        <td className="r faint nowrap">{fmtTime(entry.timestamp)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        ) : (
          <Panel title="Boards" meta={boards.length}>
            {boards.length === 0 ? (
              <Empty title="No boards shared with you yet" icon="board" variant="compact">
                Boards appear here once a revision is pushed to this organization.
              </Empty>
            ) : (
              <div>
                {boards.map((b) => (
                  <button
                    key={b.id}
                    type="button"
                    className="item-link"
                    onClick={() => navigate('codev')}
                  >
                    <span className="grow">
                      <div className="cell-main">{b.name}</div>
                      <div className="cell-sub">
                        {b.widthMm} × {b.heightMm} mm · {b.layerCount}L ·{' '}
                        {b.revisions[0]?.tag ?? 'no revisions'}
                      </div>
                    </span>
                    <span className="arrow">→</span>
                  </button>
                ))}
              </div>
            )}
          </Panel>
        )}
      </div>
    </>
  );
};
