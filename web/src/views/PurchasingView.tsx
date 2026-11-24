import React, { useEffect, useState } from 'react';
import { api } from '../api/endpoints';
import { Empty, PageHead, Panel, Stat, Status, Tag, type Tone } from '../components/ui';
import { useSession } from '../context/SessionContext';
import { fmtTime, humanize, usd } from '../lib/format';
import { hasPermission } from '../lib/rbac';
import { escapeCsvCell, sanitizeExternalUrl, sanitizeServerRedirectUrl } from '../lib/safeUrl';
import type { BomLine, OrderRecord, OrderState, PartLifecycle } from '../types/domain';

const ORDER_TONE: Record<OrderState, Tone> = {
  draft: 'plain',
  quote_requested: 'plain',
  pending_approval: 'warn',
  ordered: 'accent',
  in_fabrication: 'accent',
  shipped: 'accent',
  delivered: 'ok',
  on_hold: 'bad',
  cancelled: 'bad',
};

const LIFECYCLE_TONE: Record<PartLifecycle, Tone> = {
  Draft: 'warn',
  'In Review': 'accent',
  Released: 'ok',
  Obsolete: 'bad',
};

export const PurchasingView: React.FC = () => {
  const {
    principal,
    sandboxMode,
    boards,
    bomLines,
    setBomLines,
    orders,
    setOrders,
    mailConnectors,
    orderEmails,
    setOrderEmails,
    notify,
    recordAudit,
    navigate,
  } = useSession();

  const [pickedBoardId, setSelectedBoardId] = useState(boards[0]?.id ?? '');
  const selectedBoardId = boards.some((b) => b.id === pickedBoardId)
    ? pickedBoardId
    : (boards[0]?.id ?? '');
  const [buildQty, setBuildQty] = useState(25);
  const [alternatesLineId, setAlternatesLineId] = useState<string | null>(null);
  const [statusNote, setStatusNote] = useState('');

  // Live tenants read the BOM for the chosen board; the sandbox carries its own.
  useEffect(() => {
    if (sandboxMode || !selectedBoardId) return;
    let active = true;
    api
      .listBom(selectedBoardId)
      .then((lines) => {
        if (!active) return;
        setBomLines((prev) => [...prev.filter((l) => l.boardId !== selectedBoardId), ...lines]);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [sandboxMode, selectedBoardId, setBomLines]);

  if (!principal) return null;

  const canApproveOrders = hasPermission(principal, 'OrdersApprove');
  const canWriteOrders = hasPermission(principal, 'OrdersWrite');
  const canManageMail = hasPermission(principal, 'MailManage');

  const boardBom = bomLines.filter((l) => l.boardId === selectedBoardId);
  const totalBomUnitUsd = boardBom.reduce((acc, l) => acc + l.unitPriceUsd * l.qtyPerBoard, 0);
  const eolCount = boardBom.filter((l) => l.lifecycle === 'Obsolete' || l.fabStockQty === 0).length;
  const activeAltLine = boardBom.find((l) => l.id === alternatesLineId) ?? null;

  const handleSwapAlternate = async (line: BomLine, altMpn: string) => {
    const alt = line.alternates.find((a) => a.mpn === altMpn);
    if (!alt) return;
    try {
      if (!sandboxMode) {
        await api.swapBomAlternate(line.id, altMpn);
      }
      setBomLines((prev) =>
        prev.map((item) =>
          item.id === line.id
            ? {
                ...item,
                mpn: alt.mpn,
                manufacturer: alt.manufacturer,
                unitPriceUsd: alt.unitPriceUsd,
                fabStockQty: alt.fabStockQty,
                lifecycle: 'Released',
              }
            : item,
        ),
      );
      setAlternatesLineId(null);
      recordAudit('bom.alternate.swapped', `${line.mpn} -> ${alt.mpn}`);
      notify('success', `Swapped ${line.refdes.join(', ')} to ${alt.mpn}.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to swap alternate');
    }
  };

  const handleExportRfqCsv = () => {
    const header = ['RefDes', 'QtyPerBoard', 'TotalQty', 'MPN', 'Manufacturer', 'Lifecycle', 'UnitUSD'];
    const rows = boardBom.map((line) => [
      escapeCsvCell(line.refdes.join(' ')),
      escapeCsvCell(line.qtyPerBoard),
      escapeCsvCell(line.qtyPerBoard * buildQty),
      escapeCsvCell(line.mpn),
      escapeCsvCell(line.manufacturer),
      escapeCsvCell(line.lifecycle),
      escapeCsvCell(line.unitPriceUsd.toFixed(2)),
    ]);
    const csv = [header.map(escapeCsvCell).join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedBoardId}-rfq-${buildQty}pcs.csv`;
    link.click();
    URL.revokeObjectURL(url);
    recordAudit('purchasing.rfq.exported', `${selectedBoardId} x${buildQty}`);
    notify('success', 'Sanitized RFQ CSV exported.');
  };

  const handleTransitionOrder = async (order: OrderRecord, nextState: OrderState) => {
    try {
      const updated: OrderRecord = sandboxMode
        ? { ...order, state: nextState, updatedAt: 'just now' }
        : await api.transitionOrder(order.id, nextState);

      setOrders((prev) => prev.map((o) => (o.id === order.id ? updated : o)));
      recordAudit('order.state.changed', `${order.orderNumber} -> ${updated.state}`);

      if (updated.state === order.state && updated.approvalRequestId) {
        notify(
          'info',
          `${order.orderNumber} is awaiting a second approver (request ${updated.approvalRequestId}).`,
        );
      } else if (updated.state === order.state && updated.paymentState === 'pending') {
        notify(
          'info',
          `${order.orderNumber} is awaiting Stripe payment confirmation before moving to ${nextState}.`,
        );
      } else {
        notify('success', `${order.orderNumber} transitioned to ${updated.state}.`);
      }
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Order transition failed');
    }
  };

  const handleConnectMailbox = async (provider: 'google' | 'microsoft') => {
    if (sandboxMode) {
      notify('info', `Sandbox: ${provider === 'google' ? 'Gmail' : 'Microsoft 365'} OAuth flow ready.`);
      return;
    }
    try {
      const res = await api.connectMailbox(provider);
      const safe = sanitizeServerRedirectUrl(res.authorizeUrl);
      if (!safe) throw new Error('Blocked unsafe mailbox OAuth redirect URL');
      window.location.assign(safe);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Mailbox connection failed');
    }
  };

  const handleStripeCheckout = async (order: OrderRecord) => {
    try {
      if (sandboxMode) {
        notify(
          'info',
          `Sandbox: Stripe Checkout session prepared for ${order.orderNumber} ($${(
            order.totalCents / 100
          ).toFixed(2)}).`,
        );
        return;
      }
      const res = await api.createOrderCheckout(order.id);
      const safe = sanitizeExternalUrl(res.checkoutUrl);
      if (!safe) throw new Error('Blocked unsafe Stripe Checkout URL');
      window.location.assign(safe);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Checkout failed');
    }
  };

  const handleApplyEmailStatus = async (eventId: string) => {
    const evt = orderEmails.find((e) => e.id === eventId);
    if (!evt || !evt.proposedState) return;
    const nextState = evt.proposedState;
    try {
      if (!sandboxMode) {
        await api.applyEmailStatus(eventId);
      }
      setOrderEmails((prev) =>
        prev.map((e) => (e.id === eventId ? { ...e, applied: true } : e)),
      );
      setOrders((prev) =>
        prev.map((o) =>
          o.orderNumber === evt.orderNumber
            ? { ...o, state: nextState, updatedAt: 'just now' }
            : o,
        ),
      );
      recordAudit('mail.status.applied', `${evt.orderNumber} -> ${nextState}`);
      notify('success', `Applied parsed email update to ${evt.orderNumber}.`);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to apply status');
    }
  };

  const handleSendCustomerUpdate = async (orderId: string) => {
    if (!statusNote.trim()) return;
    try {
      if (!sandboxMode) {
        await api.sendCustomerUpdate(orderId, statusNote.trim());
      }
      recordAudit('mail.customer.notified', orderId);
      setStatusNote('');
      notify('success', 'Branded order status update queued via connected mailbox.');
    } catch (err) {
      notify('error', err instanceof Error ? err.message : 'Failed to send update');
    }
  };

  const hasBoard = selectedBoardId !== '';
  const latestOrder = orders[0];

  return (
    <>
      <PageHead
        num="03"
        eyebrow="Orders"
        title="Purchasing, BOM & Encrypted Orders"
        sub="Live BOM stock and alternates, sanitized RFQ export, a KMS-encrypted order ledger, Stripe checkout and mailbox order tracking."
      >
        {hasBoard && (
          <>
            <select
              aria-label="BOM Board"
              className="select auto"
              value={selectedBoardId}
              onChange={(e) => setSelectedBoardId(e.target.value)}
            >
              {boards.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.name}
                </option>
              ))}
            </select>
            <label className="row tight nowrap">
              <span className="field-cap">Qty</span>
              <input
                aria-label="Build Quantity"
                className="input mono w-qty"
                type="number"
                min={1}
                value={buildQty}
                onChange={(e) => setBuildQty(Math.max(1, Number(e.target.value) || 1))}
              />
            </label>
            <button
              type="button"
              className="btn btn-primary"
              disabled={boardBom.length === 0}
              onClick={handleExportRfqCsv}
            >
              Export RFQ CSV
            </button>
          </>
        )}
      </PageHead>

      <div className="stats">
        <Stat label="BOM unit cost" value={usd(totalBomUnitUsd)} sub={`${boardBom.length} lines`} />
        <Stat
          label={`Extended · ${buildQty} pcs`}
          value={usd(totalBomUnitUsd * buildQty)}
          sub="parts only"
        />
        <Stat
          label="EOL / zero stock"
          value={eolCount}
          tone={eolCount > 0 ? 'bad' : 'plain'}
          sub={eolCount > 0 ? 'needs an alternate' : 'all lines sourceable'}
        />
        <Stat
          label="Orders"
          value={orders.length}
          sub={`${orders.filter((o) => o.state === 'pending_approval').length} pending approval`}
        />
      </div>

      <Panel
        title="Bill of materials"
        meta={hasBoard ? `${boardBom.length} lines · fab stock` : undefined}
      >
        {boardBom.length === 0 ? (
          <Empty
            title={hasBoard ? 'This board has no BOM lines yet' : 'No board to price yet'}
            icon="orders"
            actions={
              !hasBoard && (
                <button type="button" className="btn" onClick={() => navigate('codev')}>
                  Go to boards
                </button>
              )
            }
          >
            {hasBoard
              ? 'BOM lines are extracted when a board revision is pushed with its schematic.'
              : 'Once a board revision is pushed, its BOM appears here with live fab stock, pricing and drop-in alternates.'}
          </Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>RefDes</th>
                  <th>MPN</th>
                  <th>Lifecycle</th>
                  <th className="r">Qty</th>
                  <th className="r">Fab Stock</th>
                  <th className="r">Unit USD</th>
                  <th className="r">Alternates</th>
                </tr>
              </thead>
              <tbody>
                {boardBom.map((line) => (
                  <tr key={line.id} className={line.id === alternatesLineId ? 'sel' : ''}>
                    <td className="dim">{line.refdes.join(', ')}</td>
                    <td>
                      <strong className="cell-main">{line.mpn}</strong>
                      <div className="cell-sub">{line.manufacturer}</div>
                    </td>
                    <td>
                      <Status tone={LIFECYCLE_TONE[line.lifecycle]}>{line.lifecycle}</Status>
                    </td>
                    <td className="num r">{line.qtyPerBoard}</td>
                    <td className={`num r${line.fabStockQty === 0 ? ' c-bad' : ''}`}>
                      {line.fabStockQty.toLocaleString()}
                    </td>
                    <td className="num r">${line.unitPriceUsd.toFixed(2)}</td>
                    <td className="r">
                      {line.alternates.length > 0 && canWriteOrders ? (
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() =>
                            setAlternatesLineId(alternatesLineId === line.id ? null : line.id)
                          }
                        >
                          {line.alternates.length} Alternate(s)
                        </button>
                      ) : (
                        <span className="faint">{line.alternates.length} available</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeAltLine && (
          <div className="alt-drawer">
            <div className="between">
              <span className="panel-title">Alternates for {activeAltLine.mpn}</span>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setAlternatesLineId(null)}
              >
                Close
              </button>
            </div>
            {activeAltLine.alternates.map((alt) => (
              <div key={alt.mpn} className="between">
                <div className="grow">
                  <div>
                    <strong className="cell-main">{alt.mpn}</strong>{' '}
                    <span className="dim">
                      {alt.manufacturer} · ${alt.unitPriceUsd.toFixed(2)} · stock{' '}
                      {alt.fabStockQty.toLocaleString()}
                    </span>
                  </div>
                  <div className="cell-sub prose">{alt.notes}</div>
                </div>
                <button
                  type="button"
                  className="btn btn-success btn-sm"
                  onClick={() => void handleSwapAlternate(activeAltLine, alt.mpn)}
                >
                  Swap into BOM
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <div className="cols-2">
        <Panel title="Order ledger" meta="AES-256-GCM envelope">
          {orders.length === 0 ? (
            <Empty title="No orders yet" icon="key" variant="compact">
              Orders are stored envelope-encrypted under this tenant&apos;s data key. They are
              created when a board is sent to the fab from Backplane.
            </Empty>
          ) : (
            orders.map((order) => (
              <div key={order.id} className="item">
                <div className="item-head">
                  <strong className="cell-main">{order.orderNumber}</strong>
                  <Tag tone={ORDER_TONE[order.state]}>{humanize(order.state)}</Tag>
                </div>
                <div className="between">
                  <span className="trunc">
                    {order.boardName} <span className="faint">× {order.quantity}</span>
                  </span>
                  <span className="num nowrap">{usd(order.totalCents / 100)}</span>
                </div>
                <div className="item-meta break">
                  ref {order.fabReference} · DEK v{order.envelopeKeyVersion} · AAD{' '}
                  {order.aadBinding}
                  {order.trackingNumber ? ` · tracking ${order.trackingNumber}` : ''} · updated{' '}
                  {fmtTime(order.updatedAt)}
                </div>

                {(canWriteOrders || (canApproveOrders && order.state === 'pending_approval')) && (
                  <div className="row tight">
                    {canApproveOrders && order.state === 'pending_approval' && (
                      <button
                        type="button"
                        className="btn btn-success btn-sm"
                        onClick={() => void handleTransitionOrder(order, 'ordered')}
                      >
                        Approve &amp; Place PO
                      </button>
                    )}
                    {canWriteOrders && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => void handleStripeCheckout(order)}
                      >
                        Pay via Stripe Checkout
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </Panel>

        <Panel
          title="Order mail"
          meta={`${mailConnectors.length} mailbox${mailConnectors.length === 1 ? '' : 'es'}`}
          actions={
            canManageMail && (
              <>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void handleConnectMailbox('google')}
                >
                  Connect Gmail
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void handleConnectMailbox('microsoft')}
                >
                  Connect Outlook
                </button>
              </>
            )
          }
        >
          {mailConnectors.length > 0 && (
            <div className="panel-body row">
              {mailConnectors.map((mc) => (
                <Status key={mc.id} tone={mc.status === 'connected' ? 'ok' : 'warn'}>
                  {mc.provider === 'gmail' ? 'gmail' : 'm365'} · {mc.mailboxEmail}
                </Status>
              ))}
            </div>
          )}

          {orderEmails.length === 0 ? (
            <Empty title="No order mail parsed" icon="mail" variant="compact">
              {mailConnectors.length === 0
                ? 'Connect the mailbox your fab replies to. Confirmations and shipping notices are parsed into proposed order states for you to apply.'
                : 'Fab confirmations and shipping notices will appear here as proposed state changes.'}
            </Empty>
          ) : (
            orderEmails.map((evt) => (
              <div key={evt.id} className="item">
                <div className="item-head">
                  <strong className="cell-main">{evt.orderNumber}</strong>
                  <div className="row tight nowrap">
                    {evt.senderVerified !== undefined && (
                      <Status tone={evt.senderVerified ? 'ok' : 'warn'}>
                        {evt.senderVerified ? 'DMARC verified' : 'unverified sender'}
                      </Status>
                    )}
                  </div>
                </div>
                <div>{evt.subject}</div>
                <div className="dim prose">{evt.sanitizedPreview}</div>
                <div className="between">
                  <span className="item-meta trunc">
                    {evt.sender} · proposes {evt.proposedState ? humanize(evt.proposedState) : 'nothing'}{' '}
                    ({Math.round(evt.confidence * 100)}%)
                  </span>
                  {evt.applied ? (
                    <Status tone="ok">applied</Status>
                  ) : evt.proposedState && canManageMail ? (
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      onClick={() => void handleApplyEmailStatus(evt.id)}
                    >
                      Apply State Transition
                    </button>
                  ) : (
                    <Status tone="idle">no transition</Status>
                  )}
                </div>
              </div>
            ))
          )}

          {canManageMail && latestOrder && (
            <div className="panel-foot">
              <input
                className="input"
                aria-label="Customer status update"
                placeholder={`Status update for ${latestOrder.orderNumber}...`}
                value={statusNote}
                onChange={(e) => setStatusNote(e.target.value)}
              />
              <button
                type="button"
                className="btn btn-sm"
                disabled={!statusNote.trim()}
                onClick={() => void handleSendCustomerUpdate(latestOrder.id)}
              >
                Send Status Email
              </button>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
};
