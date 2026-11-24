import React, { useState } from 'react';
import { api } from '../api/endpoints';
import { useSession } from '../context/SessionContext';
import { hasPermission } from '../lib/rbac';
import { escapeCsvCell, sanitizeExternalUrl, sanitizeServerRedirectUrl } from '../lib/safeUrl';
import type { BomLine, OrderRecord, OrderState } from '../types/domain';

const ORDER_BADGE: Record<OrderState, string> = {
  draft: 'badge',
  quote_requested: 'badge-cyan',
  pending_approval: 'badge-amber',
  ordered: 'badge-blue',
  in_fabrication: 'badge-purple',
  shipped: 'badge-cyan',
  delivered: 'badge-green',
  on_hold: 'badge-red',
  cancelled: 'badge-red',
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
  } = useSession();

  const [selectedBoardId, setSelectedBoardId] = useState(boards[0]?.id ?? 'brd-fc-rev4');
  const [buildQty, setBuildQty] = useState(25);
  const [alternatesLineId, setAlternatesLineId] = useState<string | null>(null);
  const [statusNote, setStatusNote] = useState('');

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

  return (
    <div className="stack-md">
      <div className="page-header">
        <div>
          <h1 className="page-title">Purchasing, BOM &amp; Encrypted Orders</h1>
          <p className="page-subtitle">
            Live BOM stock &amp; alternates, sanitized RFQ export, KMS-encrypted order ledger,
            Stripe checkout, and Gmail/Microsoft 365 order tracking.
          </p>
        </div>

        <div className="row">
          <select
            aria-label="BOM Board"
            className="select"
            value={selectedBoardId}
            onChange={(e) => setSelectedBoardId(e.target.value)}
          >
            {boards.map((b) => (
              <option key={b.id} value={b.id}>
                {b.name}
              </option>
            ))}
          </select>
          <input
            aria-label="Build Quantity"
            className="input mono"
            type="number"
            min={1}
            value={buildQty}
            onChange={(e) => setBuildQty(Math.max(1, Number(e.target.value) || 1))}
          />
          <button type="button" className="btn btn-primary" onClick={handleExportRfqCsv}>
            Export RFQ CSV
          </button>
        </div>
      </div>

      <div className="grid-4">
        <div className="stat-card">
          <div className="stat-label">BOM Unit Cost</div>
          <div className="stat-value">${totalBomUnitUsd.toFixed(2)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Extended ({buildQty} pcs)</div>
          <div className="stat-value">${(totalBomUnitUsd * buildQty).toFixed(2)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">EOL / Zero-Stock Alerts</div>
          <div className="stat-value">{eolCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Encrypted Orders</div>
          <div className="stat-value">{orders.length}</div>
        </div>
      </div>

      <div className="card stack-md">
        <div className="card-header">
          <h3 className="card-title">Live BOM &amp; Supply Chain Readiness</h3>
          <span className="badge badge-cyan">Fab Stock Sync</span>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>RefDes</th>
                <th>MPN</th>
                <th>Lifecycle</th>
                <th>Fab Stock</th>
                <th>Unit USD</th>
                <th>Alternates</th>
              </tr>
            </thead>
            <tbody>
              {boardBom.map((line) => (
                <tr key={line.id}>
                  <td className="mono">{line.refdes.join(', ')}</td>
                  <td>
                    <strong>{line.mpn}</strong>
                    <div className="text-sm muted">{line.manufacturer}</div>
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        line.lifecycle === 'Obsolete'
                          ? 'badge-red'
                          : line.lifecycle === 'Released'
                            ? 'badge-green'
                            : 'badge-amber'
                      }`}
                    >
                      {line.lifecycle}
                    </span>
                  </td>
                  <td className="mono">{line.fabStockQty.toLocaleString()}</td>
                  <td className="mono">${line.unitPriceUsd.toFixed(2)}</td>
                  <td>
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
                      <span className="muted text-sm">{line.alternates.length} available</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {activeAltLine && (
          <div className="comment-card stack-sm">
            <div className="row-between">
              <strong>Alternates for {activeAltLine.mpn}</strong>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setAlternatesLineId(null)}
              >
                Close
              </button>
            </div>
            {activeAltLine.alternates.map((alt) => (
              <div key={alt.mpn} className="row-between">
                <div>
                  <strong className="mono">{alt.mpn}</strong> ({alt.manufacturer}) — $
                  {alt.unitPriceUsd.toFixed(2)} · Stock: {alt.fabStockQty.toLocaleString()}
                  <div className="text-sm muted">{alt.notes}</div>
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
      </div>

      <div className="split-pane-equal">
        <div className="card stack-md">
          <div className="card-header">
            <h3 className="card-title">KMS Envelope-Encrypted Orders</h3>
            <span className="badge badge-green">AES-256-GCM DEK</span>
          </div>

          {orders.map((order) => (
            <div key={order.id} className="comment-card stack-sm">
              <div className="row-between">
                <strong className="mono">{order.orderNumber}</strong>
                <span className={`badge ${ORDER_BADGE[order.state]}`}>{order.state}</span>
              </div>
              <div>{order.boardName}</div>
              <div className="row-between text-sm muted mono">
                <span>
                  Total: ${(order.totalCents / 100).toFixed(2)} · Ref: {order.fabReference}
                </span>
                <span>DEK v{order.envelopeKeyVersion}</span>
              </div>
              <div className="text-sm muted mono">AAD: {order.aadBinding}</div>
              {order.trackingNumber && (
                <div className="text-sm mono">Tracking: {order.trackingNumber}</div>
              )}

              <div className="row">
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
                    className="btn btn-primary btn-sm"
                    onClick={() => void handleStripeCheckout(order)}
                  >
                    Pay via Stripe Checkout
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>

        <div className="card stack-md">
          <div className="card-header">
            <h3 className="card-title">Gmail &amp; Outlook Order Ingestion</h3>
            <div className="row">
              {canManageMail && (
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
              )}
              <span className="badge badge-blue">{mailConnectors.length} Connected</span>
            </div>
          </div>

          <div className="row">
            {mailConnectors.map((mc) => (
              <span
                key={mc.id}
                className={`badge ${mc.status === 'connected' ? 'badge-green' : 'badge-amber'}`}
              >
                {mc.provider === 'gmail' ? 'Gmail' : 'M365'}: {mc.mailboxEmail}
              </span>
            ))}
          </div>

          {orderEmails.map((evt) => (
            <div key={evt.id} className="comment-card stack-sm">
              <div className="row-between text-sm">
                <strong className="mono">{evt.orderNumber}</strong>
                <div className="row">
                  {evt.senderVerified !== undefined && (
                    <span
                      className={`badge ${evt.senderVerified ? 'badge-green' : 'badge-amber'}`}
                    >
                      {evt.senderVerified ? 'DMARC Verified' : 'Unverified Sender'}
                    </span>
                  )}
                  <span className="badge badge-cyan">
                    Proposed: {evt.proposedState ?? 'none'} ({Math.round(evt.confidence * 100)}%)
                  </span>
                </div>
              </div>
              <div>{evt.subject}</div>
              <div className="text-sm muted">{evt.sanitizedPreview}</div>
              <div className="row-between">
                <span className="text-sm muted">From: {evt.sender}</span>
                {evt.applied ? (
                  <span className="badge badge-green">Applied</span>
                ) : evt.proposedState && canManageMail ? (
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    onClick={() => void handleApplyEmailStatus(evt.id)}
                  >
                    Apply State Transition
                  </button>
                ) : (
                  <span className="badge">No Transition</span>
                )}
              </div>
            </div>
          ))}

          {canManageMail && orders[0] && (
            <div className="row">
              <input
                className="input"
                placeholder="Send customer status update for latest order..."
                value={statusNote}
                onChange={(e) => setStatusNote(e.target.value)}
              />
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => void handleSendCustomerUpdate(orders[0].id)}
              >
                Send Status Email
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
