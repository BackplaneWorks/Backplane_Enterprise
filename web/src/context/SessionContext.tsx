import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api } from '../api/endpoints';
import {
  INITIAL_APPROVAL_GATES,
  INITIAL_AUDIT_LOGS,
  INITIAL_BILLING,
  INITIAL_BOARDS,
  INITIAL_BOAT_VMS,
  INITIAL_BOM_LINES,
  INITIAL_BRIDGES,
  INITIAL_IDPS,
  INITIAL_KEY_INFO,
  INITIAL_LLM_POLICY,
  INITIAL_MAIL_CONNECTORS,
  INITIAL_ORDERS,
  INITIAL_ORDER_EMAILS,
  INITIAL_PARTS,
  INITIAL_PENDING_APPROVALS,
  INITIAL_USERS,
  buildSandboxPrincipal,
} from '../data/sandboxData';
import { isSandboxEnabled } from '../lib/env';
import { canAccessTab, getDefaultTabForRole, normalizeRole } from '../lib/rbac';
import type {
  ApprovalGate,
  AuditEntry,
  BillingSummary,
  BoardProject,
  BoatVm,
  BomLine,
  BridgeConfig,
  IdpConfig,
  KeyInfo,
  LibraryPart,
  LlmPolicy,
  MailConnector,
  NavTab,
  OrderEmailEvent,
  OrderRecord,
  OrgUser,
  PendingApproval,
  Principal,
  Role,
} from '../types/domain';

export interface ToastMessage {
  kind: 'info' | 'success' | 'error';
  text: string;
}

interface SessionContextValue {
  principal: Principal | null;
  loading: boolean;
  sandboxMode: boolean;
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  toast: ToastMessage | null;
  notify: (kind: ToastMessage['kind'], text: string) => void;
  clearToast: () => void;
  enterSandboxAsRole: (role: Role) => void;
  signOut: () => Promise<void>;
  refreshAll: () => Promise<void>;

  // Shared domain stores (synced with API when live, mutated in-memory in sandbox)
  boards: BoardProject[];
  setBoards: React.Dispatch<React.SetStateAction<BoardProject[]>>;
  parts: LibraryPart[];
  setParts: React.Dispatch<React.SetStateAction<LibraryPart[]>>;
  bomLines: BomLine[];
  setBomLines: React.Dispatch<React.SetStateAction<BomLine[]>>;
  orders: OrderRecord[];
  setOrders: React.Dispatch<React.SetStateAction<OrderRecord[]>>;
  mailConnectors: MailConnector[];
  orderEmails: OrderEmailEvent[];
  setOrderEmails: React.Dispatch<React.SetStateAction<OrderEmailEvent[]>>;
  boatVms: BoatVm[];
  setBoatVms: React.Dispatch<React.SetStateAction<BoatVm[]>>;
  llmPolicy: LlmPolicy;
  setLlmPolicy: React.Dispatch<React.SetStateAction<LlmPolicy>>;
  approvalGates: ApprovalGate[];
  setApprovalGates: React.Dispatch<React.SetStateAction<ApprovalGate[]>>;
  pendingApprovals: PendingApproval[];
  setPendingApprovals: React.Dispatch<React.SetStateAction<PendingApproval[]>>;
  auditLogs: AuditEntry[];
  setAuditLogs: React.Dispatch<React.SetStateAction<AuditEntry[]>>;
  keyInfo: KeyInfo;
  setKeyInfo: React.Dispatch<React.SetStateAction<KeyInfo>>;
  billing: BillingSummary;
  idps: IdpConfig[];
  users: OrgUser[];
  setUsers: React.Dispatch<React.SetStateAction<OrgUser[]>>;
  bridges: BridgeConfig[];
  setBridges: React.Dispatch<React.SetStateAction<BridgeConfig[]>>;
  recordAudit: (action: string, target: string) => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export const SessionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [loading, setLoading] = useState(true);
  const [sandboxMode, setSandboxMode] = useState(false);
  const [activeTab, setActiveTabState] = useState<NavTab>('codev');
  const [toast, setToast] = useState<ToastMessage | null>(null);

  const [boards, setBoards] = useState<BoardProject[]>(INITIAL_BOARDS);
  const [parts, setParts] = useState<LibraryPart[]>(INITIAL_PARTS);
  const [bomLines, setBomLines] = useState<BomLine[]>(INITIAL_BOM_LINES);
  const [orders, setOrders] = useState<OrderRecord[]>(INITIAL_ORDERS);
  const [mailConnectors, setMailConnectors] = useState<MailConnector[]>(INITIAL_MAIL_CONNECTORS);
  const [orderEmails, setOrderEmails] = useState<OrderEmailEvent[]>(INITIAL_ORDER_EMAILS);
  const [boatVms, setBoatVms] = useState<BoatVm[]>(INITIAL_BOAT_VMS);
  const [llmPolicy, setLlmPolicy] = useState<LlmPolicy>(INITIAL_LLM_POLICY);
  const [approvalGates, setApprovalGates] = useState<ApprovalGate[]>(INITIAL_APPROVAL_GATES);
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>(
    INITIAL_PENDING_APPROVALS,
  );
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>(INITIAL_AUDIT_LOGS);
  const [keyInfo, setKeyInfo] = useState<KeyInfo>(INITIAL_KEY_INFO);
  const [billing, setBilling] = useState<BillingSummary>(INITIAL_BILLING);
  const [idps, setIdps] = useState<IdpConfig[]>(INITIAL_IDPS);
  const [users, setUsers] = useState<OrgUser[]>(INITIAL_USERS);
  const [bridges, setBridges] = useState<BridgeConfig[]>(INITIAL_BRIDGES);

  const notify = useCallback((kind: ToastMessage['kind'], text: string) => {
    setToast({ kind, text });
  }, []);

  const clearToast = useCallback(() => setToast(null), []);

  const setActiveTab = useCallback(
    (tab: NavTab) => {
      if (canAccessTab(principal, tab)) {
        setActiveTabState(tab);
      }
    },
    [principal],
  );

  const recordAudit = useCallback(
    (action: string, target: string) => {
      setAuditLogs((prev) => {
        const top = prev[0];
        const nextSeq = top ? top.seq + 1 : 1;
        const prevHash = top ? top.entryHash : '00000000...0000';
        const pseudoHash = `${nextSeq.toString(16).padStart(4, '0')}c9e1...${action
          .slice(0, 4)
          .replace(/[^a-z0-9]/gi, 'f')}`;
        const entry: AuditEntry = {
          seq: nextSeq,
          timestamp: new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
          actorEmail: principal?.email ?? 'system@aeroworks.example',
          action,
          target,
          prevHash,
          entryHash: pseudoHash,
        };
        return [entry, ...prev];
      });
    },
    [principal?.email],
  );

  const loadLiveResources = useCallback(async (me: Principal) => {
    const [boardsRes, partsRes, ordersRes, vmsRes] = await Promise.allSettled([
      api.listBoards(),
      api.listParts(),
      api.listOrders(),
      api.listBoatVms(),
    ]);
    if (boardsRes.status === 'fulfilled') setBoards(boardsRes.value);
    if (partsRes.status === 'fulfilled') setParts(partsRes.value);
    if (ordersRes.status === 'fulfilled') setOrders(ordersRes.value);
    if (vmsRes.status === 'fulfilled') setBoatVms(vmsRes.value);

    if (me.role === 'org_admin') {
      const [uRes, iRes, lRes, gRes, aRes, audRes, kRes, bRes, brRes] = await Promise.allSettled([
        api.listUsers(),
        api.listIdps(),
        api.getLlmPolicy(),
        api.listApprovalGates(),
        api.listPendingApprovals(),
        api.listAuditLogs(),
        api.getKeyInfo(),
        api.getBillingSummary(),
        api.listBridges(),
      ]);
      if (uRes.status === 'fulfilled') setUsers(uRes.value);
      if (iRes.status === 'fulfilled') setIdps(iRes.value);
      if (lRes.status === 'fulfilled') setLlmPolicy(lRes.value);
      if (gRes.status === 'fulfilled') setApprovalGates(gRes.value.gates);
      if (aRes.status === 'fulfilled') setPendingApprovals(aRes.value);
      if (audRes.status === 'fulfilled') setAuditLogs(audRes.value);
      if (kRes.status === 'fulfilled') setKeyInfo(kRes.value);
      if (bRes.status === 'fulfilled') setBilling(bRes.value);
      if (brRes.status === 'fulfilled') setBridges(brRes.value);
    }

    if (me.role === 'org_admin' || me.role === 'purchasing') {
      const [mcRes, meRes] = await Promise.allSettled([
        api.listMailConnectors(),
        api.listOrderEmails(),
      ]);
      if (mcRes.status === 'fulfilled') setMailConnectors(mcRes.value);
      if (meRes.status === 'fulfilled') setOrderEmails(meRes.value);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    if (sandboxMode || !principal) return;
    await loadLiveResources(principal);
  }, [loadLiveResources, principal, sandboxMode]);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const me = await api.getMe();
        if (!active) return;
        const normalized: Principal = {
          ...me,
          role: normalizeRole(me.role),
        };
        setPrincipal(normalized);
        setSandboxMode(false);
        setActiveTabState(getDefaultTabForRole(normalized.role));
        await loadLiveResources(normalized);
      } catch {
        if (!active) return;
        setPrincipal(null);
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [loadLiveResources]);

  const enterSandboxAsRole = useCallback((role: Role) => {
    if (!isSandboxEnabled()) return;
    const nextPrincipal = buildSandboxPrincipal(role);
    setPrincipal(nextPrincipal);
    setSandboxMode(true);
    setActiveTabState(getDefaultTabForRole(role));
    setToast({
      kind: 'info',
      text: `Sandbox preview active as ${nextPrincipal.displayName} (${role}). No backend mutations sent.`,
    });
  }, []);

  const signOut = useCallback(async () => {
    if (!sandboxMode) {
      try {
        await api.logout();
      } catch {
        // clear client session regardless
      }
    }
    setPrincipal(null);
    setSandboxMode(false);
    setToast(null);
  }, [sandboxMode]);

  return (
    <SessionContext.Provider
      value={{
        principal,
        loading,
        sandboxMode,
        activeTab,
        setActiveTab,
        toast,
        notify,
        clearToast,
        enterSandboxAsRole,
        signOut,
        refreshAll,
        boards,
        setBoards,
        parts,
        setParts,
        bomLines,
        setBomLines,
        orders,
        setOrders,
        mailConnectors,
        orderEmails,
        setOrderEmails,
        boatVms,
        setBoatVms,
        llmPolicy,
        setLlmPolicy,
        approvalGates,
        setApprovalGates,
        pendingApprovals,
        setPendingApprovals,
        auditLogs,
        setAuditLogs,
        keyInfo,
        setKeyInfo,
        billing,
        idps,
        users,
        setUsers,
        bridges,
        setBridges,
        recordAudit,
      }}
    >
      {children}
    </SessionContext.Provider>
  );
};

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) {
    throw new Error('useSession must be used inside SessionProvider');
  }
  return ctx;
}
