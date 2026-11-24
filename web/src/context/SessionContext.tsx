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
import { canAccessTab, getDefaultTabForRole, hasPermission, normalizeRole } from '../lib/rbac';
import type {
  AdminSection,
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

const NAV_TABS: readonly NavTab[] = ['overview', 'codev', 'librarian', 'purchasing', 'admin'];
const ADMIN_SECTIONS: readonly AdminSection[] = [
  'llm',
  'sso',
  'vms',
  'gates',
  'bridges',
  'billing',
  'audit',
];

// A live tenant starts from nothing: synthetic demo records are only ever
// loaded by `enterSandboxAsRole`, never shown as if they were real data.
const EMPTY_LLM_POLICY: LlmPolicy = {
  providers: [],
  zdrRequired: false,
  allowExternalMcp: false,
  monthlyBudgetCents: null,
};
const EMPTY_KEY_INFO: KeyInfo = {
  activeVersion: 0,
  provider: 'local_kek',
  lastRotatedAt: '',
  wrappedDekFingerprint: '',
};
const EMPTY_BILLING: BillingSummary = {
  planName: '—',
  seatsActive: 0,
  seatsIncluded: 0,
  vmHoursThisCycle: 0,
  estimatedInvoiceUsd: 0,
  stripeCustomerLinked: false,
};

/** `#/admin/audit` -> { tab: 'admin', section: 'audit' } */
function parseHash(hash: string): { tab: NavTab | null; section: AdminSection | null } {
  const [rawTab, rawSection] = hash.replace(/^#\/?/, '').split('/');
  const tab = NAV_TABS.find((t) => t === rawTab) ?? null;
  const section = ADMIN_SECTIONS.find((sec) => sec === rawSection) ?? null;
  return { tab, section };
}

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
  adminSection: AdminSection;
  navigate: (tab: NavTab, section?: AdminSection) => void;
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
  const [adminSection, setAdminSection] = useState<AdminSection>('llm');
  const [toast, setToast] = useState<ToastMessage | null>(null);

  const [boards, setBoards] = useState<BoardProject[]>([]);
  const [parts, setParts] = useState<LibraryPart[]>([]);
  const [bomLines, setBomLines] = useState<BomLine[]>([]);
  const [orders, setOrders] = useState<OrderRecord[]>([]);
  const [mailConnectors, setMailConnectors] = useState<MailConnector[]>([]);
  const [orderEmails, setOrderEmails] = useState<OrderEmailEvent[]>([]);
  const [boatVms, setBoatVms] = useState<BoatVm[]>([]);
  const [llmPolicy, setLlmPolicy] = useState<LlmPolicy>(EMPTY_LLM_POLICY);
  const [approvalGates, setApprovalGates] = useState<ApprovalGate[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [keyInfo, setKeyInfo] = useState<KeyInfo>(EMPTY_KEY_INFO);
  const [billing, setBilling] = useState<BillingSummary>(EMPTY_BILLING);
  const [idps, setIdps] = useState<IdpConfig[]>([]);
  const [users, setUsers] = useState<OrgUser[]>([]);
  const [bridges, setBridges] = useState<BridgeConfig[]>([]);

  const notify = useCallback((kind: ToastMessage['kind'], text: string) => {
    setToast({ kind, text });
  }, []);

  const clearToast = useCallback(() => setToast(null), []);

  const navigate = useCallback(
    (tab: NavTab, section?: AdminSection) => {
      if (!canAccessTab(principal, tab)) return;
      setActiveTabState(tab);
      if (tab === 'admin' && section) setAdminSection(section);
    },
    [principal],
  );

  const setActiveTab = useCallback((tab: NavTab) => navigate(tab), [navigate]);

  // Keep the place across reloads and make back/forward work: `#/tab[/section]`.
  useEffect(() => {
    if (!principal || typeof window === 'undefined') return;
    const next = activeTab === 'admin' ? `#/admin/${adminSection}` : `#/${activeTab}`;
    if (window.location.hash !== next) {
      window.history.replaceState(null, '', next);
    }
  }, [principal, activeTab, adminSection]);

  useEffect(() => {
    if (!principal || typeof window === 'undefined') return;
    const onHashChange = () => {
      const { tab, section } = parseHash(window.location.hash);
      if (tab && canAccessTab(principal, tab)) {
        setActiveTabState(tab);
        if (tab === 'admin' && section) setAdminSection(section);
      }
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, [principal]);

  const applyStores = useCallback((seed: 'sandbox' | 'empty') => {
    const demo = seed === 'sandbox';
    setBoards(demo ? INITIAL_BOARDS : []);
    setParts(demo ? INITIAL_PARTS : []);
    setBomLines(demo ? INITIAL_BOM_LINES : []);
    setOrders(demo ? INITIAL_ORDERS : []);
    setMailConnectors(demo ? INITIAL_MAIL_CONNECTORS : []);
    setOrderEmails(demo ? INITIAL_ORDER_EMAILS : []);
    setBoatVms(demo ? INITIAL_BOAT_VMS : []);
    setLlmPolicy(demo ? INITIAL_LLM_POLICY : EMPTY_LLM_POLICY);
    setApprovalGates(demo ? INITIAL_APPROVAL_GATES : []);
    setPendingApprovals(demo ? INITIAL_PENDING_APPROVALS : []);
    setAuditLogs(demo ? INITIAL_AUDIT_LOGS : []);
    setKeyInfo(demo ? INITIAL_KEY_INFO : EMPTY_KEY_INFO);
    setBilling(demo ? INITIAL_BILLING : EMPTY_BILLING);
    setIdps(demo ? INITIAL_IDPS : []);
    setUsers(demo ? INITIAL_USERS : []);
    setBridges(demo ? INITIAL_BRIDGES : []);
  }, []);

  const recordAudit = useCallback(
    (action: string, target: string) => {
      if (!sandboxMode) {
        // Live: the server writes the hash-chained entry. Re-read it instead of
        // fabricating a local row that the chain would not contain.
        if (hasPermission(principal, 'AuditRead')) {
          api
            .listAuditLogs()
            .then(setAuditLogs)
            .catch(() => undefined);
        }
        return;
      }
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
    [principal, sandboxMode],
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
        const fromHash = typeof window === 'undefined' ? null : parseHash(window.location.hash);
        if (fromHash?.tab && canAccessTab(normalized, fromHash.tab)) {
          setActiveTabState(fromHash.tab);
          if (fromHash.section) setAdminSection(fromHash.section);
        } else {
          setActiveTabState('overview');
        }
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
    // Seed once; switching preview role keeps edits made in the sandbox.
    if (!sandboxMode) applyStores('sandbox');
    setPrincipal(nextPrincipal);
    setSandboxMode(true);
    setActiveTabState(getDefaultTabForRole(role));
    setAdminSection('llm');
    setToast({
      kind: 'info',
      text: `Sandbox preview active as ${nextPrincipal.displayName} (${role}). No backend mutations sent.`,
    });
  }, [applyStores, sandboxMode]);

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
    applyStores('empty');
    if (typeof window !== 'undefined' && window.location.hash) {
      window.history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  }, [applyStores, sandboxMode]);

  return (
    <SessionContext.Provider
      value={{
        principal,
        loading,
        sandboxMode,
        activeTab,
        setActiveTab,
        adminSection,
        navigate,
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
