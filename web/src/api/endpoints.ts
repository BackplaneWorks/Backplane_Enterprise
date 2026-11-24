import { apiRequest } from './client';
import type {
  ApprovalGate,
  ApprovalGatesResponse,
  AuditEntry,
  AuthProviderOption,
  BillingSummary,
  BoardProject,
  BoatVm,
  BomLine,
  BridgeConfig,
  BridgeDeliverySummary,
  CreateBridgeRequest,
  CreateBridgeResponse,
  EcoRecord,
  IdpConfig,
  IdpProviderKind,
  KeyInfo,
  LibraryPart,
  LlmPolicy,
  MailConnector,
  OrderEmailEvent,
  OrderRecord,
  OrderState,
  OrgUser,
  PartLifecycle,
  PendingApproval,
  PinComment,
  Principal,
  Role,
  RotateBridgeSecretResponse,
} from '../types/domain';

export interface StartOAuthResponse {
  authorizeUrl: string;
}

export interface CreateTokenResponse {
  tokenId?: string;
  token: string;
  tokenPrefix: string;
  expiresAt: string;
}

export interface HttpLibTokenSummary {
  id: string;
  label: string;
  tokenPrefix: string;
  userId: string;
  createdAt: string;
  expiresAt?: string | null;
  revokedAt?: string | null;
}

export interface CheckoutSessionResponse {
  checkoutUrl: string;
}

export const api = {
  // Auth & Me
  getMe: () => apiRequest<Principal>('/v1/me'),
  listAuthProviders: (orgSlug: string) =>
    apiRequest<AuthProviderOption[]>(
      `/v1/auth/providers?org=${encodeURIComponent(orgSlug)}`,
    ),
  startOAuth: (payload: {
    orgSlug: string;
    provider?: IdpProviderKind;
    idpId?: string;
    returnTo?: string;
  }) =>
    apiRequest<StartOAuthResponse>('/v1/auth/oauth/start', {
      method: 'POST',
      body: payload,
    }),
  logout: () => apiRequest<void>('/v1/auth/logout', { method: 'POST' }),

  // Co-Development (Boards, Pin Comments, ECOs)
  listBoards: () => apiRequest<BoardProject[]>('/v1/boards'),
  addPinComment: (
    boardId: string,
    payload: Omit<PinComment, 'id' | 'boardId' | 'authorEmail' | 'resolved' | 'createdAt'>,
  ) =>
    apiRequest<PinComment>(`/v1/boards/${encodeURIComponent(boardId)}/comments`, {
      method: 'POST',
      body: payload,
    }),
  resolvePinComment: (boardId: string, commentId: string) =>
    apiRequest<PinComment>(
      `/v1/boards/${encodeURIComponent(boardId)}/comments/${encodeURIComponent(commentId)}/resolve`,
      { method: 'POST' },
    ),
  reopenPinComment: (boardId: string, commentId: string) =>
    apiRequest<PinComment>(
      `/v1/boards/${encodeURIComponent(boardId)}/comments/${encodeURIComponent(commentId)}/reopen`,
      { method: 'POST' },
    ),
  createEco: (boardId: string, payload: { title: string; rationale: string }) =>
    apiRequest<EcoRecord>(`/v1/boards/${encodeURIComponent(boardId)}/ecos`, {
      method: 'POST',
      body: payload,
    }),
  transitionEco: (boardId: string, ecoId: string, status: EcoRecord['status']) =>
    apiRequest<EcoRecord>(
      `/v1/boards/${encodeURIComponent(boardId)}/ecos/${encodeURIComponent(ecoId)}/transition`,
      { method: 'POST', body: { status } },
    ),

  // Web Librarian & Private KiCad HTTP Library
  listParts: (query?: string) =>
    apiRequest<LibraryPart[]>(
      query ? `/v1/librarian/parts?q=${encodeURIComponent(query)}` : '/v1/librarian/parts',
    ),
  createPart: (
    payload: Omit<LibraryPart, 'id' | 'whereUsed' | 'updatedAt'>,
  ) =>
    apiRequest<LibraryPart>('/v1/librarian/parts', {
      method: 'POST',
      body: payload,
    }),
  updatePartLifecycle: (partId: string, lifecycle: PartLifecycle) =>
    apiRequest<LibraryPart>(
      `/v1/librarian/parts/${encodeURIComponent(partId)}/lifecycle`,
      {
        method: 'POST',
        body: { lifecycle },
      },
    ),
  mintHttpLibToken: (tenantSlug: string, label: string) =>
    apiRequest<CreateTokenResponse>(
      `/v1/httplib/${encodeURIComponent(tenantSlug)}/tokens`,
      {
        method: 'POST',
        body: { label },
      },
    ),
  listHttpLibTokens: (tenantSlug: string) =>
    apiRequest<HttpLibTokenSummary[]>(
      `/v1/httplib/${encodeURIComponent(tenantSlug)}/tokens`,
    ),
  revokeHttpLibToken: (tenantSlug: string, tokenId: string) =>
    apiRequest<void>(
      `/v1/httplib/${encodeURIComponent(tenantSlug)}/tokens/${encodeURIComponent(tokenId)}`,
      { method: 'DELETE' },
    ),

  // Purchasing, BOM, Encrypted Orders & Mail
  listBom: (boardId: string) =>
    apiRequest<BomLine[]>(`/v1/orders/bom/${encodeURIComponent(boardId)}`),
  swapBomAlternate: (bomLineId: string, mpn: string) =>
    apiRequest<BomLine>(`/v1/orders/bom/lines/${encodeURIComponent(bomLineId)}/swap`, {
      method: 'POST',
      body: { mpn },
    }),
  listOrders: () => apiRequest<OrderRecord[]>('/v1/orders'),
  transitionOrder: (orderId: string, state: OrderState) =>
    apiRequest<OrderRecord>(`/v1/orders/${encodeURIComponent(orderId)}/transition`, {
      method: 'POST',
      body: { state },
    }),
  createOrderCheckout: (orderId: string) =>
    apiRequest<CheckoutSessionResponse>(
      `/v1/billing/orders/${encodeURIComponent(orderId)}/checkout`,
      { method: 'POST' },
    ),
  listMailConnectors: () => apiRequest<MailConnector[]>('/v1/mail/connectors'),
  connectMailbox: (provider: 'google' | 'microsoft') =>
    apiRequest<StartOAuthResponse>(`/v1/mail/connect/${provider}`, { method: 'POST' }),
  listOrderEmails: () => apiRequest<OrderEmailEvent[]>('/v1/mail/events'),
  applyEmailStatus: (eventId: string) =>
    apiRequest<OrderRecord>(`/v1/mail/events/${encodeURIComponent(eventId)}/apply`, {
      method: 'POST',
    }),
  sendCustomerUpdate: (orderId: string, message: string) =>
    apiRequest<void>(`/v1/mail/orders/${encodeURIComponent(orderId)}/notify`, {
      method: 'POST',
      body: { message },
    }),

  // Boat VMs (Zero-Tailscale Relay)
  listBoatVms: () => apiRequest<BoatVm[]>('/v1/vms'),
  wakeBoatVm: (vmId: string) =>
    apiRequest<BoatVm>(`/v1/vms/${encodeURIComponent(vmId)}/wake`, { method: 'POST' }),
  stopBoatVm: (vmId: string) =>
    apiRequest<BoatVm>(`/v1/vms/${encodeURIComponent(vmId)}/stop`, { method: 'POST' }),

  // Admin Governance, Audit, KMS & Stripe Billing
  listUsers: () => apiRequest<OrgUser[]>('/v1/admin/users'),
  updateUserRole: (userId: string, role: Role) =>
    apiRequest<OrgUser>(`/v1/admin/users/${encodeURIComponent(userId)}/role`, {
      method: 'PATCH',
      body: { role },
    }),
  listIdps: () => apiRequest<IdpConfig[]>('/v1/admin/idp'),
  getLlmPolicy: () => apiRequest<LlmPolicy>('/v1/admin/llm-policy'),
  updateLlmPolicy: (policy: LlmPolicy) =>
    apiRequest<LlmPolicy>('/v1/admin/llm-policy', {
      method: 'PUT',
      body: policy,
    }),
  listApprovalGates: () => apiRequest<ApprovalGatesResponse>('/v1/admin/approval-gates'),
  toggleApprovalGate: (gateId: string, enabled: boolean) =>
    apiRequest<ApprovalGate>(`/v1/admin/approval-gates/${encodeURIComponent(gateId)}`, {
      method: 'PATCH',
      body: { enabled },
    }),
  listPendingApprovals: () => apiRequest<PendingApproval[]>('/v1/admin/approvals'),
  decideApproval: (
    approvalId: string,
    decision: 'approved' | 'rejected',
    reason?: string,
  ) =>
    apiRequest<PendingApproval>(
      `/v1/admin/approvals/${encodeURIComponent(approvalId)}/decide`,
      {
        method: 'POST',
        body: reason ? { decision, reason } : { decision },
      },
    ),
  listAuditLogs: () => apiRequest<AuditEntry[]>('/v1/admin/audit'),
  verifyAuditChain: () =>
    apiRequest<{ valid: boolean; count?: number }>('/v1/admin/audit/verify'),
  getKeyInfo: () => apiRequest<KeyInfo>('/v1/admin/keys'),
  rotateTenantDek: () => apiRequest<KeyInfo>('/v1/admin/keys/rotate', { method: 'POST' }),
  getBillingSummary: () => apiRequest<BillingSummary>('/v1/billing/summary'),
  openBillingPortal: () =>
    apiRequest<CheckoutSessionResponse>('/v1/billing/portal', { method: 'POST' }),

  // External Bridges & Comms (Slack, Teams, Discord, Dots/Grok Webhook, A2A Peer)
  listBridges: () => apiRequest<BridgeConfig[]>('/v1/bridges'),
  createBridge: (payload: CreateBridgeRequest) =>
    apiRequest<CreateBridgeResponse>('/v1/bridges', {
      method: 'POST',
      body: payload,
    }),
  updateBridge: (
    bridgeId: string,
    payload: Partial<
      Pick<
        BridgeConfig,
        'name' | 'enabled' | 'direction' | 'targetUrl' | 'subscribedEvents' | 'rateLimitRpm' | 'peerEnabled' | 'peerScopes'
      >
    >,
  ) =>
    apiRequest<BridgeConfig>(`/v1/bridges/${encodeURIComponent(bridgeId)}`, {
      method: 'PATCH',
      body: payload,
    }),
  deleteBridge: (bridgeId: string) =>
    apiRequest<void>(`/v1/bridges/${encodeURIComponent(bridgeId)}`, { method: 'DELETE' }),
  rotateBridgeSecret: (bridgeId: string) =>
    apiRequest<RotateBridgeSecretResponse>(
      `/v1/bridges/${encodeURIComponent(bridgeId)}/rotate-secret`,
      { method: 'POST' },
    ),
  testBridge: (bridgeId: string) =>
    apiRequest<BridgeDeliverySummary>(`/v1/bridges/${encodeURIComponent(bridgeId)}/test`, {
      method: 'POST',
    }),
  listBridgeDeliveries: (bridgeId: string) =>
    apiRequest<BridgeDeliverySummary[]>(`/v1/bridges/${encodeURIComponent(bridgeId)}/deliveries`),
};
