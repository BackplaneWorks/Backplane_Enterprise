export type Role =
  | 'org_admin'
  | 'engineer'
  | 'librarian'
  | 'purchasing'
  | 'external_reviewer';

export type Permission =
  | 'PartsRead'
  | 'PartsWrite'
  | 'PartsRelease'
  | 'OrdersRead'
  | 'OrdersWrite'
  | 'OrdersApprove'
  | 'MailManage'
  | 'BillingManage'
  | 'BoardsRead'
  | 'BoardsComment'
  | 'BoardsWrite'
  | 'VmUse'
  | 'VmManage'
  | 'LlmUse'
  | 'AdminManage'
  | 'AuditRead';

export type NavTab = 'codev' | 'librarian' | 'purchasing' | 'admin';

export interface Principal {
  tenantId: string;
  tenantSlug: string;
  tenantName: string;
  userId: string;
  email: string;
  displayName: string;
  role: Role;
  authKind: 'session' | 'user_token' | 'device_token';
  scopes: string[];
  permissions?: string[];
  assignedVmId?: string;
}

export interface BoardComponentRef {
  refdes: string;
  mpn: string;
  xMm: number;
  yMm: number;
  widthMm: number;
  heightMm: number;
  layer: 'F.Cu' | 'B.Cu';
  packageName: string;
}

export interface BoardRevision {
  id: string;
  tag: string;
  commitSha: string;
  author: string;
  createdAt: string;
  summary: string;
}

export interface PinComment {
  id: string;
  boardId: string;
  revisionId: string;
  layer: string;
  xMm: number;
  yMm: number;
  refdes?: string;
  authorEmail: string;
  body: string;
  resolved: boolean;
  createdAt: string;
}

export interface BoardDiffEntry {
  kind: 'added' | 'removed' | 'changed';
  scope: 'BOM' | 'Schematic' | 'PCB';
  target: string;
  detail: string;
}

export type EcoStatus = 'draft' | 'in_review' | 'approved' | 'implemented';

export interface EcoRecord {
  id: string;
  code: string;
  title: string;
  rationale: string;
  status: EcoStatus;
  createdBy: string;
  createdAt: string;
}

export interface BoardProject {
  id: string;
  name: string;
  slug: string;
  widthMm: number;
  heightMm: number;
  layerCount: number;
  revisions: BoardRevision[];
  components: BoardComponentRef[];
  comments: PinComment[];
  diffs: BoardDiffEntry[];
  ecos: EcoRecord[];
}

export type PartLifecycle = 'Draft' | 'In Review' | 'Released' | 'Obsolete';

export type IpcPackageFamily = 'SOIC' | 'QFN' | 'LQFP' | 'CHIP' | 'BGA';

export interface Ipc7351Spec {
  family: IpcPackageFamily;
  pinCount: number;
  pitchMm: number;
  bodyWidthMm: number;
  bodyLengthMm: number;
  padWidthMm: number;
  padLengthMm: number;
  thermalPadMm?: number;
}

export interface WhereUsedEntry {
  boardId: string;
  boardName: string;
  revisionTag: string;
  refdesList: string[];
}

export interface LibraryPart {
  id: string;
  partNumber: string;
  mpn: string;
  manufacturer: string;
  category: string;
  value: string;
  packageName: string;
  lifecycle: PartLifecycle;
  preferredByFab: boolean;
  fabStockQty: number;
  unitPriceUsd: number;
  datasheetUrl: string;
  description: string;
  attributes: Record<string, string>;
  ipcSpec: Ipc7351Spec;
  whereUsed: WhereUsedEntry[];
  updatedAt: string;
}

export interface PartAlternate {
  mpn: string;
  manufacturer: string;
  unitPriceUsd: number;
  fabStockQty: number;
  dropInCompatible: boolean;
  notes: string;
}

export interface BomLine {
  id: string;
  boardId: string;
  refdes: string[];
  qtyPerBoard: number;
  mpn: string;
  manufacturer: string;
  description: string;
  lifecycle: PartLifecycle;
  unitPriceUsd: number;
  fabStockQty: number;
  alternates: PartAlternate[];
}

export type OrderState =
  | 'draft'
  | 'quote_requested'
  | 'pending_approval'
  | 'ordered'
  | 'in_fabrication'
  | 'shipped'
  | 'delivered'
  | 'on_hold'
  | 'cancelled';

export interface OrderRecord {
  id: string;
  orderNumber: string;
  boardName: string;
  quantity: number;
  totalCents: number;
  state: OrderState;
  fabReference: string;
  trackingNumber?: string;
  envelopeKeyVersion: number;
  aadBinding: string;
  approvalRequired: boolean;
  approvalRequestId?: string | null;
  paymentState?: string | null;
  updatedAt: string;
}

export interface MailConnector {
  id: string;
  provider: 'gmail' | 'microsoft_graph';
  mailboxEmail: string;
  status: 'connected' | 'disconnected';
  lastSyncedAt: string | null;
}

export interface OrderEmailEvent {
  id: string;
  orderNumber: string;
  provider: 'gmail' | 'microsoft_graph';
  sender: string;
  subject: string;
  sanitizedPreview: string;
  proposedState: OrderState | null;
  senderVerified?: boolean;
  confidence: number;
  applied: boolean;
  receivedAt: string;
}

export interface BoatVm {
  id: string;
  name: string;
  assignedUserEmail: string;
  region: string;
  kicadVersion: string;
  tunnelState: 'connected_mtls' | 'stopped' | 'waking';
  certExpiresAt: string;
  idleMinutes: number;
  meteredHoursMonth: number;
}

export interface LlmProviderPolicy {
  provider: string;
  models: string[];
  zdr: boolean;
  baseUrl?: string | null;
}

export interface LlmPolicy {
  providers: LlmProviderPolicy[];
  zdrRequired: boolean;
  allowExternalMcp: boolean;
  monthlyBudgetCents: number | null;
}

export type ApprovalGateKind =
  | 'place_order'
  | 'modify_released_part'
  | 'modify_released_board'
  | 'enable_external_mcp'
  | 'spend_over_budget';

export interface ApprovalGate {
  id: string;
  kind: ApprovalGateKind;
  description: string;
  enabled: boolean;
  thresholdCents?: number | null;
  approvers?: string[];
  agentsOnly?: boolean;
}

export interface ApprovalGatesResponse {
  gates: ApprovalGate[];
  allowSelfApproval: boolean;
  ttlHours: number;
}

export interface PendingApproval {
  id: string;
  gateKind: ApprovalGateKind;
  subject?: string;
  summary: string | Record<string, unknown>;
  status: 'pending' | 'approved' | 'rejected';
  requestedByEmail: string;
  requestedVia?: string;
  canDecide?: boolean;
  createdAt: string;
  expiresAt?: string;
}

export interface AuditEntry {
  seq: number;
  timestamp: string;
  actorKind?: string;
  actor?: string;
  actorEmail: string;
  action: string;
  target: string;
  details?: unknown;
  prevHash: string;
  entryHash: string;
}

export interface KeyInfo {
  activeVersion: number;
  provider: 'aws_kms' | 'local_kek';
  kekId?: string;
  lastRotatedAt: string;
  wrappedDekFingerprint: string;
  versions?: number[];
}

export interface BillingSummary {
  planName: string;
  seatsActive: number;
  seatsIncluded: number;
  vmHoursThisCycle: number;
  estimatedInvoiceUsd: number;
  stripeCustomerLinked: boolean;
}

export type IdpProviderKind = 'google' | 'microsoft' | 'oidc' | 'saml';

export interface AuthProviderOption {
  id: string;
  provider: IdpProviderKind;
  displayName: string;
}

export interface IdpConfig {
  id: string;
  provider: IdpProviderKind;
  domain: string;
  displayName?: string;
  enabled: boolean;
  enforcedSso: boolean;
}

export interface OrgUser {
  id: string;
  email: string;
  displayName: string;
  role: Role;
  status: 'active' | 'invited' | 'suspended';
  lastLoginAt: string;
}

export type BridgeKind = 'webhook' | 'slack' | 'teams' | 'discord' | 'a2a';

export type BridgeDirection = 'inbound' | 'outbound' | 'bidirectional';

export type BridgeEventKind =
  | 'room.post'
  | 'bot.reply'
  | 'ask.opened'
  | 'order.status_changed'
  | 'release.published';

export type ExternalPeerScope = 'boards:read' | 'boards:comment';

export interface BridgeAdapterConfig {
  slackChannel?: string;
  discordPublicKeyHex?: string;
  discordApplicationId?: string;
  teamsAppId?: string;
  teamsServiceUrl?: string;
  a2aAgentName?: string;
  a2aAgentUrl?: string;
}

export interface BridgeConfig {
  id: string;
  publicId: string;
  name: string;
  kind: BridgeKind;
  enabled: boolean;
  direction: BridgeDirection;
  targetUrl?: string;
  subscribedEvents: BridgeEventKind[];
  secretHint: string;
  rateLimitRpm: number;
  peerEnabled: boolean;
  peerScopes: ExternalPeerScope[];
  inboundPath: string;
  a2aPath: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateBridgeRequest {
  name: string;
  kind: BridgeKind;
  direction: BridgeDirection;
  targetUrl?: string;
  subscribedEvents: BridgeEventKind[];
  rateLimitRpm: number;
  peerEnabled: boolean;
  peerScopes: ExternalPeerScope[];
  inboundSigningSecret?: string;
  adapterConfig?: BridgeAdapterConfig;
}

export interface CreateBridgeResponse {
  bridge: BridgeConfig;
  inboundSecretOnce?: string;
  outboundSecretOnce?: string;
}

export interface RotateBridgeSecretResponse {
  bridgeId: string;
  secretHint: string;
  inboundSecretOnce?: string;
  outboundSecretOnce?: string;
}

export interface BridgeDeliverySummary {
  id: string;
  bridgeId: string;
  direction: 'inbound' | 'outbound';
  deliveryId: string;
  eventType: string;
  status: 'accepted' | 'delivered' | 'rejected' | 'failed' | 'pending_approval';
  httpStatus?: number;
  createdAt: string;
}
