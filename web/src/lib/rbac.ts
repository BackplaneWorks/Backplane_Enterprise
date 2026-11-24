import type { NavTab, Permission, Principal, Role } from '../types/domain';

// Mirrors crates/bp-ent-core/src/rbac.rs as fallback for offline sandbox mode;
// when /v1/me returns `permissions`, `hasPermission` uses those server-authoritative permissions.
const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  org_admin: [
    'PartsRead',
    'PartsWrite',
    'PartsRelease',
    'BoardsRead',
    'BoardsComment',
    'BoardsWrite',
    'OrdersRead',
    'OrdersWrite',
    'OrdersApprove',
    'MailManage',
    'BillingManage',
    'VmUse',
    'VmManage',
    'LlmUse',
    'AdminManage',
    'AuditRead',
  ],
  engineer: [
    'PartsRead',
    'PartsWrite',
    'BoardsRead',
    'BoardsComment',
    'BoardsWrite',
    'OrdersRead',
    'OrdersWrite',
    'VmUse',
    'LlmUse',
  ],
  librarian: [
    'PartsRead',
    'PartsWrite',
    'PartsRelease',
    'BoardsRead',
    'BoardsComment',
    'VmUse',
    'LlmUse',
  ],
  purchasing: [
    'PartsRead',
    'BoardsRead',
    'BoardsComment',
    'OrdersRead',
    'OrdersWrite',
    'OrdersApprove',
    'MailManage',
  ],
  external_reviewer: ['BoardsRead', 'BoardsComment'],
};

const PERMISSION_MAP: Record<string, Permission> = {
  PartsRead: 'PartsRead',
  parts_read: 'PartsRead',
  'parts:read': 'PartsRead',
  PartsWrite: 'PartsWrite',
  parts_write: 'PartsWrite',
  'parts:write': 'PartsWrite',
  PartsRelease: 'PartsRelease',
  parts_release: 'PartsRelease',
  'parts:release': 'PartsRelease',
  BoardsRead: 'BoardsRead',
  boards_read: 'BoardsRead',
  'boards:read': 'BoardsRead',
  BoardsComment: 'BoardsComment',
  boards_comment: 'BoardsComment',
  'boards:comment': 'BoardsComment',
  BoardsWrite: 'BoardsWrite',
  boards_write: 'BoardsWrite',
  'boards:write': 'BoardsWrite',
  OrdersRead: 'OrdersRead',
  orders_read: 'OrdersRead',
  'orders:read': 'OrdersRead',
  OrdersWrite: 'OrdersWrite',
  orders_write: 'OrdersWrite',
  'orders:write': 'OrdersWrite',
  OrdersApprove: 'OrdersApprove',
  orders_approve: 'OrdersApprove',
  'orders:approve': 'OrdersApprove',
  MailManage: 'MailManage',
  mail_manage: 'MailManage',
  'mail:manage': 'MailManage',
  BillingManage: 'BillingManage',
  billing_manage: 'BillingManage',
  'billing:manage': 'BillingManage',
  VmUse: 'VmUse',
  vm_use: 'VmUse',
  'vm:use': 'VmUse',
  VmManage: 'VmManage',
  vm_manage: 'VmManage',
  'vm:manage': 'VmManage',
  LlmUse: 'LlmUse',
  llm_use: 'LlmUse',
  'llm:use': 'LlmUse',
  AdminManage: 'AdminManage',
  admin_manage: 'AdminManage',
  'admin:manage': 'AdminManage',
  AuditRead: 'AuditRead',
  audit_read: 'AuditRead',
  'audit:read': 'AuditRead',
};

const ROLE_LABELS: Record<Role, string> = {
  org_admin: 'Org Admin',
  engineer: 'Engineer',
  librarian: 'Librarian',
  purchasing: 'Purchasing',
  external_reviewer: 'External Reviewer',
};

export function normalizeRole(raw: string): Role {
  const cleaned = raw.trim();
  switch (cleaned) {
    case 'OrgAdmin':
    case 'org_admin':
      return 'org_admin';
    case 'Engineer':
    case 'engineer':
      return 'engineer';
    case 'Librarian':
    case 'librarian':
      return 'librarian';
    case 'Purchasing':
    case 'purchasing':
      return 'purchasing';
    case 'ExternalReviewer':
    case 'external_reviewer':
    default:
      return 'external_reviewer';
  }
}

export function normalizePermission(raw: string): Permission | null {
  return PERMISSION_MAP[raw.trim()] ?? null;
}

export function roleLabel(role: Role): string {
  return ROLE_LABELS[role];
}

export function hasPermission(
  principal: Principal | null | undefined,
  permission: Permission,
): boolean {
  if (!principal) return false;
  if (Array.isArray(principal.permissions)) {
    return principal.permissions.some((raw) => normalizePermission(raw) === permission);
  }
  return ROLE_PERMISSIONS[principal.role].includes(permission);
}

export function canAccessTab(
  principal: Principal | null | undefined,
  tab: NavTab,
): boolean {
  if (!principal) return false;
  switch (tab) {
    case 'codev':
      return hasPermission(principal, 'BoardsRead');
    case 'librarian':
      return hasPermission(principal, 'PartsRead');
    case 'purchasing':
      return (
        hasPermission(principal, 'OrdersRead') ||
        hasPermission(principal, 'OrdersWrite')
      );
    case 'admin':
      return (
        hasPermission(principal, 'AdminManage') ||
        hasPermission(principal, 'AuditRead') ||
        hasPermission(principal, 'VmManage')
      );
  }
}

export function getDefaultTabForRole(role: Role): NavTab {
  switch (role) {
    case 'org_admin':
      return 'admin';
    case 'librarian':
      return 'librarian';
    case 'purchasing':
      return 'purchasing';
    case 'engineer':
    case 'external_reviewer':
      return 'codev';
  }
}
