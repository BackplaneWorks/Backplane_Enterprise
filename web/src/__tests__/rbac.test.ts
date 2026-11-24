import { describe, expect, it } from 'vitest';
import { buildSandboxPrincipal } from '../data/sandboxData';
import {
  canAccessTab,
  getDefaultTabForRole,
  hasPermission,
  normalizePermission,
  normalizeRole,
} from '../lib/rbac';

describe('RBAC Policy & Tab Access (aligned with bp-ent-core/src/rbac.rs)', () => {
  it('normalizes both PascalCase and snake_case backend role identifiers', () => {
    expect(normalizeRole('OrgAdmin')).toBe('org_admin');
    expect(normalizeRole('org_admin')).toBe('org_admin');
    expect(normalizeRole('Engineer')).toBe('engineer');
    expect(normalizeRole('Librarian')).toBe('librarian');
    expect(normalizeRole('Purchasing')).toBe('purchasing');
    expect(normalizeRole('ExternalReviewer')).toBe('external_reviewer');
  });

  it('enforces exact parity with bp-ent-core fallback permissions for every role', () => {
    const admin = buildSandboxPrincipal('org_admin');
    expect(canAccessTab(admin, 'admin')).toBe(true);
    expect(hasPermission(admin, 'AdminManage')).toBe(true);
    expect(hasPermission(admin, 'AuditRead')).toBe(true);
    expect(hasPermission(admin, 'LlmUse')).toBe(true);
    expect(getDefaultTabForRole('org_admin')).toBe('admin');

    const engineer = buildSandboxPrincipal('engineer');
    expect(canAccessTab(engineer, 'codev')).toBe(true);
    expect(canAccessTab(engineer, 'librarian')).toBe(true);
    expect(canAccessTab(engineer, 'purchasing')).toBe(true);
    expect(canAccessTab(engineer, 'admin')).toBe(false);
    expect(hasPermission(engineer, 'BoardsWrite')).toBe(true);
    expect(hasPermission(engineer, 'OrdersWrite')).toBe(true);
    expect(hasPermission(engineer, 'LlmUse')).toBe(true);
    expect(hasPermission(engineer, 'PartsRelease')).toBe(false);
    expect(getDefaultTabForRole('engineer')).toBe('codev');

    const librarian = buildSandboxPrincipal('librarian');
    expect(hasPermission(librarian, 'PartsRelease')).toBe(true);
    expect(hasPermission(librarian, 'LlmUse')).toBe(true);
    expect(canAccessTab(librarian, 'purchasing')).toBe(false);
    expect(canAccessTab(librarian, 'admin')).toBe(false);
    expect(getDefaultTabForRole('librarian')).toBe('librarian');

    const purchasing = buildSandboxPrincipal('purchasing');
    expect(canAccessTab(purchasing, 'purchasing')).toBe(true);
    expect(hasPermission(purchasing, 'OrdersApprove')).toBe(true);
    expect(hasPermission(purchasing, 'BoardsComment')).toBe(true);
    expect(hasPermission(purchasing, 'BillingManage')).toBe(false);
    expect(hasPermission(purchasing, 'BoardsWrite')).toBe(false);
    expect(canAccessTab(purchasing, 'admin')).toBe(false);
    expect(getDefaultTabForRole('purchasing')).toBe('purchasing');

    const reviewer = buildSandboxPrincipal('external_reviewer');
    expect(canAccessTab(reviewer, 'codev')).toBe(true);
    expect(hasPermission(reviewer, 'BoardsRead')).toBe(true);
    expect(hasPermission(reviewer, 'BoardsComment')).toBe(true);
    expect(hasPermission(reviewer, 'PartsRead')).toBe(false);
    expect(canAccessTab(reviewer, 'librarian')).toBe(false);
    expect(canAccessTab(reviewer, 'purchasing')).toBe(false);
    expect(canAccessTab(reviewer, 'admin')).toBe(false);
  });

  it('derives permissions strictly from /v1/me server permissions when present', () => {
    expect(normalizePermission('parts:read')).toBe('PartsRead');
    expect(normalizePermission('orders_approve')).toBe('OrdersApprove');
    expect(normalizePermission('LlmUse')).toBe('LlmUse');

    // Narrowed device/user token on an engineer role: server permissions array wins
    const narrowed = {
      ...buildSandboxPrincipal('engineer'),
      permissions: ['parts:read', 'boards:read'],
    };
    expect(hasPermission(narrowed, 'PartsRead')).toBe(true);
    expect(hasPermission(narrowed, 'BoardsRead')).toBe(true);
    expect(hasPermission(narrowed, 'OrdersWrite')).toBe(false);
    expect(hasPermission(narrowed, 'BoardsWrite')).toBe(false);
    expect(canAccessTab(narrowed, 'purchasing')).toBe(false);
  });
});
