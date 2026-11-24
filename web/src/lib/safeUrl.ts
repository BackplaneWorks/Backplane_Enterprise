const PRIVATE_IPV4_CIDR =
  /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.|0\.)/;

function isBlockedHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal') ||
    lower === 'metadata.google.internal'
  ) {
    return true;
  }
  if (PRIVATE_IPV4_CIDR.test(lower)) {
    return true;
  }
  const stripped = lower.replace(/^\[|\]$/g, '');
  if (
    stripped === '::1' ||
    stripped === '::' ||
    stripped.startsWith('fe80:') ||
    stripped.startsWith('fc') ||
    stripped.startsWith('fd')
  ) {
    return true;
  }
  return false;
}

/**
 * Validates user-supplied external links (e.g. datasheets, Stripe portal).
 * Allows strictly https:// public URLs without embedded credentials.
 */
export function sanitizeExternalUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password) return null;
    if (!parsed.hostname || isBlockedHostname(parsed.hostname)) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

/**
 * Validates server-authorized OAuth/OIDC/SAML redirect URLs.
 * Requires https:// and rejects embedded credentials, while permitting
 * self-hosted/internal enterprise IdP hostnames (e.g. sso.corp.internal).
 */
export function sanitizeServerRedirectUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password) return null;
    if (!parsed.hostname) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

export interface KiCadDeepLinkParams {
  tenantSlug: string;
  target: 'local' | 'boat_vm';
  partId?: string;
  boardId?: string;
  refdes?: string;
  vmId?: string;
}

export function buildKiCadDeepLink(params: KiCadDeepLinkParams): string {
  const query = new URLSearchParams({
    tenant: params.tenantSlug,
    target: params.target,
  });
  if (params.partId) query.set('part_id', params.partId);
  if (params.boardId) query.set('board_id', params.boardId);
  if (params.refdes) query.set('refdes', params.refdes);
  if (params.vmId) query.set('vm_id', params.vmId);
  return `backplane://open-kicad?${query.toString()}`;
}

/**
 * Neutralizes spreadsheet formula injection (=, +, -, @, tab, CR) and formats RFC-4180 CSV cells.
 */
export function escapeCsvCell(value: string | number): string {
  const raw = String(value);
  const needsFormulaGuard = /^[=+\-@\t\r]/.test(raw);
  const safe = needsFormulaGuard ? `'${raw}` : raw;
  const escaped = safe.replaceAll('"', '""');
  return `"${escaped}"`;
}

export function buildKicadHttpLibConfig(input: {
  orgName: string;
  tenantSlug: string;
  baseUrl: string;
  token: string;
}): string {
  const cleanBase = input.baseUrl.replace(/\/+$/, '');
  const payload = {
    meta: {
      version: 1.0,
    },
    name: `${input.orgName} Private Library`,
    description: `Backplane Enterprise tenant-isolated KiCad HTTP Library (${input.tenantSlug})`,
    source: {
      type: 'REST_API',
      api_version: 'v1',
      root_url: `${cleanBase}/v1/httplib/${encodeURIComponent(input.tenantSlug)}`,
      token: input.token,
      timeout_ms: 8000,
    },
  };
  return JSON.stringify(payload, null, 2);
}
