import fs from 'node:fs';
import path from 'node:path';
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../App';
import { apiRequest } from '../api/client';
import { isSandboxEnabled } from '../lib/env';
import {
  buildKiCadDeepLink,
  escapeCsvCell,
  sanitizeExternalUrl,
  sanitizeServerRedirectUrl,
} from '../lib/safeUrl';

function collectSourceFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === '__tests__') continue;
      results.push(...collectSourceFiles(full));
    } else if (/\.(ts|tsx|css)$/.test(entry.name)) {
      results.push(full);
    }
  }
  return results;
}

describe('Web Portal Security Hardening', () => {
  it('contains zero innerHTML, dangerouslySetInnerHTML, web storage tokens, eval, inline styles, or prohibited vendor names', () => {
    const srcRoot = path.resolve(__dirname, '..');
    const files = collectSourceFiles(srcRoot);
    expect(files.length).toBeGreaterThan(10);

    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      expect(content, `${file} uses innerHTML`).not.toMatch(/\.innerHTML\b/);
      expect(content, `${file} uses dangerouslySetInnerHTML`).not.toMatch(/dangerouslySetInnerHTML/);
      expect(content, `${file} uses localStorage`).not.toMatch(/\blocalStorage\b/);
      expect(content, `${file} uses sessionStorage`).not.toMatch(/\bsessionStorage\b/);
      expect(content, `${file} uses eval`).not.toMatch(/\beval\s*\(/);
      expect(content, `${file} uses new Function`).not.toMatch(/new\s+Function\s*\(/);
      expect(content, `${file} uses inline style={{`).not.toMatch(/style=\{\{/);
      expect(content, `${file} names restricted fab directly`).not.toMatch(/\b(jlcpcb|lcsc|easyeda)\b/i);
    }
  });

  it('enforces strict CSP (connect-src self, object-src none, no unsafe-inline) and has no duplicate Dockerfile/nginx.conf in web/', () => {
    const webRoot = path.resolve(__dirname, '..', '..');
    const indexHtml = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');

    expect(indexHtml).toContain('http-equiv="Content-Security-Policy"');
    expect(indexHtml).toContain("connect-src 'self'");
    expect(indexHtml).toContain("object-src 'none'");
    expect(indexHtml).not.toContain('connect-src \'self\' wss: https:');
    expect(indexHtml).not.toContain('unsafe-inline');
    expect(indexHtml).not.toMatch(/<script\b[^>]*>[^<]+<\/script>/i);

    expect(fs.existsSync(path.join(webRoot, 'nginx.conf'))).toBe(false);
    expect(fs.existsSync(path.join(webRoot, 'Dockerfile'))).toBe(false);
  });

  it('gates sandbox mode off by default when VITE_ENABLE_SANDBOX is not 1', async () => {
    vi.unstubAllEnvs();
    expect(isSandboxEnabled()).toBe(false);

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({ error: { code: 'unauthenticated', message: 'Login required' } }),
      }),
    );

    try {
      render(React.createElement(App));
      await waitFor(() => {
        expect(screen.getByText('Continue with Google Workspace')).toBeInTheDocument();
      });
      expect(screen.queryByText('Interactive Sandbox Role Preview')).not.toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('sends X-BP-CSRF: 1 and credentials: include on mutating API calls, omitting CSRF header on GET', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ ok: true }),
    });
    vi.stubGlobal('fetch', fetchMock);

    try {
      await apiRequest('/v1/me');
      const getInit = fetchMock.mock.calls[0]?.[1] as RequestInit;
      expect(getInit.credentials).toBe('include');
      expect((getInit.headers as Record<string, string>)['X-BP-CSRF']).toBeUndefined();

      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
        await apiRequest('/v1/orders', { method, body: { test: true } });
        const lastInit = fetchMock.mock.calls.at(-1)?.[1] as RequestInit;
        expect(lastInit.credentials).toBe('include');
        expect((lastInit.headers as Record<string, string>)['X-BP-CSRF']).toBe('1');
      }
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('validates user external links strictly while allowing internal https:// IdP redirects from the server', () => {
    // User-supplied datasheet/external URLs: strict SSRF + https-only
    expect(sanitizeExternalUrl('https://www.st.com/ds.pdf')).toBe('https://www.st.com/ds.pdf');
    expect(sanitizeExternalUrl('http://www.st.com/ds.pdf')).toBeNull();
    expect(sanitizeExternalUrl('javascript:alert(1)')).toBeNull();
    expect(sanitizeExternalUrl('data:text/html,<script>alert(1)</script>')).toBeNull();
    expect(sanitizeExternalUrl('https://user:pass@example.com/')).toBeNull();
    expect(sanitizeExternalUrl('https://localhost/admin')).toBeNull();
    expect(sanitizeExternalUrl('https://127.0.0.1/admin')).toBeNull();
    expect(sanitizeExternalUrl('https://169.254.169.254/latest/meta-data/')).toBeNull();
    expect(sanitizeExternalUrl('https://10.0.0.5/internal')).toBeNull();
    expect(sanitizeExternalUrl('https://metadata.google.internal/computeMetadata/v1/')).toBeNull();
    expect(sanitizeExternalUrl('https://sso.corp.internal/realms/eng/auth')).toBeNull();

    // Server-authorized OAuth/OIDC/SAML redirect URLs: https-only, no credentials, internal hostnames allowed
    expect(sanitizeServerRedirectUrl('https://sso.corp.internal/realms/eng/auth')).toBe(
      'https://sso.corp.internal/realms/eng/auth',
    );
    expect(sanitizeServerRedirectUrl('http://sso.corp.internal/auth')).toBeNull();
    expect(sanitizeServerRedirectUrl('javascript:alert(1)')).toBeNull();
    expect(sanitizeServerRedirectUrl('https://user:pass@sso.corp.internal/auth')).toBeNull();
  });

  it('neutralizes CSV formula injection and safely encodes KiCad deep-links', () => {
    expect(escapeCsvCell('=CMD("calc")')).toBe('"\'=CMD(""calc"")"');
    expect(escapeCsvCell('+1+1')).toBe('"\'+1+1"');
    expect(escapeCsvCell('-2+3')).toBe('"\'-2+3"');
    expect(escapeCsvCell('@SUM(A1:A2)')).toBe('"\'@SUM(A1:A2)"');
    expect(escapeCsvCell('STM32H743VIT6')).toBe('"STM32H743VIT6"');

    const link = buildKiCadDeepLink({
      tenantSlug: 'aeroworks',
      target: 'boat_vm',
      boardId: 'brd-fc-rev4',
      vmId: 'vm-boat-01',
    });
    expect(link).toBe(
      'backplane://open-kicad?tenant=aeroworks&target=boat_vm&board_id=brd-fc-rev4&vm_id=vm-boat-01',
    );
  });
});
