/** Display formatting shared by every view. Pure, no locale surprises. */

const ISO_RE = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/;

/** ISO-8601 timestamps become `YYYY-MM-DD HH:MM UTC`; anything else passes through. */
export function fmtTime(value: string | null | undefined, fallback = '—'): string {
  if (!value) return fallback;
  const m = ISO_RE.exec(value);
  return m ? `${m[1]} ${m[2]} UTC` : value;
}

/** Long digests are shown as head…tail; short ones untouched. */
export function shortHash(value: string | null | undefined): string {
  if (!value) return '—';
  return value.length > 20 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

export function usd(amount: number): string {
  return `$${amount.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

export function personName(displayName: string | null | undefined, email: string): string {
  const trimmed = displayName?.trim();
  if (trimmed) return trimmed;
  return email.split('@')[0] || email;
}

export function initials(name: string): string {
  const parts = name.split(/[\s._-]+/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : name.slice(0, 2);
  return letters.toUpperCase();
}

/** `pending_approval` -> `pending approval` */
export function humanize(value: string): string {
  return value.replace(/_/g, ' ');
}
