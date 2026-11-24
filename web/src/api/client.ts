export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  signal?: AbortSignal;
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };

  if (MUTATING_METHODS.has(method)) {
    headers['X-BP-CSRF'] = '1';
  }

  let encodedBody: string | undefined;
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    encodedBody = JSON.stringify(options.body);
  }

  const response = await fetch(path, {
    method,
    credentials: 'include',
    headers,
    body: encodedBody,
    signal: options.signal,
  });

  if (!response.ok) {
    let code = `http_${response.status}`;
    let message = response.statusText || 'Request failed';
    try {
      const parsed = (await response.json()) as {
        error?: { code?: string; message?: string };
      };
      if (parsed.error?.code) code = parsed.error.code;
      if (parsed.error?.message) message = parsed.error.message;
    } catch {
      // keep HTTP fallback
    }
    throw new ApiError(response.status, code, message);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}
