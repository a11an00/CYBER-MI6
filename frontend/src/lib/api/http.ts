/**
 * Thin fetch wrapper for the CYBER-MI6 REST API (same origin; handbook §9).
 *
 * Every failure becomes an ApiError so views can show one consistent error
 * state: `status` is the HTTP status, or 0 when the API could not be reached.
 */

const DEFAULT_TIMEOUT_MS = 10_000;

export class ApiError extends Error {
  readonly status: number;
  readonly path: string;
  /** Machine-readable code from the API body, e.g. "validation_error", "http_404". */
  readonly code: string | null;

  constructor(status: number, path: string, message: string, code: string | null = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.path = path;
    this.code = code;
  }

  /**
   * True when the API could not be reached at all (offline, timeout, CORS),
   * or a gateway in front of it says so: in development the Vite proxy
   * answers 502/504 when FastAPI isn't running.
   */
  get unreachable(): boolean {
    return this.status === 0 || this.status === 502 || this.status === 504;
  }
}

type QueryValue = string | number | boolean | undefined | null;

export function buildQuery(params: Record<string, QueryValue> = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  }
  const s = search.toString();
  return s ? `?${s}` : '';
}

/**
 * app/main.py's error_response(): {"error": code, "detail": string} or, for
 * 422, {"error": "validation_error", "detail": [{loc, msg}, ...]}.
 */
function errorCode(body: unknown): string | null {
  if (!body || typeof body !== 'object' || !('error' in body)) return null;
  const code = (body as { error: unknown }).error;
  return typeof code === 'string' ? code : null;
}

function detailMessage(body: unknown): string | null {
  if (!body || typeof body !== 'object' || !('detail' in body)) return null;
  const detail = (body as { detail: unknown }).detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((d) => (d && typeof d === 'object' && 'msg' in d ? String((d as { msg: unknown }).msg) : null))
      .filter((m): m is string => m !== null);
    if (msgs.length) return msgs.join('; ');
  }
  return null;
}

export async function request<T>(
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  options: { body?: unknown; timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<T> {
  const timeout = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      signal,
      headers: { Accept: 'application/json', ...(options.body !== undefined && { 'Content-Type': 'application/json' }) },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch (err) {
    // A caller-initiated abort is not an error state; let it propagate as-is.
    if (options.signal?.aborted) throw err;
    const reason = timeout.aborted ? 'timed out' : "couldn't be reached";
    throw new ApiError(0, path, `${method} ${path} ${reason}`);
  }

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message = detailMessage(body) ?? `${method} ${path} failed (${response.status})`;
    throw new ApiError(response.status, path, message, errorCode(body));
  }
  return body as T;
}
