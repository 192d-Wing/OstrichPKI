import { config } from "@/lib/config";

// Mirrors the Yew client's ApiClient: all calls go through the same-origin
// Axum proxy at /api, which attaches the session-bound backend token. The
// browser's SameSite=Lax session cookie is the auth + CSRF posture (see
// docs/WEBUI_SHADCN_MIGRATION.md §4.3) — no token or CSRF header in JS.
export class ApiError extends Error {
  status: number;
  code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(`${config.apiBaseUrl}${path}`, {
    method,
    credentials: "same-origin",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    let code: string | undefined;
    try {
      const data = await res.json();
      message = data.message ?? data.error ?? message;
      code = data.error ?? data.code;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message, code);
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  del: <T = void>(path: string) => request<T>("DELETE", path),
};
