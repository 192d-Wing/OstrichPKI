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
      // Only adopt string fields — a structured error object must not leak as
      // "[object Object]" into the message, nor a human sentence into `code`.
      if (typeof data?.message === "string") message = data.message;
      else if (typeof data?.error === "string") message = data.error;
      if (typeof data?.code === "string") code = data.code;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message, code);
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!text) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    // A successful (2xx) response with a non-JSON body is not an error — the
    // operation succeeded; there's just nothing to deserialize.
    return undefined as T;
  }
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  del: <T = void>(path: string) => request<T>("DELETE", path),
};
