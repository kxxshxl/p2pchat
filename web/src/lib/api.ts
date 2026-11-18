import type { OneTimePreKeyWire, PreKeyBundleWire, SignedPreKeyWire } from "@parley/crypto";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface PublicUser {
  id: string;
  handle: string;
  displayName: string;
  online?: boolean;
}

export interface UserIdentity extends PublicUser {
  signingKey: string;
  identityKey: string;
  identityKeySignature: string;
}

export interface AuthResult {
  token: string;
  user: PublicUser;
}

export interface RegisterRequest {
  handle: string;
  displayName: string;
  challenge: string;
  signature: string;
  signingKey: string;
  identityKey: string;
  identityKeySignature: string;
  signedPreKey: SignedPreKeyWire;
  oneTimePreKeys: OneTimePreKeyWire[];
}

export interface KeyStatus {
  signedPreKey: { id: number; createdAt: number } | null;
  oneTimePreKeys: number;
  maxOneTimePreKeys: number;
}

export class Api {
  token: string | null = null;

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    let res: Response;
    try {
      res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      throw new ApiError(0, "network", "Can't reach the server");
    }
    if (res.status === 204) return undefined as T;
    const data = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
    if (!res.ok) throw new ApiError(res.status, data.error ?? "error", data.message ?? res.statusText);
    return data as T;
  }

  challenge(purpose: "register" | "login", handle: string) {
    return this.request<{ challenge: string }>("POST", "/api/auth/challenge", { purpose, handle });
  }
  register(body: RegisterRequest) {
    return this.request<AuthResult>("POST", "/api/auth/register", body);
  }
  login(handle: string, challenge: string, signature: string) {
    return this.request<AuthResult>("POST", "/api/auth/login", { handle, challenge, signature });
  }
  logout() {
    return this.request<void>("POST", "/api/auth/logout");
  }
  searchUsers(q: string) {
    return this.request<PublicUser[]>("GET", `/api/users?q=${encodeURIComponent(q)}`);
  }
  user(id: string) {
    return this.request<UserIdentity>("GET", `/api/users/${encodeURIComponent(id)}`);
  }
  userByHandle(handle: string) {
    return this.request<UserIdentity>("GET", `/api/users/by-handle/${encodeURIComponent(handle)}`);
  }
  bundle(id: string) {
    return this.request<PreKeyBundleWire & { userId: string }>("GET", `/api/users/${encodeURIComponent(id)}/bundle`);
  }
  keyStatus() {
    return this.request<KeyStatus>("GET", "/api/keys");
  }
  uploadOneTimePreKeys(preKeys: OneTimePreKeyWire[]) {
    return this.request<{ added: number; total: number }>("POST", "/api/keys/one-time", { preKeys });
  }
  rotateSignedPreKey(signedPreKey: SignedPreKeyWire) {
    return this.request<{ ok: true }>("PUT", "/api/keys/signed", { signedPreKey });
  }
}
