import { resolve } from "node:path";

export interface IceServer {
  urls: string | string[];
  username?: string;
  credential?: string;
}

export interface Config {
  host: string;
  port: number;
  databasePath: string;
  /** Directory with the built web client; served when set. */
  staticDir: string | null;
  iceServers: IceServer[];
  sessionTtlMs: number;
  mailboxTtlMs: number;
  /** Max queued (undelivered) messages per recipient. */
  mailboxLimit: number;
  maxOneTimePreKeys: number;
  trustProxy: boolean;
  logLevel: string;
}

function int(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value)) throw new Error(`${name} must be a number`);
  return value;
}

function iceServers(): IceServer[] {
  const raw = process.env.PARLEY_ICE_SERVERS;
  if (!raw) return [];
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("PARLEY_ICE_SERVERS must be a JSON array");
  return parsed as IceServer[];
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const hour = 60 * 60 * 1000;
  return {
    host: process.env.PARLEY_HOST ?? "0.0.0.0",
    port: int("PARLEY_PORT", 8787),
    databasePath: process.env.PARLEY_DB ?? resolve("data", "parley.sqlite"),
    staticDir: process.env.PARLEY_STATIC_DIR ?? null,
    iceServers: iceServers(),
    sessionTtlMs: int("PARLEY_SESSION_TTL_HOURS", 24 * 7) * hour,
    mailboxTtlMs: int("PARLEY_MAILBOX_TTL_DAYS", 30) * 24 * hour,
    mailboxLimit: int("PARLEY_MAILBOX_LIMIT", 5000),
    maxOneTimePreKeys: 500,
    trustProxy: process.env.PARLEY_TRUST_PROXY === "true",
    logLevel: process.env.PARLEY_LOG_LEVEL ?? "info",
    ...overrides,
  };
}
