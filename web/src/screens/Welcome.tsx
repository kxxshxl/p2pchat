import { useState, type FormEvent, type ReactNode } from "react";
import { AlertIcon, BrandMark, KeyIcon, LockIcon, RefreshIcon, ZapIcon } from "../components/icons";
import { createAccount, describeError, unlockAccount, type Session } from "../lib/account";
import type { Api } from "../lib/api";
import { Vault, WrongPassphraseError } from "../lib/vault";

const MIN_PASSPHRASE = 10;

function Hero() {
  return (
    <section className="welcome-hero">
      <div className="brand">
        <span className="brand-mark">
          <BrandMark />
        </span>
        Parley
      </div>
      <h1>Private conversations, peer to peer.</h1>
      <p className="lede">
        Messages are end-to-end encrypted in your browser with the X3DH handshake and the Double Ratchet, then sent
        straight to the other person over WebRTC whenever you are both online.
      </p>
      <ul className="feature-list">
        <Feature icon={<LockIcon />} title="The server only ever sees ciphertext">
          Your keys are generated and kept on this device, encrypted under your passphrase.
        </Feature>
        <Feature icon={<RefreshIcon />} title="Forward secrecy and self-healing sessions">
          Every message has its own key, and new Diffie-Hellman exchanges keep rotating the session.
        </Feature>
        <Feature icon={<ZapIcon />} title="Direct when possible, relayed when not">
          Data channels carry messages browser to browser; an encrypted mailbox covers the times you are offline.
        </Feature>
        <Feature icon={<KeyIcon />} title="No passwords on the server">
          You sign in by signing a one-time challenge with your identity key.
        </Feature>
      </ul>
    </section>
  );
}

function Feature({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <li>
      <span className="fi">{icon}</span>
      <div>
        <b>{title}</b>
        <span>{children}</span>
      </div>
    </li>
  );
}

function Steps({ steps }: { steps: string[] }) {
  return (
    <ol className="progress-steps" aria-live="polite">
      {steps.map((step, i) => (
        <li key={step} className={i === steps.length - 1 ? "current" : "done"}>
          {i === steps.length - 1 ? <span className="spinner" /> : <span style={{ width: 14 }}>✓</span>}
          {step}
        </li>
      ))}
    </ol>
  );
}

export function Welcome({ api, onReady }: { api: Api; onReady(session: Session): void }) {
  const [tab, setTab] = useState<"create" | "restore">("create");
  return (
    <div className="welcome">
      <Hero />
      <section className="welcome-panel">
        <div className="card">
          <div className="tabs" role="tablist">
            <button role="tab" aria-selected={tab === "create"} onClick={() => setTab("create")}>
              Create account
            </button>
            <button role="tab" aria-selected={tab === "restore"} onClick={() => setTab("restore")}>
              Restore backup
            </button>
          </div>
          {tab === "create" ? <CreateForm api={api} onReady={onReady} /> : <RestoreForm onReady={onReady} />}
        </div>
      </section>
    </div>
  );
}

function CreateForm({ api, onReady }: { api: Api; onReady(session: Session): void }) {
  const [handle, setHandle] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [steps, setSteps] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const busy = steps.length > 0 && !error;

  const handleOk = /^[a-z0-9_]{3,24}$/.test(handle);
  const valid = handleOk && displayName.trim().length > 0 && passphrase.length >= MIN_PASSPHRASE && passphrase === confirm;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!valid || busy) return;
    setError(null);
    setSteps([]);
    try {
      const session = await createAccount(api, { handle, displayName, passphrase }, (s) => setSteps((x) => [...x, s]));
      onReady(session);
    } catch (err) {
      setError(describeError(err));
      setSteps([]);
    }
  }

  return (
    <form onSubmit={submit} style={{ display: "grid", gap: 14 }}>
      <label className="field">
        <span>Handle</span>
        <div className="input-prefix">
          <b>@</b>
          <input
            className="input"
            value={handle}
            onChange={(e) => setHandle(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, ""))}
            maxLength={24}
            autoComplete="username"
            placeholder="ada"
            required
          />
        </div>
        <small>3–24 characters: a–z, 0–9 and underscores. This is how people find you.</small>
      </label>
      <label className="field">
        <span>Display name</span>
        <input
          className="input"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          maxLength={40}
          placeholder="Ada Lovelace"
          required
        />
      </label>
      <label className="field">
        <span>Device passphrase</span>
        <input
          className="input"
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          autoComplete="new-password"
          minLength={MIN_PASSPHRASE}
          required
        />
        <small>Encrypts your keys and history on this device. It never leaves the browser.</small>
      </label>
      <label className="field">
        <span>Confirm passphrase</span>
        <input
          className="input"
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          required
        />
        {confirm && confirm !== passphrase && <small className="error-text">Passphrases don't match</small>}
      </label>
      <div className="callout">
        <AlertIcon size={16} />
        <span>There is no password reset. If you forget the passphrase, the keys on this device are gone for good.</span>
      </div>
      {error && <div className="error-text" role="alert">{error}</div>}
      {busy ? (
        <Steps steps={steps} />
      ) : (
        <button className="btn primary block" disabled={!valid}>
          Generate keys &amp; create account
        </button>
      )}
    </form>
  );
}

function RestoreForm({ onReady }: { onReady(session: Session): void }) {
  const [file, setFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [steps, setSteps] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const busy = steps.length > 0 && !error;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!file || !passphrase || busy) return;
    setError(null);
    try {
      setSteps(["Reading backup"]);
      await Vault.importBackup(await file.text());
      const session = await unlockAccount(passphrase, (s) => setSteps((x) => [...x, s]));
      onReady(session);
    } catch (err) {
      if (err instanceof WrongPassphraseError) await Vault.wipe();
      setError(err instanceof WrongPassphraseError ? "That passphrase doesn't open this backup." : describeError(err));
      setSteps([]);
    }
  }

  return (
    <form onSubmit={submit} style={{ display: "grid", gap: 14 }}>
      <p>Restore an encrypted backup exported from Parley's settings. You'll need the passphrase it was made with.</p>
      <label className="field">
        <span>Backup file</span>
        <input className="input" type="file" accept=".json,application/json" onChange={(e) => setFile(e.target.files?.[0] ?? null)} style={{ paddingTop: 7 }} />
      </label>
      <label className="field">
        <span>Passphrase</span>
        <input className="input" type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
      </label>
      <div className="callout">
        <AlertIcon size={16} />
        <span>
          Only restore your most recent backup. Older backups hold old ratchet states, so conversations since then will
          need to resynchronise.
        </span>
      </div>
      {error && <div className="error-text" role="alert">{error}</div>}
      {busy ? (
        <Steps steps={steps} />
      ) : (
        <button className="btn primary block" disabled={!file || !passphrase}>
          Restore
        </button>
      )}
    </form>
  );
}

export function Unlock({ onReady, onReset }: { onReady(session: Session): void; onReset(): void }) {
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!passphrase || busy) return;
    setBusy(true);
    setError(null);
    try {
      onReady(await unlockAccount(passphrase, () => undefined));
    } catch (err) {
      setError(err instanceof WrongPassphraseError ? "Wrong passphrase." : describeError(err));
      setBusy(false);
    }
  }

  return (
    <div className="center-screen">
      <form className="card" onSubmit={submit}>
        <div className="brand">
          <span className="brand-mark">
            <BrandMark />
          </span>
          Parley
        </div>
        <div>
          <h2>Unlock this device</h2>
          <p>Your keys and messages are encrypted at rest. Enter your passphrase to decrypt them.</p>
        </div>
        <label className="field">
          <span>Passphrase</span>
          <input
            className="input"
            type="password"
            autoFocus
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {error && <div className="error-text" role="alert">{error}</div>}
        <button className="btn primary block" disabled={!passphrase || busy}>
          {busy ? <span className="spinner" /> : <LockIcon size={16} />}
          {busy ? "Deriving key…" : "Unlock"}
        </button>
        {confirmReset ? (
          <div className="callout danger">
            <AlertIcon size={16} />
            <div style={{ display: "grid", gap: 8 }}>
              <span>This permanently deletes the keys and history stored in this browser.</span>
              <div className="row">
                <button type="button" className="btn small" onClick={() => setConfirmReset(false)}>
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn small danger"
                  onClick={async () => {
                    await Vault.wipe();
                    onReset();
                  }}
                >
                  Erase this device
                </button>
              </div>
            </div>
          </div>
        ) : (
          <button type="button" className="link-btn" onClick={() => setConfirmReset(true)}>
            Use a different account
          </button>
        )}
      </form>
    </div>
  );
}
