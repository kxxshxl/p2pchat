import { formatSafetyNumber } from "@parley/crypto";
import {
  Fragment,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type FormEvent,
  type KeyboardEvent,
} from "react";
import { Avatar, Modal, Switch, formatDay, formatRelative, formatShortTime, formatTime, useToast } from "../components/common";
import {
  ActivityIcon,
  AlertIcon,
  BackIcon,
  BrandMark,
  ChatIcon,
  CheckIcon,
  ClockIcon,
  DoubleCheckIcon,
  LockIcon,
  SearchIcon,
  SendIcon,
  ServerIcon,
  SettingsIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ZapIcon,
} from "../components/icons";
import { describeError } from "../lib/account";
import type { PublicUser } from "../lib/api";
import type { ChatClient, ClientState } from "../lib/client";
import { MAX_MESSAGE_LENGTH, type ChatMessage, type Contact } from "../lib/types";
import { downloadText } from "../lib/util";
import { Vault } from "../lib/vault";
import { useTheme, type ThemeChoice } from "../theme";

function useClientState(client: ChatClient): ClientState {
  return useSyncExternalStore(client.store.subscribe, client.store.getSnapshot);
}

export function ChatScreen({
  client,
  onLock,
  onErase,
}: {
  client: ChatClient;
  onLock(): void;
  onErase(): void;
}) {
  const state = useClientState(client);
  const [panel, setPanel] = useState<"inspector" | null>(null);
  const [modal, setModal] = useState<"settings" | "safety" | null>(null);
  const [toast, showToast] = useToast();
  const active = state.contacts.find((c) => c.id === state.activePeer) ?? null;

  const unread = state.contacts.reduce((n, c) => n + c.unread, 0);
  useEffect(() => {
    document.title = unread ? `(${unread}) Parley` : "Parley";
  }, [unread]);

  return (
    <div className={`shell${active ? " has-active" : ""}`}>
      <Sidebar client={client} state={state} onSettings={() => setModal("settings")} showToast={showToast} />
      {active ? (
        <Conversation
          key={active.id}
          client={client}
          state={state}
          contact={active}
          inspectorOpen={panel === "inspector"}
          onToggleInspector={() => setPanel((p) => (p ? null : "inspector"))}
          onSafety={() => setModal("safety")}
          showToast={showToast}
        />
      ) : (
        <section className="conversation">
          <div className="empty-state">
            <div>
              <span className="empty-art">
                <ChatIcon size={28} />
              </span>
              <h2>Start an encrypted conversation</h2>
              <p>
                Search for someone by their handle. Your first message sets up a fresh X3DH session; after that every
                message gets its own key.
              </p>
            </div>
          </div>
        </section>
      )}
      {active && panel === "inspector" && <Inspector state={state} contact={active} onClose={() => setPanel(null)} />}
      {modal === "settings" && (
        <SettingsModal
          client={client}
          state={state}
          onClose={() => setModal(null)}
          onLock={onLock}
          onErase={onErase}
          showToast={showToast}
        />
      )}
      {modal === "safety" && active && <SafetyModal client={client} contact={active} onClose={() => setModal(null)} />}
      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
      {state.authError && (
        <div className="toast" role="alert" style={{ bottom: 80 }}>
          {state.authError}
        </div>
      )}
    </div>
  );
}

// ================================================================== sidebar

const CONNECTION_LABEL: Record<ClientState["connection"], string> = {
  connecting: "Connecting…",
  online: "Connected",
  offline: "Offline — retrying",
  replaced: "Open in another tab",
};

function Sidebar({
  client,
  state,
  onSettings,
  showToast,
}: {
  client: ChatClient;
  state: ClientState;
  onSettings(): void;
  showToast(text: string): void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<PublicUser[] | null>(null);

  useEffect(() => {
    const q = query.trim().replace(/^@/, "");
    if (!q) return setResults(null);
    const timer = setTimeout(() => {
      client.searchUsers(q).then(setResults, () => setResults([]));
    }, 200);
    return () => clearTimeout(timer);
  }, [client, query]);

  async function open(handle: string) {
    try {
      const contact = await client.addContactByHandle(handle);
      setQuery("");
      setResults(null);
      client.openConversation(contact.id);
    } catch (err) {
      showToast(describeError(err));
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    const q = query.trim().replace(/^@/, "").toLowerCase();
    if (/^[a-z0-9_]{3,24}$/.test(q)) void open(q);
  }

  const lastMessage = (id: string) => {
    const list = state.messages[id] ?? [];
    for (let i = list.length - 1; i >= 0; i--) if (list[i]!.kind === "text") return list[i]!;
    return undefined;
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-head">
        <span className="brand-mark" style={{ width: 32, height: 32 }}>
          <BrandMark size={18} />
        </span>
        <div className="me">
          <b>{state.account.displayName}</b>
          <span className="conn">
            <span className={`dot ${state.connection}`} />@{state.account.handle} · {CONNECTION_LABEL[state.connection]}
          </span>
        </div>
        <button className="icon-btn" onClick={onSettings} aria-label="Settings" title="Settings">
          <SettingsIcon />
        </button>
      </div>

      <form className="search" onSubmit={onSubmit} role="search">
        <div className="input-prefix">
          <b>
            <SearchIcon size={15} />
          </b>
          <input
            className="input"
            placeholder="Find people by @handle"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Find people by handle"
            onKeyDown={(e) => e.key === "Escape" && setQuery("")}
          />
        </div>
        {results && (
          <div className="search-results">
            {results.length === 0 ? (
              <div className="empty">No one found</div>
            ) : (
              results.map((u) => (
                <button type="button" key={u.id} onClick={() => void open(u.handle)}>
                  <Avatar id={u.id} name={u.displayName} small online={u.online} />
                  <span style={{ minWidth: 0 }}>
                    <b style={{ display: "block" }}>{u.displayName}</b>
                    <span className="muted">@{u.handle}</span>
                  </span>
                </button>
              ))
            )}
          </div>
        )}
      </form>

      <nav className="contact-list" aria-label="Conversations">
        {state.contacts.length === 0 && (
          <div className="sidebar-empty">
            No conversations yet. Find someone above — try opening a second browser profile and creating another
            account.
          </div>
        )}
        {state.contacts.map((c) => {
          const last = lastMessage(c.id);
          return (
            <button
              key={c.id}
              className="contact"
              aria-current={state.activePeer === c.id}
              onClick={() => client.openConversation(c.id)}
            >
              <Avatar id={c.id} name={c.displayName} online={state.presence[c.id]?.online} />
              <span style={{ minWidth: 0 }}>
                <span className="name">
                  <span>{c.displayName}</span>
                  {c.verified && <ShieldCheckIcon size={14} className="verified-icon" />}
                  {c.keyChangedAt && <ShieldAlertIcon size={14} style={{ color: "var(--warn)" }} />}
                </span>
                <span className="preview">
                  {state.typing[c.id] ? "typing…" : last ? `${last.direction === "out" ? "You: " : ""}${last.body}` : `@${c.handle}`}
                </span>
              </span>
              <span className="meta">
                {last && <span>{formatShortTime(last.sentAt)}</span>}
                {c.unread > 0 && <span className="badge">{c.unread}</span>}
              </span>
            </button>
          );
        })}
      </nav>
    </aside>
  );
}

// ================================================================== conversation

function StatusIcon({ message }: { message: ChatMessage }) {
  switch (message.status) {
    case "pending":
      return <ClockIcon size={12} aria-label="waiting to send" />;
    case "sent":
      return <CheckIcon size={13} aria-label="sent" />;
    case "delivered":
      return <DoubleCheckIcon size={14} aria-label="delivered" />;
    case "read":
      return <DoubleCheckIcon size={14} className="status-read" aria-label="read" />;
    case "failed":
      return <AlertIcon size={12} className="status-failed" aria-label="failed" />;
    default:
      return null;
  }
}

function Conversation({
  client,
  state,
  contact,
  inspectorOpen,
  onToggleInspector,
  onSafety,
  showToast,
}: {
  client: ChatClient;
  state: ClientState;
  contact: Contact;
  inspectorOpen: boolean;
  onToggleInspector(): void;
  onSafety(): void;
  showToast(text: string): void;
}) {
  const messages = state.messages[contact.id] ?? [];
  const presence = state.presence[contact.id];
  const link = state.links[contact.id];
  const [draft, setDraft] = useState("");
  const listRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const stickToBottom = useRef(true);

  useLayoutEffect(() => {
    const el = listRef.current;
    if (el && stickToBottom.current) el.scrollTop = el.scrollHeight;
  }, [messages.length, state.typing[contact.id]]);

  useEffect(() => {
    inputRef.current?.focus();
    const el = listRef.current;
    if (!el) return;
    const observer = new ResizeObserver(() => {
      if (stickToBottom.current) el.scrollTop = el.scrollHeight;
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [contact.id]);

  const send = useCallback(() => {
    const text = draft;
    if (!text.trim()) return;
    setDraft("");
    stickToBottom.current = true;
    client.setTyping(contact.id, false);
    client.sendText(contact.id, text).catch((err) => showToast(describeError(err)));
  }, [client, contact.id, draft, showToast]);

  function onKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      send();
    }
  }

  const transportChip =
    link === "open" ? (
      <span className="chip p2p" title="Messages travel directly between browsers over a WebRTC data channel">
        <ZapIcon size={11} /> Direct
      </span>
    ) : link === "connecting" ? (
      <span className="chip" title="Negotiating a direct WebRTC link">
        <span className="spinner" style={{ width: 9, height: 9, borderWidth: 1.5 }} /> Connecting
      </span>
    ) : (
      <span className="chip" title="Encrypted envelopes are relayed by the server">
        <ServerIcon size={11} /> Relayed
      </span>
    );

  return (
    <section className="conversation" aria-label={`Conversation with ${contact.displayName}`}>
      <header className="conv-head">
        <button className="icon-btn show-mobile" onClick={() => client.openConversation(null)} aria-label="Back">
          <BackIcon />
        </button>
        <Avatar id={contact.id} name={contact.displayName} online={presence?.online} />
        <div className="conv-title">
          <b>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{contact.displayName}</span>
            {contact.verified && <ShieldCheckIcon size={15} className="verified-icon" aria-label="verified" />}
          </b>
          <span className="sub">
            <span>
              @{contact.handle} ·{" "}
              {state.typing[contact.id]
                ? "typing…"
                : presence?.online
                  ? "online"
                  : presence?.lastSeenAt
                    ? `last seen ${formatRelative(presence.lastSeenAt)}`
                    : "offline"}
            </span>
          </span>
        </div>
        <span className="hide-mobile" style={{ display: "flex", gap: 6 }}>
          <span className="chip secure">
            <LockIcon size={11} /> End-to-end
          </span>
          {transportChip}
        </span>
        <button className="icon-btn" onClick={onSafety} aria-label="Safety number" title="Verify safety number">
          {contact.verified ? <ShieldCheckIcon /> : <ShieldAlertIcon />}
        </button>
        <button
          className={`icon-btn${inspectorOpen ? " active" : ""}`}
          onClick={onToggleInspector}
          aria-label="Protocol inspector"
          aria-pressed={inspectorOpen}
          title="Protocol inspector"
        >
          <ActivityIcon />
        </button>
      </header>

      {contact.keyChangedAt && (
        <div className="banner danger" role="alert">
          <ShieldAlertIcon size={18} />
          <div>
            <b>{contact.displayName}'s identity key changed.</b> Parley identities never change, so this could mean
            someone is intercepting the conversation. Compare safety numbers before continuing.
          </div>
          <button className="btn small" onClick={onSafety}>
            Verify
          </button>
          <button className="btn small ghost" onClick={() => void client.acknowledgeKeyChange(contact.id)}>
            Continue anyway
          </button>
        </div>
      )}
      {!contact.verified && !contact.keyChangedAt && messages.length > 0 && messages.length < 4 && (
        <div className="banner">
          <ShieldAlertIcon size={18} />
          <div>Not verified yet. Compare safety numbers with {contact.displayName} to rule out a man in the middle.</div>
          <button className="btn small" onClick={onSafety}>
            Compare
          </button>
        </div>
      )}

      <div
        className="messages"
        ref={listRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
        }}
        aria-live="polite"
      >
        <div className="e2e-note">
          <LockIcon size={12} /> Messages with @{contact.handle} are end-to-end encrypted with the Double Ratchet. The
          relay server can't read them.
        </div>
        {messages.map((m, i) => {
          const prev = messages[i - 1];
          const newDay = !prev || new Date(prev.sentAt).toDateString() !== new Date(m.sentAt).toDateString();
          const grouped =
            !!prev && !newDay && prev.kind === "text" && prev.direction === m.direction && m.sentAt - prev.sentAt < 120_000;
          return (
            <Fragment key={m.id}>
              {newDay && <div className="day">{formatDay(m.sentAt)}</div>}
              {m.kind === "system" ? (
                <div className="system-msg">
                  <ShieldAlertIcon size={13} /> {m.body}
                </div>
              ) : (
                <MessageBubble
                  message={m}
                  grouped={grouped}
                  showCrypto={inspectorOpen}
                  onRetry={() => void client.retry(contact.id, m.id)}
                />
              )}
            </Fragment>
          );
        })}
      </div>

      <div className="typing" aria-live="polite">
        {state.typing[contact.id] && (
          <>
            <i>
              <span />
              <span />
              <span />
            </i>
            {contact.displayName} is typing
          </>
        )}
      </div>

      <form
        className="composer"
        onSubmit={(e) => {
          e.preventDefault();
          send();
        }}
      >
        <textarea
          ref={inputRef}
          rows={1}
          value={draft}
          maxLength={MAX_MESSAGE_LENGTH}
          placeholder={contact.keyChangedAt ? "Verify the safety number to keep messaging" : "Message"}
          disabled={!!contact.keyChangedAt}
          aria-label={`Message ${contact.displayName}`}
          onChange={(e) => {
            setDraft(e.target.value);
            client.setTyping(contact.id, e.target.value.length > 0);
            e.target.style.height = "auto";
            e.target.style.height = `${Math.min(e.target.scrollHeight, 160)}px`;
          }}
          onKeyDown={onKeyDown}
          onBlur={() => client.setTyping(contact.id, false)}
        />
        <button className="send-btn" disabled={!draft.trim() || !!contact.keyChangedAt} aria-label="Send">
          <SendIcon size={20} />
        </button>
      </form>
    </section>
  );
}

function MessageBubble({
  message,
  grouped,
  showCrypto,
  onRetry,
}: {
  message: ChatMessage;
  grouped: boolean;
  showCrypto: boolean;
  onRetry(): void;
}) {
  const out = message.direction === "out";
  return (
    <div className={`msg ${out ? "out" : "in"}${grouped ? " grouped" : ""}${message.status === "failed" ? " failed" : ""}`}>
      <div className="bubble">{message.body}</div>
      {(!grouped || out || showCrypto) && (
        <div className="msg-meta">
          <span>{formatTime(message.sentAt)}</span>
          {message.transport === "p2p" && <ZapIcon size={11} aria-label="sent directly" />}
          {message.transport === "relay" && <ServerIcon size={11} aria-label="relayed" />}
          {out && <StatusIcon message={message} />}
          {message.status === "failed" && (
            <>
              <span className="status-failed">{message.error ?? "Not sent"}</span>
              <button onClick={onRetry}>Retry</button>
            </>
          )}
        </div>
      )}
      {showCrypto && message.crypto && (
        <div className="crypto-line" title="Ratchet public key · message number in chain · previous chain length · ciphertext bytes">
          {message.crypto.preKey ? "X3DH+" : ""}DR {message.crypto.ratchetKey} · n={message.crypto.counter} · pn=
          {message.crypto.previousCounter} · {message.crypto.ciphertextBytes} B
        </div>
      )}
    </div>
  );
}

// ================================================================== inspector

function Inspector({ state, contact, onClose }: { state: ClientState; contact: Contact; onClose(): void }) {
  const session = state.sessions[contact.id];
  const link = state.links[contact.id];
  const log = useMemo(
    () => (state.messages[contact.id] ?? []).filter((m) => m.crypto).slice(-14),
    [state.messages, contact.id],
  );

  return (
    <aside className="inspector" aria-label="Protocol inspector">
      <div className="panel-head">
        <ActivityIcon size={18} />
        <h3>Protocol inspector</h3>
        <button className="icon-btn" onClick={onClose} aria-label="Close inspector">
          <BackIcon style={{ transform: "rotate(180deg)" }} />
        </button>
      </div>
      <div className="panel-body">
        <section className="panel-section">
          <h4>Session</h4>
          {session ? (
            <dl className="kv">
              <dt>Established by</dt>
              <dd>{session.role === "initiator" ? "you (X3DH initiator)" : `${contact.displayName} (X3DH)`}</dd>
              <dt>Session id</dt>
              <dd className="mono">{session.id}</dd>
              <dt>Created</dt>
              <dd>{formatRelative(session.createdAt)}</dd>
              <dt>Stored sessions</dt>
              <dd>{session.sessionCount}</dd>
              <dt>X3DH header attached</dt>
              <dd>{session.awaitingReply ? "yes (awaiting first reply)" : "no"}</dd>
            </dl>
          ) : (
            <p className="explain">
              No session yet. Sending the first message fetches {contact.displayName}'s pre-key bundle, verifies its
              signatures and runs X3DH.
            </p>
          )}
        </section>

        {session && (
          <section className="panel-section">
            <h4>Double Ratchet</h4>
            <dl className="kv">
              <dt>Our ratchet key</dt>
              <dd className="mono">{session.localRatchetKey}</dd>
              <dt>Their ratchet key</dt>
              <dd className="mono">{session.remoteRatchetKey ?? "—"}</dd>
              <dt>Sending chain</dt>
              <dd>message #{session.sendCount}</dd>
              <dt>Receiving chain</dt>
              <dd>message #{session.receiveCount}</dd>
              <dt>Previous chain length</dt>
              <dd>{session.previousSendCount}</dd>
              <dt>Skipped keys cached</dt>
              <dd>{session.skippedKeys}</dd>
            </dl>
          </section>
        )}

        {log.length > 0 && (
          <section className="panel-section">
            <h4>Recent messages</h4>
            <div className="ratchet-log">
              {log.map((m, i) => {
                // A new chain starts when a sender's ratchet key differs from their previous message's.
                const prev = log.slice(0, i).reverse().find((x) => x.direction === m.direction);
                const step = !!prev && prev.crypto!.ratchetKey !== m.crypto!.ratchetKey;
                return (
                  <div key={m.id} className={`ratchet-row${step ? " step" : ""}`} title={step ? "New DH ratchet step" : undefined}>
                    <span className={m.direction === "out" ? "dir-out" : "dir-in"}>{m.direction === "out" ? "→" : "←"}</span>
                    <span>
                      {m.crypto!.ratchetKey.slice(0, 9)} n={m.crypto!.counter}
                      {m.crypto!.preKey ? " +X3DH" : ""}
                    </span>
                    <span className="muted">{m.transport === "p2p" ? "p2p" : "relay"}</span>
                  </div>
                );
              })}
            </div>
            <p className="explain" style={{ marginTop: 8 }}>
              Outlined rows start a new sending chain: that side mixed a fresh X25519 exchange into the root key.
              Receipts and typing signals are ratchet messages too, which is why counters can skip.
            </p>
          </section>
        )}

        <section className="panel-section">
          <h4>Transport</h4>
          <dl className="kv">
            <dt>Direct link</dt>
            <dd>{link === "open" ? "open (WebRTC data channel)" : link === "connecting" ? "negotiating…" : "not connected"}</dd>
            <dt>Relay</dt>
            <dd>{state.connection}</dd>
            <dt>Mode</dt>
            <dd>{state.settings.relayOnly ? "relay only (IP hidden)" : "direct when possible"}</dd>
          </dl>
        </section>

        {state.keyHealth && (
          <section className="panel-section">
            <h4>Your pre-keys</h4>
            <dl className="kv">
              <dt>One-time keys on server</dt>
              <dd>{state.keyHealth.serverOneTime}</dd>
              <dt>Signed pre-key</dt>
              <dd>
                #{state.keyHealth.signedPreKeyId} · {formatRelative(state.keyHealth.signedPreKeyCreatedAt)}
              </dd>
            </dl>
          </section>
        )}
      </div>
    </aside>
  );
}

// ================================================================== safety number

function SafetyModal({ client, contact, onClose }: { client: ChatClient; contact: Contact; onClose(): void }) {
  const number = client.safetyNumberWith(contact.id) ?? "";
  const groups = formatSafetyNumber(number);
  const [compare, setCompare] = useState("");
  const digits = compare.replace(/\D/g, "");
  const result = digits.length === 60 ? (digits === number ? "match" : "mismatch") : null;

  return (
    <Modal title={`Safety number with ${contact.displayName}`} onClose={onClose}>
      <p>
        If this number matches what {contact.displayName} sees on their device, nobody has swapped keys in transit,
        not even the server. Compare it in person, on a call, or over another channel you trust.
      </p>
      <div className="safety-grid" aria-label="Safety number">
        {groups.map((g, i) => (
          <span key={i}>{g}</span>
        ))}
      </div>
      <label className="field compare">
        <span>Paste their number to compare (optional)</span>
        <input className="input mono" value={compare} onChange={(e) => setCompare(e.target.value)} inputMode="numeric" />
        {result === "match" && (
          <span className="compare-result match">
            <ShieldCheckIcon size={16} /> Numbers match
          </span>
        )}
        {result === "mismatch" && (
          <span className="compare-result mismatch">
            <ShieldAlertIcon size={16} /> Numbers don't match. Don't trust this conversation.
          </span>
        )}
      </label>
      <div className="row">
        <button className="btn" onClick={() => navigator.clipboard?.writeText(groups.join(" "))}>
          Copy number
        </button>
        {contact.verified ? (
          <button className="btn" onClick={() => void client.setVerified(contact.id, false).then(onClose)}>
            Remove verification
          </button>
        ) : (
          <button className="btn primary" onClick={() => void client.setVerified(contact.id, true).then(onClose)}>
            <ShieldCheckIcon size={16} /> Mark as verified
          </button>
        )}
      </div>
    </Modal>
  );
}

// ================================================================== settings

function SettingsModal({
  client,
  state,
  onClose,
  onLock,
  onErase,
  showToast,
}: {
  client: ChatClient;
  state: ClientState;
  onClose(): void;
  onLock(): void;
  onErase(): void;
  showToast(text: string): void;
}) {
  const [theme, setTheme] = useTheme();
  const [confirmErase, setConfirmErase] = useState(false);
  const { settings } = state;

  async function exportBackup() {
    const text = await Vault.exportBackup();
    downloadText(`parley-${state.account.handle}-${new Date().toISOString().slice(0, 10)}.json`, text);
    showToast("Encrypted backup downloaded");
  }

  return (
    <Modal title="Settings" onClose={onClose}>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <Avatar id={state.account.userId} name={state.account.displayName} />
        <div style={{ minWidth: 0 }}>
          <b>{state.account.displayName}</b>
          <div className="muted">@{state.account.handle}</div>
          <div className="mono muted" title="Fingerprint of your identity signing key">
            key {client.ownKeyId()}
          </div>
        </div>
      </div>

      <div>
        <div className="setting">
          <div>
            <b>Relay only</b>
            <small>Never connect directly to peers. Hides your IP address from them; messages go through the server (still end-to-end encrypted).</small>
          </div>
          <Switch label="Relay only" checked={settings.relayOnly} onChange={(v) => void client.updateSettings({ relayOnly: v })} />
        </div>
        <div className="setting">
          <div>
            <b>Read receipts</b>
            <small>Let people know when you've read their messages. Receipts are encrypted too.</small>
          </div>
          <Switch label="Read receipts" checked={settings.readReceipts} onChange={(v) => void client.updateSettings({ readReceipts: v })} />
        </div>
        <div className="setting">
          <div>
            <b>Typing indicators</b>
            <small>Sent only while the other person is online, and never stored.</small>
          </div>
          <Switch label="Typing indicators" checked={settings.typingIndicators} onChange={(v) => void client.updateSettings({ typingIndicators: v })} />
        </div>
        <div className="setting">
          <div>
            <b>Theme</b>
          </div>
          <div className="segmented" role="group" aria-label="Theme">
            {(["system", "light", "dark"] as ThemeChoice[]).map((t) => (
              <button key={t} aria-pressed={theme === t} onClick={() => setTheme(t)}>
                {t[0]!.toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>

      {state.keyHealth && (
        <p className="explain">
          {state.keyHealth.serverOneTime} one-time pre-keys published · signed pre-key #{state.keyHealth.signedPreKeyId}{" "}
          rotated {formatRelative(state.keyHealth.signedPreKeyCreatedAt)}. Keys are topped up and rotated automatically.
        </p>
      )}

      <div className="row">
        <button className="btn" onClick={() => void exportBackup()}>
          Export encrypted backup
        </button>
        <button className="btn" onClick={onLock}>
          <LockIcon size={15} /> Lock
        </button>
      </div>
      {confirmErase ? (
        <div className="callout danger">
          <AlertIcon size={16} />
          <div style={{ display: "grid", gap: 8 }}>
            <span>Sign out and permanently erase your keys and messages from this browser? Export a backup first if you want to keep them.</span>
            <div className="row">
              <button className="btn small" onClick={() => setConfirmErase(false)}>
                Cancel
              </button>
              <button className="btn small danger" onClick={onErase}>
                Erase everything
              </button>
            </div>
          </div>
        </div>
      ) : (
        <button className="btn danger" onClick={() => setConfirmErase(true)}>
          Sign out &amp; erase this device
        </button>
      )}
    </Modal>
  );
}
