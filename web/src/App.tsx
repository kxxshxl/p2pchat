import { useCallback, useEffect, useRef, useState } from "react";
import { BrandMark } from "./components/icons";
import type { Session } from "./lib/account";
import { Api } from "./lib/api";
import { ChatClient } from "./lib/client";
import { Vault } from "./lib/vault";
import { ChatScreen } from "./screens/Chat";
import { Unlock, Welcome } from "./screens/Welcome";

type Phase = "boot" | "welcome" | "locked" | "chat" | "elsewhere";

const api = new Api();

/**
 * Only one tab may drive the account at a time: two tabs advancing the same ratchet state
 * independently would desynchronise every session.
 */
function useTabLock(): { held: boolean; lost: boolean; takeOver(): void } {
  const [held, setHeld] = useState(false);
  const [lost, setLost] = useState(false);
  const release = useRef<(() => void) | null>(null);

  const acquire = useCallback((steal: boolean) => {
    if (!("locks" in navigator)) {
      setHeld(true);
      return;
    }
    const options: LockOptions = steal ? { steal: true } : { ifAvailable: true };
    navigator.locks
      .request("parley-active-tab", options, (lock) => {
        if (!lock) {
          setHeld(false);
          return undefined;
        }
        setHeld(true);
        setLost(false);
        return new Promise<void>((resolve) => {
          release.current = resolve;
        });
      })
      .catch(() => {
        // another tab stole the lock
        setHeld(false);
        setLost(true);
      });
  }, []);

  useEffect(() => {
    acquire(false);
    return () => release.current?.();
  }, [acquire]);

  return { held, lost, takeOver: () => acquire(true) };
}

export function App() {
  const [phase, setPhase] = useState<Phase>("boot");
  const [client, setClient] = useState<ChatClient | null>(null);
  const tab = useTabLock();

  useEffect(() => {
    void Vault.exists().then((exists) => setPhase(exists ? "locked" : "welcome"));
  }, []);

  useEffect(() => {
    if (tab.lost && client) {
      client.stop();
      setClient(null);
      setPhase("elsewhere");
    }
  }, [tab.lost, client]);

  const onReady = useCallback(async (session: Session) => {
    const next = new ChatClient({ api, ...session });
    await next.start();
    setClient(next);
    setPhase("chat");
  }, []);

  const lock = useCallback(() => {
    client?.stop();
    api.token = null;
    setClient(null);
    setPhase("locked");
  }, [client]);

  const erase = useCallback(async () => {
    await client?.signOut();
    await Vault.wipe();
    setClient(null);
    setPhase("welcome");
  }, [client]);

  if (!tab.held || phase === "elsewhere") {
    return (
      <div className="center-screen">
        <div className="card" style={{ textAlign: "center", justifyItems: "center" }}>
          <span className="brand-mark">
            <BrandMark />
          </span>
          <h2>Parley is open in another tab</h2>
          <p>Only one tab can use your keys at a time, so the ratchet state stays consistent.</p>
          <button className="btn primary" onClick={() => {
            tab.takeOver();
            setPhase((p) => (p === "elsewhere" ? "locked" : p));
          }}>
            Use Parley here
          </button>
        </div>
      </div>
    );
  }

  switch (phase) {
    case "boot":
      return (
        <div className="center-screen">
          <span className="spinner" />
        </div>
      );
    case "welcome":
      return <Welcome api={api} onReady={(s) => void onReady(s)} />;
    case "locked":
      return <Unlock onReady={(s) => void onReady(s)} onReset={() => setPhase("welcome")} />;
    case "chat":
      return client ? <ChatScreen client={client} onLock={lock} onErase={() => void erase()} /> : null;
    default:
      return null;
  }
}
