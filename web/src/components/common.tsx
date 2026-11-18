import { useEffect, useRef, useState, type ReactNode } from "react";
import { CloseIcon } from "./icons";

/** Deterministic avatar colour from the user id — never from the (attacker-chosen) display name. */
function hue(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return h % 360;
}

export function Avatar({
  id,
  name,
  online,
  small,
}: {
  id: string;
  name: string;
  online?: boolean;
  small?: boolean;
}) {
  const initials = name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => [...w][0]!.toUpperCase())
    .join("");
  return (
    <span className={`avatar${small ? " small" : ""}`} style={{ background: `hsl(${hue(id)} 45% 42%)` }}>
      {initials || "?"}
      {online && <span className="presence" aria-label="online" />}
    </span>
  );
}

export function Modal({
  title,
  onClose,
  children,
  labelledBy = "modal-title",
}: {
  title: string;
  onClose(): void;
  children: ReactNode;
  labelledBy?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previous?.focus?.();
    };
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={labelledBy} tabIndex={-1} ref={ref}>
        <div className="modal-head">
          <h2 id={labelledBy}>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function Switch({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange(value: boolean): void;
  label: string;
}) {
  return (
    <label className="switch">
      <input type="checkbox" role="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} aria-label={label} />
      <span />
    </label>
  );
}

export function useToast(): [string | null, (text: string) => void] {
  const [text, setText] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const show = (value: string) => {
    setText(value);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setText(null), 3500);
  };
  return [text, show];
}

export function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

export function formatDay(ts: number): string {
  const d = new Date(ts);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86_400_000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
}

export function formatRelative(ts: number | null | undefined): string {
  if (!ts) return "";
  const diff = Date.now() - ts;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return new Date(ts).toLocaleDateString([], { month: "short", day: "numeric" });
}

export function formatShortTime(ts: number): string {
  const d = new Date(ts);
  if (d.toDateString() === new Date().toDateString()) return formatTime(ts);
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}
