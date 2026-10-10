import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { Reach } from "./api";
import { useTheme } from "./theme";

/* -------------------------------------------------------------------- icons */

const PATHS: Record<string, React.ReactNode> = {
  servers: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="2" />
      <rect x="3" y="13" width="18" height="7" rx="2" />
    </>
  ),
  functions: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M3 9h18M9 9v11" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  check: <path d="M20 6 9 17l-5-5" />,
  "check-circle": (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M8.5 12.5 11 15l4.5-5" />
    </>
  ),
  shield: <path d="M12 3l7 3v5.5c0 4.2-2.9 7.6-7 9.5-4.1-1.9-7-5.3-7-9.5V6l7-3z" />,
  "shield-check": (
    <>
      <path d="M12 3l7 3v5.5c0 4.2-2.9 7.6-7 9.5-4.1-1.9-7-5.3-7-9.5V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  list: <path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01" />,
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </>
  ),
  chevron: <path d="m6 9 6 6 6-6" />,
  lock: (
    <>
      <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
      <path d="M8 10.5V7a4 4 0 0 1 8 0v3.5" />
    </>
  ),
  /* Reads: an eye, open. */
  eye: (
    <>
      <path d="M2.5 12S6.2 5.8 12 5.8 21.5 12 21.5 12 17.8 18.2 12 18.2 2.5 12 2.5 12z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  /* Writes: a pen over a sheet. The sheet is the `file` outline cut short at
     the lower right so the nib has somewhere to land. */
  "pen-file": (
    <>
      <path d="M19 11V8l-5-5H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h4" />
      <path d="M14 3v5h5" />
      <path d="M20.3 13.9a1.6 1.6 0 0 1 0 2.3l-4.7 4.7-3.1.8.8-3.1 4.7-4.7a1.6 1.6 0 0 1 2.3 0z" />
    </>
  ),
  /* The three reach marks. One family, not three borrowed glyphs: the same
     shield every time, carrying the glyph for what the shield is holding back.
     Drawn like `shield-check` — outline plus one simple interior shape — because
     that is the detail level that survives the 13px the reach badge renders at.
     Kept inside x 8–16.5, y 8–15.5, which is the shield's clear interior before
     it narrows to the tip. */
  "reach-read": (
    <>
      <path d="M12 3l7 3v5.5c0 4.2-2.9 7.6-7 9.5-4.1-1.9-7-5.3-7-9.5V6l7-3z" />
      <path d="M8.8 11.6c.9-1.3 1.9-2 3.2-2s2.3.7 3.2 2c-.9 1.3-1.9 2-3.2 2s-2.3-.7-3.2-2z" />
      {/* Filled, not stroked: at 1.7 a stroked pupil closes the lens into a blob. */}
      <circle cx="12" cy="11.6" r=".9" fill="currentColor" stroke="none" />
    </>
  ),
  "reach-write": (
    <>
      <path d="M12 3l7 3v5.5c0 4.2-2.9 7.6-7 9.5-4.1-1.9-7-5.3-7-9.5V6l7-3z" />
      <path d="M14.4 8.2a1.15 1.15 0 0 1 1.6 1.6l-4.3 4.3-2.2.6.6-2.2 4.3-4.3z" />
    </>
  ),
  "reach-locked": (
    <>
      <path d="M12 3l7 3v5.5c0 4.2-2.9 7.6-7 9.5-4.1-1.9-7-5.3-7-9.5V6l7-3z" />
      <rect x="9.2" y="11" width="5.6" height="4" rx="1" />
      <path d="M10.4 11V9.9a1.6 1.6 0 0 1 3.2 0V11" />
    </>
  ),
  alert: (
    <>
      <path d="M10.3 4.3 2.8 17.2A2 2 0 0 0 4.5 20.2h15a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z" />
      <path d="M12 9.5v4M12 17h.01" />
    </>
  ),
  external: <path d="M14 4h6v6M20 4l-8.5 8.5M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" />,
  file: (
    <>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <path d="M14 3v5h5" />
    </>
  ),
  plug: (
    <>
      <path d="M9 3v6M15 3v6" />
      <path d="M6 9h12v3a6 6 0 0 1-12 0z" />
      <path d="M12 18v3" />
    </>
  ),
  braces: <path d="M8 4c-2 0-2 3-2 4s0 3-2 4c2 1 2 3 2 4s0 4 2 4M16 4c2 0 2 3 2 4s0 3 2 4c-2 1-2 3-2 4s0 4-2 4" />,
  timer: (
    <>
      <circle cx="12" cy="13" r="8" />
      <path d="M12 9.5V13l2.5 1.5M9.5 2.5h5" />
    </>
  ),
  sort: <path d="M4 7h10M4 12h7M4 17h4M17 5v14M17 19l3-3M17 19l-3-3" />,
  "arrow-down": <path d="M12 5v14M12 19l5-5M12 19l-5-5" />,
  "arrow-up": <path d="M12 19V5M12 5l5 5M12 5 7 10" />,
  collapse: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M15 4v16M11.5 10l-2.5 2 2.5 2" />
    </>
  ),
  expand: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M15 4v16M9 10l2.5 2L9 14" />
    </>
  ),
  refresh: <path d="M20 11a8 8 0 1 0-.7 4M20 5v6h-6" />,
  download: <path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19h14" />,
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15a2 2 0 0 1-1-1.7V6a2 2 0 0 1 2-2h7.3A2 2 0 0 1 15 5" />
    </>
  ),
  close: <path d="M6 6l12 12M18 6 6 18" />,
  spinner: <path d="M12 3a9 9 0 1 0 9 9" />,
  sun: (
    <>
      <circle cx="12" cy="12" r="4.2" />
      <path d="M12 2.6v2.1M12 19.3v2.1M4.4 4.4l1.5 1.5M18.1 18.1l1.5 1.5M2.6 12h2.1M19.3 12h2.1M4.4 19.6l1.5-1.5M18.1 5.9l1.5-1.5" />
    </>
  ),
  /* A waning crescent rather than a filled disc: at 15px a stroked outline is
     the only form that still reads as a moon next to the sun's rays. */
  moon: <path d="M20.2 14.4A8.4 8.4 0 0 1 9.6 3.8a8.4 8.4 0 1 0 10.6 10.6z" />
};

export function Icon({
  name,
  size = 16,
  className = ""
}: {
  name: keyof typeof PATHS | string;
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 ${className}`}
      aria-hidden
    >
      {PATHS[name] ?? null}
    </svg>
  );
}

/* ------------------------------------------------------------------- badges */

const EFFECT_STYLE: Record<string, string> = {
  read: "text-read border-read/40 bg-read/10",
  write: "text-write border-write/40 bg-write/10",
  destructive: "text-destructive border-destructive/40 bg-destructive/10"
};

const VERDICT_STYLE: Record<string, string> = {
  allow: "text-allow border-allow/40 bg-allow/10",
  approve: "text-approve border-approve/40 bg-approve/10",
  deny: "text-deny border-deny/40 bg-deny/10"
};

const SEVERITY_STYLE: Record<string, string> = {
  high: "text-high border-high/40 bg-high/10",
  medium: "text-medium border-medium/40 bg-medium/10",
  low: "text-low border-low/40 bg-low/10"
};

function Pill({ tone, children, title }: { tone: string; children: React.ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${tone}`}
    >
      {children}
    </span>
  );
}

/** Always carries the word, never colour alone. */
export const EffectBadge = ({ effect }: { effect: string }) => (
  <Pill tone={EFFECT_STYLE[effect] ?? SEVERITY_STYLE["low"]!}>{effect}</Pill>
);

export const VerdictBadge = ({ kind, title }: { kind: string; title?: string }) => (
  <Pill tone={VERDICT_STYLE[kind] ?? SEVERITY_STYLE["low"]!} title={title}>
    {kind === "allow" ? "allowed" : kind === "approve" ? "needs approval" : "refused"}
  </Pill>
);

export const SeverityBadge = ({ severity }: { severity: string }) => (
  <Pill tone={SEVERITY_STYLE[severity] ?? SEVERITY_STYLE["low"]!}>{severity}</Pill>
);

export const Tag = ({ children, title }: { children: React.ReactNode; title?: string }) => (
  <Pill tone="text-ink-soft border-edge bg-edge/30" title={title}>
    {children}
  </Pill>
);

/**
 * How each reach state is named, drawn and toned. One table, so the breadcrumb,
 * the rail and a page header cannot end up describing the same server three
 * different ways — which is how the old badge drifted from the rest of the page
 * in the first place.
 *
 * A traffic-light scale, read at a glance: green where nothing can be changed,
 * amber where writes are in reach, red where the surface is shut. The amber is
 * the existing write colour, so a surface that can write stays coloured like
 * the write functions that make it one.
 *
 * `key` stays in the API's spelling (`read-only`, `approve-writes`, `locked`)
 * while `label` is the display form. They are deliberately separate: the key is
 * a wire value the server sends and must not be retyped for presentation.
 */
export const REACH: Record<Reach, { key: Reach; label: string; icon: string; tone: string; title: string }> = {
  "read-only": {
    key: "read-only",
    label: "Read Only",
    icon: "reach-read",
    tone: "text-allow border-allow/40 bg-allow/10",
    title: "Only read functions can run. Nothing the model calls here can change data upstream."
  },
  "approve-writes": {
    key: "approve-writes",
    label: "Write",
    icon: "reach-write",
    tone: "text-write border-write/40 bg-write/10",
    title: "Functions that change data are reachable — some outright, some only after an approval."
  },
  locked: {
    key: "locked",
    label: "Locked",
    icon: "reach-locked",
    tone: "text-deny border-deny/40 bg-deny/10",
    title: "Nothing is reachable: every advertised function is refused by policy or switched off here."
  }
};

/**
 * The table lookup, never done inline.
 *
 * `reach` is absent on a server the console could not load, and on any API
 * older than the field itself — a running console serves the UI bundle off
 * disk, so a rebuilt front end routinely meets a server process that predates
 * it. Indexing `REACH` directly made that case throw during render, which took
 * the whole page down rather than the one badge.
 */
export const reachInfo = (reach: string | undefined | null) =>
  (reach !== undefined && reach !== null ? REACH[reach as Reach] : undefined) ?? null;

/** The scale, in the order a reader should meet it: most constrained first. */
const REACH_ORDER: readonly Reach[] = ["read-only", "approve-writes", "locked"];

/**
 * The whole reach scale, not just this server's place on it.
 *
 * The badge alone answers "what is this server?" but not "as against what?",
 * and the three states only mean anything as a set — `read-only` is reassuring
 * precisely because `approve-writes` was possible and is not the case here. So
 * the popover shows all three, each with its own mark, with this server's row
 * called out, rather than explaining the one state in isolation.
 *
 * Portalled to the body for the same reason `Modal` is: the badge sits inside
 * the `.glass` card, which clips and, carrying `will-change`, is the containing
 * block for `position: fixed` — rendered in place the panel would be positioned
 * against the card and then clipped by it.
 */
function ReachLegend({
  current,
  anchor,
  onClose,
  onPointerEnter,
  onPointerLeave
}: {
  current: Reach | null;
  anchor: DOMRect;
  onClose: () => void;
  onPointerEnter: () => void;
  onPointerLeave: () => void;
}) {
  const panel = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  // Placed after a measuring pass rather than from a guessed height: the panel
  // is opened from a header at the top of the window and from a field far down
  // the Protection page, and only the real height says which side it fits on.
  useEffect(() => {
    const el = panel.current;
    if (!el) return;
    const { width, height } = el.getBoundingClientRect();
    const margin = 8;
    const left = Math.min(Math.max(margin, anchor.left), window.innerWidth - width - margin);
    const below = anchor.bottom + 6;
    const top = below + height + margin > window.innerHeight ? Math.max(margin, anchor.top - height - 6) : below;
    setPos({ top, left });
  }, [anchor]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    // Scrolling moves the anchor out from under a fixed panel, so close rather
    // than chase it. `capture` catches scrolls inside the page's own panes too.
    addEventListener("keydown", onKey);
    addEventListener("scroll", onClose, true);
    addEventListener("resize", onClose);
    return () => {
      removeEventListener("keydown", onKey);
      removeEventListener("scroll", onClose, true);
      removeEventListener("resize", onClose);
    };
  }, [onClose]);

  return createPortal(
    <div
      ref={panel}
      role="dialog"
      aria-label="What each reach state means"
      onPointerEnter={onPointerEnter}
      onPointerLeave={onPointerLeave}
      style={{
        top: pos?.top ?? anchor.bottom + 6,
        left: pos?.left ?? anchor.left,
        // Hidden for the measuring pass only, so the panel is never seen at the
        // wrong place before it is told the right one.
        visibility: pos ? "visible" : "hidden"
      }}
      className="glass-modal glass-pop fixed z-50 w-[22rem] max-w-[calc(100vw-1rem)] rounded-xl p-3 text-[0.8125rem] leading-relaxed"
    >
      <p className="mb-2 px-0.5 text-xs font-semibold text-ink-soft">What the model can reach here</p>
      <ul className="flex flex-col gap-1">
        {REACH_ORDER.map((key) => {
          const entry = REACH[key];
          const active = key === current;
          return (
            <li
              key={key}
              className={`rounded-lg px-2 py-1.5 ${active ? "bg-edge/40 ring-1 ring-edge" : ""}`}
              {...(active ? { "aria-current": "true" as const } : {})}
            >
              <div className="mb-0.5 flex items-center gap-1.5">
                <Pill tone={entry.tone}>
                  <Icon name={entry.icon} size={12} />
                  {entry.label}
                </Pill>
                {/* Named, not just highlighted: the ring alone is colour, and
                    this is the one row the reader is actually standing on. */}
                {active && <span className="text-xs font-medium text-ink-soft">this server</span>}
              </div>
              <p className="text-ink-soft">{entry.title}</p>
            </li>
          );
        })}
      </ul>
    </div>,
    document.body
  );
}

/**
 * What the model can actually do, as measured. Never `defaults.mode` — that is
 * what policy falls back to, and the Protection page is where it belongs.
 *
 * Renders nothing at all when the state is unknown: a missing badge reads as
 * "not reported", while a guessed one would read as a claim about the server.
 *
 * Hover or click opens the full scale. Both, because the two are different
 * questions — a pointer passing over wants the reminder, a click wants to read
 * and compare — and because hover alone would put the explanation out of reach
 * of the keyboard and of touch.
 */
export const ReachBadge = ({ reach, size = 12 }: { reach: string | undefined | null; size?: number }) => {
  const r = reachInfo(reach);
  const [open, setOpen] = useState(false);
  const [anchor, setAnchor] = useState<DOMRect | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const closing = useRef<number | undefined>(undefined);

  const show = () => {
    clearTimeout(closing.current);
    const rect = trigger.current?.getBoundingClientRect();
    if (rect) setAnchor(rect);
    setOpen(true);
  };

  // A grace period, so the pointer can cross the gap between the badge and the
  // panel without the panel vanishing underneath it mid-travel.
  const hide = () => {
    clearTimeout(closing.current);
    closing.current = window.setTimeout(() => setOpen(false), 120);
  };

  const close = () => {
    clearTimeout(closing.current);
    setOpen(false);
  };

  useEffect(() => () => clearTimeout(closing.current), []);

  if (!r) return null;
  return (
    <>
      <button
        ref={trigger}
        type="button"
        aria-expanded={open}
        aria-label={`Reach: ${r.label}. ${r.title}`}
        onPointerEnter={show}
        onPointerLeave={hide}
        onFocus={show}
        onBlur={hide}
        onClick={() => (open ? close() : show())}
        className="rounded-full focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      >
        <Pill tone={`${r.tone} cursor-help`}>
          <Icon name={r.icon} size={size} />
          {r.label}
        </Pill>
      </button>
      {open && anchor && (
        <ReachLegend
          current={r.key}
          anchor={anchor}
          onClose={close}
          onPointerEnter={() => clearTimeout(closing.current)}
          onPointerLeave={hide}
        />
      )}
    </>
  );
};

/* -------------------------------------------------------------------- layout */

export function Panel({
  title,
  subtitle,
  children,
  actions
}: {
  title?: string;
  subtitle?: string;
  children: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border border-edge bg-raise">
      {title && (
        <header className="flex items-start justify-between gap-4 border-b border-edge px-4 py-3">
          <div>
            <h2 className="text-sm font-semibold">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-ink-soft">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="px-4 py-3">{children}</div>
    </section>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-ink-soft">{label}</dt>
      <dd className="text-sm">{children}</dd>
    </div>
  );
}

export const Mono = ({ children }: { children: React.ReactNode }) => (
  <code className="mono rounded bg-edge/40 px-1 py-0.5 text-[0.8em]">{children}</code>
);

export function Button({
  children,
  onClick,
  tone = "neutral",
  disabled,
  type = "button"
}: {
  children: React.ReactNode;
  onClick?: () => void;
  tone?: "neutral" | "primary" | "approve" | "deny";
  disabled?: boolean;
  type?: "button" | "submit";
}) {
  const tones = {
    neutral: "border-edge bg-raise-strong shadow-xs hover:bg-raise-hover",
    primary: "border-transparent bg-mint text-on-mint shadow-xs hover:brightness-95",
    approve: "border-allow/50 text-allow hover:bg-allow/10",
    deny: "border-deny/50 text-deny hover:bg-deny/10"
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${tones[tone]}`}
    >
      {children}
    </button>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="py-6 text-center text-sm text-ink-soft">{children}</p>;
}

/**
 * Hover text that actually appears.
 *
 * The native `title` attribute needs a second of stillness, draws in OS chrome
 * and on some setups never shows at all, which makes it useless for explaining
 * a control. This draws the bubble itself: shown on hover and on keyboard focus,
 * positioned from the trigger's rect and rendered through a portal with
 * `position: fixed`, so a scrolling ancestor cannot clip it. It closes on scroll
 * rather than following the trigger, which is cheaper than tracking and reads
 * the same at this size.
 */
export function Hint({ label, children }: { label: string; children: React.ReactNode }) {
  const ref = useRef<HTMLSpanElement>(null);
  const [at, setAt] = useState<{ top: number; left: number } | null>(null);

  function show() {
    const box = ref.current?.getBoundingClientRect();
    if (box) setAt({ top: box.bottom + 8, left: box.left + box.width / 2 });
  }
  const hide = () => setAt(null);

  useEffect(() => {
    if (!at) return;
    window.addEventListener("scroll", hide, true);
    window.addEventListener("resize", hide);
    return () => {
      window.removeEventListener("scroll", hide, true);
      window.removeEventListener("resize", hide);
    };
  }, [at]);

  return (
    <span
      ref={ref}
      className="contents"
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
      /* A tap should not leave the bubble stranded on a touch screen. */
      onTouchStart={hide}
    >
      {children}
      {at &&
        createPortal(
          <span
            role="tooltip"
            style={{ top: at.top, left: at.left }}
            className="pointer-events-none fixed z-50 max-w-72 -translate-x-1/2 rounded-lg bg-ink px-2.5 py-1.5 text-xs leading-snug text-surface shadow-lg"
          >
            {label}
          </span>,
          document.body
        )}
    </span>
  );
}

export function Banner({ tone, children }: { tone: "ok" | "warn" | "bad"; children: React.ReactNode }) {
  const tones = {
    ok: "border-allow/40 bg-allow/10 text-allow",
    warn: "border-medium/40 bg-medium/10 text-medium",
    bad: "border-deny/40 bg-deny/10 text-deny"
  };
  return <div className={`rounded-md border px-3 py-2 text-sm ${tones[tone]}`}>{children}</div>;
}

/**
 * A modal dialog. Escape and a click on the backdrop both cancel, and focus
 * lands inside it so the keyboard is not left behind on the page underneath.
 *
 * Portalled to the body, which is not cosmetic. Rendered in place it would sit
 * inside the content card, and the card is `.glass` with `will-change` and
 * `overflow: hidden` — so it is the containing block for `position: fixed`, it
 * clips, and, because it carries a `backdrop-filter` of its own, it is a
 * backdrop root. Anything inside it can only sample the card's own frosted
 * output, never the page, so the dialog's glass would have nothing behind it
 * to refract and the scrim would cover the card alone and leave the rail lit.
 */
export function Modal({
  title,
  onClose,
  children,
  footer
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    addEventListener("keydown", onKey);
    panel.current?.querySelector<HTMLElement>("button, input")?.focus();
    return () => removeEventListener("keydown", onKey);
  }, [onClose]);

  return createPortal(
    <div
      role="presentation"
      onClick={onClose}
      className="modal-scrim fixed inset-0 z-50 flex items-center justify-center p-6"
    >
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
        className="glass-modal w-full max-w-md overflow-hidden rounded-2xl"
      >
        <header className="modal-rule flex items-start justify-between gap-3 border-b px-5 py-3.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1 text-ink-faint transition hover:bg-raise-strong hover:text-ink"
          >
            <Icon name="close" size={15} />
          </button>
        </header>
        <div className="px-5 py-4 text-[0.8125rem] leading-relaxed">{children}</div>
        {footer && <footer className="modal-rule flex items-center gap-2 border-t px-5 py-3">{footer}</footer>}
      </div>
    </div>,
    document.body
  );
}

/**
 * A warning the user can switch off for good.
 *
 * Stored per browser rather than on the server: it is a preference about how
 * much hand-holding this person wants, not a property of the server being
 * reviewed, and it must never travel with the configuration. A browser that
 * refuses storage simply keeps showing the warning, which is the safe way for
 * this to fail.
 */
export function useDismissed(key: string): { dismissed: boolean; dismiss: () => void } {
  const storageKey = `hmcp.dismissed.${key}`;
  const [dismissed, setDismissed] = useState(() => {
    try {
      return localStorage.getItem(storageKey) === "1";
    } catch {
      return false;
    }
  });
  return {
    dismissed,
    dismiss: () => {
      try {
        localStorage.setItem(storageKey, "1");
      } catch {
        /* a session without storage keeps being warned */
      }
      setDismissed(true);
    }
  };
}

/**
 * The light/dark control, in the rail's header.
 *
 * Shows the theme it would switch *to* rather than the one in force: the pane
 * around it already says which that is, so drawing the current state would make
 * the button the one thing on screen that has to be read twice.
 */
export function ThemeToggle() {
  const { theme, toggle, following } = useTheme();
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${next} mode${following ? " (currently following the system)" : ""}`}
      title={`Switch to ${next} mode`}
      className="nav-item glass-item ml-auto flex h-8 w-8 items-center justify-center rounded-[10px] text-ink-soft hover:text-ink"
    >
      <Icon name={next === "dark" ? "moon" : "sun"} size={15} />
    </button>
  );
}

/* ---------------------------------------------------------------- redaction */

const REDACTION_HELP: Record<string, string> = {
  key: "The argument's name looked like a secret, so the value was hidden by name rather than by content. A harmless value can be hidden this way.",
  circular: "The value referred back to itself.",
  "max-depth": "The value was nested deeper than the redactor follows."
};

/**
 * Renders a redaction marker as an explained chip.
 *
 * The markers are meaningful but cryptic, and one of them fires on an argument
 * merely *named* `session`. Printing them raw invites the conclusion that a
 * secret leaked, so each is labelled with why the value is not shown.
 */
function RedactionChip({ pattern }: { pattern: string }) {
  const help =
    REDACTION_HELP[pattern] ??
    `The value matched a known credential shape (${pattern}), so it was replaced before being written to disk.`;
  return (
    <span
      title={help}
      className="inline-flex items-center gap-1 rounded border border-edge bg-edge/40 px-1.5 py-0.5 text-xs text-ink-soft"
    >
      <span aria-hidden>•</span>
      redacted
      {pattern !== "key" && <span className="opacity-70">— {pattern}</span>}
    </span>
  );
}

function RedactedValue({ value }: { value: unknown }) {
  if (typeof value === "string") {
    const marker = /^\[redacted:([a-z0-9-]+)\]$/.exec(value);
    if (marker) return <RedactionChip pattern={marker[1]!} />;
    const truncated = /^(.*)…\[truncated (\d+) chars\]$/s.exec(value);
    if (truncated) {
      return (
        <span>
          <span className="mono">{truncated[1]}</span>
          <span className="ml-1 text-xs text-ink-soft">+{truncated[2]} more characters</span>
        </span>
      );
    }
    return <span className="mono break-all">{value}</span>;
  }
  if (value === null) return <span className="text-ink-soft">null</span>;
  if (typeof value !== "object") return <span className="mono">{String(value)}</span>;

  if (Array.isArray(value)) {
    return (
      <ol className="ml-4 list-decimal space-y-0.5">
        {value.map((item, i) => (
          <li key={i}>
            <RedactedValue value={item} />
          </li>
        ))}
      </ol>
    );
  }
  return (
    <dl className="space-y-0.5">
      {Object.entries(value as Record<string, unknown>).map(([k, v]) => (
        <div key={k} className="flex flex-wrap items-baseline gap-2">
          <dt className="mono text-xs text-ink-soft">{k}</dt>
          <dd>
            <RedactedValue value={v} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function RedactedArgs({ args, error }: { args: unknown; error?: string | null }) {
  if (error) return <p className="text-xs text-medium">{error}</p>;
  if (args === null || args === undefined) return <p className="text-xs text-ink-soft">no arguments recorded</p>;
  if (typeof args === "object" && !Array.isArray(args) && Object.keys(args).length === 0) {
    return <p className="text-xs text-ink-soft">no arguments</p>;
  }
  return (
    <div className="rounded border border-edge bg-raise px-2 py-1.5">
      <RedactedValue value={args} />
    </div>
  );
}

/* -------------------------------------------------------------------- hooks */

/**
 * Fetch with optional polling, paused while the tab is hidden so a console
 * left open overnight is not asking questions nobody is reading.
 */
export function useResource<T>(
  load: () => Promise<T>,
  deps: unknown[],
  intervalMs?: number
): { data: T | null; error: string | null; loading: boolean; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    let live = true;
    setLoading(true);
    loadRef
      .current()
      .then((value) => {
        if (!live) return;
        setData(value);
        setError(null);
      })
      .catch((err: Error) => live && setError(err.message))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  useEffect(() => {
    if (!intervalMs) return;
    const id = setInterval(() => {
      if (!document.hidden) setTick((t) => t + 1);
    }, intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);

  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}

export function relativeTime(ms: number): string {
  const delta = ms - Date.now();
  const abs = Math.abs(delta);
  const unit = abs < 60_000 ? "s" : abs < 3_600_000 ? "m" : abs < 86_400_000 ? "h" : "d";
  const divisor = unit === "s" ? 1000 : unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000;
  const value = Math.round(abs / divisor);
  return delta >= 0 ? `in ${value}${unit}` : `${value}${unit} ago`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}
