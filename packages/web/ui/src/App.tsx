import { useEffect, useState } from "react";
import { api, ApiError, type ServerSummary } from "./api";
import { Banner, Icon, Mono, Panel, ReachBadge, reachInfo, useResource } from "./components";
import { Functions } from "./pages/Functions";
import { Approvals } from "./pages/Approvals";
import { Settings } from "./pages/Settings";
import { Protection } from "./pages/Protection";
import { Audit } from "./pages/Audit";

type Tab = "functions" | "approvals" | "settings" | "protection" | "audit";

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: "functions", label: "Functions", icon: "functions" },
  { id: "approvals", label: "Approvals", icon: "clock" },
  { id: "settings", label: "Pre-approvals", icon: "check-circle" },
  { id: "protection", label: "Protection", icon: "shield" },
  { id: "audit", label: "Audit log", icon: "list" }
];

function currentTab(): Tab {
  const path = location.pathname.replace(/^\//, "");
  return (TABS.find((t) => t.id === path)?.id ?? "functions") as Tab;
}

export function App() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  /**
   * The startup URL carries the token once. It is exchanged for an HttpOnly
   * cookie and then removed from the address bar, so it does not linger in
   * history or in a Referer.
   */
  useEffect(() => {
    const token = new URLSearchParams(location.search).get("t");
    const settle = (ok: boolean) => setAuthed(ok);

    if (token) {
      api
        .session(token)
        .then(() => {
          history.replaceState(null, "", location.pathname);
          settle(true);
        })
        .catch((err: Error) => {
          setAuthError(err.message);
          settle(false);
        });
      return;
    }
    // No token in the URL: a cookie from earlier may still be good.
    api
      .servers()
      .then(() => settle(true))
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) settle(false);
        else setAuthError(String(err.message));
        settle(false);
      });
  }, []);

  if (authed === null) return <Centered>Connecting…</Centered>;
  if (!authed) {
    return (
      <Centered>
        <div className="max-w-md space-y-3">
          <h1 className="text-lg font-semibold">This console needs the startup link</h1>
          <p className="text-sm text-ink-soft">
            Open the URL that <Mono>hmcp-web</Mono> printed when it started. It carries a one-time token
            which is exchanged for a session.
          </p>
          {authError && <Banner tone="bad">{authError}</Banner>}
        </div>
      </Centered>
    );
  }

  return <Shell />;
}

function Shell() {
  const servers = useResource(() => api.servers(), [], 30000);
  const [serverId, setServerId] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>(currentTab());

  useEffect(() => {
    const onPop = () => setTab(currentTab());
    addEventListener("popstate", onPop);
    return () => removeEventListener("popstate", onPop);
  }, []);

  function go(next: Tab) {
    setTab(next);
    history.pushState(null, "", `/${next}`);
  }

  const list = servers.data ?? [];
  const usable = list.filter((s) => s.ok);
  const active = usable.find((s) => s.id === serverId) ?? usable[0] ?? null;

  useEffect(() => {
    if (active && active.id !== serverId) setServerId(active.id);
  }, [active, serverId]);

  if (servers.error) {
    return (
      <Centered>
        <Banner tone="bad">{servers.error}</Banner>
      </Centered>
    );
  }
  if (servers.loading && list.length === 0) return <Centered>Loading servers…</Centered>;

  return (
    <div className="stage flex h-screen gap-0 p-3">
      <aside className="glass rail flex w-[268px] shrink-0 flex-col rounded-[20px] p-3">
        <div className="flex items-center gap-2.5 px-2 py-2">
          <span className="glass-item flex h-8 w-8 items-center justify-center rounded-[10px] text-ink">
            <Icon name="shield-check" size={17} />
          </span>
          <span className="leading-tight">
            <span className="block text-[0.8125rem] font-semibold tracking-tight">hardened-mcp</span>
            <span className="block text-[0.6875rem] text-ink-soft">console</span>
          </span>
        </div>

        <nav className="mt-4 flex flex-col gap-0.5">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => go(t.id)}
              className={`nav-item flex items-center gap-2.5 rounded-xl px-3 py-2 text-left text-[0.8125rem] font-medium ${
                tab === t.id
                  ? "nav-selected text-accent-strong"
                  : "text-ink-soft hover:bg-accent/14 hover:text-ink"
              }`}
            >
              <Icon name={t.icon} size={16} className={tab === t.id ? "text-accent-strong" : "text-ink-faint"} />
              {t.label}
            </button>
          ))}
        </nav>

        {active && (
          <div className="mt-auto rounded-xl px-3 py-2.5 text-[0.6875rem] leading-relaxed text-ink-soft">
            <span className="flex items-center gap-1.5 font-medium text-ink">
              <Icon name={reachInfo(active.reach)?.icon ?? "shield"} size={13} className={scanTone(active)} />
              {reachInfo(active.reach)?.label ?? "not reported"}
            </span>
            <span className="mt-0.5 block">
              {active.toolCount ?? 0} functions · {findingCount(active)} findings
            </span>
          </div>
        )}
      </aside>

      {/* Overlaps the rail and carries a leftward shadow, so the rail reads as
          tucked behind it until it is hovered and swings forward. */}
      {/* -ml-12 is the shared seam: the card covers this strip of the rail at
          rest, and the rail covers the same strip of the card on hover. */}
      <main className="glass stage-main relative z-10 -ml-12 flex min-w-0 flex-1 flex-col overflow-hidden rounded-[20px] shadow-[-22px_0_44px_-26px_oklch(0.2_0_0/40%),0_14px_44px_-20px_oklch(0.2_0_0/26%)]">
        <TopBar servers={list} active={active} onPick={setServerId} />

        <div className="flex min-h-0 flex-1 flex-col">
          {list.some((s) => !s.ok) && (
            <div className="border-b border-edge px-7 py-3">
              <Broken servers={list} />
            </div>
          )}

          {!active ? (
            <div className="min-h-0 flex-1 overflow-y-auto p-7">
              <NoServers />
            </div>
          ) : tab === "functions" ? (
            /* The reach badge and the rail's summary are served by `servers`,
               not by the Functions page's own resource, so a switch flipped in
               there has to say so or the chrome keeps the old answer until the
               30s poll catches up. */
            <Functions serverId={active.id} onServerChanged={servers.reload} />
          ) : (
            <div className="min-h-0 flex-1 overflow-y-auto p-7">
              {tab === "approvals" && <Approvals serverId={active.id} />}
              {tab === "settings" && <Settings serverId={active.id} />}
              {tab === "protection" && <Protection serverId={active.id} />}
              {tab === "audit" && <Audit serverId={active.id} />}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

const highCount = (s: ServerSummary) => s.counts?.["high"] ?? 0;
const findingCount = (s: ServerSummary) => Object.values(s.counts ?? {}).reduce((a, b) => a + b, 0);
/* The rail stays colourless unless something is actually wrong. */
const scanTone = (s: ServerSummary) => (highCount(s) > 0 ? "text-deny" : "text-ink-faint");

/** The breadcrumb strip: which server is in view, and whether it is healthy. */
function TopBar({
  servers,
  active,
  onPick
}: {
  servers: ServerSummary[];
  active: ServerSummary | null;
  onPick: (id: string) => void;
}) {
  const high = active ? highCount(active) : 0;
  return (
    <header className="flex items-center justify-between gap-4 border-b border-edge px-5 py-2.5">
      <div className="flex min-w-0 items-center gap-2 text-sm">
        <Icon name="servers" size={16} className="text-ink-faint" />
        <span className="text-ink-soft">Servers</span>
        <span className="text-ink-faint">/</span>
        <div className="relative flex items-center">
          <select
            value={active?.id ?? ""}
            onChange={(e) => onPick(e.target.value)}
            className="mono appearance-none rounded-md bg-transparent py-1 pr-6 pl-1.5 text-sm font-medium hover:bg-subtle focus:outline-none"
          >
            {servers.map((s) => (
              <option key={s.id} value={s.id} disabled={!s.ok}>
                {s.label} {s.ok ? "" : "(unavailable)"}
              </option>
            ))}
          </select>
          <Icon name="chevron" size={14} className="pointer-events-none absolute right-1.5 text-ink-faint" />
        </div>
        {active?.reach && <ReachBadge reach={active.reach} />}
      </div>

      {active && (
        <div className="flex shrink-0 items-center gap-3 text-xs text-ink-soft">
          <span className="hidden sm:inline">
            {active.kind === "gateway" ? "Gateway" : "Generated"}
            {active.api?.title ? ` · ${active.api.title}` : ""}
          </span>
          <span className="flex items-center gap-1.5">
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                high > 0 ? "bg-deny" : findingCount(active) > 0 ? "bg-write" : "bg-accent"
              }`}
              aria-hidden
            />
            {high > 0
              ? `${high} high findings`
              : findingCount(active) > 0
                ? `${findingCount(active)} findings`
                : "Scan clean"}
          </span>
          {active.tenantError && (
            <span className="flex items-center gap-1 text-write" title={active.tenantError}>
              <Icon name="alert" size={13} /> tenant unresolved
            </span>
          )}
        </div>
      )}
    </header>
  );
}

function Broken({ servers }: { servers: ServerSummary[] }) {
  const broken = servers.filter((s) => !s.ok);
  if (broken.length === 0) return null;
  return (
    <div className="mb-4 space-y-2">
      {broken.map((s) => (
        <Banner key={s.id} tone="warn">
          <strong>{s.label}</strong> could not be loaded: {s.error}
        </Banner>
      ))}
    </div>
  );
}

function NoServers() {
  return (
    <Panel title="No server registered yet">
      <p className="text-sm text-ink-soft">
        Register a generated server directory — the one holding <Mono>tools.json</Mono> and{" "}
        <Mono>policy.yaml</Mono> — or a gateway config:
      </p>
      <pre className="mono mt-3 overflow-x-auto rounded-md border border-edge bg-surface p-3 text-xs">
        {`curl -s localhost:7777/api/v1/servers \\
  -H 'Content-Type: application/json' \\
  -H "X-HMCP-CSRF: $(...)" \\
  -d '{"kind":"generated","label":"Billing","dir":"/path/to/billing-mcp"}'`}
      </pre>
      <p className="mt-3 text-sm text-ink-soft">
        Or add it to <Mono>~/.hmcp/servers.json</Mono> directly and reload.
      </p>
    </Panel>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="flex min-h-full items-center justify-center p-8 text-center">{children}</div>;
}
