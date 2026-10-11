import { useEffect, useState } from "react";
import { api, ApiError, type ServerSummary, type TenantInfo } from "./api";
import { Banner, Icon, Mono, Panel, ReachBadge, ThemeToggle, reachInfo, useResource } from "./components";
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
  /*
   * Whose rows the whole console is showing.
   *
   * `null` means "not chosen", which is a real state and not the same as the
   * empty tenant: a hosted gateway serves many tenants at once and the console
   * cannot speak for any of them until someone says which. Every scoped
   * request carries this, and the backend refuses rather than guessing, so an
   * unchosen tenant produces a visible message instead of an empty page that
   * looks like a quiet gateway.
   */
  const [tenant, setTenant] = useState<string | null>(null);

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

  const tenants = useResource(() => (active ? api.tenants(active.id) : Promise.resolve(null)), [active?.id]);

  /* A tenant chosen for one gateway means nothing on the next one. */
  useEffect(() => {
    setTenant(null);
  }, [active?.id]);

  /*
   * Where the gateway is bound to one tenant, the backend assumes it and the
   * selector simply shows which. Where it is not, nothing is chosen until
   * someone chooses.
   */
  const effectiveTenant = tenant ?? tenants.data?.assumed ?? null;

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
          <ThemeToggle />
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
              <Icon name={reachInfo(active.reach)?.icon ?? "shield"} size={13} className={liveTone(active)} />
              {reachInfo(active.reach)?.label ?? "surface unknown"}
            </span>
            {/* `toolCount` is null until a gateway reports, and null is not
                zero: rendering it as "0 functions" claimed an empty surface
                for a gateway that had simply said nothing. */}
            <span className="mt-0.5 block">
              {active.toolCount === null || active.toolCount === undefined
                ? "nothing reported yet"
                : `${active.toolCount} functions · ${active.running ? "running" : "not running"}`}
            </span>
          </div>
        )}
      </aside>

      {/* Overlaps the rail and carries a leftward shadow, so the rail reads as
          tucked behind it until it is hovered and swings forward. */}
      {/* -ml-12 is the shared seam: the card covers this strip of the rail at
          rest, and the rail covers the same strip of the card on hover. */}
      {/* The at-rest shadow is `.stage-main`'s own, in styles.css, so it themes
          with every other shadow rather than being a literal colour here. */}
      <main className="glass stage-main relative z-10 -ml-12 flex min-w-0 flex-1 flex-col overflow-hidden rounded-[20px]">
        <TopBar
          servers={list}
          active={active}
          onPick={setServerId}
          tenants={tenants.data}
          tenant={effectiveTenant}
          onPickTenant={setTenant}
        />

        <div className="flex min-h-0 flex-1 flex-col">
          {list.some((s) => !s.ok) && (
            <div className="border-b border-edge px-7 py-3">
              <Broken servers={list} />
            </div>
          )}

          {!active ? (
            <div className="min-h-0 flex-1 overflow-y-auto p-7">
              <NoServers onAdded={servers.reload} />
            </div>
          ) : tab === "functions" ? (
            /* The reach badge and the rail's summary are served by `servers`,
               not by the Functions page's own resource, so a switch flipped in
               there has to say so or the chrome keeps the old answer until the
               30s poll catches up. */
            <Functions serverId={active.id} tenant={effectiveTenant} onServerChanged={servers.reload} />
          ) : (
            <div className="min-h-0 flex-1 overflow-y-auto p-7">
              {tab === "approvals" && <Approvals serverId={active.id} tenant={effectiveTenant} />}
              {tab === "settings" && <Settings serverId={active.id} tenant={effectiveTenant} />}
              {tab === "protection" && <Protection serverId={active.id} tenant={effectiveTenant} />}
              {tab === "audit" && <Audit serverId={active.id} tenant={effectiveTenant} />}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

/* The rail stays colourless unless something is actually worth saying. */
const liveTone = (s: ServerSummary) => (s.surfaceStale ? "text-write" : "text-ink-faint");

/** The breadcrumb strip: which server is in view, and whether it is healthy. */
function TopBar({
  servers,
  active,
  onPick,
  tenants,
  tenant,
  onPickTenant
}: {
  servers: ServerSummary[];
  active: ServerSummary | null;
  onPick: (id: string) => void;
  tenants: TenantInfo | null | undefined;
  tenant: string | null;
  onPickTenant: (tenant: string | null) => void;
}) {
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

        {/*
         * Only where the gateway actually has tenants. A gateway with none
         * scopes everything to one place, and offering a choice there would
         * invent a distinction the gateway does not make.
         */}
        {active && tenants?.configured && (
          <>
            <span className="text-ink-faint">/</span>
            <Icon name="users" size={15} className="text-ink-faint" />
            <div className="relative flex items-center">
              <select
                value={tenant ?? ""}
                onChange={(e) => onPickTenant(e.target.value || null)}
                className={`mono appearance-none rounded-md bg-transparent py-1 pr-6 pl-1.5 text-sm font-medium hover:bg-subtle focus:outline-none ${
                  tenant === null ? "text-write" : ""
                }`}
                title={
                  tenants.whyNotAssumed ??
                  `Rows are keyed by tenant. This console is showing ${tenant}'s approvals, grants and switches.`
                }
              >
                <option value="">
                  {tenants.assumed === null ? "choose a tenant…" : `(${tenants.assumed})`}
                </option>
                {tenants.tenants
                  .filter((t) => t !== "")
                  .map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
              </select>
              <Icon name="chevron" size={14} className="pointer-events-none absolute right-1.5 text-ink-faint" />
            </div>
          </>
        )}
      </div>

      {active && (
        <div className="flex shrink-0 items-center gap-3 text-xs text-ink-soft">
          <span className="hidden sm:inline">
            Gateway
            {active.upstreams && active.upstreams.length > 0 ? ` · ${active.upstreams.join(", ")}` : ""}
          </span>
          {/*
           * Whether a gateway is actually running, which is the thing that
           * decides whether anything else on screen can be believed. This used
           * to report a scan verdict that was computed from an empty finding
           * list, so it said "Scan clean" about a gateway it had never heard
           * from.
           */}
          <span className="flex items-center gap-1.5">
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                active.running ? "bg-accent" : active.surfaceStale ? "bg-write" : "bg-ink-faint"
              }`}
              aria-hidden
            />
            {active.running ? "Running" : active.surfaceStale ? "Not running" : "Never reported"}
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

/*
 * A form rather than a curl snippet.
 *
 * The snippet this replaces hardcoded a port, a label and a path that were
 * nothing to do with this install, and a CSRF header it could not actually
 * produce — so it could not be copied and run as written. The console already
 * knows its own origin and holds the CSRF cookie, so it can simply do it.
 */
function NoServers({ onAdded }: { onAdded: () => void }) {
  const [label, setLabel] = useState("");
  const [configPath, setConfigPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setFailed(null);
    try {
      await api.addServer({
        id: label.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "gateway",
        kind: "gateway",
        label: label.trim() || "Gateway",
        config_path: configPath.trim(),
        added_at: new Date().toISOString()
      });
      onAdded();
    } catch (err) {
      setFailed((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="No gateway registered yet">
      <p className="text-sm text-ink-soft">
        Point the console at a gateway config. It is read, not run: registering does not connect the gateway&rsquo;s
        upstreams, and the tool list fills in once the gateway itself has started.
      </p>
      <form onSubmit={submit} className="mt-4 space-y-3">
        <label className="block">
          <span className="text-xs text-ink-soft">Name</span>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Notes gateway"
            className="mt-1 w-full rounded-lg border border-edge bg-raise px-3 py-2 text-sm"
          />
        </label>
        <label className="block">
          <span className="text-xs text-ink-soft">Path to gateway.yaml</span>
          <input
            value={configPath}
            onChange={(e) => setConfigPath(e.target.value)}
            placeholder="~/.hmcp/gateway.yaml"
            className="mono mt-1 w-full rounded-lg border border-edge bg-raise px-3 py-2 text-[0.8125rem]"
          />
        </label>
        {failed && <Banner tone="bad">{failed}</Banner>}
        <button
          type="submit"
          disabled={busy || configPath.trim().length === 0}
          className="rounded-lg border border-edge bg-raise px-3 py-1.5 text-sm font-medium hover:bg-subtle disabled:opacity-50"
        >
          {busy ? "Registering…" : "Register"}
        </button>
      </form>
      <p className="mt-3 text-sm text-ink-soft">
        Or add it to <Mono>~/.hmcp/servers.json</Mono> directly and reload.
      </p>
    </Panel>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="flex min-h-full items-center justify-center p-8 text-center">{children}</div>;
}
