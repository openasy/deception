import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  DonutChart,
  EmptyState,
  EntityChip,
  FacetFilter,
  FilterBar,
  KpiCard,
  KpiGrid,
  navigate,
  OverviewGrid,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SegmentedControl,
  SelectField,
  StatusBadge,
  StatusStrip,
  Switch,
  TextField,
  toLocale,
  TONE_COLORS,
  useLocalePreference,
  usePath,
  useThemePreference,
  type Column,
  type ProductId,
  type Tone,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import {
  Bird,
  CalendarDays,
  Check,
  Copy,
  Download,
  KeyRound,
  LayoutDashboard,
  LogIn,
  LogOut,
  Plus,
  ShieldCheck,
  Siren,
  Trash2,
  UserRound,
  Users,
  Wrench,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  TEMPLATES,
  Unauthorized,
  type Bait,
  type Canary,
  type CanaryState,
  type ProductLink,
  type Summary,
  type Template,
  type Trigger,
  type TriggerDetail,
  type TriggerStatus,
} from "./api.ts";
import { useT } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["canaries", "triggers", "setup", "account", "members", "signin", "tokens", "about"] as const;
type Route = { page: "overview" | (typeof PAGES)[number] } | { page: "trigger"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["overview", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "triggers" && id) return { page: "trigger", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "overview" };
}

/** A query parameter of the address, such as the canary a list is narrowed to. */
const param = (name: string) => new URLSearchParams(window.location.search).get(name);

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const day = (iso: string) => new Date(`${iso}T00:00:00Z`).toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });

const STATE_TONE: Record<CanaryState, Tone> = { armed: "success", triggered: "critical", disabled: "neutral" };
const STATUS_TONE: Record<TriggerStatus, Tone> = { open: "critical", confirmed: "danger", test: "neutral" };

function Code({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <pre tabIndex={0} aria-label={label} className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs whitespace-pre-wrap text-fg">
      {children}
    </pre>
  );
}

function CanaryStateBadge({ state }: { state: CanaryState }) {
  const t = useT();
  return <StatusBadge tone={STATE_TONE[state]}>{t(`states.${state}`)}</StatusBadge>;
}

function TriggerStatusBadge({ status }: { status: TriggerStatus }) {
  const t = useT();
  return <StatusBadge tone={STATUS_TONE[status]}>{t(`statuses.${status}`)}</StatusBadge>;
}

/** What the trigger says about the incident it opened in Incidents, if deception is linked to it. */
function IncidentLink({ incident }: { incident: Trigger["incident"] }) {
  const t = useT();
  if (!incident) return null;
  if (incident.state === "opened" && incident.url)
    return (
      <a href={incident.url} className="inline-flex items-center gap-1 text-xs">
        <Siren className="size-3" aria-hidden /> {incident.key}
      </a>
    );
  return (
    <span className="text-xs text-fg-muted" title={incident.error ?? undefined}>
      {incident.state === "failed" ? t("incident.failed") : t("incident.pending")}
    </span>
  );
}

// ---------------------------------------------------------------- Overview

function OverviewPage({ summary }: { summary: Summary }) {
  const t = useT();
  const s = summary;
  const open = s.latest.find((x) => x.status === "open");
  const columns = useTriggerColumns();
  return (
    <>
      <PageHeader
        title={t("overviewPage.overview")}
        description={t("overviewPage.description", { count: s.canaries.total })}
        actions={
          <Button variant="primary" icon={<Plus />} onClick={() => navigate("/canaries?new=1")}>
            {t("canariesPage.newCanary")}
          </Button>
        }
      />
      {s.triggers.open > 0 && (
        <Callout
          tone="critical"
          title={t("overviewPage.openTriggers", { count: s.triggers.open })}
          action={
            <Button size="sm" variant="danger" onClick={() => navigate(open ? `/triggers/${open.id}` : "/triggers?status=open")}>
              {t("overviewPage.look")}
            </Button>
          }
        >
          {open?.canary
            ? t("overviewPage.wasUsedFrom", { name: open.canary.name, source: open.source, when: when(open.firstAt) })
            : t("overviewPage.nobodyHasAReason")}
        </Callout>
      )}
      {s.incidents.failing > 0 && (
        <Callout tone="warning" title={t("overviewPage.incidentsFailing", { count: s.incidents.failing })}>
          {t("overviewPage.incidentsFailingDetail")}
        </Callout>
      )}
      <KpiGrid minWidth={150}>
        <KpiCard label={t("overviewPage.armed")} value={s.canaries.armed} icon={Bird} tone="success" href="/canaries" />
        <KpiCard
          label={t("overviewPage.triggered")}
          value={s.canaries.triggered}
          icon={Zap}
          tone={s.canaries.triggered ? "critical" : "success"}
          href="/canaries"
        />
        <KpiCard label={t("overviewPage.needLook")} value={s.triggers.open} icon={Siren} tone={s.triggers.open ? "critical" : "success"} href="/triggers" />
        <KpiCard
          label={t("overviewPage.triggers30Days")}
          value={s.triggers.last30Days}
          icon={CalendarDays}
          trend={s.triggers.perDay.map((d) => d.triggers)}
          trendColor={TONE_COLORS.critical}
        />
        <KpiCard
          label={t("overviewPage.lastTrigger")}
          value={s.triggers.lastAt ? day(s.triggers.lastAt.slice(0, 10)) : t("overviewPage.never")}
          icon={ShieldCheck}
        />
      </KpiGrid>
      <Panel title={t("overviewPage.last30Days")} description={t("overviewPage.last30DaysDetail")}>
        <StatusStrip
          label={t("overviewPage.last30Days")}
          height={36}
          start={t("overviewPage.daysAgo", { n: 30 })}
          end={t("overviewPage.today")}
          cells={s.triggers.perDay.map((d) => ({
            id: d.date,
            label: day(d.date),
            tone: d.triggers ? "critical" : "success",
            detail: t("overviewPage.dayDetail", { count: d.triggers }),
          }))}
        />
      </Panel>
      <OverviewGrid layout="halves">
        <Panel title={t("overviewPage.byState")} description={t("overviewPage.byStateDetail")}>
          <DonutChart
            label={t("overviewPage.byState")}
            caption={t("overviewPage.canaries")}
            slices={(["armed", "triggered", "disabled"] as const).map((k) => ({
              id: k,
              name: t(`states.${k}`),
              value: s.canaries[k],
              color: TONE_COLORS[STATE_TONE[k]],
              href: `/canaries?state=${k}`,
            }))}
          />
        </Panel>
        <Panel title={t("overviewPage.byKind")} description={t("overviewPage.byKindDetail")}>
          <DonutChart
            label={t("overviewPage.byKind")}
            caption={t("overviewPage.canaries")}
            slices={(["url", "dns", "aws-key"] as const).map((k) => ({
              id: k,
              name: t(`kinds.${k}`),
              value: s.canaries.byKind[k],
              href: `/canaries?kind=${k}`,
            }))}
          />
        </Panel>
      </OverviewGrid>
      <Panel title={t("overviewPage.latestTriggers")} flush>
        <DataTable
          label={t("overviewPage.latestTriggers")}
          columns={columns}
          rows={s.latest}
          getRowId={(x) => x.id}
          onRowClick={(x) => navigate(`/triggers/${x.id}`)}
          minWidth={760}
          empty={<EmptyState title={t("overviewPage.noTriggers")}>{t("overviewPage.noTriggersDetail")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

/** The first screen, until a canary is made. */
function WelcomePage({ summary }: { summary: Summary }) {
  const t = useT();
  return (
    <>
      <PageHeader title={t("welcomePage.getStarted")} description={t("welcomePage.description")} />
      <Panel title={t("welcomePage.howItWorks")}>
        <ol className="deception-steps text-sm">
          <li>{t("welcomePage.step1")}</li>
          <li>{t("welcomePage.step2")}</li>
          <li>{t("welcomePage.step3")}</li>
        </ol>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button variant="primary" icon={<Plus />} onClick={() => navigate("/canaries?new=1")}>
            {t("canariesPage.newCanary")}
          </Button>
          <Button icon={<Wrench />} onClick={() => navigate("/setup")}>
            {t("product.setup")}
          </Button>
        </div>
      </Panel>
      {!summary.setup.dnsZone && <Callout title={t("welcomePage.noDns")}>{t("welcomePage.noDnsDetail")}</Callout>}
    </>
  );
}

// ---------------------------------------------------------------- Canaries

/** Shows a bait to copy or save: the one thing someone plants. */
function BaitView({ bait }: { bait: Bait }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const save = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([bait.content], { type: "text/plain" }));
    a.download = bait.file;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <div className="flex flex-col gap-2">
      <Code label={t("bait.contents")}>{bait.content}</Code>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" icon={copied ? <Check /> : <Copy />} onClick={() => void navigator.clipboard.writeText(bait.content).then(() => setCopied(true))}>
          {copied ? t("bait.copied") : t("bait.copy")}
        </Button>
        {bait.file && (
          <Button size="sm" icon={<Download />} onClick={save}>
            {t("bait.save", { file: bait.file })}
          </Button>
        )}
      </div>
    </div>
  );
}

function NewCanaryDialog({ call, summary, open, onClose, onMade }: { call: Call; summary: Summary; open: boolean; onClose: () => void; onMade: () => void }) {
  const t = useT();
  const [template, setTemplate] = useState<Template>("kubeconfig");
  const [name, setName] = useState("");
  const [location, setLocation] = useState("");
  const [host, setHost] = useState("");
  const [keyId, setKeyId] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string>();
  const [made, setMade] = useState<{ canary: Canary; bait: Bait }>();
  const kind = TEMPLATES.find((x) => x.id === template)!.kind;
  const noDns = kind === "dns" && !summary.setup.dnsZone;

  const reset = () => {
    setName("");
    setLocation("");
    setHost("");
    setKeyId("");
    setSecret("");
    setError(undefined);
    setMade(undefined);
  };
  const close = () => (reset(), onClose());
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const body = { name: name.trim(), template, location, host, ...(kind === "aws-key" && { accessKeyId: keyId.trim(), secretAccessKey: secret.trim() }) };
      setMade(await call<{ canary: Canary; bait: Bait }>("/api/v1/canaries", { method: "POST", body: JSON.stringify(body) }));
      setError(undefined);
      onMade();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  if (made)
    return (
      <Dialog
        open={open}
        onOpenChange={(o) => !o && close()}
        title={t("newCanary.plantIt", { name: made.canary.name })}
        description={t(`newCanary.plant.${made.canary.template}`)}
        icon={<Bird />}
        iconTone="success"
        size="lg"
        footer={
          <Button variant="primary" onClick={close}>
            {t("newCanary.done")}
          </Button>
        }
      >
        <BaitView bait={made.bait} />
      </Dialog>
    );
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && close()}
      title={t("canariesPage.newCanary")}
      description={t("newCanary.description")}
      size="lg"
      onSubmit={submit}
      footer={
        <>
          <Button type="button" onClick={close}>
            {t("newCanary.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={!name.trim() || noDns}>
            {t("newCanary.make")}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-2.5">
        <SelectField
          label={t("newCanary.template")}
          value={template}
          onChange={(e) => setTemplate(e.target.value as Template)}
          options={TEMPLATES.map((x) => ({ value: x.id, label: `${t(`templates.${x.id}`)} (${t(`kinds.${x.kind}`)})` }))}
        />
        <p className="m-0 text-xs text-fg-muted">{t(`templateHints.${template}`)}</p>
        {noDns && (
          <Callout tone="warning" title={t("newCanary.noDns")}>
            {t("newCanary.noDnsDetail")}
          </Callout>
        )}
        <TextField label={t("newCanary.name")} value={name} onChange={(e) => setName(e.target.value)} placeholder={t(`placeholders.name.${template}`)} />
        <div className="grid gap-2 sm:grid-cols-2">
          <TextField
            label={t("newCanary.location")}
            mono
            value={location}
            onChange={(e) => setLocation(e.target.value)}
            placeholder={t(`placeholders.location.${template}`)}
            hint={t("newCanary.locationHint")}
          />
          <TextField label={t("newCanary.host")} mono value={host} onChange={(e) => setHost(e.target.value)} placeholder="worker-prod-04" />
        </div>
        {kind === "aws-key" && (
          <>
            <Callout title={t("newCanary.awsFirst")}>
              {t("newCanary.awsFirstDetail")} <a href="/setup">{t("product.setup")}</a>.
            </Callout>
            <div className="grid gap-2 sm:grid-cols-2">
              <TextField label={t("newCanary.accessKeyId")} mono value={keyId} onChange={(e) => setKeyId(e.target.value)} placeholder="AKIA…" />
              <TextField
                label={t("newCanary.secretAccessKey")}
                mono
                type="password"
                autoComplete="off"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            </div>
          </>
        )}
        {error && <p className="m-0 text-xs text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}

/** One canary: where it is, its bait, and turning it off or deleting it. */
function CanaryDialog({ call, canary, onClose, onChanged }: { call: Call; canary: Canary; onClose: () => void; onChanged: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const editor = can("editor");
  const [location, setLocation] = useState(canary.location);
  const [host, setHost] = useState(canary.host);
  const [note, setNote] = useState(canary.note);
  const [bait, setBait] = useState<Bait>();
  const [error, setError] = useState<string>();
  const [removing, setRemoving] = useState(false);
  const changed = location !== canary.location || host !== canary.host || note !== canary.note;
  const act = async (path: string, init: RequestInit) => {
    try {
      await call(path, init);
      setError(undefined);
      onChanged();
      return true;
    } catch (err) {
      setError((err as Error).message);
      return false;
    }
  };
  const patch = (body: Record<string, unknown>) => act(`/api/v1/canaries/${canary.id}`, { method: "PATCH", body: JSON.stringify(body) });
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={canary.name}
      description={`${t(`templates.${canary.template}`)} · ${t(`kinds.${canary.kind}`)}`}
      size="lg"
      footer={
        <>
          {can("admin") &&
            (removing ? (
              <Button
                variant="danger"
                icon={<Trash2 />}
                onClick={() => void act(`/api/v1/canaries/${canary.id}`, { method: "DELETE" }).then((ok) => ok && onClose())}
              >
                {t("canaryDialog.deleteForGood")}
              </Button>
            ) : (
              <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
                {t("canaryDialog.delete")}
              </Button>
            ))}
          <Button onClick={() => navigate(`/triggers?canary=${encodeURIComponent(canary.id)}`)}>
            {t("canaryDialog.triggers", { count: canary.triggers })}
          </Button>
          {editor && (
            <Button variant="primary" disabled={!changed} onClick={() => void patch({ location, host, note })}>
              {t("canaryDialog.save")}
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-2.5">
        <dl className="deception-facts text-sm">
          <dt className="text-fg-muted">{t("canaryDialog.state")}</dt>
          <dd>
            <CanaryStateBadge state={canary.state} />
          </dd>
          <dt className="text-fg-muted">{t(`canaryDialog.address.${canary.kind}`)}</dt>
          <dd className="font-mono text-xs">{canary.address ?? t("canaryDialog.noZone")}</dd>
          <dt className="text-fg-muted">{t("canaryDialog.made")}</dt>
          <dd>{t("canaryDialog.madeBy", { when: when(canary.createdAt), who: canary.createdBy })}</dd>
        </dl>
        {removing && (
          <Callout tone="danger" title={t("canaryDialog.deleteTitle")}>
            {t("canaryDialog.deleteDetail")}
          </Callout>
        )}
        <div className="grid gap-2 sm:grid-cols-2">
          <TextField label={t("newCanary.location")} mono value={location} disabled={!editor} onChange={(e) => setLocation(e.target.value)} />
          <TextField label={t("newCanary.host")} mono value={host} disabled={!editor} onChange={(e) => setHost(e.target.value)} />
        </div>
        <TextField label={t("canaryDialog.note")} value={note} disabled={!editor} onChange={(e) => setNote(e.target.value)} />
        {editor && (
          <Switch
            checked={canary.enabled}
            onCheckedChange={(v) => void patch({ enabled: v })}
            label={t("canaryDialog.enabled")}
            description={t("canaryDialog.enabledDetail")}
          />
        )}
        {editor &&
          (bait ? (
            <BaitView bait={bait} />
          ) : (
            <div>
              <Button size="sm" onClick={() => void call<Bait>(`/api/v1/canaries/${canary.id}/bait`).then(setBait, (err: Error) => setError(err.message))}>
                {t("canaryDialog.showBait")}
              </Button>
            </div>
          ))}
        {error && <p className="m-0 text-xs text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}

function CanariesPage({ call, summary, reload }: { call: Call; summary: Summary; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [canaries, setCanaries] = useState<Canary[]>();
  const [kinds, setKinds] = useState<string[]>(() => (param("kind") ? [param("kind")!] : []));
  const [states, setStates] = useState<string[]>(() => (param("state") ? [param("state")!] : []));
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(() => param("new") === "1" && can("editor"));
  const [openId, setOpenId] = useState(() => param("open"));
  const load = useCallback(
    () =>
      void call<{ canaries: Canary[] }>("/api/v1/canaries").then(
        (r) => setCanaries(r.canaries),
        () => setCanaries([]),
      ),
    [call],
  );
  useEffect(load, [load]);
  const changed = () => (load(), reload());

  const query = q.trim().toLowerCase();
  const rows = (canaries ?? []).filter(
    (c) =>
      (!kinds.length || kinds.includes(c.kind)) &&
      (!states.length || states.includes(c.state)) &&
      (!query || [c.name, c.location, c.host].some((x) => x.toLowerCase().includes(query))),
  );
  const opened = canaries?.find((c) => c.id === openId);
  const columns: Column<Canary>[] = [
    {
      id: "name",
      header: t("canariesPage.canary"),
      width: "26%",
      sortValue: (c) => c.name,
      cell: (c) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{c.name}</span>
          <span className="text-2xs text-fg-muted">{t(`templates.${c.template}`)}</span>
        </span>
      ),
    },
    { id: "kind", header: t("canariesPage.kind"), width: "110px", sortValue: (c) => c.kind, cell: (c) => <Badge>{t(`kinds.${c.kind}`)}</Badge> },
    {
      id: "where",
      header: t("canariesPage.where"),
      cell: (c) => (
        <span className="flex min-w-0 flex-col items-start gap-0.5">
          <span className="deception-clamp font-mono text-xs" title={c.location}>
            {c.location || "–"}
          </span>
          {c.host && <EntityChip kind="host" value={c.host} />}
        </span>
      ),
    },
    { id: "state", header: t("canariesPage.state"), width: "120px", sortValue: (c) => c.state, cell: (c) => <CanaryStateBadge state={c.state} /> },
    { id: "triggers", header: t("canariesPage.triggers"), width: "90px", align: "right", mono: true, sortValue: (c) => c.triggers, cell: (c) => c.triggers },
    {
      id: "last",
      header: t("canariesPage.lastTrigger"),
      width: "150px",
      align: "right",
      sortValue: (c) => c.lastTriggeredAt ?? "",
      cell: (c) => <span className="whitespace-nowrap text-fg-muted">{c.lastTriggeredAt ? when(c.lastTriggeredAt) : t("overviewPage.never")}</span>,
    },
  ];
  return (
    <>
      <PageHeader
        title={t("canariesPage.canaries")}
        description={t("canariesPage.description")}
        meta={
          summary.canaries.triggered ? (
            <StatusBadge tone="critical">{t("canariesPage.triggeredCount", { count: summary.canaries.triggered })}</StatusBadge>
          ) : undefined
        }
        actions={
          can("editor") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setCreating(true)}>
              {t("canariesPage.newCanary")}
            </Button>
          )
        }
      />
      <Panel title={t("canariesPage.canaries")} description={t("canariesPage.shown", { shown: rows.length, total: canaries?.length ?? 0 })} flush>
        <div className="border-b border-line px-3 py-2">
          <FilterBar onClear={kinds.length || states.length || q ? () => (setKinds([]), setStates([]), setQ("")) : undefined}>
            <FacetFilter
              label={t("canariesPage.kind")}
              selected={kinds}
              onChange={setKinds}
              options={(["url", "dns", "aws-key"] as const).map((k) => ({
                value: k,
                label: t(`kinds.${k}`),
                count: canaries?.filter((c) => c.kind === k).length,
              }))}
            />
            <FacetFilter
              label={t("canariesPage.state")}
              selected={states}
              onChange={setStates}
              options={(["armed", "triggered", "disabled"] as const).map((s) => ({
                value: s,
                label: t(`states.${s}`),
                count: canaries?.filter((c) => c.state === s).length,
              }))}
            />
            <SearchInput label={t("canariesPage.search")} className="w-56" value={q} onChange={(e) => setQ(e.target.value)} />
          </FilterBar>
        </div>
        <DataTable
          label={t("canariesPage.canaries")}
          columns={columns}
          rows={rows}
          loading={!canaries}
          getRowId={(c) => c.id}
          onRowClick={(c) => setOpenId(c.id)}
          minWidth={860}
          empty={<EmptyState title={t("canariesPage.none")}>{t("canariesPage.noneDetail")}</EmptyState>}
        />
      </Panel>
      <NewCanaryDialog call={call} summary={summary} open={creating} onClose={() => setCreating(false)} onMade={changed} />
      {opened && <CanaryDialog key={opened.id + opened.enabled} call={call} canary={opened} onClose={() => setOpenId(null)} onChanged={changed} />}
    </>
  );
}

// ---------------------------------------------------------------- Triggers

function useTriggerColumns(): Column<Trigger>[] {
  const t = useT();
  return [
    {
      id: "when",
      header: t("triggersPage.when"),
      width: "150px",
      sortValue: (x) => x.firstAt,
      cell: (x) => <span className="whitespace-nowrap">{when(x.firstAt)}</span>,
    },
    {
      id: "canary",
      header: t("triggersPage.canary"),
      cell: (x) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{x.canary?.name ?? t("triggersPage.deleted")}</span>
          <span className="deception-clamp text-2xs text-fg-muted" title={x.detail}>
            {x.detail}
          </span>
        </span>
      ),
    },
    {
      id: "source",
      header: t("triggersPage.source"),
      width: "170px",
      cell: (x) => (
        <span className="flex flex-col items-start gap-0.5">
          <EntityChip kind="ip" value={x.source} hideKind />
          <span className="text-2xs text-fg-muted">{t(`channels.${x.channel}`)}</span>
        </span>
      ),
    },
    { id: "hits", header: t("triggersPage.uses"), width: "70px", align: "right", mono: true, sortValue: (x) => x.hits, cell: (x) => x.hits },
    {
      id: "status",
      header: t("triggersPage.status"),
      width: "150px",
      cell: (x) => (
        <span className="flex flex-col items-start gap-0.5">
          <TriggerStatusBadge status={x.status} />
          <IncidentLink incident={x.incident} />
        </span>
      ),
    },
  ];
}

function TriggersPage({ call }: { call: Call }) {
  const t = useT();
  const canary = param("canary");
  const [status, setStatus] = useState<TriggerStatus | "all">(() => (param("status") as TriggerStatus | null) ?? "all");
  const [page, setPage] = useState<{ triggers: Trigger[]; nextCursor?: string }>();
  const columns = useTriggerColumns();
  const query = useMemo(() => {
    const p = new URLSearchParams({ limit: "100" });
    if (status !== "all") p.set("status", status);
    if (canary) p.set("canary", canary);
    return p.toString();
  }, [status, canary]);
  useEffect(() => {
    setPage(undefined);
    void call<{ triggers: Trigger[]; nextCursor?: string }>(`/api/v1/triggers?${query}`).then(setPage, () => setPage({ triggers: [] }));
  }, [call, query]);
  const more = () =>
    page?.nextCursor &&
    void call<{ triggers: Trigger[]; nextCursor?: string }>(`/api/v1/triggers?${query}&cursor=${encodeURIComponent(page.nextCursor)}`).then((next) =>
      setPage({ triggers: [...page.triggers, ...next.triggers], nextCursor: next.nextCursor }),
    );
  return (
    <>
      <PageHeader
        title={t("triggersPage.triggers")}
        description={t("triggersPage.description")}
        actions={
          <SegmentedControl
            label={t("triggersPage.status")}
            value={status}
            onChange={setStatus}
            options={[
              { value: "all", label: t("triggersPage.all") },
              { value: "open", label: t("statuses.open") },
              { value: "confirmed", label: t("statuses.confirmed") },
              { value: "test", label: t("statuses.test") },
            ]}
          />
        }
      />
      {canary && (
        <Callout
          title={t("triggersPage.oneCanary")}
          action={
            <Button size="sm" onClick={() => navigate("/triggers")}>
              {t("triggersPage.showAll")}
            </Button>
          }
        >
          {page?.triggers[0]?.canary?.name ?? canary}
        </Callout>
      )}
      <Panel title={t("triggersPage.triggers")} flush>
        <DataTable
          label={t("triggersPage.triggers")}
          columns={columns}
          rows={page?.triggers ?? []}
          loading={!page}
          getRowId={(x) => x.id}
          onRowClick={(x) => navigate(`/triggers/${x.id}`)}
          minWidth={760}
          empty={<EmptyState title={t("overviewPage.noTriggers")}>{t("overviewPage.noTriggersDetail")}</EmptyState>}
        />
        {page?.nextCursor && (
          <div className="border-t border-line px-3 py-2">
            <Button size="sm" onClick={more}>
              {t("triggersPage.more")}
            </Button>
          </div>
        )}
      </Panel>
    </>
  );
}

function TriggerPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [trigger, setTrigger] = useState<TriggerDetail | null>();
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const load = useCallback(() => void call<TriggerDetail>(`/api/v1/triggers/${encodeURIComponent(id)}`).then(setTrigger, () => setTrigger(null)), [call, id]);
  useEffect(load, [load]);
  const decide = async (status: TriggerStatus) => {
    try {
      await call(`/api/v1/triggers/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify({ status, ...(reason.trim() && { reason: reason.trim() }) }),
      });
      setError(undefined);
      setReason("");
      load();
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  if (trigger === null)
    return (
      <EmptyState title={t("triggerPage.notFound")} action={<Button onClick={() => navigate("/triggers")}>{t("triggerPage.back")}</Button>}>
        {t("triggerPage.notFoundDetail")}
      </EmptyState>
    );
  if (!trigger) return <EmptyState title={t("product.loading")} icon={<Bird />} />;
  const c = trigger.canary;
  return (
    <>
      <PageHeader
        title={c?.name ?? t("triggersPage.deleted")}
        breadcrumbs={[{ label: t("triggersPage.triggers"), href: "/triggers" }, { label: when(trigger.firstAt) }]}
        description={t("triggerPage.description", { source: trigger.source, when: when(trigger.firstAt) })}
        meta={<TriggerStatusBadge status={trigger.status} />}
      />
      {trigger.status === "open" && (
        <Callout tone="critical" title={t("triggerPage.treatAsBreach")}>
          {t("triggerPage.treatAsBreachDetail")}
        </Callout>
      )}
      {trigger.incident?.error && (
        <Callout tone="warning" title={t("triggerPage.incidentError")}>
          {trigger.incident.error}
        </Callout>
      )}
      <OverviewGrid>
        <Panel title={t("triggerPage.whatHappened")}>
          <dl className="deception-facts text-sm">
            <dt className="text-fg-muted">{t("triggersPage.source")}</dt>
            <dd>
              <EntityChip kind="ip" value={trigger.source} hideKind />
              {trigger.channel === "dns" && <p className="m-0 mt-1 text-xs text-fg-muted">{t("triggerPage.dnsSource")}</p>}
            </dd>
            <dt className="text-fg-muted">{t("triggerPage.how")}</dt>
            <dd>{t(`channels.${trigger.channel}`)}</dd>
            {trigger.userAgent && (
              <>
                <dt className="text-fg-muted">{t("triggerPage.userAgent")}</dt>
                <dd className="font-mono text-xs">{trigger.userAgent}</dd>
              </>
            )}
            <dt className="text-fg-muted">{t("triggerPage.uses")}</dt>
            <dd>{t("triggerPage.usesDetail", { count: trigger.hits, first: when(trigger.firstAt), last: when(trigger.lastAt) })}</dd>
            {c && (
              <>
                <dt className="text-fg-muted">{t("triggerPage.planted")}</dt>
                <dd className="font-mono text-xs">{c.location || "–"}</dd>
                {c.host && (
                  <>
                    <dt className="text-fg-muted">{t("newCanary.host")}</dt>
                    <dd>
                      <EntityChip kind="host" value={c.host} />
                    </dd>
                  </>
                )}
              </>
            )}
            {trigger.incident && (
              <>
                <dt className="text-fg-muted">{t("triggerPage.incident")}</dt>
                <dd>
                  <IncidentLink incident={trigger.incident} />
                </dd>
              </>
            )}
          </dl>
        </Panel>
        <Panel title={t("triggerPage.decide")} description={t("triggerPage.decideDetail")}>
          {trigger.status !== "open" && (
            <p className="m-0 mb-2 text-sm">
              {t(`triggerPage.decided.${trigger.status}`, { who: trigger.decidedBy ?? "", when: trigger.decidedAt ? when(trigger.decidedAt) : "" })}
              {trigger.reason && <span className="text-fg-muted">: {trigger.reason}</span>}
            </p>
          )}
          {can("editor") && (
            <div className="flex flex-col gap-2">
              {trigger.status === "open" && (
                <TextField label={t("triggerPage.reason")} value={reason} onChange={(e) => setReason(e.target.value)} hint={t("triggerPage.reasonHint")} />
              )}
              <div className="flex flex-wrap gap-1.5">
                {trigger.status === "open" ? (
                  <>
                    <Button size="sm" variant="danger" icon={<Siren />} onClick={() => void decide("confirmed")}>
                      {t("triggerPage.confirm")}
                    </Button>
                    <Button size="sm" disabled={!reason.trim()} onClick={() => void decide("test")}>
                      {t("triggerPage.markTest")}
                    </Button>
                  </>
                ) : (
                  <Button size="sm" onClick={() => void decide("open")}>
                    {t("triggerPage.reopen")}
                  </Button>
                )}
              </div>
              {error && <p className="m-0 text-xs text-danger">{error}</p>}
            </div>
          )}
        </Panel>
      </OverviewGrid>
      <Panel title={t("triggerPage.timeline")} description={t("triggerPage.timelineDetail")}>
        <ol aria-label={t("triggerPage.timeline")} className="deception-list flex flex-col gap-1">
          {trigger.timeline.map((h, i) => (
            <li key={`${h.at}-${i}`} className="deception-use text-sm">
              <span className="font-mono text-2xs text-fg-muted">{when(h.at)}</span>
              <span className="deception-wrap font-mono text-xs">{h.detail}</span>
            </li>
          ))}
        </ol>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage({ summary }: { summary: Summary }) {
  const t = useT();
  const origin = window.location.origin;
  const zone = summary.setup.dnsZone;
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.description")} />
      <Panel title={t("setupPage.urls")} description={t("setupPage.urlsDetail")}>
        <dl className="deception-facts text-sm">
          <dt className="text-fg-muted">DECEPTION_CANARY_URL</dt>
          <dd className="font-mono text-xs">{summary.setup.canaryUrl}</dd>
        </dl>
        {summary.setup.canaryUrl === origin && <p className="m-0 mt-2 text-xs text-fg-muted">{t("setupPage.sameAddress")}</p>}
      </Panel>
      <Panel title={t("setupPage.dns")} description={zone ? t("setupPage.dnsOn", { zone }) : t("setupPage.dnsOff")}>
        <Code>{`# 1. deception answers the zone: publish its DNS port on UDP 53
DECEPTION_DNS_ZONE=${zone ?? "canary.example.com"}
ports: ["53:5353/udp"]

# 2. delegate the zone to it, in the parent zone
${zone ?? "canary.example.com"}.  NS  deception-dns.example.com.
deception-dns.example.com.  A   <the address of this host>`}</Code>
      </Panel>
      <Panel title={t("setupPage.aws")} description={t("setupPage.awsDetail")}>
        <Code>{`# A user that may do nothing, and a key for it
aws iam create-user --user-name backup-svc
aws iam put-user-policy --user-name backup-svc --policy-name deny-all \\
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
aws iam create-access-key --user-name backup-svc

# Every 5 minutes: what CloudTrail saw the key do
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \\
  --start-time "$(date -u -d '-15 min' +%FT%TZ)" \\
  | curl -sf -X POST -H "Authorization: Bearer $DECEPTION_INGEST_TOKEN" \\
    -H 'content-type: application/json' --data-binary @- ${origin}/api/v1/cloudtrail`}</Code>
      </Panel>
      <Panel title={t("setupPage.incidents")}>
        <p className="m-0 text-sm">{summary.incidents.on ? t("setupPage.incidentsOn") : t("setupPage.incidentsOff")}</p>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settingsPage.${page}.title`)}
        description={t(`settingsPage.${page}.description`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const path = usePath();
  const route = parseRoute(path);
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "deception" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "overview", label: msg("product.overview"), icon: LayoutDashboard },
    { id: "canaries", label: msg("product.canaries"), icon: Bird, count: summary?.canaries.total || undefined },
    { id: "triggers", label: msg("product.triggers"), icon: Zap, count: summary?.triggers.open || undefined },
    { id: "setup", label: msg("product.setup"), icon: Wrench },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const settings = route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens";

  return (
    <AppShell
      product="deception"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={route.page === "trigger" ? "triggers" : route.page}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {settings ? (
        <SettingsPage page={route.page as "account" | "members" | "signin" | "tokens"} />
      ) : !summary ? (
        <EmptyState title={msg("product.loading")} icon={<Bird />}>
          {msg("product.reading")}
        </EmptyState>
      ) : route.page === "overview" && summary.canaries.total === 0 ? (
        <WelcomePage summary={summary} />
      ) : route.page === "overview" ? (
        <OverviewPage summary={summary} />
      ) : route.page === "canaries" ? (
        // The address carries the filters, so a link from the overview opens the list narrowed.
        <CanariesPage key={path + window.location.search} call={call} summary={summary} reload={reload} />
      ) : route.page === "triggers" ? (
        <TriggersPage key={window.location.search} call={call} />
      ) : route.page === "trigger" ? (
        <TriggerPage key={route.id} call={call} id={route.id} reload={reload} />
      ) : (
        <SetupPage summary={summary} />
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Deception">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
