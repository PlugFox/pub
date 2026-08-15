import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { cn } from "@pub/ui/cn";
import { EmptyState } from "@pub/ui/empty-state";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { A, createAsync, query, revalidate, useParams } from "@solidjs/router";
import { createMemo, createSignal, For, type JSX, Show } from "solid-js";
import { formatBytes, formatDateTime, formatNumber, formatRelative } from "../format";
import { api, describeError } from "../state/api";
import { pushToast } from "../state/toast-store";
import { AdminAuditPanel } from "./admin-audit";
import { AdminOrgsPanel, AdminUsersPanel } from "./admin-people";
import { AdminSettingsPanel } from "./admin-settings";
import { AdminSupplyChainPanel } from "./admin-supply-chain";

/*
 * Instance administration.
 *
 * The tab is a path segment (`/app/admin/audit`), same reasoning as the
 * package page: an admin sharing "look at the audit log filtered like this"
 * needs a URL, and each panel keeps its own filters and cursor in the query
 * string.
 *
 * ACCESS IS THE SERVER'S CALL. `users.is_instance_admin` is read from the row
 * on every request and never carried in a token claim (decision 19's
 * addendum), so the client cannot know whether the caller is an admin without
 * asking. It asks by loading the panel: a non-admin gets 403 and this screen
 * renders that, rather than pretending to gate what it cannot decide.
 */

const ADMIN_TABS = ["stats", "settings", "users", "orgs", "supply-chain", "audit", "jobs"] as const;
type AdminTab = (typeof ADMIN_TABS)[number];
const DEFAULT_TAB: AdminTab = "stats";

const TAB_LABELS: Record<AdminTab, { readonly id: string; readonly en: string }> = {
  stats: app.adminTabStats,
  settings: app.adminTabSettings,
  users: app.adminTabUsers,
  orgs: app.adminTabOrgs,
  "supply-chain": app.adminTabSupplyChain,
  audit: app.adminTabAudit,
  jobs: app.adminTabJobs,
};

export function readAdminTab(raw: string | undefined): AdminTab {
  if (raw === undefined || raw === "") return DEFAULT_TAB;
  return (ADMIN_TABS as readonly string[]).includes(raw) ? (raw as AdminTab) : DEFAULT_TAB;
}

const statsQuery = query(() => api.admin.stats(), "admin-stats");

function Stat(props: { readonly label: string; readonly value: string }): JSX.Element {
  return (
    <div class="flex flex-col gap-1 rounded-xl border border-line bg-surface p-4">
      <dt class="text-xs text-ink-muted">{props.label}</dt>
      <dd class="text-xl font-semibold text-ink">{props.value}</dd>
    </div>
  );
}

function StatsPanel(): JSX.Element {
  const stats = createAsync(() => statsQuery());
  return (
    <Show when={stats()}>
      {(loaded) => (
        <div class="flex flex-col gap-8">
          <section class="flex flex-col gap-3">
            <h2 class="text-lg font-semibold text-ink">{t(app.adminStatsRegistry)}</h2>
            <dl class="grid gap-3 sm:grid-cols-3">
              <Stat
                label={t(app.adminStatPackages)}
                value={formatNumber(loaded().registry.packages)}
              />
              <Stat
                label={t(app.adminStatPublic)}
                value={formatNumber(loaded().registry.public_packages)}
              />
              <Stat
                label={t(app.adminStatVersions)}
                value={formatNumber(loaded().registry.versions)}
              />
              <Stat
                label={t(app.adminStatRetracted)}
                value={formatNumber(loaded().registry.retracted_versions)}
              />
              <Stat
                label={t(app.adminStatTombstoned)}
                value={formatNumber(loaded().registry.tombstoned_versions)}
              />
              <Stat
                label={t(app.adminStatStorage)}
                value={formatBytes(loaded().registry.archive_bytes)}
              />
            </dl>
          </section>

          <section class="flex flex-col gap-3">
            <h2 class="text-lg font-semibold text-ink">{t(app.adminStatsAccounts)}</h2>
            <dl class="grid gap-3 sm:grid-cols-3">
              <Stat label={t(app.adminStatUsers)} value={formatNumber(loaded().users.total)} />
              <Stat label={t(app.adminStatActive)} value={formatNumber(loaded().users.active)} />
              <Stat
                label={t(app.adminStatSuspended)}
                value={formatNumber(loaded().users.suspended)}
              />
              <Stat label={t(app.adminStatAdmins)} value={formatNumber(loaded().users.admins)} />
              <Stat label={t(app.adminStatDeleted)} value={formatNumber(loaded().users.deleted)} />
              <Stat label={t(app.adminStatOrgs)} value={formatNumber(loaded().orgs)} />
            </dl>
          </section>

          <section class="flex flex-col gap-3">
            <h2 class="text-lg font-semibold text-ink">{t(app.adminStatsUpstream)}</h2>
            <dl class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat
                label={t(app.adminStatCachedPackages)}
                value={formatNumber(loaded().upstream_cache.packages)}
              />
              <Stat
                label={t(app.adminStatCachedVersions)}
                value={formatNumber(loaded().upstream_cache.cached_versions)}
              />
              <Stat
                label={t(app.adminStatCachedBytes)}
                value={formatBytes(loaded().upstream_cache.cached_bytes)}
              />
              <Stat
                label={t(app.adminStatShadowingActive)}
                value={formatNumber(loaded().shadowing_active)}
              />
            </dl>
          </section>

          {/*
            The two alarm tables are the reason this dashboard exists: a
            shadowing alarm (S-17) and a refused upstream archive (S-19) are
            what an operator must not learn about from a user.
          */}
          <Show when={loaded().shadowing.length > 0}>
            <section class="flex flex-col gap-3">
              <div class="flex flex-wrap items-baseline justify-between gap-3">
                <h2 class="text-lg font-semibold text-ink">{t(app.adminShadowingTitle)}</h2>
                {/*
                  The dashboard is the alarm and shows the newest twenty; the
                  register behind it is where an operator investigates.
                */}
                <A
                  href="/admin/supply-chain"
                  class="text-sm text-accent underline-offset-4 hover:underline"
                >
                  {t(app.adminRegisterOpen)}
                </A>
              </div>
              <Alert intent="warning">{t(app.adminShadowingBody)}</Alert>
              <Table label={t(app.adminShadowingTitle)}>
                <TableHead>
                  <TableRow>
                    <TableHeaderCell>{t(app.adminShadowingName)}</TableHeaderCell>
                    <TableHeaderCell>{t(app.adminShadowingUpstream)}</TableHeaderCell>
                    <TableHeaderCell>{t(app.adminShadowingSeen)}</TableHeaderCell>
                    <TableHeaderCell>{t(app.adminShadowingActive)}</TableHeaderCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <For each={loaded().shadowing}>
                    {(alarm) => (
                      <TableRow>
                        <TableCell class="font-mono text-xs">{alarm.name}</TableCell>
                        <TableCell class="font-mono text-xs text-ink-muted">
                          {alarm.upstream}
                        </TableCell>
                        <TableCell class="whitespace-nowrap text-ink-muted">
                          {formatRelative(alarm.last_seen_at)}
                        </TableCell>
                        <TableCell>
                          <Badge variant={alarm.active ? "warning" : "neutral"}>
                            {formatNumber(alarm.observations)}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    )}
                  </For>
                </TableBody>
              </Table>
            </section>
          </Show>

          <Show when={loaded().quarantine.length > 0}>
            <section class="flex flex-col gap-3">
              <div class="flex flex-wrap items-baseline justify-between gap-3">
                <h2 class="text-lg font-semibold text-ink">{t(app.adminQuarantineTitle)}</h2>
                <A
                  href="/admin/supply-chain"
                  class="text-sm text-accent underline-offset-4 hover:underline"
                >
                  {t(app.adminRegisterOpen)}
                </A>
              </div>
              <Alert intent="danger">{t(app.adminQuarantineBody)}</Alert>
              <Table label={t(app.adminQuarantineTitle)}>
                <TableHead>
                  <TableRow>
                    <TableHeaderCell>{t(app.pkgVersion)}</TableHeaderCell>
                    <TableHeaderCell>{t(app.adminQuarantineExpected)}</TableHeaderCell>
                    <TableHeaderCell>{t(app.adminQuarantineActual)}</TableHeaderCell>
                    <TableHeaderCell>{t(app.adminShadowingSeen)}</TableHeaderCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <For each={loaded().quarantine}>
                    {(entry) => (
                      <TableRow>
                        <TableCell class="font-mono text-xs">
                          {entry.name}@{entry.version}
                        </TableCell>
                        <TableCell class="font-mono text-xs text-ink-muted">
                          {entry.expected_sha256.slice(0, 16)}…
                        </TableCell>
                        <TableCell class="font-mono text-xs text-ink-muted">
                          {entry.actual_sha256.slice(0, 16)}…
                        </TableCell>
                        <TableCell class="whitespace-nowrap text-ink-muted">
                          {formatRelative(entry.last_seen_at)}
                        </TableCell>
                      </TableRow>
                    )}
                  </For>
                </TableBody>
              </Table>
            </section>
          </Show>
        </div>
      )}
    </Show>
  );
}

function JobsPanel(): JSX.Element {
  const stats = createAsync(() => statsQuery());
  const [busy, setBusy] = createSignal<string | null>(null);
  const [summary, setSummary] = createSignal<{ job: string; text: string } | null>(null);

  const run = async (job: string): Promise<void> => {
    if (busy() !== null) return;
    setBusy(job);
    setSummary(null);
    try {
      const result = await api.admin.runJob(job);
      // The job's own summary document is the feedback: "done" would not tell
      // an operator whether the reindex actually reindexed anything.
      setSummary({ job: result.job, text: JSON.stringify(result.summary, null, 2) });
      pushToast(t(app.adminJobRan, { job }), "success");
      await revalidate("admin-stats");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(null);
    }
  };

  return (
    <Show when={stats()}>
      {(loaded) => (
        <div class="flex flex-col gap-6">
          <Alert intent="info">{t(app.adminJobsIntro)}</Alert>

          <Show
            when={loaded().runnable_jobs.length > 0}
            fallback={<EmptyState title={t(app.adminJobsNone)} />}
          >
            <div class="flex flex-wrap gap-3">
              <For each={loaded().runnable_jobs}>
                {(job) => (
                  <Button intent="outline" disabled={busy() !== null} onClick={() => void run(job)}>
                    {busy() === job ? t(app.adminJobRunning, { job }) : t(app.adminJobRun, { job })}
                  </Button>
                )}
              </For>
            </div>
          </Show>

          <Show when={summary()}>
            {(value) => (
              <Card>
                <CardHeader>
                  <h2 class="text-base font-semibold text-ink">
                    {t(app.adminJobSummary, { job: value().job })}
                  </h2>
                </CardHeader>
                <CardContent>
                  <pre class="overflow-x-auto rounded-lg border border-line bg-canvas p-4 font-mono text-xs text-ink">
                    {value().text}
                  </pre>
                </CardContent>
              </Card>
            )}
          </Show>

          <Show when={loaded().jobs.length > 0}>
            <Table label={t(app.adminTabJobs)}>
              <TableHead>
                <TableRow>
                  <TableHeaderCell>{t(app.adminJobName)}</TableHeaderCell>
                  <TableHeaderCell>{t(app.adminJobLastSuccess)}</TableHeaderCell>
                  <TableHeaderCell>{t(app.adminJobRuns)}</TableHeaderCell>
                  <TableHeaderCell>{t(app.adminJobProcessed)}</TableHeaderCell>
                  {/* The drain reports its standing dead-letter count here ("drain (3 dead)").
                      Dropping this column is what made a dead mail plane invisible outside the
                      raw stats JSON — roadmap D43, decision 29. */}
                  <TableHeaderCell>{t(app.adminJobPhase)}</TableHeaderCell>
                  <TableHeaderCell>{t(app.adminJobFailures)}</TableHeaderCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <For each={loaded().jobs}>
                  {(job) => (
                    <TableRow>
                      <TableCell class="font-mono text-xs">{job.name}</TableCell>
                      <TableCell class="whitespace-nowrap text-ink-muted">
                        {job.last_success_at === null || job.last_success_at === undefined
                          ? t(app.adminJobNever)
                          : formatDateTime(job.last_success_at)}
                      </TableCell>
                      <TableCell>{formatNumber(job.runs)}</TableCell>
                      <TableCell>{formatNumber(job.processed)}</TableCell>
                      <TableCell class="font-mono text-xs">
                        <Show when={job.phase} fallback={<span class="text-ink-muted">—</span>}>
                          {(phase) => (
                            <Badge variant={/\bdead\b/.test(phase()) ? "danger" : "neutral"}>
                              {phase()}
                            </Badge>
                          )}
                        </Show>
                      </TableCell>
                      <TableCell>
                        <Badge variant={job.failures > 0 ? "danger" : "neutral"}>
                          {formatNumber(job.failures)}
                        </Badge>
                        <Show when={job.last_error}>
                          {(message) => <p class="pt-1 text-xs text-danger-ink">{message()}</p>}
                        </Show>
                      </TableCell>
                    </TableRow>
                  )}
                </For>
              </TableBody>
            </Table>
          </Show>
        </div>
      )}
    </Show>
  );
}

export function AdminScreen(): JSX.Element {
  const params = useParams<{ tab?: string }>();
  const tab = createMemo(() => readAdminTab(params.tab));

  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-col gap-2">
        <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.navAdmin)}</h1>
        <p class="max-w-2xl text-ink-muted">{t(app.adminSubtitle)}</p>
      </header>

      {/* Links, not `role="tab"` — see the note in screens/package.tsx. */}
      <nav aria-label={t(app.navAdmin)} class="border-b border-line">
        <ul class="flex overflow-x-auto">
          <For each={ADMIN_TABS}>
            {(entry) => (
              <li class="shrink-0">
                <A
                  href={entry === DEFAULT_TAB ? "/admin" : `/admin/${entry}`}
                  aria-current={tab() === entry ? "page" : undefined}
                  class={cn(
                    "-mb-px inline-block cursor-pointer border-b-2 px-4 py-2 text-sm font-medium",
                    "outline-none transition-colors focus-visible:ring-2 focus-visible:ring-accent",
                    tab() === entry
                      ? "border-accent text-ink"
                      : "border-transparent text-ink-muted hover:text-ink",
                  )}
                >
                  {t(TAB_LABELS[entry])}
                </A>
              </li>
            )}
          </For>
        </ul>
      </nav>

      <div class="min-w-0">
        <Show when={tab() === "stats"}>
          <StatsPanel />
        </Show>
        <Show when={tab() === "settings"}>
          <AdminSettingsPanel />
        </Show>
        <Show when={tab() === "users"}>
          <AdminUsersPanel />
        </Show>
        <Show when={tab() === "orgs"}>
          <AdminOrgsPanel />
        </Show>
        <Show when={tab() === "supply-chain"}>
          <AdminSupplyChainPanel />
        </Show>
        <Show when={tab() === "audit"}>
          <AdminAuditPanel />
        </Show>
        <Show when={tab() === "jobs"}>
          <JobsPanel />
        </Show>
      </div>
    </section>
  );
}
