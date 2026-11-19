import type { FlagValue } from '../lib/args';
import { getBooleanFlag, getStringFlag } from '../lib/args';
import type { ResolvedContext } from '../lib/context';
import { requestJson } from '../lib/client';
import { outputJson } from '../lib/output';
import { buildQuery } from '../lib/format';

type ScopeProfile = {
  id: string;
  slug: string;
  org_id?: string | null;
  profile: string | null;
  ruleset?: number | null;
  effective: string;
  effective_ruleset?: number | null;
};

interface SecurityReport {
  days: number;
  current_ruleset?: number;
  instance_profile: string;
  instance_ruleset?: number | null;
  new_project_profile: string | null;
  registry?: { key_version: string | null; stale_environments: number };
  orgs: ScopeProfile[];
  projects: ScopeProfile[];
  summary: Array<{ rule: string; count: number; projects: number; actors: number }>;
  findings: Array<{
    rule: string;
    project_id: string | null;
    actor_type: string;
    actor_id: string;
    count: number;
    last_seen: string;
  }>;
}

const PROFILES = ['legacy', 'audit', 'strict'];

/** `eve doctor security [--org <id>] [--project <id>] [--days <n>]` */
export async function handleDoctor(
  subcommand: string | undefined,
  flags: Record<string, FlagValue>,
  context: ResolvedContext,
): Promise<void> {
  if (subcommand !== 'security') {
    throw new Error('Usage: eve doctor security [--org <id>] [--project <id>] [--days <n>] [--json]');
  }
  const json = Boolean(flags.json);
  const query = buildQuery({
    org_id: getStringFlag(flags, ['org']),
    project_id: getStringFlag(flags, ['project']),
    days: getStringFlag(flags, ['days']),
  });
  const report = await requestJson<SecurityReport>(context, `/system/security/report${query}`);
  if (json) {
    outputJson(report, json);
    return;
  }

  const own = (p: string | null) => (p ? p : 'inherited');
  const current = report.current_ruleset ?? 1;
  const stamped = (profile: string, ruleset: number | null | undefined) =>
    describeStampedProfile(profile, ruleset, current);
  console.log(`Instance profile: ${stamped(report.instance_profile, report.instance_ruleset)}`);
  console.log(`New projects:     ${report.new_project_profile ?? 'inherit'}`);
  if (report.registry) {
    const stale = report.registry.stale_environments;
    console.log(`Registry key:     ${report.registry.key_version ?? 'EVE_REGISTRY_CREDENTIAL_KEY not set'}` +
      (stale > 0 ? `; ${stale} environment(s) on an older key (eve system security reconcile)` : '; every environment current'));
  }
  console.log('');
  console.log('Orgs:');
  for (const org of report.orgs) {
    console.log(`  ${org.slug.padEnd(24)} ${org.effective.padEnd(7)} (${own(org.profile)})  ${org.id}${stampNote(org, current)}`);
  }
  console.log('Projects:');
  for (const project of report.projects) {
    console.log(`  ${project.slug.padEnd(24)} ${project.effective.padEnd(7)} (${own(project.profile)})  ${project.id}${stampNote(project, current)}`);
  }
  console.log('');
  if (report.summary.length === 0) {
    console.log(`No findings in the last ${report.days} days.`);
  } else {
    console.log(`Findings in the last ${report.days} days (what strict refused or would refuse):`);
    for (const rule of report.summary) {
      console.log(`  ${rule.rule.padEnd(36)} ${String(rule.count).padStart(6)} sightings  ${rule.projects} project(s)  ${rule.actors} actor(s)`);
    }
    console.log('');
    console.log('Latest:');
    for (const f of report.findings.slice(0, 20)) {
      console.log(`  ${f.last_seen}  ${f.rule}  ${f.project_id ?? '-'}  ${f.actor_type}:${f.actor_id}  x${f.count}`);
    }
  }
  console.log('');
  console.log('A project with no findings can move to strict: eve system security profile strict --project <id>');
  console.log('Setting strict again takes the newest rules.');
}

/**
 * "strict", or "strict (P1 rules); P2 rules on audit" for a strict set
 * before the newest rule set.
 */
export function describeStampedProfile(profile: string, ruleset: number | null | undefined, current: number): string {
  if (profile !== 'strict' || !ruleset || ruleset >= current) return profile;
  const newer = Array.from({ length: current - ruleset }, (_, i) => `P${ruleset + 1 + i}`).join(', ');
  return `strict (${ruleset === 1 ? 'P1' : `P1-P${ruleset}`} rules); ${newer} rules on audit`;
}

function stampNote(scope: ScopeProfile, current: number): string {
  const described = describeStampedProfile(scope.effective, scope.effective_ruleset, current);
  return described === scope.effective ? '' : `  ${described}`;
}

interface ReconcileReport {
  registry: {
    key_version: string;
    resigned: number;
    already_current: number;
    without_pull_secret: number;
    failed: Array<{ environment_id: string; error: string }>;
  };
  /** Runner SandboxTemplates and SandboxWarmPools (absent from an older API). */
  runner_templates?: {
    backend: 'sandbox' | 'pod';
    namespace: string;
    reason?: string;
    runtime_class?: string | null;
    warm_pools?: Record<string, number>;
  };
}

/**
 * `eve system security profile <legacy|audit|strict|clear>
 *   [--org <id> | --project <id> | --new-projects]`
 * With no scope flag it sets the instance profile.
 *
 * `eve system security reconcile`: bring environments in line with the
 * profiles (registry pull secrets re-signed with the current key) and render
 * the runner templates and warm pools from the instance settings.
 */
export async function handleSystemSecurity(
  positionals: string[],
  flags: Record<string, FlagValue>,
  context: ResolvedContext,
  json: boolean,
): Promise<void> {
  const [action, value] = positionals;
  const usage =
    'Usage: eve system security profile <legacy|audit|strict|clear> [--org <id> | --project <id> | --new-projects] [--force]\n' +
    '       eve system security reconcile';
  if (action === 'reconcile') {
    const result = await requestJson<ReconcileReport>(context, '/system/security/reconcile', { method: 'POST', body: {} });
    if (json) {
      outputJson(result, json);
      return;
    }
    const r = result.registry;
    console.log(`Registry pull secrets, key version ${r.key_version}:`);
    console.log(`  re-signed ${r.resigned}, already current ${r.already_current}, without a pull secret ${r.without_pull_secret}, failed ${r.failed.length}`);
    for (const failure of r.failed) {
      console.log(`  ${failure.environment_id}: ${failure.error}`);
    }
    if (r.failed.length > 0) {
      console.log('Environments that failed stay on their old key; run eve system security reconcile again.');
    }
    const t = result.runner_templates;
    if (t?.backend === 'sandbox') {
      const pools = Object.entries(t.warm_pools ?? {}).map(([cls, size]) => `${cls} ${size}`).join(', ');
      console.log(`Runner templates in ${t.namespace}: runtime class ${t.runtime_class ?? 'none'}; warm pools ${pools || 'none'}`);
    } else if (t) {
      console.log(`Runner pods are created directly in ${t.namespace} (${t.reason ?? 'no agent-sandbox'})`);
    }
    return;
  }
  if (action !== 'profile' || !value) throw new Error(usage);
  if (value !== 'clear' && !PROFILES.includes(value)) throw new Error(usage);

  const org = getStringFlag(flags, ['org']);
  const project = getStringFlag(flags, ['project']);
  const newProjects = getBooleanFlag(flags, ['new-projects']) ?? false;
  if ([org, project, newProjects ? 'x' : undefined].filter(Boolean).length > 1) {
    throw new Error('Give at most one of --org, --project and --new-projects');
  }
  const scope = org ? 'org' : project ? 'project' : newProjects ? 'new_projects' : 'instance';
  const force = getBooleanFlag(flags, ['force']) ?? false;
  const body = {
    scope,
    ...(org || project ? { id: org ?? project } : {}),
    profile: value === 'clear' ? null : value,
    ...(force ? { force: true } : {}),
  };

  const result = await requestJson<{ scope: string; id: string | null; profile: string | null; ruleset?: number | null }>(
    context,
    '/system/security/profile',
    { method: 'PUT', body },
  );
  if (json) {
    outputJson(result, json);
    return;
  }
  const target = result.id ? `${result.scope} ${result.id}` : result.scope;
  const cleared = result.scope === 'instance'
    ? 'cleared (the instance profile is now legacy)'
    : result.scope === 'new_projects'
      ? 'cleared (new projects inherit)'
      : 'cleared (inherits)';
  const covers = result.profile === 'strict' && result.ruleset
    ? ` (rule set ${result.ruleset}: ${result.ruleset === 1 ? 'P1' : `P1-P${result.ruleset}`} rules)`
    : '';
  console.log(`Security profile for ${target}: ${result.profile ?? cleared}${covers}`);
}

interface StorageCounts {
  secrets: { v1: number; v2: number; other: number };
  integration_tokens: { plain: number; sealed: number };
  oauth_client_secrets: { plain: number; sealed: number };
}

interface ReencryptReport {
  dry_run: boolean;
  write_format: 'v1' | 'v2';
  before: StorageCounts;
  after: StorageCounts;
  reencrypted: { secrets: number; integration_tokens: number; oauth_client_secrets: number };
  skipped: { changed: number; unreadable: number };
  remaining: number;
}

/**
 * `eve system secrets reencrypt [--dry-run]`: move stored credentials to v2.
 * Attended: after it, releases that read only v1 cannot read them.
 */
export async function handleSystemSecrets(
  positionals: string[],
  flags: Record<string, FlagValue>,
  context: ResolvedContext,
  json: boolean,
): Promise<void> {
  const [action] = positionals;
  if (action !== 'reencrypt') {
    throw new Error('Usage: eve system secrets reencrypt [--dry-run] [--json]');
  }
  const dryRun = getBooleanFlag(flags, ['dry-run']) ?? false;
  const report = await requestJson<ReencryptReport>(context, '/system/secrets/reencrypt', {
    method: 'POST',
    body: { dry_run: dryRun },
  });
  if (json) {
    outputJson(report, json);
    return;
  }
  const counts = (label: string, c: StorageCounts) => {
    console.log(`${label}:`);
    console.log(`  secrets               v1 ${c.secrets.v1}  v2 ${c.secrets.v2}${c.secrets.other ? `  other ${c.secrets.other}` : ''}`);
    console.log(`  integration tokens    plain ${c.integration_tokens.plain}  sealed ${c.integration_tokens.sealed}`);
    console.log(`  OAuth client secrets  plain ${c.oauth_client_secrets.plain}  sealed ${c.oauth_client_secrets.sealed}`);
  };
  counts(report.dry_run ? 'Stored now' : 'Before', report.before);
  if (report.dry_run) {
    console.log(`New writes use ${report.write_format}. Nothing was changed.`);
    console.log(`${report.remaining} row(s) would be re-encrypted. After that, releases below 0.1.327 cannot read them.`);
    return;
  }
  counts('After', report.after);
  const r = report.reencrypted;
  console.log(`Re-encrypted: ${r.secrets} secret(s), ${r.integration_tokens} integration token set(s), ${r.oauth_client_secrets} OAuth client secret(s).`);
  if (report.skipped.changed) {
    console.log(`${report.skipped.changed} row(s) changed during the pass kept their new value; run again to take them.`);
  }
  if (report.skipped.unreadable) {
    console.log(`${report.skipped.unreadable} secret(s) do not open with the master key; set them again or delete them.`);
  }
  console.log(report.remaining === 0
    ? 'No v1 or plain rows are left. New writes use v2.'
    : `${report.remaining} v1 or plain row(s) left. New writes use v2.`);
}
