import type { FlagValue } from '../lib/args';
import { getBooleanFlag, getStringFlag } from '../lib/args';
import type { ResolvedContext } from '../lib/context';
import { requestJson } from '../lib/client';
import { outputJson } from '../lib/output';
import { buildQuery } from '../lib/format';

type ScopeProfile = { id: string; slug: string; org_id?: string | null; profile: string | null; effective: string };

interface SecurityReport {
  days: number;
  instance_profile: string;
  new_project_profile: string | null;
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
  console.log(`Instance profile: ${report.instance_profile}`);
  console.log(`New projects:     ${report.new_project_profile ?? 'inherit'}`);
  console.log('');
  console.log('Orgs:');
  for (const org of report.orgs) {
    console.log(`  ${org.slug.padEnd(24)} ${org.effective.padEnd(7)} (${own(org.profile)})  ${org.id}`);
  }
  console.log('Projects:');
  for (const project of report.projects) {
    console.log(`  ${project.slug.padEnd(24)} ${project.effective.padEnd(7)} (${own(project.profile)})  ${project.id}`);
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
}

/**
 * `eve system security profile <legacy|audit|strict|clear>
 *   [--org <id> | --project <id> | --new-projects]`
 * With no scope flag it sets the instance profile.
 */
export async function handleSystemSecurity(
  positionals: string[],
  flags: Record<string, FlagValue>,
  context: ResolvedContext,
  json: boolean,
): Promise<void> {
  const [action, value] = positionals;
  const usage =
    'Usage: eve system security profile <legacy|audit|strict|clear> [--org <id> | --project <id> | --new-projects]';
  if (action !== 'profile' || !value) throw new Error(usage);
  if (value !== 'clear' && !PROFILES.includes(value)) throw new Error(usage);

  const org = getStringFlag(flags, ['org']);
  const project = getStringFlag(flags, ['project']);
  const newProjects = getBooleanFlag(flags, ['new-projects']) ?? false;
  if ([org, project, newProjects ? 'x' : undefined].filter(Boolean).length > 1) {
    throw new Error('Give at most one of --org, --project and --new-projects');
  }
  const scope = org ? 'org' : project ? 'project' : newProjects ? 'new_projects' : 'instance';
  const body = { scope, ...(org || project ? { id: org ?? project } : {}), profile: value === 'clear' ? null : value };

  const result = await requestJson<{ scope: string; id: string | null; profile: string | null }>(
    context,
    '/system/security/profile',
    { method: 'PUT', body },
  );
  if (json) {
    outputJson(result, json);
    return;
  }
  const target = result.id ? `${result.scope} ${result.id}` : result.scope;
  console.log(`Security profile for ${target}: ${result.profile ?? 'cleared (inherits)'}`);
}
