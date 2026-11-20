import { describe, expect, it } from 'vitest';
import { configSchema } from '../../config/schema.js';
import { harnessAdapters } from '../../harnesses/adapters/index.js';
import * as harnesses from '../../harnesses/index.js';
import { ManifestSchema } from '../../schemas/manifest.js';
import * as egress from '../egress-policies.js';
import * as hosts from '../index.js';

/**
 * egress.allow_hosts: the hosts a project's pods may reach on the internet.
 * The manifest declares them (`x-eve.egress.hosts`, at project level and on
 * each service), each harness brings its model API hosts and runners add the
 * project's git host. With the GKE provider the worker writes one
 * FQDNNetworkPolicy per host; under `strict` the internet rule and the
 * allow-all companions are not rendered, so only those policies open the
 * internet.
 */
const api = hosts as Record<string, any>;
const harnessApi = harnesses as Record<string, any>;
const NS = 'eve-acme-shop-prod';
const PROJECT = 'proj_01jabcdefghjkmnpqrstvwxyz0';
const settings = { platformNamespace: 'eve', privateCidrs: [] };

function projectHosts(list: unknown) {
  return ManifestSchema.safeParse({ 'x-eve': { egress: { hosts: list } } });
}

function serviceHosts(list: unknown) {
  return ManifestSchema.safeParse({
    services: { web: { image: 'web:1', 'x-eve': { networking: { egress: 'nat' }, egress: { hosts: list } } } },
  });
}

const accepted = [
  'api.example.com',
  '*.example.com',
  { name: 'smtp.example.com', port: 587 },
  { pattern: '*.cdn.example.com' },
  { name: 'hooks.example.com' },
];

const refused: Array<[string, unknown]> = [
  ['a two-level wildcard', '*.*.example.com'],
  ['a wildcard inside the name', 'api.*.example.com'],
  ['a bare *', '*'],
  ['a wildcard over a top-level domain', '*.com'],
  ['a scheme', 'https://api.example.com'],
  ['a path', 'api.example.com/v1'],
  ['a port in the string', 'api.example.com:8443'],
  ['an IPv4 address', '203.0.113.7'],
  ['an IPv6 address', '2001:db8::1'],
  ['a single label', 'localhost'],
  ['a cluster service name', 'web.shop.svc.cluster.local'],
  ['name and pattern together', { name: 'api.example.com', pattern: '*.example.com' }],
  ['a pattern given as a name', { name: '*.example.com' }],
  ['a name given as a pattern', { pattern: 'api.example.com' }],
  ['port 0', { name: 'api.example.com', port: 0 }],
  ['a port above 65535', { name: 'api.example.com', port: 70000 }],
  ['an unknown field', { name: 'api.example.com', protocol: 'UDP' }],
  // Wildcard DNS services answer any name under them with the address it spells.
  ['a pattern under nip.io', '*.nip.io'],
  ['a pattern deeper under sslip.io', '*.app.sslip.io'],
  ['a pattern under xip.io', { pattern: '*.xip.io' }],
  ['a pattern under localtest.me', '*.localtest.me'],
  ['a name under nip.io', '10.0.0.1.nip.io'],
];

describe('manifest x-eve.egress.hosts', () => {
  it('accepts names, one-label patterns and the object form, at project level and on a service', () => {
    expect(projectHosts(accepted).success).toBe(true);
    const service = serviceHosts(accepted);
    expect(service.success).toBe(true);
    // The service's existing networking.egress setting is untouched by the new key.
    expect((service as any).data.services.web['x-eve'].networking).toEqual({ egress: 'nat' });
  });

  it.each(refused)('refuses %s', (_label, entry) => {
    expect(projectHosts([entry]).success).toBe(false);
    expect(serviceHosts([entry]).success).toBe(false);
  });

  it('refuses more than 50 entries in one list', () => {
    const many = Array.from({ length: 51 }, (_, i) => `h${i}.example.com`);
    expect(projectHosts(many.slice(0, 50)).success).toBe(true);
    expect(projectHosts(many).success).toBe(false);
    expect(serviceHosts(many).success).toBe(false);
  });

  it('reads an entry in canonical form: lower case, port 443 by default', () => {
    expect(api.parseEgressHost('API.Example.com')).toEqual({ name: 'api.example.com', port: 443 });
    expect(api.parseEgressHost('*.Example.com')).toEqual({ pattern: '*.example.com', port: 443 });
    expect(api.parseEgressHost({ name: 'smtp.example.com', port: 587 })).toEqual({ name: 'smtp.example.com', port: 587 });
    expect(api.parseEgressHost('https://api.example.com')).toBeNull();
  });
});

describe('the addresses a declared name resolves to', () => {
  const resolver = (answers: Record<string, string[]>) => async (host: string) => {
    if (!(host in answers)) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: 'ENOTFOUND' });
    return answers[host];
  };

  it('refuses a name that resolves to a private, CGNAT, link-local, loopback or operator-private address, naming both', async () => {
    const answers = {
      'db.example.com': ['10.20.0.5'],
      'nat.example.com': ['100.64.1.1'],
      'meta.example.com': ['169.254.169.254'],
      'loop.example.com': ['127.0.0.1'],
      'v6.example.com': ['fd00::1'],
      'svc.example.com': ['34.118.224.10'],
      'api.example.com': ['93.184.216.34'],
    };
    const problems = await api.egressHostAddressProblems(
      Object.keys(answers).map((name) => ({ name, port: 443 })),
      { privateCidrs: ['34.118.224.0/20'], resolve: resolver(answers) },
    );
    expect(problems).toHaveLength(6);
    expect(problems.join('\n')).toMatch(/db\.example\.com.*10\.20\.0\.5/);
    for (const name of ['nat', 'meta', 'loop', 'v6', 'svc']) expect(problems.join('\n')).toContain(`${name}.example.com`);
    expect(problems.join('\n')).not.toContain('api.example.com');
  });

  it('resolves each name once, skips patterns, and lets a name that does not resolve pass', async () => {
    const seen: string[] = [];
    const resolve = async (host: string) => {
      seen.push(host);
      if (host === 'later.example.com') throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
      return ['93.184.216.34'];
    };
    const problems = await api.egressHostAddressProblems([
      { name: 'api.example.com', port: 443 },
      { name: 'api.example.com', port: 8443 },
      { pattern: '*.cdn.example.com', port: 443 },
      { name: 'later.example.com', port: 443 },
    ], { resolve });
    expect(problems).toEqual([]);
    expect(seen.sort()).toEqual(['api.example.com', 'later.example.com']);
  });
});

describe('harness default hosts', () => {
  it('every harness declares its model API hosts, each a valid entry', () => {
    for (const adapter of harnessAdapters as Array<{ name: string; egressHosts?: string[] }>) {
      expect(adapter.egressHosts, adapter.name).toBeDefined();
      expect(adapter.egressHosts!.length, adapter.name).toBeGreaterThan(0);
      for (const host of adapter.egressHosts!) expect(api.egressHostProblem(host), `${adapter.name}: ${host}`).toBeNull();
    }
  });

  it('names the hosts each harness talks to', () => {
    const of = (name: string) => harnessApi.harnessEgressHosts([name]).map((h: { name: string }) => h.name).sort();
    expect(of('claude')).toEqual(['api.anthropic.com']);
    expect(of('mclaude')).toEqual(['api.anthropic.com']);
    expect(of('zai')).toEqual(['api.z.ai']);
    expect(of('gemini')).toEqual(['generativelanguage.googleapis.com']);
    expect(of('codex')).toEqual(['api.openai.com', 'auth.openai.com', 'chatgpt.com']);
    expect(of('code')).toEqual(['api.openai.com', 'auth.openai.com', 'chatgpt.com']);
    expect(of('pi')).toEqual(['api.anthropic.com', 'api.openai.com', 'api.z.ai', 'generativelanguage.googleapis.com']);
  });

  it('with no names, gives every harness host once', () => {
    const all = harnessApi.harnessEgressHosts().map((h: { name: string; port: number }) => `${h.name}:${h.port}`);
    expect(new Set(all).size).toBe(all.length);
    expect(all).toEqual(expect.arrayContaining(['api.anthropic.com:443', 'chatgpt.com:443', 'api.z.ai:443']));
  });
});

describe('the git host of a project repository', () => {
  it('reads HTTPS, scp-style and ssh URLs, and nothing for local paths or addresses', () => {
    expect(api.gitEgressHost('https://github.com/acme/shop.git')).toEqual({ name: 'github.com', port: 443 });
    expect(api.gitEgressHost('git@github.com:acme/shop.git')).toEqual({ name: 'github.com', port: 22 });
    expect(api.gitEgressHost('ssh://git@git.example.com:2222/acme/shop.git')).toEqual({ name: 'git.example.com', port: 2222 });
    expect(api.gitEgressHost('http://git.example.com/acme/shop')).toEqual({ name: 'git.example.com', port: 80 });
    expect(api.gitEgressHost('file:///srv/repos/shop')).toBeNull();
    expect(api.gitEgressHost('/srv/repos/shop')).toBeNull();
    expect(api.gitEgressHost('https://203.0.113.7/acme/shop.git')).toBeNull();
    expect(api.gitEgressHost(null)).toBeNull();
  });
});

describe('FQDN policies (GKE FQDNNetworkPolicy)', () => {
  const declared = ['api.example.com', '*.cdn.example.com', { name: 'smtp.example.com', port: 587 }];

  it('for a project with three hosts and the Claude harness: one policy per host, selecting the project label, all four listed', () => {
    const list = api.runnerAllowHosts({ projectHosts: declared, harnesses: ['claude'], repoUrl: null });
    const policies = api.runnerFqdnPolicies('eve-runners', PROJECT, list);

    expect(policies).toHaveLength(4);
    for (const policy of policies) {
      expect(policy.apiVersion).toBe('networking.gke.io/v1alpha1');
      expect(policy.kind).toBe('FQDNNetworkPolicy');
      expect(policy.metadata.namespace).toBe('eve-runners');
      expect(policy.metadata.name).toMatch(/^eve-fqdn-[0-9a-f]{16}$/);
      expect(policy.metadata.labels).toMatchObject({
        'app.kubernetes.io/managed-by': 'eve-horizon',
        'eve.horizon/egress': 'fqdn',
        'eve.horizon/project-id': PROJECT,
      });
      expect(policy.spec.podSelector).toEqual({ matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': PROJECT } });
      expect(policy.spec.egress).toHaveLength(1);
      expect(policy.spec.egress[0].matches).toHaveLength(1);
    }
    const listed = policies.map((p: any) => ({ ...p.spec.egress[0].matches[0], port: p.spec.egress[0].ports[0].port }));
    expect(listed).toEqual(expect.arrayContaining([
      { name: 'api.example.com', port: 443 },
      { pattern: '*.cdn.example.com', port: 443 },
      { name: 'smtp.example.com', port: 587 },
      { name: 'api.anthropic.com', port: 443 },
    ]));
    expect(policies.every((p: any) => p.spec.egress[0].ports[0].protocol === 'TCP')).toBe(true);
    expect(new Set(policies.map((p: any) => p.metadata.name)).size).toBe(4);
  });

  it('adds the git host, and lists a host the harness and the project both name once', () => {
    const list = api.runnerAllowHosts({
      projectHosts: ['api.anthropic.com'], harnesses: ['claude'], repoUrl: 'https://github.com/acme/shop.git',
    });
    expect(list).toEqual([{ name: 'api.anthropic.com', port: 443 }, { name: 'github.com', port: 443 }]);
  });

  it('keeps names stable for the same host and distinct across projects', () => {
    const one = api.runnerFqdnPolicies('eve-runners', PROJECT, [{ name: 'api.example.com', port: 443 }]);
    const again = api.runnerFqdnPolicies('eve-runners', PROJECT, [{ name: 'api.example.com', port: 443 }]);
    const other = api.runnerFqdnPolicies('eve-runners', 'proj_other', [{ name: 'api.example.com', port: 443 }]);
    expect(one[0].metadata.name).toBe(again[0].metadata.name);
    expect(one[0].metadata.name).not.toBe(other[0].metadata.name);
  });

  it('in an env namespace: the project list for every pod, a service list for that service only', () => {
    const policies = api.envFqdnPolicies(NS, PROJECT, {
      project: [{ name: 'api.example.com', port: 443 }],
      services: { 'Web_App': [{ name: 'hooks.example.com', port: 443 }] },
    });
    expect(policies).toHaveLength(2);
    const byHost = Object.fromEntries(policies.map((p: any) => [p.spec.egress[0].matches[0].name, p]));
    expect(byHost['api.example.com'].spec.podSelector).toEqual({});
    expect(byHost['hooks.example.com'].spec.podSelector).toEqual({ matchLabels: { 'eve.component': 'web_app' } });
    for (const p of policies) {
      expect(p.metadata.namespace).toBe(NS);
      expect(p.metadata.labels['eve.horizon/egress']).toBe('fqdn');
    }
  });

  it('reads the declared lists from a manifest', () => {
    const lists = api.manifestEgressHosts({
      'x-eve': { egress: { hosts: ['api.example.com'] } },
      services: { web: { 'x-eve': { egress: { hosts: [{ name: 'smtp.example.com', port: 587 }] } } }, db: { image: 'pg' } },
    });
    expect(lists).toEqual({
      project: [{ name: 'api.example.com', port: 443 }],
      services: { web: [{ name: 'smtp.example.com', port: 587 }] },
    });
    expect(api.manifestEgressHosts(null)).toEqual({ project: [], services: {} });
  });
});

describe('egress.allow_hosts and the internet rule', () => {
  const hasInternet = (policies: any[]) =>
    policies.some((p) => p.spec.egress.some((rule: any) => (rule.to ?? []).some((peer: any) => peer.ipBlock?.cidr === '0.0.0.0/0')));
  const allowAll = (policies: any[]) =>
    policies.filter((p) => p.spec.egress.some((rule: any) => Object.keys(rule).length === 0)).map((p) => p.metadata.name);

  it('under strict renders no internet rule and no allow-all companion, in env namespaces and for runners', () => {
    const env = (egress.envEgressPolicies as any)(NS, 'strict', {}, settings, 'strict');
    expect(hasInternet(env)).toBe(false);
    expect(allowAll(env)).toEqual([]);
    expect(env.map((p: any) => p.metadata.name)).toEqual(['eve-egress', 'eve-egress-metadata']);

    const runners = (egress.runnerEgressPolicies as any)('eve-runners', PROJECT, 'strict', {}, settings, 'strict');
    expect(hasInternet(runners)).toBe(false);
    expect(allowAll(runners)).toEqual([]);
    expect(runners).toHaveLength(1);
  });

  it('under strict drops the companions even when egress.default_deny runs under audit', () => {
    const env = (egress.envEgressPolicies as any)(NS, 'audit', {}, settings, 'strict');
    expect(allowAll(env)).toEqual([]);
    expect(hasInternet(env)).toBe(false);
    const runners = (egress.runnerEgressPolicies as any)('eve-runners', PROJECT, 'audit', {}, settings, 'strict');
    expect(allowAll(runners)).toEqual([]);
  });

  it('under audit keeps the internet rule and the companions beside the FQDN policies', () => {
    const env = (egress.envEgressPolicies as any)(NS, 'audit', {}, settings, 'audit');
    expect(hasInternet(env)).toBe(true);
    expect(allowAll(env)).toEqual(['eve-egress-audit']);
    const strictEnv = (egress.envEgressPolicies as any)(NS, 'strict', {}, settings, 'audit');
    expect(hasInternet(strictEnv)).toBe(true);
    const runners = (egress.runnerEgressPolicies as any)('eve-runners', PROJECT, 'strict', {}, settings, 'audit');
    expect(hasInternet(runners)).toBe(true);
    expect(api.runnerFqdnPolicies('eve-runners', PROJECT, [{ name: 'api.example.com', port: 443 }])).toHaveLength(1);
  });
});

describe('EVE_EGRESS_FQDN_PROVIDER', () => {
  it('defaults to none and accepts gke only', () => {
    const shape = (configSchema as any).shape.EVE_EGRESS_FQDN_PROVIDER;
    expect(shape).toBeDefined();
    expect(shape.parse(undefined)).toBe('none');
    expect(shape.parse('gke')).toBe('gke');
    expect(shape.safeParse('calico').success).toBe(false);
  });
});
