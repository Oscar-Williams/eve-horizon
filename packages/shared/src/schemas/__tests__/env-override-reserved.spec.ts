import { describe, expect, it } from 'vitest';
import { CreateJobRequestSchema, isReservedEnvKey } from '../job.js';
import { ManifestSchema } from '../manifest.js';
import { WorkflowInvokeRequestSchema } from '../workflow.js';
import { PipelineDefinitionSchema } from '../pipeline.js';
import { ChatHintsSchema } from '../agent-primitives.js';
import { BatchNodeSchema } from '../batch.js';

const PROVIDER_CREDENTIALS = [
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_AUTH_TOKEN',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'OPENAI_API_KEY',
  'CODEX_AUTH_JSON',
  'CODEX_OAUTH_ACCESS_TOKEN',
  'GOOGLE_API_KEY',
  'GEMINI_API_KEY',
  'Z_AI_API_KEY',
  'ZAI_API_KEY',
];

const ROUTING = [
  'ANTHROPIC_BASE_URL',
  'OPENAI_BASE_URL',
  'GOOGLE_GEMINI_BASE_URL',
  'OPENAI_API_BASE',
  'ANTHROPIC_CUSTOM_HEADERS',
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
];

function jobAccepts(env_overrides: Record<string, string>): boolean {
  return CreateJobRequestSchema.safeParse({ description: 'run', env_overrides }).success;
}

function workflowInvokeAccepts(env_overrides: Record<string, string>): boolean {
  return WorkflowInvokeRequestSchema.safeParse({ env_overrides }).success;
}

function manifestStepAccepts(env_overrides: Record<string, string>): boolean {
  return ManifestSchema.safeParse({
    workflows: { wf: { steps: [{ name: 'one', agent: { prompt: 'Run' }, env_overrides }] } },
  }).success;
}

function pipelineStepAccepts(env_overrides: Record<string, string>): boolean {
  return PipelineDefinitionSchema.safeParse({
    steps: [{ name: 'one', agent: { prompt: 'Run' }, env_overrides }],
  }).success;
}

function chatHintsAccept(env_overrides: Record<string, string>): boolean {
  return ChatHintsSchema.safeParse({ env_overrides }).success;
}

const ENTRY_POINTS: Array<[string, (env: Record<string, string>) => boolean]> = [
  ['job create', jobAccepts],
  ['workflow invoke', workflowInvokeAccepts],
  ['manifest workflow step', manifestStepAccepts],
  ['pipeline step', pipelineStepAccepts],
  ['chat hints', chatHintsAccept],
];

describe('env override names reserved for model credentials and routing', () => {
  it('refuses a literal ANTHROPIC_BASE_URL and HTTPS_PROXY at every entry point', () => {
    for (const [name, accepts] of ENTRY_POINTS) {
      expect(accepts({ ANTHROPIC_BASE_URL: 'https://models.example.test' }), name).toBe(false);
      expect(accepts({ HTTPS_PROXY: 'http://proxy.example.test:3128' }), name).toBe(false);
    }
  });

  it('refuses a lowercase proxy name', () => {
    expect(jobAccepts({ https_proxy: 'http://proxy.example.test:3128' })).toBe(false);
    expect(isReservedEnvKey('https_proxy')).toBe(true);
    expect(isReservedEnvKey('Http_Proxy')).toBe(true);
  });

  it('refuses every provider credential, even as a secret reference', () => {
    for (const key of PROVIDER_CREDENTIALS) {
      expect(jobAccepts({ [key]: 'literal-value' }), key).toBe(false);
      expect(jobAccepts({ [key]: '${secret.SOME_KEY}' }), key).toBe(false);
      expect(isReservedEnvKey(key.toLowerCase()), key).toBe(true);
    }
  });

  it('refuses every routing name given a literal value', () => {
    for (const key of ROUTING) {
      expect(jobAccepts({ [key]: '1' }), key).toBe(false);
      expect(isReservedEnvKey(key), key).toBe(true);
    }
  });

  it('allows a routing name whose whole value is one secret reference', () => {
    for (const [name, accepts] of ENTRY_POINTS) {
      expect(accepts({ ANTHROPIC_BASE_URL: '${secret.EDEN_TEST_BASE_URL}' }), name).toBe(true);
      expect(accepts({ HTTPS_PROXY: '${secret.EGRESS_PROXY}' }), name).toBe(true);
    }
  });

  it('refuses a routing value that only embeds a secret reference', () => {
    expect(jobAccepts({ ANTHROPIC_BASE_URL: 'https://${secret.MODEL_HOST}/v1' })).toBe(false);
    expect(jobAccepts({ ANTHROPIC_BASE_URL: '${secret.A}${secret.B}' })).toBe(false);
  });

  it('keeps the names tenants pass today', () => {
    expect(jobAccepts({
      FIRECRAWL_API_KEY: '${secret.FIRECRAWL_API_KEY}',
      TAVILY_API_KEY: '${secret.TAVILY_API_KEY}',
      BASH_DEFAULT_TIMEOUT_MS: '900000',
      BASH_MAX_TIMEOUT_MS: '1800000',
      CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS: '0',
      CLAUDE_CODE_MAX_OUTPUT_TOKENS: '160000',
      DEAL_ID: 'deal_1',
      CLOUD_FS_MOUNT_ID: 'mnt_1',
    })).toBe(true);
  });

  it('gives batch nodes no env overrides to carry', () => {
    const parsed = BatchNodeSchema.parse({
      key: 'one',
      title: 'One',
      env_overrides: { ANTHROPIC_BASE_URL: 'https://models.example.test' },
    } as Record<string, unknown>);
    expect(parsed).not.toHaveProperty('env_overrides');
  });
});

describe('names that load code or set TLS trust', () => {
  const LOADERS = [
    'LD_PRELOAD',
    'LD_LIBRARY_PATH',
    'DYLD_INSERT_LIBRARIES',
    'DYLD_LIBRARY_PATH',
    'BASH_ENV',
    'ENV',
    'NODE_OPTIONS',
    'PYTHONPATH',
    'PYTHONSTARTUP',
  ];
  const TLS_TRUST = ['SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'];

  it.each(LOADERS)('refuses %s as an override, literal or secret', (key) => {
    expect(isReservedEnvKey(key)).toBe(true);
    expect(jobAccepts({ [key]: '/tmp/x' })).toBe(false);
    expect(jobAccepts({ [key]: '${secret.LOADER}' })).toBe(false);
  });

  it.each(TLS_TRUST)('takes %s only from a single ${secret.KEY}', (key) => {
    expect(isReservedEnvKey(key)).toBe(true);
    expect(jobAccepts({ [key]: '/etc/ssl/custom' })).toBe(false);
    expect(jobAccepts({ [key]: '${secret.CA_BUNDLE}' })).toBe(true);
  });
});

