import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BuilderModule } from '../builder.module.js';
import { BUILD_BACKEND } from '../image-builder.interface.js';

const providers = Reflect.getMetadata('providers', BuilderModule) as Array<any>;
const factory = providers.find((provider) => provider.provide === BUILD_BACKEND).useFactory;
const docker = { kind: 'buildx' };
const kaniko = { kind: 'kaniko' };
const buildkit = { kind: 'buildkit' };
const sandbox = { kind: 'sandbox' };

afterEach(() => vi.unstubAllEnvs());

describe('builder selection', () => {
  it('selects the registered sandbox backend explicitly', () => {
    vi.stubEnv('EVE_BUILD_BACKEND', 'sandbox');
    vi.stubEnv('EVE_RUNTIME', 'k8s');
    expect(factory(docker, kaniko, buildkit, sandbox)).toBe(sandbox);
  });

  it('rejects an unknown selection before a build can use another backend', () => {
    vi.stubEnv('EVE_BUILD_BACKEND', 'sandbxo');
    expect(() => factory(docker, kaniko, buildkit, sandbox)).toThrow(/EVE_BUILD_BACKEND/);
  });

  it('preserves the configured backends and Kubernetes default', () => {
    for (const [value, selected] of [['buildkit', buildkit], ['kaniko', kaniko], ['docker', docker], ['buildx', docker]] as const) {
      vi.stubEnv('EVE_BUILD_BACKEND', value);
      expect(factory(docker, kaniko, buildkit, sandbox)).toBe(selected);
    }
    vi.stubEnv('EVE_BUILD_BACKEND', '');
    vi.stubEnv('EVE_RUNTIME', 'k8s');
    expect(factory(docker, kaniko, buildkit, sandbox)).toBe(buildkit);
  });
});
