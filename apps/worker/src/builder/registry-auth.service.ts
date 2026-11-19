import { Injectable, Logger } from '@nestjs/common';
import yaml from 'yaml';
import {
  loadConfig,
  mintRegistryPushCredential,
  registryCredentialKey,
  REGISTRY_PUSH_USERNAME,
  resolveProjectSecrets,
} from '@eve/shared';
import { RegistryAuth, RegistryConfig } from './image-builder.interface.js';

@Injectable()
export class RegistryAuthService {
  private readonly logger = new Logger(RegistryAuthService.name);

  /**
   * Resolve registry authentication from manifest and project secrets.
   *
   * Two paths:
   * - `registry: "eve"` — a short-lived push credential scoped to the project's repository prefix
   * - `registry: { host, ... }` — resolves username/token from project secrets (BYO registry)
   */
  async resolve(
    projectId: string,
    manifestYaml: string,
  ): Promise<{ auth: RegistryAuth; config: RegistryConfig }> {
    const parsed = yaml.parse(manifestYaml) as {
      registry?:
        | string
        | {
            host?: string;
            namespace?: string;
            auth?: { username_secret?: string; token_secret?: string };
          };
    } | null;

    const registry = parsed?.registry;

    // ── Eve-native registry ─────────────────────────────────────────────
    if (registry === 'eve') {
      return this.resolveEveRegistry(projectId);
    }

    // ── BYO registry (existing path) ────────────────────────────────────
    const registryObj =
      typeof registry === 'object' ? registry : undefined;
    return this.resolveByoRegistry(projectId, registryObj);
  }

  // ────────────────────────────────────────────────────────────────────────
  // Eve-native registry: a project-scoped push credential
  // ────────────────────────────────────────────────────────────────────────

  private async resolveEveRegistry(projectId: string): Promise<{
    auth: RegistryAuth;
    config: RegistryConfig;
  }> {
    const config = loadConfig();
    const host = config.EVE_REGISTRY_HOST;

    if (!host) {
      throw new Error(
        'Eve registry not configured: EVE_REGISTRY_HOST is not set',
      );
    }

    const signer = registryCredentialKey({
      EVE_REGISTRY_CREDENTIAL_KEY: config.EVE_REGISTRY_CREDENTIAL_KEY,
      EVE_INTERNAL_API_KEY: config.EVE_INTERNAL_API_KEY,
    });
    if (!signer) {
      throw new Error(
        'Eve registry requires EVE_REGISTRY_CREDENTIAL_KEY (or EVE_INTERNAL_API_KEY) to sign build credentials',
      );
    }

    // A push credential scoped to this project's repository prefix, signed
    // with the registry credential key, never an internal key: the docker config is written where the build backend
    // can read it (Kaniko mounts it into the build pod). BuildKit follows the
    // Docker v2 token auth flow: the registry challenges with 401, BuildKit
    // GETs the token endpoint with Basic auth (these creds), and the API grants
    // push and pull under `<project id>/` only.
    const username = REGISTRY_PUSH_USERNAME;
    const password = mintRegistryPushCredential(projectId, signer.key);

    const dockerConfigJson = this.buildDockerConfigJson(host, username, password);

    const registryConfig: RegistryConfig = { host, eveProjectId: projectId };
    const registryAuth: RegistryAuth = {
      host,
      username,
      token: password,
      dockerConfigJson,
    };

    this.logger.log(`Resolved Eve-native registry auth for ${host}`);

    return { auth: registryAuth, config: registryConfig };
  }

  // ────────────────────────────────────────────────────────────────────────
  // BYO registry: resolve credentials from project secrets
  // ────────────────────────────────────────────────────────────────────────

  private async resolveByoRegistry(
    projectId: string,
    registry:
      | {
          host?: string;
          namespace?: string;
          auth?: { username_secret?: string; token_secret?: string };
        }
      | undefined,
  ): Promise<{ auth: RegistryAuth; config: RegistryConfig }> {
    const host = registry?.host;

    if (!host) {
      throw new Error('Registry host not configured in manifest');
    }

    // Resolve secrets via internal API
    const result = await resolveProjectSecrets(projectId);
    if (!result.resolved) {
      throw new Error(
        `Cannot resolve secrets for registry auth: ${result.error}`,
      );
    }

    const usernameKey = registry?.auth?.username_secret ?? 'GHCR_USERNAME';
    const tokenKey = registry?.auth?.token_secret ?? 'GITHUB_TOKEN';

    const username = result.secrets.find(
      (secret) => secret.key === usernameKey,
    )?.value;
    const token =
      result.secrets.find((secret) => secret.key === tokenKey)?.value ??
      result.secrets.find((secret) => secret.key === 'GH_TOKEN')?.value;

    if (!username || !token) {
      throw new Error(
        `Registry auth missing for ${host}. Expected secrets: ${usernameKey} and ${tokenKey}`,
      );
    }

    const dockerConfigJson = this.buildDockerConfigJson(host, username, token);

    const registryConfig: RegistryConfig = {
      host,
      namespace: registry?.namespace,
      auth: registry?.auth
        ? {
            username_secret: registry.auth.username_secret,
            token_secret: registry.auth.token_secret,
          }
        : undefined,
    };

    const registryAuth: RegistryAuth = {
      host,
      username,
      token,
      dockerConfigJson,
    };

    this.logger.log(`Resolved registry auth for ${host}`);

    return { auth: registryAuth, config: registryConfig };
  }

  // ────────────────────────────────────────────────────────────────────────
  // Shared helpers
  // ────────────────────────────────────────────────────────────────────────

  private buildDockerConfigJson(
    host: string,
    username: string,
    password: string,
  ): string {
    const auth = Buffer.from(`${username}:${password}`).toString('base64');
    const dockerConfig = {
      auths: {
        [host]: { username, password, auth },
      },
    };
    return Buffer.from(JSON.stringify(dockerConfig)).toString('base64');
  }
}
