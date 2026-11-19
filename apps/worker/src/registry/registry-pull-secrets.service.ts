import { Inject, Injectable, Logger } from '@nestjs/common';
import * as k8s from '@kubernetes/client-node';
import { environmentQueries, type Db } from '@eve/db';
import {
  deriveNamespace,
  mintRegistryPullCredential,
  registryCredentialKey,
  verifyRegistryPullCredential,
} from '@eve/shared';
import { K8sService } from '../deployer/k8s.service';
import { isK8sNotFound } from '../deployer/k8s-error.js';
import { EVE_REGISTRY_SECRET_NAME, evePullCredentialIn, evePullSecretManifest } from './eve-pull-secret.js';

export interface RegistryResignReport {
  /** The version of the key every re-signed secret now carries. */
  key_version: string;
  /** Pull secrets rewritten with a credential signed with the current key. */
  resigned: number;
  /** Pull secrets already signed with the current key at the current epoch: only recorded. */
  already_current: number;
  /** Environments with no Eve pull secret in their namespace: nothing to re-sign, recorded as current. */
  without_pull_secret: number;
  /** Environments that could not be re-signed; they stay stale. */
  failed: Array<{ environment_id: string; error: string }>;
}

/**
 * Re-signs environments' `eve-registry` pull secrets with the registry
 * credential key (`EVE_REGISTRY_CREDENTIAL_KEY`), with no workload restart:
 * kubelet reads the new secret at its next pull. Each environment is then
 * recorded on the current key version, at its current pull epoch, which is
 * what the instance's strict flip and the removal of the legacy internal key
 * wait for. Run by `eve system security reconcile`.
 *
 * With no credential key set, it re-signs with the internal key instead (the
 * `internal` version): the way back before rolling back to a release that
 * verifies only credentials the internal key signed.
 */
@Injectable()
export class RegistryPullSecretsService {
  private readonly logger = new Logger(RegistryPullSecretsService.name);
  private readonly environments: ReturnType<typeof environmentQueries>;
  private coreApi?: k8s.CoreV1Api;

  constructor(
    @Inject('DB') db: Db,
    private readonly k8sService: K8sService,
  ) {
    this.environments = environmentQueries(db);
  }

  async resign(): Promise<RegistryResignReport> {
    const signer = registryCredentialKey();
    if (!signer) {
      throw new Error('Neither EVE_REGISTRY_CREDENTIAL_KEY nor EVE_INTERNAL_API_KEY is set on the worker: there is no registry key to re-sign with');
    }
    const report: RegistryResignReport = {
      key_version: signer.version,
      resigned: 0,
      already_current: 0,
      without_pull_secret: 0,
      failed: [],
    };

    for (const env of await this.environments.listRegistryKeyCandidates(signer.version)) {
      try {
        const namespace = deriveNamespace(env.org_slug, env.project_slug, env.name, env.namespace);
        const live = evePullCredentialIn(await this.readSecretData(namespace, EVE_REGISTRY_SECRET_NAME));
        if (!live) {
          await this.environments.recordRegistryKeyVersion(env.id, signer.version, env.registry_pull_epoch);
          report.without_pull_secret += 1;
          continue;
        }
        const claims = verifyRegistryPullCredential(live.credential, signer.key);
        if (claims && claims.environmentId === env.id && claims.epoch === env.registry_pull_epoch) {
          await this.environments.recordRegistryKeyVersion(env.id, signer.version, env.registry_pull_epoch);
          report.already_current += 1;
          continue;
        }
        const epoch = await this.environments.bumpRegistryPullEpoch(env.id);
        if (epoch === null) continue; // deleted meanwhile
        const credential = mintRegistryPullCredential(
          { projectId: env.project_id, environmentId: env.id, namespace, epoch },
          signer.key,
        );
        await this.k8sService.applyManifest(namespace, evePullSecretManifest(namespace, live.host, credential));
        await this.environments.recordRegistryKeyVersion(env.id, signer.version, epoch);
        report.resigned += 1;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        this.logger.warn(`Could not re-sign the registry pull secret of environment ${env.id}: ${message}`);
        report.failed.push({ environment_id: env.id, error: message });
      }
    }
    this.logger.log(
      `Registry pull secrets on key version ${report.key_version}: ${report.resigned} re-signed, ` +
        `${report.already_current} already current, ${report.without_pull_secret} without a pull secret, ` +
        `${report.failed.length} failed`,
    );
    return report;
  }

  /** The data of a Secret, or null when it or its namespace does not exist. */
  async readSecretData(namespace: string, name: string): Promise<Record<string, string> | null> {
    if (!this.coreApi) {
      const kc = new k8s.KubeConfig();
      kc.loadFromDefault();
      this.coreApi = kc.makeApiClient(k8s.CoreV1Api);
    }
    try {
      const response = await this.coreApi.readNamespacedSecret(name, namespace);
      return response.body.data ?? null;
    } catch (error) {
      if (isK8sNotFound(error)) return null;
      throw error;
    }
  }
}
