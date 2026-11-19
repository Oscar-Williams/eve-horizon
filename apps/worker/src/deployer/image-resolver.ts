import { Logger } from '@nestjs/common';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadConfig,
  isEveRegistry,
  eveRegistryImageRef,
  getRegistryConfig,
  serviceHelperEnv,
  type Manifest,
  type Service,
} from '@eve/shared';
import { K8sService } from './k8s.service';

/** The parts of an image's config the deployer reads. */
export interface ImageConfig {
  /** The image's `USER` as written; '' when it sets none (root). */
  user: string;
}

/** Runs `crane` with these arguments and extra env; resolves to its stdout. */
export type CraneRunner = (args: string[], env: Record<string, string | undefined>) => Promise<string>;

const CRANE_TIMEOUT_MS = 30_000;
const IMAGE_CONFIG_CACHE_MAX = 500;

const runCrane: CraneRunner = (args, env) => new Promise((resolve, reject) => {
  execFile('crane', args, {
    env: serviceHelperEnv(env),
    timeout: CRANE_TIMEOUT_MS,
    maxBuffer: 4 * 1024 * 1024,
  }, (error, stdout, stderr) => {
    if (error) {
      reject(new Error(String(stderr || error.message).trim()));
      return;
    }
    resolve(stdout);
  });
});

/**
 * ImageResolver - Resolves image references, digests, and registry hosts for
 * rendered workloads. Extracted from DeployerService.
 */
export class ImageResolver {
  /** Configs of digest-pinned images, which cannot change. */
  private readonly configCache = new Map<string, ImageConfig>();

  constructor(
    private readonly k8sService: K8sService,
    private readonly logger: Logger,
    private readonly crane: CraneRunner = runCrane,
  ) {}

  /**
   * Read an image's config with `crane config`, without pulling its layers.
   * Pull credentials, when given, go into a DOCKER_CONFIG directory made for
   * this call and removed after it. Null when the config cannot be read.
   */
  async readImageConfig(image: string, options: { dockerConfigJson?: string | null } = {}): Promise<ImageConfig | null> {
    const cached = this.configCache.get(image);
    if (cached) return cached;
    let dir: string | undefined;
    try {
      if (options.dockerConfigJson) {
        dir = await fs.mkdtemp(join(tmpdir(), 'eve-image-config-'));
        await fs.writeFile(join(dir, 'config.json'), options.dockerConfigJson, { mode: 0o600 });
      }
      const args = [...(this.isClusterLocalRegistry(image) ? ['--insecure'] : []), 'config', image];
      const output = await this.crane(args, { DOCKER_CONFIG: dir });
      const parsed = JSON.parse(output) as { config?: { User?: unknown } } | null;
      const user = parsed?.config?.User;
      const config: ImageConfig = { user: typeof user === 'string' ? user : '' };
      if (image.includes('@sha256:')) {
        if (this.configCache.size >= IMAGE_CONFIG_CACHE_MAX) this.configCache.clear();
        this.configCache.set(image, config);
      }
      return config;
    } catch (error) {
      this.logger.warn(`Could not read the image config of ${image}: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    } finally {
      if (dir) await fs.rm(dir, { recursive: true, force: true });
    }
  }

  /** An in-cluster or loopback registry, which serves plain HTTP. */
  private isClusterLocalRegistry(image: string): boolean {
    const firstSlash = image.indexOf('/');
    if (firstSlash <= 0) return false;
    const host = image.slice(0, firstSlash).replace(/:\d+$/, '');
    return host === 'localhost' || host === '127.0.0.1' || /\.svc(\.cluster\.local)?$/.test(host);
  }

  /**
   * Resolve the registry host from the manifest's registry config.
   * Returns null if no registry prefix should be applied.
   */
  resolveRegistryHost(manifest: Manifest): string | null {
    if (isEveRegistry(manifest)) {
      return loadConfig().EVE_REGISTRY_HOST ?? null;
    }
    const registryConfig = getRegistryConfig(manifest);
    if (registryConfig?.host) {
      return registryConfig.host;
    }
    return null;
  }

  /**
   * Prefix a bare image name with the registry host.
   * A "bare" image has no registry qualifier in its first path segment
   * (no `.`, `:`, and isn't `localhost`).
   */
  prefixRegistryHost(image: string, registryHost: string | null): string {
    if (!registryHost || !image) {
      return image;
    }
    const firstSlash = image.indexOf('/');
    const firstSegment = firstSlash > 0 ? image.slice(0, firstSlash) : image;
    const hasRegistry =
      firstSegment.includes('.') ||
      firstSegment.includes(':') ||
      firstSegment === 'localhost';
    if (hasRegistry) {
      return image;
    }
    return `${registryHost}/${image}`;
  }

  /**
   * Registry-qualified image for a service at deploy time. With the Eve-native
   * registry, a project's images live under its repository prefix, so a bare
   * image, or one naming the Eve registry host, is placed there (matching
   * where the build pushed it). Anything else follows `prefixRegistryHost`.
   */
  resolveServiceImage(image: string, manifest: Manifest, projectId: string): string {
    const registryHost = this.resolveRegistryHost(manifest);
    if (registryHost && isEveRegistry(manifest)) {
      const firstSlash = image.indexOf('/');
      const firstSegment = firstSlash > 0 ? image.slice(0, firstSlash) : image;
      const isBare = this.prefixRegistryHost(image, registryHost) !== image;
      return isBare || firstSegment === registryHost
        ? eveRegistryImageRef(image, registryHost, projectId)
        : image;
    }
    return this.prefixRegistryHost(image, registryHost);
  }

  resolveImageRef(baseImage: unknown, digest?: string, imageTag?: string): string {
    if (typeof baseImage !== 'string' || baseImage.length === 0) {
      if (!digest) {
        throw new Error('Component image missing');
      }
      return digest;
    }

    // If we have a digest, use it (pinned to specific image)
    if (digest && digest.length > 0) {
      if (digest.includes('/') || digest.includes('@')) {
        return digest;
      }
      const normalizedDigest = digest.startsWith('sha256:') ? digest : `sha256:${digest}`;
      return `${baseImage}@${normalizedDigest}`;
    }

    // If baseImage already has a tag (contains ':' after the last '/'), use as-is
    const lastSlash = baseImage.lastIndexOf('/');
    const afterSlash = lastSlash >= 0 ? baseImage.slice(lastSlash + 1) : baseImage;
    if (afterSlash.includes(':')) {
      return baseImage;
    }

    // Apply imageTag if provided, otherwise default to 'latest'
    const tag = imageTag || 'latest';
    return `${baseImage}:${tag}`;
  }

  resolveServiceDigest(
    serviceName: string,
    service: Service,
    allServices: Record<string, Service>,
    imageDigests?: Record<string, string>,
  ): string | undefined {
    if (!imageDigests || Object.keys(imageDigests).length === 0) {
      return undefined;
    }

    const directDigest = imageDigests[serviceName];
    if (typeof directDigest === 'string' && directDigest.length > 0) {
      return directDigest;
    }

    if (!service || typeof service.image !== 'string' || service.image.length === 0) {
      return undefined;
    }

    const targetRepo = this.normalizeImageRepository(service.image);
    for (const [candidateName, digest] of Object.entries(imageDigests)) {
      if (!digest || candidateName === serviceName) {
        continue;
      }
      const candidateService = allServices[candidateName];
      if (!candidateService || typeof candidateService.image !== 'string' || candidateService.image.length === 0) {
        continue;
      }
      if (this.normalizeImageRepository(candidateService.image) === targetRepo) {
        return digest;
      }
    }

    return undefined;
  }

  normalizeImageRepository(image: string): string {
    const withoutDigest = image.split('@')[0];
    const lastSlash = withoutDigest.lastIndexOf('/');
    const lastColon = withoutDigest.lastIndexOf(':');
    if (lastColon > lastSlash) {
      return withoutDigest.slice(0, lastColon);
    }
    return withoutDigest;
  }

  async normalizeImageForKubelet(image: string): Promise<string> {
    const firstSlash = image.indexOf('/');
    if (firstSlash <= 0) {
      return image;
    }

    const registry = image.slice(0, firstSlash);
    const repository = image.slice(firstSlash + 1);
    if (!repository) {
      return image;
    }

    const hostPortMatch = registry.match(/^([^:]+)(?::(\d+))?$/);
    if (!hostPortMatch) {
      return image;
    }
    const host = hostPortMatch[1];
    const port = hostPortMatch[2];

    const svcMatch = host.match(/^([a-z0-9-]+)\.([a-z0-9-]+)\.svc(?:\.cluster\.local)?$/i);
    if (!svcMatch) {
      return image;
    }

    const serviceName = svcMatch[1];
    const namespace = svcMatch[2];

    // Keep eve-registry service hostnames intact so kubelet uses the
    // configured insecure-registry host mapping (ClusterIP rewrites break it).
    if (serviceName === 'eve-registry') {
      return image;
    }

    try {
      const clusterIP = await this.k8sService.getServiceClusterIP(namespace, serviceName);
      if (!clusterIP) {
        return image;
      }
      const normalizedRegistry = port ? `${clusterIP}:${port}` : clusterIP;
      return `${normalizedRegistry}/${repository}`;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(
        `Failed to resolve ClusterIP for registry host ${host}, using original image ref: ${message}`,
      );
      return image;
    }
  }
}
