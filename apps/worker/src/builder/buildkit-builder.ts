import { Injectable, Logger } from '@nestjs/common';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { bindProcessCancellation, eveRegistryImageRef } from '@eve/shared';
import {
  BuildAllParams,
  BuildResult,
  BuildServiceParams,
  BuildBackend,
} from './image-builder.interface.js';
import { serviceHelperEnv } from '@eve/shared';

function isTruthy(value: string | undefined): boolean {
  if (!value) return false;
  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function normalizeHost(value: string): string {
  return value.trim().toLowerCase();
}

function parseHostFromImageRef(imageRef: string): string | null {
  const imageNoTag = imageRef.split('@')[0] ?? imageRef;
  const firstSegment = imageNoTag.split('/')[0];
  if (!firstSegment) return null;
  if (
    firstSegment.includes('.') ||
    firstSegment.includes(':') ||
    firstSegment === 'localhost'
  ) {
    return firstSegment;
  }
  return null;
}

/**
 * The BuildKit registry cache to use for a build. A cache on the Eve registry
 * becomes one per project (under the project's prefix): a shared cache would
 * let one project's build feed layers into another's, and a project's push
 * credential cannot write outside its prefix anyway.
 */
export function resolveBuildkitCacheRepo(
  cacheRepo: string | undefined,
  registryHost: string,
  eveProjectId: string | undefined,
): string | undefined {
  if (cacheRepo && eveProjectId && cacheRepo.startsWith(`${registryHost}/`)) {
    return eveRegistryImageRef(cacheRepo, registryHost, eveProjectId);
  }
  return cacheRepo || undefined;
}

export function resolveIsolatedCacheRepo(configured: string | undefined, params: BuildServiceParams): string | undefined {
  if (!configured) return undefined;
  if (params.registryConfig.eveProjectId && configured.startsWith(`${params.registryAuth.host}/`)) {
    return resolveBuildkitCacheRepo(configured, params.registryAuth.host, params.projectId);
  }
  return `${params.imageRef}:eve-cache-${params.projectId}`;
}

function parseHostFromRegistryRef(ref: string): string | null {
  const candidate = ref.split('@')[0]?.split(':')[0] ?? ref;
  const firstSegment = candidate.split('/')[0];
  if (!firstSegment) return null;
  if (
    firstSegment.includes('.') ||
    firstSegment.includes(':') ||
    firstSegment === 'localhost'
  ) {
    return firstSegment;
  }
  return null;
}

function isLikelyInsecureHost(host: string): boolean {
  const normalized = normalizeHost(host);
  return (
    normalized === 'localhost' ||
    normalized.startsWith('localhost:') ||
    normalized.startsWith('127.') ||
    normalized.startsWith('host.docker.internal') ||
    normalized.includes('.svc') ||
    normalized.includes('.cluster.local') ||
    normalized.startsWith('k3d-registry') ||
    normalized.startsWith('eve-registry')
  );
}

function resolveInsecureRegistryHosts(): Set<string> {
  const raw = process.env.EVE_BUILDKIT_INSECURE_REGISTRIES;
  if (!raw) return new Set();
  return new Set(
    raw
      .split(',')
      .map((entry) => normalizeHost(entry))
      .filter((entry) => entry.length > 0),
  );
}

export function shouldUseInsecureRegistryForHost(
  host: string | null,
  insecureHosts: Set<string> = resolveInsecureRegistryHosts(),
): boolean {
  if (!host) return false;
  if (isTruthy(process.env.EVE_BUILDKIT_INSECURE_ALL)) return true;

  const normalized = normalizeHost(host);
  if (insecureHosts.has(normalized)) return true;
  return isLikelyInsecureHost(normalized);
}

function extractFailedStage(outputLines: string[]): string | null {
  for (let i = outputLines.length - 1; i >= 0; i--) {
    const match = outputLines[i].match(/#\d+\s+\[([^\]]+)\]\s+(.+)/);
    if (match) return `[${match[1]}] ${match[2]}`;
  }
  return null;
}

@Injectable()
export class BuildKitBuilder implements BuildBackend {
  readonly kind = 'buildkit' as const;
  private readonly logger = new Logger(BuildKitBuilder.name);

  async buildAll(_params: BuildAllParams): Promise<BuildResult> {
    throw new Error('Use ImageBuilderService.buildAll() instead');
  }

  async buildService(params: BuildServiceParams): Promise<string> {
    return this.buildServiceAt(params, this.resolveBuildkitAddr());
  }

  /** The sandbox backend supplies its verified, build-specific endpoint. */
  async buildServiceAt(params: BuildServiceParams, addr: string, isolated = false): Promise<string> {
    params.signal?.throwIfAborted();
    this.logger.log(
      `Building service ${params.serviceName} with tag ${params.tag} (buildkit ${addr})`,
    );
    params.onLog?.(`buildkit addr: ${addr}`);

    let tempDir: string | undefined;

    try {
      tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'buildkit-'));
      const dockerConfigPath = path.join(tempDir, 'config.json');
      const metadataPath = path.join(tempDir, 'metadata.json');

      const dockerConfigJson = Buffer.from(
        params.registryAuth.dockerConfigJson,
        'base64',
      ).toString('utf-8');
      await fs.writeFile(dockerConfigPath, dockerConfigJson, { encoding: 'utf-8', mode: 0o600 });

      const buildContext = params.service.build?.context ?? '.';
      const dockerfile = params.service.build?.dockerfile ?? 'Dockerfile';
      let contextPath = path.resolve(params.workspacePath, buildContext);
      const normalizedContext = path
        .normalize(buildContext)
        .replace(/^\.[\\/]?/, '');
      const normalizedDockerfile = path
        .normalize(dockerfile)
        .replace(/^\.[\\/]?/, '');

      let relativeDockerfile = normalizedDockerfile;
      if (
        normalizedContext &&
        normalizedDockerfile.startsWith(normalizedContext + path.sep)
      ) {
        relativeDockerfile = normalizedDockerfile.slice(
          normalizedContext.length + 1,
        );
      }

      if (isolated) {
        const workspaceRoot = await fs.realpath(params.workspacePath);
        const contextRoot = await fs.realpath(contextPath);
        const inside = (root: string, candidate: string): boolean => {
          const relative = path.relative(root, candidate);
          return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
        };
        if (!inside(workspaceRoot, contextRoot)) throw new Error('Build context is outside the checkout');
        const dockerfilePath = await fs.realpath(path.resolve(contextRoot, relativeDockerfile));
        if (!inside(contextRoot, dockerfilePath)) throw new Error('Dockerfile is outside the build context');
        // Never send clone metadata (including authenticated remotes/reflogs).
        // A snapshot also keeps a Dockerfile-specific ignore file from opting it in.
        const snapshot = path.join(tempDir, 'context');
        await fs.cp(contextRoot, snapshot, {
          recursive: true, dereference: false, verbatimSymlinks: true,
          filter: (source) => {
            params.signal?.throwIfAborted();
            return path.basename(source) !== '.git';
          },
        });
        params.signal?.throwIfAborted();
        contextPath = snapshot;
      }

      const fullImageTag = `${params.imageRef}:${params.tag}`;
      const insecureHosts = resolveInsecureRegistryHosts();
      const imageRegistryHost = parseHostFromImageRef(params.imageRef);
      const insecureOutput =
        shouldUseInsecureRegistryForHost(params.registryAuth.host, insecureHosts) ||
        shouldUseInsecureRegistryForHost(imageRegistryHost, insecureHosts);
      const outputSpec = insecureOutput
        ? `type=image,name=${fullImageTag},push=true,registry.insecure=true`
        : `type=image,name=${fullImageTag},push=true`;

      const args = [
        '--addr',
        addr,
        'build',
        '--progress=plain',
        '--frontend',
        'dockerfile.v0',
        '--local',
        `context=${contextPath}`,
        '--local',
        `dockerfile=${contextPath}`,
        '--opt',
        `filename=${relativeDockerfile}`,
        '--output',
        outputSpec,
        '--metadata-file',
        metadataPath,
      ];
      if (insecureOutput) {
        params.onLog?.(`buildkit registry transport: insecure for ${params.registryAuth.host}`);
      }

      const cacheRepo = resolveBuildkitCacheRepo(
        isolated ? resolveIsolatedCacheRepo(process.env.EVE_BUILDKIT_CACHE_REPO, params) : process.env.EVE_BUILDKIT_CACHE_REPO,
        params.registryAuth.host,
        params.registryConfig.eveProjectId,
      );
      if (cacheRepo) {
        const cacheHost = parseHostFromRegistryRef(cacheRepo);
        const insecureCache = shouldUseInsecureRegistryForHost(cacheHost, insecureHosts);
        const exportCacheSpec = insecureCache
          ? `type=registry,ref=${cacheRepo},mode=max,registry.insecure=true`
          : `type=registry,ref=${cacheRepo},mode=max`;
        const importCacheSpec = insecureCache
          ? `type=registry,ref=${cacheRepo},registry.insecure=true`
          : `type=registry,ref=${cacheRepo}`;
        args.push(
          '--export-cache',
          exportCacheSpec,
          '--import-cache',
          importCacheSpec,
        );
        params.onLog?.(
          `buildkit cache repo: ${cacheRepo}${insecureCache ? ' (insecure transport)' : ''}`,
        );
      }

      if (params.repoUrl) {
        args.push(
          '--opt',
          `label:org.opencontainers.image.source=${params.repoUrl}`,
        );
      }
      args.push(
        '--opt',
        `label:org.opencontainers.image.description=Eve Horizon built image: ${params.serviceName}`,
      );

      // Build args (auto-injected + manifest-defined)
      args.push('--opt', `build-arg:GIT_SHA=${params.gitSha}`);
      args.push('--opt', `build-arg:BUILD_DATE=${new Date().toISOString()}`);
      for (const [key, value] of Object.entries(params.service.build?.args ?? {})) {
        args.push('--opt', `build-arg:${key}=${value}`);
      }

      params.onLog?.(`Running buildctl build --push for ${fullImageTag}`);

      const outputLines: string[] = [];
      const { exitCode } = await this.spawnBuildctl(args, {
        cwd: params.workspacePath,
        signal: params.signal,
        env: {
          DOCKER_CONFIG: tempDir,
        },
        onLine: (line) => {
          outputLines.push(line);
          params.onLog?.(line);
        },
      });

      if (exitCode !== 0) {
        const tail = outputLines.slice(-30).join('\n');
        const failedStage = extractFailedStage(outputLines);
        throw new Error(
          `buildctl failed with exit code ${exitCode}` +
          (failedStage ? ` at ${failedStage}` : '') +
          `\n--- Last ${Math.min(outputLines.length, 30)} lines ---\n${tail}`,
        );
      }

      params.signal?.throwIfAborted();
      const digest = await this.extractDigest(metadataPath, outputLines);
      this.logger.log(`Service ${params.serviceName} pushed with digest: ${digest}`);
      params.onLog?.(`Digest: ${digest}`);
      return digest;
    } finally {
      if (tempDir) {
        try {
          await fs.rm(tempDir, { recursive: true, force: true });
        } catch (err) {
          throw new Error(`buildkit_auth_cleanup_failed: ${tempDir}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }
  }

  private resolveBuildkitAddr(): string {
    return (
      process.env.EVE_BUILDKIT_ADDR ??
      process.env.BUILDKIT_HOST ??
      'tcp://buildkitd.eve.svc:1234'
    );
  }

  private async spawnBuildctl(
    args: string[],
    opts: {
      signal?: AbortSignal;
      cwd?: string;
      env?: Record<string, string>;
      onLine?: (line: string) => void;
    },
  ): Promise<{ exitCode: number }> {
    // Allowlisted env plus the per-build DOCKER_CONFIG; no service credentials.
    const env = serviceHelperEnv(opts.env);

    opts.signal?.throwIfAborted();
    const proc = spawn('buildctl', args, {
      cwd: opts.cwd,
      env,
      detached: process.platform !== 'win32',
    });

    const releaseCancellation = bindProcessCancellation(proc, opts.signal);
    const onLine = opts.onLine;
    const stdoutBuffer = this.createLineBuffer(onLine);
    const stderrBuffer = this.createLineBuffer(onLine);

    proc.stdout?.on('data', (chunk) => stdoutBuffer.push(chunk.toString()));
    proc.stderr?.on('data', (chunk) => stderrBuffer.push(chunk.toString()));

    try {
      const exitCode = await new Promise<number>((resolve, reject) => {
        proc.on('error', reject);
        proc.on('close', (code) => resolve(code ?? 1));
      });
      opts.signal?.throwIfAborted();
      return { exitCode };
    } finally {
      await releaseCancellation();
      stdoutBuffer.flush();
      stderrBuffer.flush();
    }
  }

  private createLineBuffer(onLine?: (line: string) => void) {
    let buffer = '';
    return {
      push: (chunk: string) => {
        if (!onLine) return;
        buffer += chunk;
        let index = buffer.indexOf('\n');
        while (index >= 0) {
          const line = buffer.slice(0, index).replace(/\r$/, '');
          buffer = buffer.slice(index + 1);
          if (line) {
            onLine(line);
          }
          index = buffer.indexOf('\n');
        }
      },
      flush: () => {
        if (!onLine) return;
        const line = buffer.replace(/\r$/, '');
        if (line) {
          onLine(line);
        }
        buffer = '';
      },
    };
  }

  private async extractDigest(
    metadataPath: string,
    outputLines: string[],
  ): Promise<string> {
    try {
      const metadataRaw = await fs.readFile(metadataPath, 'utf-8');
      const metadata = JSON.parse(metadataRaw) as Record<string, unknown>;
      const direct = metadata['containerimage.digest'] as string | undefined;
      if (direct) {
        return direct;
      }
      const exporter = metadata['exporter-response'] as Record<string, unknown> | undefined;
      const digest = typeof exporter?.['digest'] === 'string' ? exporter['digest'] : undefined;
      if (digest) {
        return digest;
      }
    } catch (err) {
      this.logger.warn(`Failed to parse buildkit metadata: ${err}`);
    }

    const combined = outputLines.join('\n');
    const match = combined.match(/sha256:[a-f0-9]{64}/g);
    if (match && match.length > 0) {
      return match[match.length - 1];
    }

    throw new Error('BuildKit build succeeded but no digest found');
  }
}
