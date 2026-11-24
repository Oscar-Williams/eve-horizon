import { Module } from '@nestjs/common';
import { DeployerModule } from '../deployer/deployer.module.js';
import { ImageBuilderService } from './image-builder.service.js';
import { RegistryAuthService } from './registry-auth.service.js';
import { DockerBuildxBuilder } from './docker-buildx-builder.js';
import { KanikoBuilder } from './kaniko-builder.js';
import { BuildKitBuilder } from './buildkit-builder.js';
import { SandboxBuildKitBuilder } from './sandbox-buildkit-builder.js';
import { BUILD_BACKEND } from './image-builder.interface.js';

@Module({
  imports: [DeployerModule],
  providers: [
    ImageBuilderService,
    RegistryAuthService,
    DockerBuildxBuilder,
    KanikoBuilder,
    BuildKitBuilder,
    SandboxBuildKitBuilder,
    {
      provide: BUILD_BACKEND,
      useFactory: (
        dockerBuilder: DockerBuildxBuilder,
        kanikoBuilder: KanikoBuilder,
        buildkitBuilder: BuildKitBuilder,
        sandboxBuilder: SandboxBuildKitBuilder,
      ) => {
        const configured = (process.env.EVE_BUILD_BACKEND ?? '').toLowerCase();
        if (configured === 'sandbox') return sandboxBuilder;
        if (configured === 'kaniko') {
          return kanikoBuilder;
        }
        if (configured === 'buildkit') {
          return buildkitBuilder;
        }
        if (configured === 'buildx' || configured === 'docker') {
          return dockerBuilder;
        }

        if (configured) throw new Error(`Unknown EVE_BUILD_BACKEND: ${configured}`);

        const inK8s =
          process.env.EVE_RUNTIME === 'k8s' ||
          Boolean(process.env.KUBERNETES_SERVICE_HOST);
        return inK8s ? buildkitBuilder : dockerBuilder;
      },
      inject: [DockerBuildxBuilder, KanikoBuilder, BuildKitBuilder, SandboxBuildKitBuilder],
    },
  ],
  exports: [ImageBuilderService, RegistryAuthService],
})
export class BuilderModule {}
