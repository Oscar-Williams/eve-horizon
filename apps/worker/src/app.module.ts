import { Module } from '@nestjs/common';
import { DatabaseModule } from './database/database.module';
import { HealthModule } from './health/health.module';
import { InvokeModule } from './invoke/invoke.module';
import { ActionExecutorModule } from './action-executor/action-executor.module';
import { DeployerModule } from './deployer/deployer.module';
import { PipelineRunnerModule } from './pipeline-runner/pipeline-runner.module';
import { ScriptExecutorModule } from './script-executor/script-executor.module';
import { BuilderModule } from './builder/builder.module.js';
import { ReaperModule } from './reaper/reaper.module';
import { RegistryModule } from './registry/registry.module.js';
import { RunnerTemplatesModule } from './runner-templates/runner-templates.module.js';
import { NetworkModule } from './network/network.module.js';
import { ServiceTokensModule } from './service-tokens/service-tokens.module';

@Module({
  imports: [
    DatabaseModule,
    HealthModule,
    InvokeModule,
    ActionExecutorModule,
    DeployerModule,
    PipelineRunnerModule,
    ScriptExecutorModule,
    BuilderModule,
    ReaperModule,
    RegistryModule,
    RunnerTemplatesModule,
    NetworkModule,
    ServiceTokensModule,
  ],
})
export class AppModule {}
