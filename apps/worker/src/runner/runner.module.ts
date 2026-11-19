import { Module, type DynamicModule } from '@nestjs/common';
import { RunnerController } from './runner.controller.js';
import { RUNNER_EXECUTOR, RunnerJobExecutor, type RunnerExecutor } from './runner.executor.js';
import { RUNNER_SELF_CHECK, noSelfCheck, type RunnerSelfCheck } from './runner-self-check.js';

/**
 * The runner entrypoint's module: one controller, and the job executor. It
 * loads no database module and none of the worker's deployer, builder,
 * reaper or pipeline modules.
 */
@Module({})
export class RunnerModule {
  static register(opts: { executor?: RunnerExecutor; selfCheck?: RunnerSelfCheck } = {}): DynamicModule {
    return {
      module: RunnerModule,
      controllers: [RunnerController],
      providers: [
        { provide: RUNNER_EXECUTOR, useValue: opts.executor ?? new RunnerJobExecutor() },
        { provide: RUNNER_SELF_CHECK, useValue: opts.selfCheck ?? noSelfCheck },
      ],
    };
  }
}
