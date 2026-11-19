import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import type { LoggerService } from '@nestjs/common';
import { RunnerModule } from './runner.module.js';
import type { RunnerExecutor } from './runner.executor.js';
import type { RunnerSelfCheck } from './runner-self-check.js';

/** The runner's HTTP app (no database, no internal key). */
export async function createRunnerApp(opts: {
  executor?: RunnerExecutor;
  selfCheck?: RunnerSelfCheck;
  logger?: LoggerService | false;
} = {}): Promise<NestFastifyApplication> {
  return NestFactory.create<NestFastifyApplication>(
    RunnerModule.register({ executor: opts.executor, selfCheck: opts.selfCheck }),
    new FastifyAdapter({ bodyLimit: 32 * 1024 * 1024 }),
    { logger: opts.logger === undefined ? undefined : opts.logger },
  );
}
