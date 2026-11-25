/**
 * The runner pod's entrypoint (dist/runner/main.js). It runs one job and
 * holds no platform credential: no database URL and no internal key. The
 * worker submits the prepared job; the runner reports through the attempt's
 * push-only routes with the job's own token.
 */
import 'reflect-metadata';
import type { LoggerService } from '@nestjs/common';
import { checkProcessIsolation, initServiceTelemetry, RUNNER_PORT } from '@eve/shared';
import { createRunnerApp } from './runner.app.js';

async function bootstrap() {
  const port = process.env.WORKER_PORT ? parseInt(process.env.WORKER_PORT, 10) : RUNNER_PORT;
  const logger = (await initServiceTelemetry('runner')) as LoggerService;
  // The harness runs as this process's UID; it must not read the runner's
  // memory, nor the environment of the pod's init (tini, PID 1).
  checkProcessIsolation(logger, 'RUNNER', process.env, {}, { init: true });
  const app = await createRunnerApp({ logger });
  const server = app.getHttpServer();
  const timeoutMs = parseInt(process.env.EVE_WORKER_REQUEST_TIMEOUT_MS || '3600000', 10);
  server.setTimeout(timeoutMs);
  await app.listen(port, '0.0.0.0');
  logger.log(`Runner listening on port ${port}`);
}

bootstrap();
