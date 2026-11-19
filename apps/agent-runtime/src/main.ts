import 'dotenv/config';
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import type { LoggerService } from '@nestjs/common';
import {
  assertInternalApiKeyConfigured,
  initServiceTelemetry,
  registerCorrelationIdHook,
  legacyInternalKeyJudge,
  registerInternalAuthHook,
} from '@eve/shared';
import { internalLegacyKeyDecider, type Db } from '@eve/db';
import { AppModule } from './app.module';
import { checkProcessIsolation } from '@eve/shared';

function resolvePort(): number {
  const raw = process.env.AGENT_RUNTIME_PORT ?? process.env.EVE_AGENT_RUNTIME_PORT;
  return raw ? parseInt(raw, 10) : 4812;
}

async function bootstrap() {
  const port = resolvePort();

  const logger = (await initServiceTelemetry('agent-runtime')) as LoggerService;
  // Every route except /health requires an internal key (fails closed).
  assertInternalApiKeyConfigured(logger, 'AGENT_RUNTIME');

  // Harnesses run as this process's UID; they must not be able to read its
  // environment (DATABASE_URL, EVE_INTERNAL_API_KEY) through /proc.
  checkProcessIsolation(logger, 'AGENT-RUNTIME');

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
    { logger },
  );

  registerCorrelationIdHook(app.getHttpAdapter().getInstance());
  // The core key passes; a call with only the legacy key follows the
  // instance's internal.service_key rule (refused under strict).
  registerInternalAuthHook(app.getHttpAdapter().getInstance(), {
    onLegacyKey: legacyInternalKeyJudge(internalLegacyKeyDecider(app.get<Db>('DB'), 'agent-runtime')),
  });

  app.enableShutdownHooks();
  await app.listen(port, '0.0.0.0');
  logger.log(`Agent runtime listening on port ${port}`);
}

bootstrap();
