import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { SecretsModule } from '../secrets/secrets.module.js';
import { ChatModule } from '../chat/chat.module.js';
import { AttemptsRunnerController } from './attempts.runner.controller.js';
import { RunnerAttemptsService } from './runner-attempts.service.js';

/** The push-only routes runner pods report through, with their attempt's job token. */
@Module({
  imports: [AuthModule, SecretsModule, ChatModule],
  controllers: [AttemptsRunnerController],
  providers: [RunnerAttemptsService],
})
export class RunnerAttemptsModule {}
