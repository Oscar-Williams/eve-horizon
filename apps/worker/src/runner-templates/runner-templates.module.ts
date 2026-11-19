import { Module } from '@nestjs/common';
import { RunnerTemplatesController } from './runner-templates.controller.js';
import { RunnerTemplatesService } from './runner-templates.service.js';

@Module({
  controllers: [RunnerTemplatesController],
  providers: [RunnerTemplatesService],
})
export class RunnerTemplatesModule {}
