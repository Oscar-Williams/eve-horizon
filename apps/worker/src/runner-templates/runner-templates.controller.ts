import { Controller, HttpCode, Post } from '@nestjs/common';
import { RunnerTemplatesService, type RunnerTemplatesReport } from './runner-templates.service.js';

@Controller('runner/templates')
export class RunnerTemplatesController {
  constructor(private readonly templates: RunnerTemplatesService) {}

  /** Render and apply the runner SandboxTemplates and SandboxWarmPools (internal key; called by reconcile). */
  @Post('reconcile')
  @HttpCode(200)
  reconcile(): Promise<RunnerTemplatesReport> {
    return this.templates.reconcile();
  }
}
