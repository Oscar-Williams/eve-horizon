import { Module } from '@nestjs/common';
import { JobsController } from './jobs.controller.js';
import { JobsService } from './jobs.service.js';
import { JobLogsService } from './job-logs.service.js';
import { JobReceiptsService } from './job-receipts.service.js';
import { JobBatchService } from './job-batch.service.js';
import { AuthModule } from '../auth/auth.module.js';
import { SecurityModule } from '../security/security.module.js';

@Module({
  // SecurityModule is global; it is named here because run jobs and approvals
  // are held to the project's security profile.
  imports: [AuthModule, SecurityModule],
  controllers: [JobsController],
  providers: [JobsService, JobLogsService, JobReceiptsService, JobBatchService],
  exports: [JobsService],
})
export class JobsModule {}
