import { Module } from '@nestjs/common';
import { OrgQueriesController } from './org-queries.controller.js';
import { OrgQueriesService } from './org-queries.service.js';
import { SecurityModule } from '../security/security.module.js';

@Module({
  imports: [SecurityModule],
  controllers: [OrgQueriesController],
  providers: [OrgQueriesService],
  exports: [OrgQueriesService],
})
export class OrgQueriesModule {}
