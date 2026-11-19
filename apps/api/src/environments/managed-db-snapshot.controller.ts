import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Body,
  Query,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { RequirePermission } from '../auth/permission.decorator.js';
import { ENVDB_EXPORT_RULE, RbacService } from '../auth/rbac.service.js';
import { CurrentUser } from '../common/request-decorators.js';
import type { AuthUser } from '../auth/auth.types.js';
import { ManagedDbSnapshotService } from './managed-db-snapshot.service.js';
import {
  CreateSnapshotRequestSchema,
  RestoreSnapshotRequestSchema,
  type CreateSnapshotRequest,
  type RestoreSnapshotRequest,
} from '@eve/shared';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe.js';

@ApiTags('managed-db-snapshots')
@ApiBearerAuth()
@Controller()
export class ManagedDbSnapshotController {
  constructor(
    private readonly snapshotService: ManagedDbSnapshotService,
    private readonly rbac: RbacService,
  ) {}

  @RequirePermission('envdb:write')
  @Post('projects/:id/envs/:name/db/snapshots')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create managed DB snapshot' })
  async createSnapshot(
    @Param('id') projectId: string,
    @Param('name') envName: string,
    @Body(new ZodValidationPipe(CreateSnapshotRequestSchema)) body: CreateSnapshotRequest,
  ) {
    return this.snapshotService.createSnapshot(projectId, envName, {
      retention: body.retention,
    });
  }

  @RequirePermission('envdb:read')
  @Get('projects/:id/envs/:name/db/snapshots')
  @ApiOperation({ summary: 'List managed DB snapshots' })
  async listSnapshots(
    @Param('id') projectId: string,
    @Param('name') envName: string,
    @Query('status') status?: string,
    @Query('limit') limit?: string,
  ) {
    return this.snapshotService.listSnapshots(projectId, envName, {
      status,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
  }

  @RequirePermission('envdb:read')
  @Get('projects/:id/envs/:name/db/snapshots/:snapshotId')
  @ApiOperation({ summary: 'Get managed DB snapshot details' })
  async getSnapshot(
    @Param('id') projectId: string,
    @Param('name') envName: string,
    @Param('snapshotId') snapshotId: string,
  ) {
    return this.snapshotService.getSnapshot(projectId, envName, snapshotId);
  }

  @RequirePermission('envdb:write')
  @Delete('projects/:id/envs/:name/db/snapshots/:snapshotId')
  @ApiOperation({ summary: 'Delete managed DB snapshot' })
  async deleteSnapshot(
    @Param('id') projectId: string,
    @Param('name') envName: string,
    @Param('snapshotId') snapshotId: string,
  ) {
    return this.snapshotService.deleteSnapshot(projectId, envName, snapshotId);
  }

  @RequirePermission('envdb:write')
  @Post('projects/:id/envs/:name/db/restore')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Restore managed DB from snapshot' })
  async restoreFromSnapshot(
    @Param('id') projectId: string,
    @Param('name') envName: string,
    @Body(new ZodValidationPipe(RestoreSnapshotRequestSchema)) body: RestoreSnapshotRequest,
  ) {
    return this.snapshotService.restoreFromSnapshot(projectId, envName, body);
  }

  /**
   * A full dump, presigned for an hour: it needs `envdb:export` (rule
   * envdb.export). Outside a strict project `envdb:read` stands for it.
   */
  @RequirePermission('envdb:read')
  @Get('projects/:id/envs/:name/db/snapshots/:snapshotId/download')
  @ApiOperation({ summary: 'Get presigned download URL for snapshot (needs envdb:export under a strict project)' })
  async downloadSnapshot(
    @Param('id') projectId: string,
    @Param('name') envName: string,
    @Param('snapshotId') snapshotId: string,
    @CurrentUser() caller?: AuthUser,
  ) {
    // No caller means authentication is disabled (local development).
    if (caller) {
      await this.rbac.requireOperatorRight(caller, projectId, 'envdb:export', ENVDB_EXPORT_RULE, { env: envName, snapshot: snapshotId });
    }
    return this.snapshotService.getDownloadUrl(projectId, envName, snapshotId);
  }

  @RequirePermission('envdb:read')
  @Get('projects/:id/envs/:name/db/backup-status')
  @ApiOperation({ summary: 'Get managed DB backup schedule and status' })
  async getBackupStatus(
    @Param('id') projectId: string,
    @Param('name') envName: string,
  ) {
    return this.snapshotService.getBackupStatus(projectId, envName);
  }
}
