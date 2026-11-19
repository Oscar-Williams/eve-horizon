import {
  Body,
  Controller,
  DefaultValuePipe,
  Delete,
  Get,
  NotFoundException,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiParam, ApiQuery, ApiTags } from '@nestjs/swagger';
import { RequirePermission } from '../auth/permission.decorator.js';
import type { AuthUser } from '../auth/auth.service.js';
import { ScopedAccessService } from '../auth/scoped-access.service.js';
import { AgentMemoryService } from './agent-memory.service.js';
import { RbacService } from '../auth/rbac.service.js';
import type { Permission } from '../auth/permissions.js';
import { CorrelationId, CurrentUser } from '../common/request-decorators.js';

function normalizePath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed.startsWith('/')) return `/${trimmed}`;
  return trimmed;
}

function parseCsv(raw?: string): string[] {
  if (!raw) return [];
  return raw.split(',').map((item) => item.trim()).filter(Boolean);
}

@ApiTags('agent-memory')
@ApiBearerAuth()
@Controller()
export class AgentMemoryController {
  constructor(
    private readonly memory: AgentMemoryService,
    private readonly scopedAccess: ScopedAccessService,
    private readonly rbac: RbacService,
  ) {}

  @RequirePermission('orgdocs:write')
  @Post('orgs/:org_id/agents/:agent_slug/memory')
  @ApiOperation({ summary: 'Create/update an agent memory entry' })
  async setMemory(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Body() body: {
      category: 'learnings' | 'decisions' | 'runbooks' | 'context' | 'conventions' | 'user';
      key: string;
      content: string;
      mime_type?: string;
      confidence?: number;
      tags?: string[];
      supersedes?: string;
      metadata?: Record<string, unknown>;
      review_due?: string;
      expires_at?: string;
      lifecycle_status?: 'active' | 'stale' | 'archived' | 'expired';
    },
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    const path = this.memory.memoryPath(agentSlug, body.category, body.key);
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:write',
      user: caller,
      resource: {
        type: 'orgdocs',
        id: path,
        action: 'write',
      },
      request_id: correlationId,
    });
    return this.memory.setMemory(orgId, agentSlug, body, caller?.user_id, correlationId);
  }

  @RequirePermission('orgdocs:read')
  @Get('orgs/:org_id/agents/:agent_slug/memory')
  @ApiOperation({ summary: 'List memory entries for an agent/shared namespace' })
  @ApiQuery({ name: 'category', required: false })
  @ApiQuery({ name: 'tags', required: false, description: 'Comma-separated tags' })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  async listMemory(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Query('category') category: string | undefined,
    @Query('tags') tags: string | undefined,
    @Query('limit', new DefaultValuePipe(100), ParseIntPipe) limit: number,
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    const prefix = category
      ? this.memory.memoryPath(agentSlug, category, 'placeholder-key').replace('/placeholder-key.md', '/')
      : normalizePath(`/agents/${agentSlug}/memory/`);
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:read',
      user: caller,
      resource: {
        type: 'orgdocs',
        id: prefix,
        action: 'read',
      },
      request_id: correlationId,
    });
    return this.memory.listMemory(orgId, agentSlug, {
      category,
      tags: parseCsv(tags),
      limit,
    });
  }

  @RequirePermission('orgdocs:read')
  @Get('orgs/:org_id/agents/:agent_slug/memory/:key')
  @ApiOperation({ summary: 'Get one memory entry by key' })
  @ApiQuery({ name: 'category', required: false })
  async getMemory(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Param('key') key: string,
    @Query('category') category: string | undefined,
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    const path = category
      ? this.memory.memoryPath(agentSlug, category, key)
      : normalizePath(`/agents/${agentSlug}/memory/`);
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:read',
      user: caller,
      resource: {
        type: 'orgdocs',
        id: path,
        action: 'read',
      },
      request_id: correlationId,
    });
    return this.memory.getMemory(orgId, agentSlug, key, category);
  }

  @RequirePermission('orgdocs:write')
  @Put('orgs/:org_id/agents/:agent_slug/memory/:key')
  @ApiOperation({ summary: 'Update a memory entry by key' })
  async updateMemory(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Param('key') key: string,
    @Body() body: {
      category: 'learnings' | 'decisions' | 'runbooks' | 'context' | 'conventions' | 'user';
      content: string;
      mime_type?: string;
      confidence?: number;
      tags?: string[];
      supersedes?: string;
      metadata?: Record<string, unknown>;
      review_due?: string;
      expires_at?: string;
      lifecycle_status?: 'active' | 'stale' | 'archived' | 'expired';
    },
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    const path = this.memory.memoryPath(agentSlug, body.category, key);
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:write',
      user: caller,
      resource: {
        type: 'orgdocs',
        id: path,
        action: 'write',
      },
      request_id: correlationId,
    });
    return this.memory.setMemory(
      orgId,
      agentSlug,
      {
        ...body,
        key,
      },
      caller?.user_id,
      correlationId,
    );
  }

  @RequirePermission('orgdocs:write')
  @Delete('orgs/:org_id/agents/:agent_slug/memory/:key')
  @ApiOperation({ summary: 'Delete a memory entry by key/category' })
  @ApiQuery({ name: 'category', required: true })
  async deleteMemory(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Param('key') key: string,
    @Query('category') category: string,
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    const path = this.memory.memoryPath(agentSlug, category, key);
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:write',
      user: caller,
      resource: {
        type: 'orgdocs',
        id: path,
        action: 'write',
      },
      request_id: correlationId,
    });
    return this.memory.deleteMemory(orgId, agentSlug, category, key, caller?.user_id, correlationId);
  }

  @RequirePermission('orgdocs:read')
  @Get('orgs/:org_id/memory/search')
  @ApiOperation({ summary: 'Search memory namespaces' })
  async searchMemory(
    @Param('org_id') orgId: string,
    @Query('q') q: string,
    @Query('agent') agent: string | undefined,
    @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:read',
      user: caller,
      request_id: correlationId,
      reach: 'filtered',
    });
    const result = await this.memory.searchMemory(orgId, q, { agent, limit });
    return { ...result, data: await this.withinReach(orgId, result.data, caller) };
  }

  @RequirePermission('orgdocs:write')
  @Put('orgs/:org_id/agents/:agent_slug/kv/:namespace/:key')
  @ApiOperation({ summary: 'Set agent KV value with optional TTL' })
  async kvPut(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Param('namespace') namespace: string,
    @Param('key') key: string,
    @Body() body: { value: unknown; ttl_seconds?: number },
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:write',
      user: caller,
      // Names no org doc itself: judged by the path it acts on under a non-legacy org profile.
      reach: { type: 'orgdocs', id: this.memory.kvPath(agentSlug, namespace, key), action: 'write' },
      request_id: correlationId,
    });
    return this.memory.kvPut(orgId, agentSlug, namespace, key, body.value, body.ttl_seconds);
  }

  @RequirePermission('orgdocs:read')
  @Get('orgs/:org_id/agents/:agent_slug/kv/:namespace/:key')
  @ApiOperation({ summary: 'Get agent KV value' })
  async kvGet(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Param('namespace') namespace: string,
    @Param('key') key: string,
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:read',
      user: caller,
      // Names no org doc itself: judged by the path it acts on under a non-legacy org profile.
      reach: { type: 'orgdocs', id: this.memory.kvPath(agentSlug, namespace, key), action: 'read' },
      request_id: correlationId,
    });
    return this.memory.kvGet(orgId, agentSlug, namespace, key);
  }

  @RequirePermission('orgdocs:read')
  @Get('orgs/:org_id/agents/:agent_slug/kv/:namespace')
  @ApiOperation({ summary: 'List keys in an agent KV namespace' })
  async kvList(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Param('namespace') namespace: string,
    @Query('limit', new DefaultValuePipe(100), ParseIntPipe) limit: number,
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:read',
      user: caller,
      // Names no org doc itself: judged by the path it acts on under a non-legacy org profile.
      reach: { type: 'orgdocs', id: this.memory.kvPath(agentSlug, namespace), action: 'read' },
      request_id: correlationId,
    });
    return this.memory.kvList(orgId, agentSlug, namespace, limit);
  }

  @RequirePermission('orgdocs:read')
  @Post('orgs/:org_id/agents/:agent_slug/kv/:namespace/mget')
  @ApiOperation({ summary: 'Batch get keys in an agent KV namespace' })
  async kvMget(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Param('namespace') namespace: string,
    @Body() body: { keys?: string[] },
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:read',
      user: caller,
      // Names no org doc itself: judged by the path it acts on under a non-legacy org profile.
      reach: { type: 'orgdocs', id: this.memory.kvPath(agentSlug, namespace), action: 'read' },
      request_id: correlationId,
    });
    return this.memory.kvMget(orgId, agentSlug, namespace, body.keys ?? []);
  }

  @RequirePermission('orgdocs:write')
  @Delete('orgs/:org_id/agents/:agent_slug/kv/:namespace/:key')
  @ApiOperation({ summary: 'Delete agent KV value' })
  async kvDelete(
    @Param('org_id') orgId: string,
    @Param('agent_slug') agentSlug: string,
    @Param('namespace') namespace: string,
    @Param('key') key: string,
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:write',
      user: caller,
      // Names no org doc itself: judged by the path it acts on under a non-legacy org profile.
      reach: { type: 'orgdocs', id: this.memory.kvPath(agentSlug, namespace, key), action: 'write' },
      request_id: correlationId,
    });
    return this.memory.kvDelete(orgId, agentSlug, namespace, key);
  }

  @RequirePermission('orgdocs:read')
  @Get('orgs/:org_id/search')
  @ApiOperation({ summary: 'Unified org search across memory/docs/threads/attachments/events' })
  @ApiQuery({ name: 'q', required: true })
  @ApiQuery({ name: 'sources', required: false, description: 'Comma-separated sources' })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'agent', required: false })
  async unifiedSearch(
    @Param('org_id') orgId: string,
    @Query('q') q: string,
    @Query('sources') sources: string | undefined,
    @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
    @Query('agent') agent: string | undefined,
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:read',
      user: caller,
      request_id: correlationId,
      reach: 'filtered',
    });
    const result = await this.memory.unifiedSearch(orgId, q, {
      sources: parseCsv(sources),
      limit,
      agent,
    });
    const data = await this.withinProjectRights(result.data, caller);
    return { ...result, data: await this.withinReach(orgId, data, caller) };
  }

  /**
   * Search results stay within what the caller reaches, under the org's
   * profile (see ScopedAccessService.filterToReach): org docs and memory by
   * their path; for a job token also only its own project's attachments and
   * events, and no org threads, which are not in a token's scope.
   */
  private withinReach<T extends Record<string, unknown>>(orgId: string, rows: T[], caller: AuthUser | undefined): Promise<T[]> {
    return this.scopedAccess.filterToReach({
      org_id: orgId,
      user: caller,
      permission: 'orgdocs:read',
      items: rows,
      inReach: (row, reach) => {
        if (typeof row.path === 'string') {
          return reach.covers({ type: 'orgdocs', id: row.path, action: 'read' });
        }
        if (row.source === 'attachments' || row.source === 'events') {
          return reach.jobProjectId === undefined || row.project_id === reach.jobProjectId;
        }
        return reach.jobProjectId === undefined;
      },
    });
  }


  /**
   * Results that belong to a project (job attachments, events) stay only
   * where the caller holds the right a project route would need there, under
   * the project's profile (see RbacService.requireProjectAccessFromOrgRoute).
   */
  private async withinProjectRights<T extends Record<string, unknown>>(rows: T[], caller: AuthUser | undefined): Promise<T[]> {
    const needs: Record<string, Permission> = { attachments: 'jobs:read', events: 'events:read' };
    const decided = new Map<string, boolean>();
    const kept: T[] = [];
    for (const row of rows) {
      const permission = needs[String(row.source)];
      const projectId = typeof row.project_id === 'string' ? row.project_id : null;
      if (!permission || !projectId) {
        kept.push(row);
        continue;
      }
      const key = `${projectId}|${permission}`;
      if (!decided.has(key)) {
        decided.set(key, await this.rbac.mayReachProjectFromOrgRoute(caller, projectId, [permission], { listing: 'org_search' }));
      }
      if (decided.get(key)) kept.push(row);
    }
    return kept;
  }

  @RequirePermission('threads:write')
  @Post('orgs/:org_id/threads/:thread_id/distill')
  @ApiOperation({ summary: 'Distill thread messages into durable docs/memory' })
  @ApiParam({ name: 'thread_id', type: String })
  async distillThread(
    @Param('org_id') orgId: string,
    @Param('thread_id') threadId: string,
    @Body() body: {
      to_path?: string;
      agent?: string;
      category?: 'learnings' | 'decisions' | 'runbooks' | 'context' | 'conventions';
      key?: string;
      prompt?: string;
      auto?: boolean;
      threshold?: number;
      interval?: string;
    },
    @CurrentUser() caller: AuthUser | undefined,
    @CorrelationId() correlationId: string | undefined,
  ) {
    // Distillation writes to org docs — assert orgdocs:write in addition to threads:write
    await this.scopedAccess.assert({
      org_id: orgId,
      permission: 'orgdocs:write',
      user: caller,
      // Names no org doc itself: judged by the path it acts on under a non-legacy org profile.
      reach: { type: 'orgdocs', id: this.memory.distillTargetPath(threadId, body), action: 'write' },
      request_id: correlationId,
    });
    // A project's thread is read with that project's rights. An org thread
    // has no project, and an unknown thread is left to the service's 404.
    const owner = await this.rbac.getResourceProjectContext('thread', threadId).catch((error: unknown) => {
      if (error instanceof NotFoundException) return null;
      throw error;
    });
    if (owner) {
      await this.rbac.requireProjectAccessFromOrgRoute(caller, owner.project_id, ['threads:read'], { thread: threadId });
    }
    return this.memory.distillThread(orgId, threadId, body, caller?.user_id, correlationId);
  }
}
