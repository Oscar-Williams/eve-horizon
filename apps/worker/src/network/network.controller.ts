import { BadRequestException, Body, Controller, HttpCode, Post } from '@nestjs/common';
import { EgressPolicies, type NetworkReconcileReport } from './egress-policies.js';

@Controller('network')
export class NetworkController {
  constructor(private readonly egress: EgressPolicies) {}

  /**
   * Bring env and runner egress policies in line with the profiles: one
   * project, an org's projects, or every project (which also removes the
   * runner policies of deleted projects). Called by the API after a profile
   * change and by `eve system security reconcile`.
   */
  @Post('reconcile')
  @HttpCode(200)
  async reconcile(@Body() body: { project_id?: unknown; org_id?: unknown } | undefined): Promise<NetworkReconcileReport> {
    const projectId = body?.project_id;
    const orgId = body?.org_id;
    for (const [name, value] of [['project_id', projectId], ['org_id', orgId]] as const) {
      if (value !== undefined && (typeof value !== 'string' || value.length === 0)) {
        throw new BadRequestException(`${name} must be a non-empty string`);
      }
    }
    return this.egress.reconcile({ projectId: projectId as string | undefined, orgId: orgId as string | undefined });
  }
}
