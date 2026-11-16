/**
 * App-link tokens for a running agent job.
 *
 * Each app link the job resolved (`hints.resolved_app_links`) gets a token for
 * the `job:<id>` principal, bound to the job's attempt: it stops working when
 * the attempt ends. Tokens last an hour; a longer job refreshes them with its
 * own job token (`POST /jobs/{job_id}/app-link-tokens`, `eve job
 * app-link-token`).
 */

import type { HarnessInvocation } from '../types/harness.js';
import type { AppApiInfo, AppApiCliInfo } from '../schemas/api-source.js';
import { mintAppLinkToken } from '../api-client/auth-client.js';

export const JOB_APP_LINK_TOKEN_TTL_SECONDS = 60 * 60;

export interface ResolvedAppLink {
  name: string;
  alias: string;
  subscription_id: string;
  type?: string;
  base_url: string;
  scopes?: string[];
  producer_project_id?: string;
  producer_env?: string;
  cli?: AppApiCliInfo;
}

export async function mintJobAppLinkTokens(
  invocation: Pick<HarnessInvocation, 'jobId' | 'attemptId'>,
  links: ResolvedAppLink[],
): Promise<AppApiInfo[]> {
  const withTokens: AppApiInfo[] = [];
  for (const link of links) {
    const token = await mintAppLinkToken({
      subscriptionId: link.subscription_id,
      consumerPrincipal: `job:${invocation.jobId}`,
      producerEnv: link.producer_env,
      ttlSeconds: JOB_APP_LINK_TOKEN_TTL_SECONDS,
      ...(invocation.attemptId ? { attemptId: invocation.attemptId } : {}),
    });
    withTokens.push({
      ...link,
      origin: 'app_link',
      type: link.type ?? 'openapi',
      token: token?.access_token,
    });
  }
  return withTokens;
}
