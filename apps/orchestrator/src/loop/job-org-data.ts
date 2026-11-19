/** The orchestrator's org data decision lives in @eve/shared, shared with the worker's executors. */
export {
  holdJobOrgData,
  withoutOrgData,
  scopeReachesOrgData,
  ORG_DATA_NO_USER_RULE,
  ORG_DATA_SCOPE_UNJUDGED_RULE,
  ORG_DATA_UNSCOPED_RULE,
  type DecideOrgDataRule,
} from '@eve/shared';
