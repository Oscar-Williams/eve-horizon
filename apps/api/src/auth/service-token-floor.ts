/**
 * The earliest `iat` an environment's service tokens (and the app-link tokens
 * injected into its services) may carry, in whole seconds: the environment's
 * creation, or its `service_tokens_not_before` when that is later. A token
 * issued before the environment row was created belongs to an earlier
 * environment of the same name; one issued before the floor was revoked by
 * `eve env rotate-service-tokens`. Null when neither is known.
 */
export function serviceTokenFloor(environment: {
  created_at?: Date | string | null;
  service_tokens_not_before?: Date | string | null;
}): number | null {
  const floors = [environment.created_at, environment.service_tokens_not_before]
    .map(wholeSeconds)
    .filter((value): value is number => value !== null);
  return floors.length > 0 ? Math.max(...floors) : null;
}

function wholeSeconds(value: Date | string | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}
