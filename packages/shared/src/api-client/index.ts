export { emitRunnerEvent } from './event-emitter.js';
export type {
  RunnerEmitterEventType,
  RunnerEmitterEventPayload,
  EmitEventResult,
} from './event-emitter.js';

export { resolveProjectSecrets, updateSecret } from './secret-client.js';
export type { SecretResolutionResult } from './secret-client.js';

export { fetchSigningKey, mintAppLinkToken, mintJobToken, mintServiceToken } from './auth-client.js';
export type { AppLinkTokenResult, JobTokenResult, ServiceTokenResult, SigningKeyResult } from './auth-client.js';

export {
  apiPath,
  internalApiFetch,
  internalAuthHeaders,
  isPlainApiPath,
  internalTokenMatches,
  INTERNAL_TOKEN_HEADER,
} from './internal-fetch.js';
export type { InternalApiFetchOptions } from './internal-fetch.js';

export {
  hasInternalCredential,
  identifyInternalCaller,
  internalKeyHash,
  judgeInternalCall,
  INTERNAL_CALLER_HASHES_ENV,
  INTERNAL_KEY_ENV,
  INTERNAL_KEY_SERVICES,
  SERVICE_KEY_HEADER,
} from './internal-keys.js';
export type { InternalCall, InternalKeyService } from './internal-keys.js';

export { RunnerApiClient, RunnerApiError } from './runner-client.js';
export type { RunnerApiClientOptions } from './runner-client.js';
