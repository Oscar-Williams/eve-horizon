import { z } from 'zod';
import { PaginationSchema } from './common.js';

export const SecretTypeSchema = z.enum(['env_var', 'file', 'github_token', 'ssh_key']);
export type SecretType = z.infer<typeof SecretTypeSchema>;

export const CreateSecretRequestSchema = z.object({
  key: z.string().min(1),
  value: z.string().min(1),
  type: SecretTypeSchema.optional().default('env_var'),
});

export type CreateSecretRequest = z.infer<typeof CreateSecretRequestSchema>;

export const UpdateSecretRequestSchema = z.object({
  value: z.string().min(1).optional(),
  type: SecretTypeSchema.optional(),
});

export type UpdateSecretRequest = z.infer<typeof UpdateSecretRequestSchema>;

export const SecretResponseSchema = z.object({
  id: z.string(),
  scope_type: z.enum(['user', 'org', 'project', 'system']),
  scope_id: z.string(),
  key: z.string(),
  type: SecretTypeSchema,
  created_at: z.string(),
  updated_at: z.string(),
});

export type SecretResponse = z.infer<typeof SecretResponseSchema>;

export const SecretMaskedResponseSchema = SecretResponseSchema.extend({
  /** A fixed mask: never a character of the value. */
  masked_value: z.string(),
  /** The value's length in characters. */
  length: z.number().int().nonnegative(),
  /** 12 hex of an HMAC over the scope, key and value: equal values in one place match. */
  fingerprint: z.string(),
});

export type SecretMaskedResponse = z.infer<typeof SecretMaskedResponseSchema>;

export const SecretListResponseSchema = z.object({
  data: z.array(SecretResponseSchema),
  pagination: PaginationSchema,
});

export type SecretListResponse = z.infer<typeof SecretListResponseSchema>;

export const SecretResolveRequestSchema = z.object({
  project_id: z.string(),
  user_id: z.string().optional(),
  /** The job the secrets are delivered to, so its secret binding can be judged. */
  job_id: z.string().optional(),
  /** That job's selected harness, whose provider keys a binding always keeps. */
  harness: z.string().optional(),
});

export type SecretResolveRequest = z.infer<typeof SecretResolveRequestSchema>;

export const SecretResolveItemSchema = z.object({
  key: z.string(),
  value: z.string(),
  type: SecretTypeSchema,
  scope_type: z.enum(['user', 'org', 'project', 'system']).optional(),
  scope_id: z.string().optional(),
});

export type SecretResolveItem = z.infer<typeof SecretResolveItemSchema>;

export const SecretResolveResponseSchema = z.object({
  data: z.array(SecretResolveItemSchema),
});

export type SecretResolveResponse = z.infer<typeof SecretResolveResponseSchema>;

export const SecretMissingItemSchema = z.object({
  key: z.string(),
  hints: z.array(z.string()),
  suggestion: z.string().optional(),
});

export type SecretMissingItem = z.infer<typeof SecretMissingItemSchema>;

export const SecretValidationResultSchema = z.object({
  missing: z.array(SecretMissingItemSchema),
});

export type SecretValidationResult = z.infer<typeof SecretValidationResultSchema>;

export const SecretValidateRequestSchema = z.object({
  keys: z.array(z.string()).min(1).optional(),
  manifest_yaml: z.string().min(1).optional(),
});

export type SecretValidateRequest = z.infer<typeof SecretValidateRequestSchema>;

export const SecretEnsureRequestSchema = z.object({
  keys: z.array(z.string()).min(1),
});

export type SecretEnsureRequest = z.infer<typeof SecretEnsureRequestSchema>;

export const SecretExportRequestSchema = z.object({
  keys: z.array(z.string()).min(1),
});

export type SecretExportRequest = z.infer<typeof SecretExportRequestSchema>;

export const SecretExportItemSchema = z.object({
  key: z.string(),
  value: z.string(),
});

export type SecretExportItem = z.infer<typeof SecretExportItemSchema>;

export const SecretEnsureResponseSchema = z.object({
  created: z.array(z.string()),
  existing: z.array(z.string()),
  /** The values this call generated: shown once, here, and never again under a strict project. */
  values: z.array(SecretExportItemSchema),
});

export type SecretEnsureResponse = z.infer<typeof SecretEnsureResponseSchema>;

export const SecretExportResponseSchema = z.object({
  data: z.array(SecretExportItemSchema),
});

export type SecretExportResponse = z.infer<typeof SecretExportResponseSchema>;

export const SecretsReencryptRequestSchema = z.object({
  /** Count rows by format and change nothing. */
  dry_run: z.boolean().optional(),
});

export type SecretsReencryptRequest = z.infer<typeof SecretsReencryptRequestSchema>;

export const SecretStorageCountsSchema = z.object({
  secrets: z.object({ v1: z.number(), v2: z.number(), other: z.number() }),
  integration_tokens: z.object({ plain: z.number(), sealed: z.number() }),
  oauth_client_secrets: z.object({ plain: z.number(), sealed: z.number() }),
});

export type SecretStorageCounts = z.infer<typeof SecretStorageCountsSchema>;

export const SecretsReencryptResponseSchema = z.object({
  dry_run: z.boolean(),
  /** The format new writes use after this call. */
  write_format: z.enum(['v1', 'v2']),
  before: SecretStorageCountsSchema,
  after: SecretStorageCountsSchema,
  reencrypted: z.object({
    secrets: z.number(),
    integration_tokens: z.number(),
    oauth_client_secrets: z.number(),
  }),
  skipped: z.object({
    /** Rows written while this pass ran: they keep their new value; the next pass takes them. */
    changed: z.number(),
    /** Rows the master key cannot open; set them again. */
    unreadable: z.number(),
  }),
  /** v1 secrets and plain OAuth columns left. */
  remaining: z.number(),
});

export type SecretsReencryptResponse = z.infer<typeof SecretsReencryptResponseSchema>;
