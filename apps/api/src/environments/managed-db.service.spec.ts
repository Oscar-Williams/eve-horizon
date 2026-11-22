import { describe, expect, it } from 'vitest';
import { ManagedDbService } from './managed-db.service';

// `eve db status` reads GET .../db/managed: the declared roles as the
// manifest gave them, and the provisioned logins (never a password). A
// schema-owner role shows the schema it owns.

function serviceWith(tenant: Record<string, unknown>, roles: Array<Record<string, unknown>>): ManagedDbService {
  const svc = new ManagedDbService((() => Promise.resolve([])) as never);
  Object.assign(svc, {
    environments: { findByProjectAndName: async () => ({ id: 'env_1' }) },
    projects: { findById: async () => ({ id: 'proj_shop', org_id: 'org_acme' }) },
    managedDb: {
      listTenantsByOrg: async () => [tenant],
      listTenantRoles: async () => roles,
    },
  });
  return svc;
}

const tenant = {
  id: 'mdbt_1',
  org_id: 'org_acme',
  project_id: 'proj_shop',
  env_id: 'env_1',
  service_name: 'db',
  instance_id: 'mdbi_1',
  db_name: 'acme-shop-staging-1a2b3c',
  class: 'db.p1',
  desired_class: null,
  status: 'provisioning',
  credential_secret_ref: 'postgres://owner:secret@db.internal:5432/acme-shop-staging-1a2b3c',
  last_error_code: null,
  last_error_message: null,
  desired_extensions: [],
  enabled_extensions: [],
  desired_roles: [
    { name: 'app', grants: 'readwrite' },
    { name: 'gotrue', grants: { schema: 'auth', owner: true } },
  ],
  ready_at: null,
  created_at: new Date('2026-11-22T10:00:00Z'),
  updated_at: new Date('2026-11-22T10:00:00Z'),
};

describe('ManagedDbService status roles', () => {
  it('lists a schema-owner role with the schema it owns, and no credential', async () => {
    const svc = serviceWith(tenant, [
      {
        name: 'app', grants: 'readwrite', schema_name: null,
        db_user: 'acme-shop-staging-u-1a2b3c-app', credential_secret_ref: 'postgres://app:apppw@db.internal/x',
      },
      {
        name: 'gotrue', grants: 'owner', schema_name: 'auth',
        db_user: 'acme-shop-staging-u-1a2b3c-gotrue', credential_secret_ref: 'postgres://gotrue:gotruepw@db.internal/x',
      },
    ]);

    const status = await svc.getManagedDb('proj_shop', 'staging');

    expect(status.declared_roles).toEqual([
      { name: 'app', grants: 'readwrite' },
      { name: 'gotrue', grants: { schema: 'auth', owner: true } },
    ]);
    expect(status.roles).toEqual([
      { name: 'app', grants: 'readwrite', username: 'acme-shop-staging-u-1a2b3c-app' },
      { name: 'gotrue', grants: 'owner', schema: 'auth', username: 'acme-shop-staging-u-1a2b3c-gotrue' },
    ]);
    expect(JSON.stringify(status)).not.toMatch(/pw@/);
  });
});
