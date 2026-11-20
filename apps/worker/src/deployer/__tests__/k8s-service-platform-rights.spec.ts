import { describe, expect, it, vi } from 'vitest';
import { K8sService } from '../k8s.service.js';

/**
 * In the platform namespace the worker may create and delete Secrets (kaniko
 * build credentials) but not read any, so eve-app and the platform's other
 * Secrets stay out of its reach: createSecret creates first and replaces only
 * on a conflict, never reading.
 */
function k8sError(statusCode: number): Error {
  return Object.assign(new Error(`HTTP ${statusCode}`), { statusCode, response: { statusCode } });
}

function k8sWith() {
  const coreApi = {
    readNamespacedSecret: vi.fn().mockRejectedValue(k8sError(403)),
    createNamespacedSecret: vi.fn().mockResolvedValue({}),
    replaceNamespacedSecret: vi.fn().mockResolvedValue({}),
  };
  const k8s = new K8sService();
  Object.assign(k8s as any, { coreApi, available: true, logger: { log: vi.fn(), warn: vi.fn() } });
  return { k8s, coreApi };
}

describe('K8sService.createSecret', () => {
  it('creates a new Secret without reading it first', async () => {
    const { k8s, coreApi } = k8sWith();
    await k8s.createSecret('eve', 'kaniko-cfg-web-1', { 'config.json': '{}' });
    expect(coreApi.readNamespacedSecret).not.toHaveBeenCalled();
    expect(coreApi.createNamespacedSecret).toHaveBeenCalledWith('eve', expect.objectContaining({
      metadata: { name: 'kaniko-cfg-web-1', namespace: 'eve' },
      stringData: { 'config.json': '{}' },
    }));
  });

  it('replaces one that exists, still without reading it', async () => {
    const { k8s, coreApi } = k8sWith();
    coreApi.createNamespacedSecret.mockRejectedValueOnce(k8sError(409));
    await k8s.createSecret('eve-acme-shop-prod', 'app', { k: 'v' });
    expect(coreApi.readNamespacedSecret).not.toHaveBeenCalled();
    expect(coreApi.replaceNamespacedSecret).toHaveBeenCalledWith('app', 'eve-acme-shop-prod', expect.objectContaining({ stringData: { k: 'v' } }));
  });
});
