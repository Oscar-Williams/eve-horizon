import { describe, expect, it } from 'vitest';
import { isImplicitPublicIngress, isPublicIngress } from '../security/public-ingress.js';

describe('isPublicIngress', () => {
  const implicit = { ports: [3000] };
  const declared = { ports: [3000], 'x-eve': { ingress: { public: true, port: 3000 } } };
  const blockOnly = { ports: [3000], x_eve: { ingress: { port: 3000, domains: ['a.example.com'] } } };
  const closed = { ports: [3000], 'x-eve': { ingress: { public: false } } };

  it('decides by public: true when an ingress block exists, whatever the profile', () => {
    for (const profile of ['legacy', 'audit', 'strict'] as const) {
      expect(isPublicIngress(declared, profile)).toBe(true);
      expect(isPublicIngress(blockOnly, profile)).toBe(false);
      expect(isPublicIngress(closed, profile)).toBe(false);
    }
  });

  it('keeps a service with ports and no block public except under strict', () => {
    expect(isPublicIngress(implicit, 'legacy')).toBe(true);
    expect(isPublicIngress(implicit, 'audit')).toBe(true);
    expect(isPublicIngress(implicit, 'strict')).toBe(false);
    expect(isImplicitPublicIngress(implicit)).toBe(true);
    expect(isImplicitPublicIngress(declared)).toBe(false);
  });

  it('never makes a service without ports public', () => {
    expect(isPublicIngress({ 'x-eve': { role: 'worker' } }, 'legacy')).toBe(false);
    expect(isImplicitPublicIngress({ ports: [] })).toBe(false);
  });
});
