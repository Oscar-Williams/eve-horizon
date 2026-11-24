import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { IN_CLUSTER_KUBECONFIG, kubectlInvocation } from './k8s-runner.js';

const IN_CLUSTER = { PATH: '/usr/bin', HOME: '/home/node', KUBERNETES_SERVICE_HOST: '10.2.0.1', KUBERNETES_SERVICE_PORT: '443' };
const present = (path: string) => path === IN_CLUSTER_KUBECONFIG;
const absent = () => false;

describe('kubectlInvocation', () => {
  it("inside a cluster, gives kubectl the image's kubeconfig and the service address", () => {
    const { args, env } = kubectlInvocation(['get', 'pod', 'p'], IN_CLUSTER, present);
    expect(env.KUBECONFIG).toBe(IN_CLUSTER_KUBECONFIG);
    expect(args).toEqual(['--request-timeout=10s', '--server=https://10.2.0.1:443', 'get', 'pod', 'p']);
  });

  it('brackets an IPv6 service address', () => {
    const { args } = kubectlInvocation(['get', 'ns'], { ...IN_CLUSTER, KUBERNETES_SERVICE_HOST: 'fd00:10:2::1' }, present);
    expect(args).toContain('--server=https://[fd00:10:2::1]:443');
  });

  it('leaves an explicit KUBECONFIG alone and adds no server', () => {
    const { args, env } = kubectlInvocation(['get', 'ns'], { ...IN_CLUSTER, KUBECONFIG: '/dev/kube.yaml' }, present);
    expect(env.KUBECONFIG).toBe('/dev/kube.yaml');
    expect(args).toEqual(['--request-timeout=10s', 'get', 'ns']);
  });

  it('changes nothing outside a cluster or without the image file', () => {
    const outside = kubectlInvocation(['get', 'ns'], { PATH: '/usr/bin' }, present);
    expect(outside.env.KUBECONFIG).toBeUndefined();
    expect(outside.args).toEqual(['--request-timeout=10s', 'get', 'ns']);
    const noFile = kubectlInvocation(['get', 'ns'], IN_CLUSTER, absent);
    expect(noFile.env.KUBECONFIG).toBeUndefined();
    expect(noFile.args).toEqual(['--request-timeout=10s', 'get', 'ns']);
  });

  it('refuses a service address that is not a plain host and port', () => {
    for (const bad of [
      { KUBERNETES_SERVICE_HOST: 'evil.example/x?', KUBERNETES_SERVICE_PORT: '443' },
      { KUBERNETES_SERVICE_HOST: '10.2.0.1', KUBERNETES_SERVICE_PORT: '443 --insecure-skip-tls-verify' },
      { KUBERNETES_SERVICE_HOST: '', KUBERNETES_SERVICE_PORT: '443' },
    ]) {
      const { args, env } = kubectlInvocation(['get', 'ns'], { ...IN_CLUSTER, ...bad }, present);
      expect(env.KUBECONFIG).toBeUndefined();
      expect(args.some((a) => a.startsWith('--server'))).toBe(false);
    }
  });

  it('turns kuberc off in and out of a cluster', () => {
    expect(kubectlInvocation(['get', 'ns'], IN_CLUSTER, present).env.KUBERC).toBe('off');
    expect(kubectlInvocation(['get', 'ns'], { PATH: '/usr/bin', KUBERC: '/home/node/.kube/kuberc' }, absent).env.KUBERC).toBe('off');
  });

  it('passes no worker credential to kubectl', () => {
    const { env } = kubectlInvocation(['get', 'ns'], { ...IN_CLUSTER, DATABASE_URL: 'postgres://secret', EVE_INTERNAL_API_KEY: 'k' }, present);
    expect(env).not.toHaveProperty('DATABASE_URL');
    expect(env).not.toHaveProperty('EVE_INTERNAL_API_KEY');
    expect(env.KUBERNETES_SERVICE_HOST).toBe('10.2.0.1');
  });

  it('the image kubeconfig names only the mounted token and CA', () => {
    const file = readFileSync(join(__dirname, '..', '..', '..', '..', 'docker', 'worker', 'in-cluster.kubeconfig'), 'utf8');
    expect(file).toContain('tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token');
    expect(file).toContain('certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt');
    expect(file).not.toMatch(/^\s*token:/m);
    expect(file).not.toMatch(/insecure-skip-tls-verify/);
    expect(file).not.toMatch(/client-key|client-certificate/);
  });

  it('the image installs it root-owned and read-only', () => {
    const dockerfile = readFileSync(join(__dirname, '..', '..', 'Dockerfile'), 'utf8');
    expect(dockerfile).toContain(`COPY docker/worker/in-cluster.kubeconfig ${IN_CLUSTER_KUBECONFIG}`);
    expect(dockerfile).toMatch(/chown -R root:root \/etc\/eve\/kube/);
    expect(dockerfile).toMatch(/chmod 0444 \/etc\/eve\/kube\/in-cluster\.kubeconfig/);
  });
});
