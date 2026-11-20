import { Logger, Module, type OnApplicationBootstrap, type OnModuleInit } from '@nestjs/common';
import type { Db } from '@eve/db';
import { DeployerModule } from '../deployer/deployer.module';
import { K8sService } from '../deployer/k8s.service';
import { EgressPolicies } from './egress-policies.js';
import { ManagedNamespaceReconciler } from './managed-namespaces.js';
import { NetworkController } from './network.controller.js';
import { registerRunnerEgress } from './runner-egress.js';

/**
 * egress.default_deny and egress.allow_hosts: env and runner policies,
 * reconcile, and the dispatch hook. At start-up, the managed-namespace
 * reconcile labels and binds env namespaces from earlier releases.
 */
@Module({
  imports: [DeployerModule],
  controllers: [NetworkController],
  providers: [{
    provide: EgressPolicies,
    inject: ['DB', K8sService],
    useFactory: (db: Db, k8s: K8sService) => new EgressPolicies(db, k8s),
  }, {
    provide: ManagedNamespaceReconciler,
    inject: ['DB', K8sService],
    useFactory: (db: Db, k8s: K8sService) => new ManagedNamespaceReconciler(db, k8s),
  }],
})
export class NetworkModule implements OnModuleInit, OnApplicationBootstrap {
  private readonly logger = new Logger(NetworkModule.name);

  constructor(
    private readonly egress: EgressPolicies,
    private readonly namespaces: ManagedNamespaceReconciler,
    private readonly k8s: K8sService,
  ) {}

  onModuleInit(): void {
    registerRunnerEgress(this.egress);
  }

  /** In the background: start-up never waits on the cluster. */
  onApplicationBootstrap(): void {
    if (!this.k8s.isAvailable()) return;
    void this.namespaces.reconcile().catch((error: unknown) => {
      this.logger.warn(`Managed-namespace reconcile failed: ${error instanceof Error ? error.message : String(error)}`);
    });
  }
}
