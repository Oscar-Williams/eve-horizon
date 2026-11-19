import { Module, type OnModuleInit } from '@nestjs/common';
import type { Db } from '@eve/db';
import { DeployerModule } from '../deployer/deployer.module';
import { K8sService } from '../deployer/k8s.service';
import { EgressPolicies } from './egress-policies.js';
import { NetworkController } from './network.controller.js';
import { registerRunnerEgress } from './runner-egress.js';

/** egress.default_deny: env and runner NetworkPolicies, reconcile, and the dispatch hook. */
@Module({
  imports: [DeployerModule],
  controllers: [NetworkController],
  providers: [{
    provide: EgressPolicies,
    inject: ['DB', K8sService],
    useFactory: (db: Db, k8s: K8sService) => new EgressPolicies(db, k8s),
  }],
})
export class NetworkModule implements OnModuleInit {
  constructor(private readonly egress: EgressPolicies) {}

  onModuleInit(): void {
    registerRunnerEgress(this.egress);
  }
}
