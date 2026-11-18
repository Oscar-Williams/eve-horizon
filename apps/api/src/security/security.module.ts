import { Global, Module } from '@nestjs/common';
import { SecurityController } from './security.controller.js';
import { SecurityService } from './security.service.js';

/** Security profiles: available to every module so each rule can call the gate. */
@Global()
@Module({
  controllers: [SecurityController],
  providers: [SecurityService],
  exports: [SecurityService],
})
export class SecurityModule {}
