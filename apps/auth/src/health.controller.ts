import { loadServiceConfig } from '@kovcheg/config';
import { createServiceHealth, serviceHealthJsonSchema } from '@kovcheg/contracts';
import type { ServiceHealth } from '@kovcheg/contracts';
import { Controller, Get, Inject, Optional, ServiceUnavailableException } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';

import { authRuntimeToken } from './a2/runtime.js';
import type { AuthRuntime } from './a2/runtime.js';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(
    @Optional() @Inject(authRuntimeToken) private readonly runtime: AuthRuntime | undefined,
  ) {}

  @ApiOkResponse({
    description: 'The auth process is running.',
    schema: serviceHealthJsonSchema,
  })
  @Get('live')
  live(): ServiceHealth {
    return createServiceHealth('auth', 'live', { build: loadServiceConfig('auth').build });
  }

  @ApiOkResponse({
    description: 'The auth process is ready for local requests.',
    schema: serviceHealthJsonSchema,
  })
  @Get('ready')
  async ready(): Promise<ServiceHealth> {
    if (this.runtime === undefined || !(await this.runtime.isReady())) {
      throw new ServiceUnavailableException('Auth dependencies are unavailable');
    }
    return createServiceHealth('auth', 'ready', { build: loadServiceConfig('auth').build });
  }
}
