import { loadServiceConfig } from '@kovcheg/config';
import { createServiceHealth, serviceHealthJsonSchema } from '@kovcheg/contracts';
import type { ServiceHealth } from '@kovcheg/contracts';
import { Controller, Get, Inject, ServiceUnavailableException } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';

import type { RealtimeTransportReadiness } from './realtime/realtime.module.js';
import { realtimeTransportReadinessToken } from './realtime/realtime.module.js';
import type { RealtimeRepository } from './realtime/realtime.repository.js';
import { realtimeRepositoryToken } from './realtime/realtime.repository.js';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(
    @Inject(realtimeRepositoryToken) private readonly repository: RealtimeRepository,
    @Inject(realtimeTransportReadinessToken)
    private readonly transport: RealtimeTransportReadiness,
  ) {}

  @ApiOkResponse({
    description: 'The API process is running.',
    schema: serviceHealthJsonSchema,
  })
  @Get('live')
  live(): ServiceHealth {
    return createServiceHealth('api', 'live', { build: loadServiceConfig('api').build });
  }

  @ApiOkResponse({
    description: 'The API process is ready for local requests.',
    schema: serviceHealthJsonSchema,
  })
  @Get('ready')
  async ready(): Promise<ServiceHealth> {
    if (!this.transport.isReady() || !(await this.repository.isReady())) {
      throw new ServiceUnavailableException('API dependencies are unavailable');
    }
    return createServiceHealth('api', 'ready', { build: loadServiceConfig('api').build });
  }
}
