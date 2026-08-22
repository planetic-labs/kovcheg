import { loadServiceConfig } from '@kovcheg/config';
import { createServiceHealth } from '@kovcheg/contracts';
import type { ServiceHealth } from '@kovcheg/contracts';
import { Controller, Get } from '@nestjs/common';

@Controller('health')
export class HealthController {
  @Get('live')
  live(): ServiceHealth {
    return createServiceHealth('worker', 'live', {
      build: loadServiceConfig('worker').build,
    });
  }

  @Get('ready')
  ready(): ServiceHealth {
    return createServiceHealth('worker', 'ready', {
      build: loadServiceConfig('worker').build,
    });
  }
}
