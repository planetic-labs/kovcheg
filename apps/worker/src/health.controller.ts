import { createServiceHealth } from '@kovcheg/contracts';
import type { ServiceHealth } from '@kovcheg/contracts';
import { Controller, Get } from '@nestjs/common';

@Controller('health')
export class HealthController {
  @Get('live')
  live(): ServiceHealth {
    return createServiceHealth('worker', 'live');
  }

  @Get('ready')
  ready(): ServiceHealth {
    return createServiceHealth('worker', 'ready');
  }
}
